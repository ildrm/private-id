import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { MemoryDatabase } from "../src/repository.js";
import { testConfig } from "../src/config.js";
import { AccountService } from "../src/accounts.js";
import { CredentialService, isAdult } from "../src/credentials.js";
import { VerifierService } from "../src/verifiers.js";
import { ProofProvider } from "../src/proof-provider.js";
import { ProofService, pkceChallenge } from "../src/proofs.js";
import { planCatalog } from "../src/catalog.js";
import { createUser, testPassword } from "./helpers.js";
import { secret } from "../src/security.js";

async function fixture() {
  let time = Date.parse("2026-09-07T12:00:00.000Z");
  const clock = () => time,
    db = new MemoryDatabase(),
    config = testConfig(),
    plans = planCatalog(config),
    accounts = new AccountService(db, config, clock);
  const admin = await createUser(accounts, "admin@example.test", {
      roles: ["USER", "IDENTITY_ADMIN", "SECURITY_ADMIN"],
    }),
    issuer = await createUser(accounts, "issuer@example.test", { mfa: true }),
    user = await createUser(accounts, "customer@example.test");
  const credentials = new CredentialService(db, config, plans, clock),
    verifiers = new VerifierService(db, config, clock),
    provider = await ProofProvider.create(config, clock),
    proofs = new ProofService(db, config, plans, provider, clock);
  const trust = await credentials.registerIssuer(issuer.principal, {
    issuerName: "Synthetic test issuer",
    jurisdiction: "DE",
    supportedClaims: ["adult_verified", "unique_person", "kyc_valid"],
    assuranceLevel: "HIGH",
    policy: "Synthetic test evidence is accepted for this fixture only.",
  });
  await credentials.reviewIssuer(
    admin.principal,
    trust.id,
    "TRUSTED",
    "Reviewed synthetic fixture authority",
  );
  const client = await verifiers.register(issuer.principal, {
    clientId: "review-client",
    name: "Synthetic verifier",
    redirectUris: ["https://verifier.test/callback"],
    allowedClaims: ["account_valid", "adult_verified", "unique_person"],
    purpose: "Verify minimal synthetic identity claims for test access.",
    environment: "SANDBOX",
  });
  await verifiers.review(
    admin.principal,
    client.application.id,
    "ACTIVE",
    "Reviewed synthetic fixture application",
  );
  const credential = await credentials.issue(issuer.principal, {
    userId: user.user.id,
    issuerId: trust.id,
    type: "Identity evidence",
    claims: { adult_verified: true, unique_person: true },
    birthDate: "1990-01-01",
    evidenceReference: "synthetic-evidence-reference",
    assuranceLevel: "SUBSTANTIAL",
    expiresInSeconds: 3600,
  });
  const issue = async () => {
    const r = await proofs.create(user.principal, {
      clientId: client.application.id,
      requestedClaims: ["adult_verified", "account_valid"],
    });
    const result = await proofs.decide(user.principal, r.id, true);
    return result.proof!;
  };
  return {
    db,
    config,
    plans,
    accounts,
    admin,
    issuer,
    user,
    credentials,
    verifiers,
    provider,
    proofs,
    trust,
    client,
    credential,
    issue,
    clock,
    advance: (ms: number) => {
      time += ms;
    },
  };
}
test("selective proof uses a protected envelope and exactly one concurrent redemption succeeds", async () => {
  const f = await fixture(),
    token = await f.issue();
  const decoded = JSON.parse(
    Buffer.from(token.split(".")[1], "base64url").toString(),
  );
  assert.deepEqual(decoded.claims, {
    adult_verified: true,
    account_valid: true,
  });
  assert.equal(decoded.birthDate, undefined);
  assert.equal(decoded.exp - decoded.iat, 300);
  const results = await Promise.allSettled([
    f.proofs.verify(token, f.client.application.id, f.client.clientSecret),
    f.proofs.verify(token, f.client.application.id, f.client.clientSecret),
  ]);
  assert.equal(results.filter((x) => x.status === "fulfilled").length, 1);
  await assert.rejects(
    f.proofs.verify(token, f.client.application.id, "wrong-secret", false),
  );
});
for (const action of [
  "credential",
  "connection",
  "suspension",
  "deletion",
  "issuer",
  "verifier",
  "restore",
] as const)
  test(`unused proof remains invalid after ${action}`, async () => {
    const f = await fixture(),
      token = await f.issue();
    if (action === "credential")
      await f.credentials.revoke(
        f.issuer.principal,
        f.credential.id,
        "Synthetic compromised evidence",
      );
    if (action === "connection" || action === "restore") {
      await f.proofs.revokeAccess(f.user.principal, f.client.application.id);
      if (action === "restore")
        await f.proofs.restoreAccess(f.user.principal, f.client.application.id);
    }
    if (action === "suspension") {
      await f.accounts.setStatus(
        f.admin.principal,
        f.user.user.id,
        "SUSPENDED",
        "Security investigation",
      );
      await assert.rejects(f.accounts.authenticate(f.user.login.accessToken));
    }
    if (action === "deletion")
      await f.accounts.requestDeletion(f.user.principal, testPassword);
    if (action === "issuer")
      await f.credentials.reviewIssuer(
        f.admin.principal,
        f.trust.id,
        "SUSPENDED",
        "Issuer no longer trusted",
      );
    if (action === "verifier")
      await f.verifiers.review(
        f.admin.principal,
        f.client.application.id,
        "SUSPENDED",
        "Verifier no longer trusted",
      );
    await assert.rejects(
      f.proofs.verify(token, f.client.application.id, f.client.clientSecret),
    );
  });
test("revoked clients cannot obtain approval for an existing pending request", async () => {
  const f = await fixture();
  const r = await f.proofs.create(f.user.principal, {
    clientId: f.client.application.id,
    requestedClaims: ["adult_verified"],
  });
  await f.verifiers.review(
    f.admin.principal,
    f.client.application.id,
    "SUSPENDED",
    "Reviewing changed client policy",
  );
  await assert.rejects(f.proofs.decide(f.user.principal, r.id, true));
  assert.equal((await f.proofs.get(f.user.principal, r.id)).status, "PENDING");
});
test("unknown/reserved claims are rejected at registration and issuance", async () => {
  const f = await fixture();
  await assert.rejects(
    f.verifiers.register(f.issuer.principal, {
      clientId: "bad-client",
      name: "Bad verifier",
      redirectUris: ["https://verifier.test/callback"],
      allowedClaims: ["exp"],
      purpose: "Invalid reserved claims test.",
      environment: "SANDBOX",
    }),
  );
  await assert.rejects(
    f.credentials.issue(f.issuer.principal, {
      userId: f.user.user.id,
      issuerId: f.trust.id,
      type: "Invalid",
      claims: { exp: 4102444800 },
      evidenceReference: "synthetic-evidence-reference",
      assuranceLevel: "LOW",
      expiresInSeconds: 3600,
    }),
  );
});
test("unknown evidence does not become a false verification and conflicts roll back consent and quota", async () => {
  const f = await fixture();
  await f.credentials.issue(f.issuer.principal, {
    userId: f.user.user.id,
    issuerId: f.trust.id,
    type: "Conflicting uniqueness",
    claims: { unique_person: false },
    evidenceReference: "conflicting-evidence-reference",
    assuranceLevel: "SUBSTANTIAL",
    expiresInSeconds: 3600,
  });
  const r = await f.proofs.create(f.user.principal, {
    clientId: f.client.application.id,
    requestedClaims: ["unique_person"],
  });
  await assert.rejects(
    f.proofs.decide(f.user.principal, r.id, true),
    /Conflicting/,
  );
  assert.equal((await f.proofs.get(f.user.principal, r.id)).status, "PENDING");
  assert.equal((await f.proofs.dashboard(f.user.principal)).usage.proofs, 0);
});
test("expiration boundary and pending-request expiry are enforced with an injected clock", async () => {
  const f = await fixture(),
    token = await f.issue();
  f.advance(300000);
  await assert.rejects(
    f.proofs.verify(token, f.client.application.id, f.client.clientSecret),
  );
  const r = await f.proofs.create(f.user.principal, {
    clientId: f.client.application.id,
    requestedClaims: ["adult_verified"],
  });
  f.advance(600000);
  await assert.rejects(f.proofs.decide(f.user.principal, r.id, true), /fresh/);
});
test("authorization code is bound to client, redirect, PKCE, nonce, and a one-time transaction", async () => {
  const f = await fixture(),
    verifier = secret(),
    nonce = secret(),
    state = secret();
  const r = await f.proofs.create(f.user.principal, {
    clientId: f.client.application.id,
    requestedClaims: ["account_valid"],
    redirectUri: "https://verifier.test/callback",
    codeChallenge: pkceChallenge(verifier),
    nonce,
    state,
  });
  const result = await f.proofs.decide(f.user.principal, r.id, true),
    redirect = new URL(result.redirectUrl!);
  assert.equal(redirect.searchParams.get("state"), state);
  assert.equal(redirect.hash, "");
  const input = {
    clientId: f.client.application.id,
    clientSecret: f.client.clientSecret,
    code: redirect.searchParams.get("code")!,
    codeVerifier: verifier,
    redirectUri: "https://verifier.test/callback",
  };
  await assert.rejects(
    f.proofs.redeemCode({ ...input, codeVerifier: secret() }),
  );
  await assert.rejects(
    f.proofs.redeemCode({
      ...input,
      redirectUri: "https://attacker.test/callback",
    }),
  );
  assert.equal((await f.proofs.redeemCode(input)).nonce, nonce);
  await assert.rejects(f.proofs.redeemCode(input));
});
test("free-plan proof quota applies to successful issuance only", async () => {
  const f = await fixture();
  for (let i = 0; i < 20; i++) await f.issue();
  await assert.rejects(f.issue(), /allowance/);
  assert.equal((await f.proofs.dashboard(f.user.principal)).usage.proofs, 20);
});
test("calendar age policy uses March 1 for leap-day birthdays in non-leap years", () => {
  assert.equal(isAdult("2008-02-29", "2026-02-28"), false);
  assert.equal(isAdult("2008-02-29", "2026-03-01"), true);
  assert.equal(isAdult("2008-09-07", "2026-09-07"), true);
  assert.throws(() => isAdult("2027-01-01", "2026-09-07"));
});
test("signing-key rotation preserves pairwise subjects and supports permitted old public keys", async () => {
  const a = generateKeyPairSync("ed25519"),
    b = generateKeyPairSync("ed25519"),
    privatePem = (key: typeof a) =>
      key.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem = (key: typeof a) =>
      key.publicKey.export({ type: "spki", format: "pem" }).toString();
  const base = testConfig({
      signingPrivateKey: privatePem(a),
      signingKeyId: "a",
    }),
    first = await ProofProvider.create(base),
    second = await ProofProvider.create({
      ...base,
      signingPrivateKey: privatePem(b),
      signingKeyId: "b",
      signingPublicKeys: { a: publicPem(a) },
    });
  const token = await first.sign({
    userId: "user",
    clientId: "client",
    requestId: "r",
    jti: "j",
    claims: { account_valid: true },
    expiresAt: Math.floor(Date.now() / 1000) + 300,
  });
  assert.equal(
    first.subject("user", "client"),
    second.subject("user", "client"),
  );
  assert.equal((await second.verify(token, "client")).iss, base.issuer);
  assert.equal((await second.jwks()).keys.length, 2);
  assert.ok((await second.jwks()).keys.every((k) => !("d" in k)));
});

test("new contradictory evidence invalidates issued proofs and prevents approval of a stale preview", async () => {
  const f = await fixture(),
    request = await f.proofs.create(f.user.principal, {
      clientId: f.client.application.id,
      requestedClaims: ["unique_person"],
    });
  const preview = await f.proofs.preview(f.user.principal, request.id),
    issued = await f.proofs.decide(
      f.user.principal,
      request.id,
      true,
      preview.previewHash,
    );
  const pending = await f.proofs.create(f.user.principal, {
      clientId: f.client.application.id,
      requestedClaims: ["unique_person"],
    }),
    oldPreview = await f.proofs.preview(f.user.principal, pending.id);
  await f.credentials.issue(f.issuer.principal, {
    userId: f.user.user.id,
    issuerId: f.trust.id,
    type: "Updated identity evidence",
    claims: { unique_person: false },
    evidenceReference: "updated-synthetic-evidence",
    assuranceLevel: "HIGH",
    expiresInSeconds: 3600,
  });
  await assert.rejects(
    f.proofs.verify(
      issued.proof!,
      f.client.application.id,
      f.client.clientSecret,
    ),
  );
  await assert.rejects(
    f.proofs.decide(f.user.principal, pending.id, true, oldPreview.previewHash),
    /Evidence changed/,
  );
  assert.equal(
    (await f.proofs.get(f.user.principal, pending.id)).status,
    "PENDING",
  );
});
