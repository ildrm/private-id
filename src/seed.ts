import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { createServices } from "./services.js";
import type { Database } from "./repository.js";
import type { Config } from "./config.js";
import { secret, totp } from "./security.js";
import { requireThat } from "./errors.js";
export async function seed(db: Database, config: Config) {
  requireThat(
    config.mode === "development" && !config.enableBilling,
    "DEVELOPMENT_ONLY",
    "Synthetic seeding requires development mode with live billing disabled",
  );
  if (await db.transaction((tx) => tx.get("metadata", "synthetic-seed")))
    return {
      status: "already_seeded",
      credentialsFile: resolve(".data/synthetic-accounts.json"),
    };
  const s = await createServices(db, config),
    batch = randomUUID().slice(0, 8),
    result: Record<string, unknown> = {};
  async function account(name: string, staff = false) {
    const email = `${name}-${batch}@synthetic.test`,
      password = `Synthetic-${secret()}`;
    const user = await s.accounts.register({ email, password });
    // Explicit synthetic-only setup must not race the live mail worker.
    await db.transaction(async (tx) => {
      const record = (await tx.get("accounts", user.id))!;
      record.emailVerified = true;
      await tx.put("accounts", record);
      for (const table of ["challenges", "mail"] as const)
        for (const row of await tx.list(table, {
          where: { userId: user.id },
          limit: 100,
        }))
          await tx.delete(table, row.id);
    });
    let login = await s.accounts.login({ email, password }),
      principal = (await s.accounts.authenticate(login.accessToken)).principal;
    const mfa = await s.accounts.startMfa(principal, password),
      codes = (
        await s.accounts.confirmMfa(
          principal,
          totp(mfa.secret, Math.floor(Date.now() / 30000)),
        )
      ).recoveryCodes;
    if (staff) {
      await s.accounts.enrollAdministrator(
        user.id,
        ["USER", "IDENTITY_ADMIN", "SECURITY_ADMIN"],
        "Explicit synthetic development seed",
      );
      login = await s.accounts.login({ email, password, code: codes.shift() });
      principal = (await s.accounts.authenticate(login.accessToken)).principal;
    }
    result[name] = {
      accountId: user.id,
      email,
      password,
      authenticatorKey: mfa.secret,
      recoveryCodes: codes,
    };
    return { user, principal };
  }
  const admin = await account("admin", true),
    owner = await account("issuer"),
    customer = await account("customer");
  const issuer = await s.credentials.registerIssuer(owner.principal, {
    issuerName: "Synthetic development issuer",
    jurisdiction: "DE",
    supportedClaims: [
      "adult_verified",
      "identity_verified",
      "unique_person",
      "jurisdiction",
    ],
    assuranceLevel: "LOW",
    policy:
      "Synthetic fixtures only. No real identity validation or legal eligibility is asserted.",
  });
  await s.credentials.reviewIssuer(
    admin.principal,
    issuer.id,
    "TRUSTED",
    "Synthetic development-only fixture; no real-world assurance",
  );
  await s.credentials.issue(owner.principal, {
    issuerId: issuer.id,
    userId: customer.user.id,
    type: "SyntheticIdentity",
    claims: {
      adult_verified: true,
      identity_verified: true,
      unique_person: true,
      jurisdiction: "DE",
    },
    birthDate: "1990-01-01",
    assuranceLevel: "LOW",
    evidenceReference: "synthetic-fixture-only",
    expiresInSeconds: 86400,
  });
  const verifier = await s.verifiers.register(owner.principal, {
    clientId: "synthetic-verifier",
    name: "Synthetic verifier",
    redirectUris: ["http://localhost:3002/callback"],
    allowedClaims: ["account_valid", "adult_verified", "jurisdiction"],
    environment: "SANDBOX",
    purpose: "Exercise explicit consent using synthetic development accounts.",
  });
  await s.verifiers.review(
    admin.principal,
    verifier.application.id,
    "ACTIVE",
    "Synthetic development-only relying party",
  );
  result.verifier = {
    clientId: verifier.application.id,
    clientSecret: verifier.clientSecret,
    redirectUri: "http://localhost:3002/callback",
  };
  await mkdir(".data", { recursive: true, mode: 0o700 });
  const credentialsFile = resolve(".data/synthetic-accounts.json");
  await writeFile(credentialsFile, JSON.stringify(result, null, 2), {
    mode: 0o600,
    flag: "wx",
  });
  await db.transaction((tx) =>
    tx.insert("metadata", {
      id: "synthetic-seed",
      createdAt: new Date().toISOString(),
      value: { batch, accounts: 3 },
    }),
  );
  return {
    status: "seeded",
    credentialsFile,
    accounts: 3,
    issuerId: issuer.id,
  };
}
