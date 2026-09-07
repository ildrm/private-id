import { randomUUID, createHash } from "node:crypto";
import { z } from "zod";
import type { Config } from "./config.js";
import { authorize, activeAccount, type Principal } from "./accounts.js";
import type { Database, Transaction, Query } from "./repository.js";
import {
  claimsSchema,
  claimSchema,
  type Claims,
  type ClaimName,
  type ProofRequest,
  type Account,
} from "./models.js";
import { assuranceRank, liveIssuer, validateClaims } from "./credentials.js";
import { activeVerifier, verifyClientSecret } from "./verifiers.js";
import { ProofProvider } from "./proof-provider.js";
import { effectivePlan, consumeProofAllowance, type Plan } from "./catalog.js";
import { digest, equal, secret } from "./security.js";
import { AppError, requireThat } from "./errors.js";
import { audit } from "./audit.js";
export const requestInput = z
  .object({
    clientId: z.string().min(3).max(60),
    requestedClaims: z.array(claimSchema).min(1).max(12),
    redirectUri: z.url().optional(),
    state: z.string().min(16).max(512).optional(),
    nonce: z.string().min(16).max(256).optional(),
    codeChallenge: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/)
      .optional(),
  })
  .strict();
export const pkceChallenge = (verifier: string) =>
  createHash("sha256").update(verifier).digest("base64url");
export class ProofService {
  constructor(
    private db: Database,
    private config: Config,
    private plans: Plan[],
    public provider: ProofProvider,
    private clock = () => Date.now(),
  ) {}
  private now() {
    return new Date(this.clock()).toISOString();
  }
  safeRequest(request: ProofRequest) {
    const { codeHash, proofHash, disclosures, sources, ...safe } = request;
    return safe;
  }
  async create(principal: Principal, input: unknown) {
    const value = requestInput.parse(input);
    const federation = !!(
      value.redirectUri ||
      value.state ||
      value.nonce ||
      value.codeChallenge
    );
    requireThat(
      !federation ||
        (value.redirectUri &&
          value.state &&
          value.nonce &&
          value.codeChallenge),
      "INCOMPLETE_AUTHORIZATION",
      "Authorization requests require redirect URI, state, nonce, and S256 PKCE",
    );
    return this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock()),
        client = await activeVerifier(tx, value.clientId, this.config);
      requireThat(
        value.requestedClaims.every((c) => client.allowedClaims.includes(c)),
        "CLAIM_NOT_ALLOWED",
        "The verifier is not authorized to request these claims",
        403,
      );
      requireThat(
        !value.redirectUri || client.redirectUris.includes(value.redirectUri),
        "INVALID_REDIRECT",
        "Redirect URI must exactly match an approved value",
      );
      const access = await tx.get("access", `${user.id}:${client.id}`);
      requireThat(
        access?.status !== "REVOKED",
        "ACCESS_REVOKED",
        "Restore this connection before creating a new request",
        403,
      );
      requireThat(
        (await tx.count("requests", { userId: user.id, status: "PENDING" })) <
          20,
        "REQUEST_LIMIT",
        "Resolve pending proof requests before creating more",
        429,
      );
      const now = this.now(),
        request: ProofRequest = {
          id: randomUUID(),
          createdAt: now,
          userId: user.id,
          clientId: client.id,
          clientName: client.name,
          purpose: client.purpose,
          requestedClaims: [...new Set(value.requestedClaims)],
          policyVersion: "1",
          status: "PENDING",
          expiresAt: new Date(this.clock() + 600000).toISOString(),
          clientVersion: client.version,
          accountVersion: user.authVersion,
          accessVersion: access?.version ?? 1,
          sources: [],
          redirectUri: value.redirectUri,
          state: value.state,
          nonce: value.nonce,
          codeChallenge: value.codeChallenge,
        };
      await tx.insert("requests", request);
      await audit(
        tx,
        "proof.requested",
        user.id,
        request.id,
        { clientId: client.id, claims: request.requestedClaims },
        client.organizationId,
      );
      return this.safeRequest(request);
    });
  }
  private async resolve(tx: Transaction, user: Account, names: ClaimName[]) {
    const credentials = (
      await tx.list("credentials", {
        where: { userId: user.id, status: "ACTIVE" },
        limit: 1000,
      })
    ).filter((c) => c.expiresAt > this.now());
    const issuers = new Map<
      string,
      Awaited<ReturnType<typeof liveIssuer>> | null
    >();
    for (const credential of credentials)
      if (!issuers.has(credential.issuerId)) {
        try {
          issuers.set(
            credential.issuerId,
            await liveIssuer(tx, credential.issuerId, this.clock()),
          );
        } catch (error) {
          if (
            error instanceof AppError &&
            [401, 403, 422].includes(error.status)
          )
            issuers.set(credential.issuerId, null);
          else throw error;
        }
      }
    const claims: Claims = {},
      sources: ProofRequest["sources"] = [];
    let expiresAt = Math.floor(this.clock() / 1000) + this.config.proofSeconds;
    for (const name of names) {
      if (name === "account_valid") {
        claims[name] = true;
        continue;
      }
      const candidates = credentials.filter(
        (c) =>
          Object.hasOwn(c.claims, name) &&
          issuers.get(c.issuerId)?.supportedClaims.includes(name) &&
          assuranceRank[c.assuranceLevel] <=
            assuranceRank[issuers.get(c.issuerId)!.assuranceLevel],
      );
      candidates.sort(
        (a, b) =>
          assuranceRank[b.assuranceLevel] - assuranceRank[a.assuranceLevel] ||
          b.createdAt.localeCompare(a.createdAt) ||
          a.id.localeCompare(b.id),
      );
      const best = candidates[0];
      requireThat(
        best,
        "CLAIM_UNAVAILABLE",
        `No current trusted evidence supports ${name}`,
        422,
      );
      const sameAssurance = candidates.filter(
        (c) => c.assuranceLevel === best.assuranceLevel,
      );
      requireThat(
        sameAssurance.every((c) => c.claims[name] === best.claims[name]),
        "CONFLICTING_EVIDENCE",
        `Conflicting ${name} evidence must be resolved by its issuers`,
        422,
      );
      claims[name] = best.claims[name];
      expiresAt = Math.min(
        expiresAt,
        Math.floor(Date.parse(best.expiresAt) / 1000),
      );
      const issuer = issuers.get(best.issuerId)!;
      if (!sources.some((s) => s.credentialId === best.id))
        sources.push({
          credentialId: best.id,
          issuerId: issuer.id,
          issuerVersion: issuer.version,
        });
    }
    return { claims: validateClaims(claims), sources, expiresAt };
  }
  private async validateAuthority(tx: Transaction, request: ProofRequest) {
    const user = await activeAccount(tx, request.userId),
      client = await activeVerifier(tx, request.clientId, this.config);
    requireThat(
      user.authVersion === request.accountVersion &&
        client.version === request.clientVersion,
      "PROOF_REVOKED",
      "Account or verifier authorization has changed",
      409,
    );
    const access = await tx.get("access", `${user.id}:${client.id}`);
    requireThat(
      access?.status !== "REVOKED" &&
        (access?.version ?? 1) === request.accessVersion,
      "PROOF_REVOKED",
      "Connected access was revoked or changed",
      409,
    );
    requireThat(
      request.requestedClaims.every((c) => client.allowedClaims.includes(c)),
      "PROOF_REVOKED",
      "Claim policy changed",
      409,
    );
    for (const source of request.sources) {
      const credential = await tx.get("credentials", source.credentialId),
        issuer = await liveIssuer(tx, source.issuerId, this.clock());
      requireThat(
        credential?.status === "ACTIVE" &&
          credential.userId === user.id &&
          credential.issuerId === issuer.id &&
          credential.expiresAt > this.now() &&
          issuer.version === source.issuerVersion,
        "PROOF_REVOKED",
        "Source evidence expired or was revoked",
        409,
      );
    }
    if (request.disclosures) {
      const current = await this.resolve(tx, user, request.requestedClaims);
      requireThat(
        request.requestedClaims.every(
          (name) => current.claims[name] === request.disclosures![name],
        ),
        "PROOF_REVOKED",
        "Current evidence no longer supports the approved disclosure",
        409,
      );
    }
    return { user, client };
  }
  async preview(principal: Principal, id: string) {
    return this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock()),
        request = await tx.get("requests", id);
      requireThat(
        request?.userId === user.id,
        "NOT_FOUND",
        "Request not found",
        404,
      );
      requireThat(
        request.status === "PENDING" && request.expiresAt > this.now(),
        "REQUEST_EXPIRED",
        "Request is no longer pending",
        409,
      );
      await this.validateAuthority(tx, request);
      const resolved = await this.resolve(tx, user, request.requestedClaims);
      return {
        claims: resolved.claims,
        previewHash: digest(JSON.stringify(resolved.claims)),
        expiresAt: new Date(resolved.expiresAt * 1000).toISOString(),
      };
    });
  }
  async decide(
    principal: Principal,
    id: string,
    approve: boolean,
    previewHash?: string,
  ) {
    return this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock()),
        request = await tx.get("requests", id);
      requireThat(
        request?.userId === user.id,
        "NOT_FOUND",
        "Proof request not found",
        404,
      );
      requireThat(
        request.status === "PENDING",
        "ALREADY_DECIDED",
        "This request has already been decided",
        409,
      );
      requireThat(
        request.expiresAt > this.now(),
        "REQUEST_EXPIRED",
        "Create a fresh proof request",
        409,
      );
      if (!approve) {
        request.status = "DENIED";
        request.decidedAt = this.now();
        await tx.put("requests", request);
        await audit(tx, "proof.denied", user.id, id);
        return {
          request: this.safeRequest(request),
          ...(request.redirectUri
            ? {
                redirectUrl: this.redirect(request, { error: "access_denied" }),
              }
            : {}),
        };
      }
      const { client } = await this.validateAuthority(tx, request);
      const resolved = await this.resolve(tx, user, request.requestedClaims);
      requireThat(
        !previewHash ||
          equal(previewHash, digest(JSON.stringify(resolved.claims))),
        "CONSENT_CHANGED",
        "Evidence changed since your preview. Review the values again.",
        409,
      );
      requireThat(
        resolved.expiresAt > Math.floor(this.clock() / 1000),
        "CLAIM_EXPIRING",
        "Evidence is expiring; renew it before approval",
        422,
      );
      const existingAccess = await tx.get("access", `${user.id}:${client.id}`),
        { plan } = await effectivePlan(tx, user.id, this.plans, this.now());
      requireThat(
        existingAccess?.status === "ACTIVE" ||
          (await tx.count("access", { userId: user.id, status: "ACTIVE" })) <
            plan.limits.connections,
        "QUOTA_EXCEEDED",
        "The connected-application limit has been reached",
        429,
      );
      await consumeProofAllowance(tx, user.id, this.plans, this.now());
      request.sources = resolved.sources;
      request.disclosures = resolved.claims;
      request.decidedAt = this.now();
      request.status = "ISSUED";
      request.jti = randomUUID();
      request.expiresAt = new Date(
        (request.codeChallenge
          ? Math.min(resolved.expiresAt, Math.floor(this.clock() / 1000) + 60)
          : resolved.expiresAt) * 1000,
      ).toISOString();
      let proof: string | undefined, redirectUrl: string | undefined;
      if (request.codeChallenge) {
        const code = secret();
        request.codeHash = digest(code);
        redirectUrl = this.redirect(request, { code });
      } else {
        proof = await this.provider.sign({
          userId: user.id,
          clientId: client.id,
          requestId: id,
          jti: request.jti,
          claims: resolved.claims,
          expiresAt: resolved.expiresAt,
        });
        request.proofHash = digest(proof);
      }
      await tx.put("requests", request);
      await tx.put("access", {
        id: `${user.id}:${client.id}`,
        createdAt: existingAccess?.createdAt ?? this.now(),
        userId: user.id,
        clientId: client.id,
        status: "ACTIVE",
        version: existingAccess?.version ?? 1,
        lastProofAt: this.now(),
        shared: [
          ...new Set([
            ...(existingAccess?.shared ?? []),
            ...request.requestedClaims,
          ]),
        ],
      });
      await audit(
        tx,
        "proof.issued",
        user.id,
        id,
        { clientId: client.id, claims: request.requestedClaims },
        client.organizationId,
      );
      return {
        request: this.safeRequest(request),
        ...(proof ? { proof } : {}),
        ...(redirectUrl ? { redirectUrl } : {}),
      };
    });
  }
  private redirect(request: ProofRequest, parameters: Record<string, string>) {
    requireThat(
      request.redirectUri && request.state,
      "INVALID_AUTHORIZATION",
      "Authorization context is missing",
    );
    const url = new URL(request.redirectUri);
    for (const [key, value] of Object.entries({
      ...parameters,
      state: request.state,
    }))
      url.searchParams.set(key, value);
    return url.href;
  }
  async redeemCode(input: {
    clientId: string;
    clientSecret?: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }) {
    requireThat(
      /^[A-Za-z0-9._~-]{43,128}$/.test(input.codeVerifier),
      "INVALID_GRANT",
      "Invalid PKCE verifier",
    );
    return this.db.transaction(async (tx) => {
      const client = await activeVerifier(tx, input.clientId, this.config);
      verifyClientSecret(client, input.clientSecret, true);
      const request = (
        await tx.list("requests", {
          where: { codeHash: digest(input.code), clientId: input.clientId },
          limit: 1,
        })
      )[0];
      requireThat(
        request &&
          request.status === "ISSUED" &&
          request.expiresAt > this.now() &&
          request.redirectUri === input.redirectUri &&
          equal(pkceChallenge(input.codeVerifier), request.codeChallenge ?? ""),
        "INVALID_GRANT",
        "The authorization code is invalid, expired, used, or bound to a different transaction",
        400,
      );
      await this.validateAuthority(tx, request);
      const claims = claimsSchema.parse(request.disclosures),
        exp = Math.floor(Date.parse(request.expiresAt) / 1000);
      const proof = await this.provider.sign({
        userId: request.userId,
        clientId: request.clientId,
        requestId: request.id,
        jti: request.jti!,
        claims,
        expiresAt: exp,
        nonce: request.nonce,
      });
      request.proofHash = digest(proof);
      request.status = "REDEEMED";
      request.redeemedAt = this.now();
      await tx.put("requests", request);
      await audit(
        tx,
        "proof.redeemed",
        client.id,
        request.id,
        {},
        client.organizationId,
      );
      return {
        token_type: "privateid-proof",
        proof,
        claims,
        subject: this.provider.subject(request.userId, client.id),
        nonce: request.nonce,
        expiresAt: request.expiresAt,
      };
    });
  }
  async verify(
    proof: string,
    clientId: string,
    clientSecret: string,
    consume = true,
  ) {
    const payload = await this.provider.verify(proof, clientId);
    return this.db.transaction(async (tx) => {
      const client = await activeVerifier(tx, clientId, this.config);
      verifyClientSecret(client, clientSecret);
      const request = await tx.get("requests", payload.request_id);
      requireThat(
        request &&
          request.clientId === client.id &&
          request.proofHash &&
          equal(request.proofHash, digest(proof)) &&
          request.jti === payload.jti &&
          request.expiresAt > this.now(),
        "INVALID_PROOF",
        "Proof is no longer valid",
        400,
      );
      requireThat(
        consume
          ? request.status === "ISSUED"
          : ["ISSUED", "REDEEMED"].includes(request.status),
        "PROOF_REPLAYED",
        "Proof has been consumed or revoked",
        409,
      );
      await this.validateAuthority(tx, request);
      if (consume) {
        request.status = "REDEEMED";
        request.redeemedAt = this.now();
        await tx.put("requests", request);
        await audit(
          tx,
          "proof.redeemed",
          client.id,
          request.id,
          {},
          client.organizationId,
        );
      }
      return {
        valid: true,
        claims: payload.claims,
        subject: payload.sub,
        expiresAt: new Date(payload.exp * 1000).toISOString(),
        ...(payload.nonce ? { nonce: payload.nonce } : {}),
      };
    });
  }
  async list(principal: Principal, query: Query = {}) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      return (
        await tx.list("requests", {
          ...query,
          where: { userId: principal.accountId },
        })
      ).map((r) => this.safeRequest(r));
    });
  }
  async get(principal: Principal, id: string) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      const request = await tx.get("requests", id);
      requireThat(
        request?.userId === principal.accountId,
        "NOT_FOUND",
        "Proof request not found",
        404,
      );
      return this.safeRequest(request);
    });
  }
  async connections(principal: Principal, query: Query = {}) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      return tx.list("access", {
        ...query,
        where: { userId: principal.accountId },
      });
    });
  }
  async revokeAccess(principal: Principal, clientId: string) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      const access = await tx.get(
        "access",
        `${principal.accountId}:${clientId}`,
      );
      requireThat(access, "NOT_FOUND", "Connection not found", 404);
      access.status = "REVOKED";
      access.version++;
      access.revokedAt = this.now();
      await tx.put("access", access);
      await audit(
        tx,
        "application.access_revoked",
        principal.accountId,
        clientId,
      );
      return { revoked: true };
    });
  }
  async restoreAccess(principal: Principal, clientId: string) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      const access = await tx.get(
        "access",
        `${principal.accountId}:${clientId}`,
      );
      requireThat(access, "NOT_FOUND", "Connection not found", 404);
      const { plan } = await effectivePlan(
        tx,
        principal.accountId,
        this.plans,
        this.now(),
      );
      requireThat(
        (await tx.count("access", {
          userId: principal.accountId,
          status: "ACTIVE",
        })) < plan.limits.connections,
        "QUOTA_EXCEEDED",
        "The connection limit has been reached",
        429,
      );
      access.version++;
      access.status = "ACTIVE";
      delete access.revokedAt;
      await tx.put("access", access);
      await audit(
        tx,
        "application.access_restored",
        principal.accountId,
        clientId,
      );
      return { restored: true, requiresNewConsent: true };
    });
  }
  async dashboard(principal: Principal) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      const userId = principal.accountId,
        now = this.now(),
        effective = await effectivePlan(tx, userId, this.plans, now),
        usage = await tx.get("usage", `${userId}:${now.slice(0, 7)}`);
      return {
        plan: { ...effective.plan, stripePriceId: undefined },
        subscriptionStatus: effective.subscription?.status ?? "free",
        usage: {
          proofs: usage?.proofs ?? 0,
          period: now.slice(0, 7),
          credentials: await tx.count("credentials", {
            userId,
            status: "ACTIVE",
          }),
          connections: await tx.count("access", { userId, status: "ACTIVE" }),
        },
        counts: {
          pendingRequests: await tx.count("requests", {
            userId,
            status: "PENDING",
          }),
          approvedRequests: await tx.count("requests", {
            userId,
            status: "ISSUED",
          }),
          disclosures: await tx.count("requests", {
            userId,
            status: "REDEEMED",
          }),
        },
      };
    });
  }
}
