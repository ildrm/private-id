import { z } from "zod";
import { authorize, type Principal } from "./accounts.js";
import { organizationPermission, requireMfa } from "./organizations.js";
import { claimSchema, type Verifier } from "./models.js";
import type { Database, Query, Transaction } from "./repository.js";
import type { Config } from "./config.js";
import { audit } from "./audit.js";
import { requireThat } from "./errors.js";
import { digest, equal, secret } from "./security.js";
export const verifierInput = z
  .object({
    clientId: z.string().regex(/^[a-z][a-z0-9-]{2,59}$/),
    name: z.string().min(2).max(120),
    organizationId: z.string().optional(),
    redirectUris: z.array(z.url()).min(1).max(10),
    allowedClaims: z.array(claimSchema).min(1).max(12),
    environment: z.enum(["SANDBOX", "PRODUCTION"]),
    purpose: z.string().min(10).max(2000),
  })
  .strict();
export function validateRedirect(
  value: string,
  environment: "SANDBOX" | "PRODUCTION",
) {
  const url = new URL(value);
  requireThat(
    !url.username && !url.password && !url.hash && !url.search,
    "INVALID_REDIRECT",
    "Redirect URLs cannot contain credentials, fragments, or query strings",
  );
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  requireThat(
    url.protocol === "https:" ||
      (environment === "SANDBOX" && local && url.protocol === "http:"),
    "INVALID_REDIRECT",
    "Redirects require HTTPS; sandbox loopback HTTP is permitted",
  );
  return url.href;
}
export async function activeVerifier(
  tx: Transaction,
  id: string,
  config: Config,
) {
  const verifier = await tx.get("verifiers", id);
  requireThat(
    verifier?.status === "ACTIVE",
    "CLIENT_UNAVAILABLE",
    "The verifier is not active",
    403,
  );
  requireThat(
    config.mode !== "production" || verifier.environment === "PRODUCTION",
    "SANDBOX_CLIENT",
    "Sandbox clients cannot request production proofs",
    403,
  );
  if (verifier.ownerId) {
    const owner = await tx.get("accounts", verifier.ownerId);
    requireThat(
      owner?.status === "ACTIVE" && owner.emailVerified,
      "CLIENT_UNAVAILABLE",
      "The verifier owner is inactive",
      403,
    );
  }
  if (verifier.organizationId)
    requireThat(
      (await tx.get("organizations", verifier.organizationId))?.status ===
        "ACTIVE",
      "CLIENT_UNAVAILABLE",
      "The verifier organization is inactive",
      403,
    );
  return verifier;
}
export function verifyClientSecret(
  verifier: Verifier,
  value?: string,
  allowPublic = false,
) {
  requireThat(
    verifier.secretHash
      ? !!value && equal(digest(value), verifier.secretHash)
      : allowPublic,
    "INVALID_CLIENT",
    "Client authentication failed",
    401,
  );
}
export class VerifierService {
  constructor(
    private db: Database,
    private config: Config,
    private clock = () => Date.now(),
  ) {}
  private safe({ secretHash, ...value }: Verifier) {
    return { ...value, confidential: !!secretHash };
  }
  async register(principal: Principal, input: unknown) {
    const value = verifierInput.parse(input),
      clientSecret = secret(),
      redirects = value.redirectUris.map((r) =>
        validateRedirect(r, value.environment),
      );
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      await requireMfa(tx, principal);
      const organization = value.organizationId
        ? await organizationPermission(
            tx,
            principal,
            value.organizationId,
            ["OWNER", "VERIFIER"],
            this.clock(),
          )
        : undefined;
      requireThat(
        (await tx.count("verifiers", {
          ownerId: organization?.ownerId ?? principal.accountId,
        })) < 20,
        "VERIFIER_LIMIT",
        "At most twenty verifier identities per account",
        429,
      );
      const verifier: Verifier = {
        id: value.clientId,
        createdAt: new Date(this.clock()).toISOString(),
        ownerId: organization?.ownerId ?? principal.accountId,
        organizationId: value.organizationId,
        name: value.name,
        redirectUris: redirects,
        allowedClaims: [...new Set(value.allowedClaims)],
        environment: value.environment,
        purpose: value.purpose,
        secretHash: digest(clientSecret),
        status: "PENDING",
        version: 1,
      };
      await tx.insert("verifiers", verifier);
      await audit(
        tx,
        "verifier.submitted",
        principal.accountId,
        verifier.id,
        {},
        verifier.organizationId,
      );
      return { application: this.safe(verifier), clientSecret };
    });
  }
  async review(
    principal: Principal,
    id: string,
    status: "ACTIVE" | "SUSPENDED" | "REVOKED",
    reason: string,
  ) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, ["IDENTITY_ADMIN"], this.clock());
      const verifier = await tx.get("verifiers", id);
      requireThat(verifier, "NOT_FOUND", "Verifier not found", 404);
      requireThat(
        verifier.ownerId !== principal.accountId &&
          (!verifier.organizationId ||
            !(await tx.get(
              "memberships",
              `${verifier.organizationId}:${principal.accountId}`,
            ))),
        "INDEPENDENT_REVIEW_REQUIRED",
        "A different administrator must review the verifier",
      );
      requireThat(
        verifier.status !== "REVOKED",
        "CLIENT_REVOKED",
        "A revoked client cannot be reactivated",
      );
      verifier.status = status;
      verifier.reviewedBy = principal.accountId;
      verifier.version++;
      await tx.put("verifiers", verifier);
      await audit(
        tx,
        "verifier.reviewed",
        principal.accountId,
        id,
        { status, reason: z.string().min(10).max(1000).parse(reason) },
        verifier.organizationId,
      );
      return this.safe(verifier);
    });
  }
  private async canManage(
    tx: Transaction,
    principal: Principal,
    verifier: Verifier,
  ) {
    const user = await authorize(tx, principal, [], this.clock());
    await requireMfa(tx, principal);
    if (verifier.organizationId)
      await organizationPermission(
        tx,
        principal,
        verifier.organizationId,
        ["OWNER", "VERIFIER"],
        this.clock(),
      );
    else
      requireThat(
        verifier.ownerId === user.id,
        "FORBIDDEN",
        "Verifier belongs to another account",
        403,
      );
  }
  async rotateSecret(principal: Principal, id: string) {
    const clientSecret = secret();
    return this.db.transaction(async (tx) => {
      const verifier = await tx.get("verifiers", id);
      requireThat(verifier, "NOT_FOUND", "Verifier not found", 404);
      await this.canManage(tx, principal, verifier);
      verifier.secretHash = digest(clientSecret);
      verifier.version++;
      await tx.put("verifiers", verifier);
      await audit(
        tx,
        "verifier.secret_rotated",
        principal.accountId,
        id,
        {},
        verifier.organizationId,
      );
      return { clientSecret };
    });
  }
  async update(principal: Principal, id: string, input: unknown) {
    const value = verifierInput
      .omit({ clientId: true, organizationId: true })
      .parse(input);
    return this.db.transaction(async (tx) => {
      const verifier = await tx.get("verifiers", id);
      requireThat(verifier, "NOT_FOUND", "Verifier not found", 404);
      await this.canManage(tx, principal, verifier);
      requireThat(
        verifier.status !== "REVOKED",
        "CLIENT_REVOKED",
        "Register a new client instead",
      );
      Object.assign(verifier, value, {
        redirectUris: value.redirectUris.map((r) =>
          validateRedirect(r, value.environment),
        ),
        status: "PENDING",
        version: verifier.version + 1,
      });
      await tx.put("verifiers", verifier);
      await audit(
        tx,
        "verifier.updated",
        principal.accountId,
        id,
        {},
        verifier.organizationId,
      );
      return this.safe(verifier);
    });
  }
  async list(principal: Principal, query: Query = {}) {
    return this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock());
      if (query.organizationId)
        await organizationPermission(
          tx,
          principal,
          query.organizationId,
          ["OWNER", "VERIFIER"],
          this.clock(),
        );
      const rows = await tx.list("verifiers", {
        ...query,
        where: query.organizationId
          ? { organizationId: query.organizationId }
          : user.roles.includes("IDENTITY_ADMIN")
            ? {}
            : { ownerId: user.id },
      });
      return rows.map((r) => this.safe(r));
    });
  }
  async publicInfo(id: string) {
    return this.db.transaction(async (tx) => {
      const v = await activeVerifier(tx, id, this.config);
      return {
        id: v.id,
        name: v.name,
        purpose: v.purpose,
        allowedClaims: v.allowedClaims,
        redirectUris: v.redirectUris,
      };
    });
  }
}
