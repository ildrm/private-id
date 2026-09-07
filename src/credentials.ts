import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Config } from "./config.js";
import { authorize, activeAccount, type Principal } from "./accounts.js";
import { organizationPermission, requireMfa } from "./organizations.js";
import {
  claimsSchema,
  claimSchema,
  assuranceSchema,
  type Claims,
  type Credential,
  type Issuer,
} from "./models.js";
import type { Database, Transaction, Query } from "./repository.js";
import { effectivePlan, type Plan } from "./catalog.js";
import { requireThat } from "./errors.js";
import { audit } from "./audit.js";
import { seal } from "./security.js";
export const issuerInput = z
  .object({
    issuerName: z.string().min(2).max(120),
    organizationId: z.string().optional(),
    jurisdiction: z.string().regex(/^[A-Z]{2}$/),
    supportedClaims: z.array(claimSchema).min(1).max(12),
    assuranceLevel: assuranceSchema,
    policy: z.string().min(10).max(2000),
  })
  .strict();
export const credentialInput = z
  .object({
    userId: z.string().min(1),
    issuerId: z.string().min(1),
    type: z.string().min(1).max(100),
    claims: claimsSchema,
    birthDate: z.iso.date().optional(),
    assuranceLevel: assuranceSchema,
    evidenceReference: z.string().min(10).max(2000),
    expiresInSeconds: z.number().int().min(60).max(31536000),
    supersedes: z.array(z.string()).max(20).default([]),
  })
  .strict();
export const assuranceRank = { LOW: 1, SUBSTANTIAL: 2, HIGH: 3 } as const;
export function isAdult(birthDate: string, today: string) {
  z.iso.date().parse(birthDate);
  requireThat(
    birthDate <= today,
    "INVALID_BIRTH_DATE",
    "Birth date must not be in the future",
  );
  const [year, month, day] = birthDate.split("-").map(Number),
    [y, m, d] = today.split("-").map(Number);
  return y - year - (m < month || (m === month && d < day) ? 1 : 0) >= 18;
}
export function validateClaims(claims: Claims) {
  requireThat(
    Object.keys(claims).length > 0,
    "EMPTY_CLAIMS",
    "At least one supported claim is required",
  );
  for (const [name, value] of Object.entries(claims)) {
    requireThat(
      name === "jurisdiction"
        ? typeof value === "string" && /^[A-Z]{2}$/.test(value)
        : typeof value === "boolean",
      "INVALID_CLAIM_TYPE",
      `Invalid value for ${name}`,
    );
  }
  return claims;
}
export async function liveIssuer(
  tx: Transaction,
  id: string,
  _now = Date.now(),
) {
  const issuer = await tx.get("issuers", id);
  requireThat(
    issuer?.status === "TRUSTED",
    "UNTRUSTED_ISSUER",
    "The credential issuer is not trusted",
    422,
  );
  await activeAccount(tx, issuer.ownerId);
  if (issuer.organizationId)
    requireThat(
      (await tx.get("organizations", issuer.organizationId))?.status ===
        "ACTIVE",
      "UNTRUSTED_ISSUER",
      "The issuer organization is inactive",
      422,
    );
  return issuer;
}
export class CredentialService {
  constructor(
    private db: Database,
    private config: Config,
    private plans: Plan[],
    private clock = () => Date.now(),
  ) {}
  async registerIssuer(principal: Principal, input: unknown) {
    const value = issuerInput.parse(input);
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      await requireMfa(tx, principal);
      const organization = value.organizationId
        ? await organizationPermission(
            tx,
            principal,
            value.organizationId,
            ["OWNER", "ISSUER"],
            this.clock(),
          )
        : undefined;
      requireThat(
        (await tx.count("issuers", {
          ownerId: organization?.ownerId ?? principal.accountId,
        })) < 20,
        "ISSUER_LIMIT",
        "At most twenty issuer identities per account",
        429,
      );
      const issuer: Issuer = {
        ...value,
        id: randomUUID(),
        createdAt: new Date(this.clock()).toISOString(),
        ownerId: organization?.ownerId ?? principal.accountId,
        status: "PENDING",
        version: 1,
      };
      await tx.insert("issuers", issuer);
      await audit(
        tx,
        "issuer.submitted",
        principal.accountId,
        issuer.id,
        {},
        value.organizationId,
      );
      return issuer;
    });
  }
  async reviewIssuer(
    principal: Principal,
    id: string,
    status: "TRUSTED" | "SUSPENDED" | "REVOKED",
    reason: string,
  ) {
    return this.db.transaction(async (tx) => {
      await authorize(
        tx,
        principal,
        ["IDENTITY_ADMIN", "SECURITY_ADMIN"],
        this.clock(),
      );
      const issuer = await tx.get("issuers", id);
      requireThat(issuer, "NOT_FOUND", "Issuer not found", 404);
      requireThat(
        issuer.ownerId !== principal.accountId &&
          (!issuer.organizationId ||
            !(await tx.get(
              "memberships",
              `${issuer.organizationId}:${principal.accountId}`,
            ))),
        "INDEPENDENT_REVIEW_REQUIRED",
        "A different administrator must review the issuer",
      );
      requireThat(
        issuer.status !== "REVOKED",
        "ISSUER_REVOKED",
        "A revoked issuer cannot be reactivated",
        409,
      );
      issuer.status = status;
      issuer.version++;
      issuer.reviewedBy = principal.accountId;
      issuer.reviewedAt = new Date(this.clock()).toISOString();
      issuer.reason = z.string().min(10).max(1000).parse(reason);
      await tx.put("issuers", issuer);
      await audit(
        tx,
        "issuer.reviewed",
        principal.accountId,
        id,
        { status, reason },
        issuer.organizationId,
      );
      return issuer;
    });
  }
  async issuers(principal: Principal | undefined, query: Query = {}) {
    return this.db.transaction(async (tx) => {
      if (!principal)
        return (
          await tx.list("issuers", { ...query, where: { status: "TRUSTED" } })
        ).map(
          ({
            id,
            issuerName,
            jurisdiction,
            assuranceLevel,
            supportedClaims,
            policy,
          }) => ({
            id,
            issuerName,
            jurisdiction,
            assuranceLevel,
            supportedClaims,
            policy,
          }),
        );
      const user = await authorize(tx, principal, [], this.clock());
      const staff = user.roles.some((r) =>
        ["IDENTITY_ADMIN", "SECURITY_ADMIN"].includes(r),
      );
      if (query.organizationId)
        await organizationPermission(
          tx,
          principal,
          query.organizationId,
          ["OWNER", "ISSUER"],
          this.clock(),
        );
      return tx.list("issuers", {
        ...query,
        where: query.organizationId
          ? { organizationId: query.organizationId }
          : staff
            ? {}
            : { ownerId: user.id },
      });
    });
  }
  private async canIssue(
    tx: Transaction,
    principal: Principal,
    issuer: Issuer,
  ) {
    const user = await authorize(tx, principal, [], this.clock());
    await requireMfa(tx, principal);
    if (issuer.organizationId) {
      await organizationPermission(
        tx,
        principal,
        issuer.organizationId,
        ["OWNER", "ISSUER"],
        this.clock(),
      );
    } else
      requireThat(
        issuer.ownerId === user.id,
        "FORBIDDEN",
        "Use an issuer identity owned by your account",
        403,
      );
  }
  async issue(principal: Principal, input: unknown) {
    const value = credentialInput.parse(input),
      claims = validateClaims(value.claims),
      now = new Date(this.clock()).toISOString();
    if ("adult_verified" in claims) {
      requireThat(
        value.birthDate,
        "BIRTH_DATE_REQUIRED",
        "Provide the evidence-backed birth date to derive adult status",
      );
      requireThat(
        claims.adult_verified === isAdult(value.birthDate, now.slice(0, 10)),
        "AGE_MISMATCH",
        "Adult status does not match the supplied birth date",
      );
    }
    return this.db.transaction(async (tx) => {
      const issuer = await liveIssuer(tx, value.issuerId, this.clock());
      await this.canIssue(tx, principal, issuer);
      await activeAccount(tx, value.userId);
      requireThat(
        Object.keys(claims).every((c) =>
          issuer.supportedClaims.includes(claimSchema.parse(c)),
        ) &&
          assuranceRank[value.assuranceLevel] <=
            assuranceRank[issuer.assuranceLevel],
        "ISSUER_AUTHORITY",
        "Claims or assurance exceed this issuer’s reviewed authority",
        403,
      );
      for (const id of value.supersedes) {
        const previous = await tx.get("credentials", id);
        requireThat(
          previous?.userId === value.userId && previous.issuerId === issuer.id,
          "INVALID_SUPERSESSION",
          "Only this issuer’s credentials for the same customer can be superseded",
        );
        previous.revokedAt = now;
        previous.revocationReason = "Superseded by new evidence";
        previous.status = "REVOKED";
        await tx.put("credentials", previous);
        await audit(
          tx,
          "credential.superseded",
          principal.accountId,
          id,
          {},
          issuer.organizationId,
        );
      }
      const { plan } = await effectivePlan(tx, value.userId, this.plans, now);
      requireThat(
        (await tx.count("credentials", {
          userId: value.userId,
          status: "ACTIVE",
        })) < plan.limits.credentials,
        "QUOTA_EXCEEDED",
        "The customer’s active credential limit has been reached",
        429,
      );
      const credential: Credential = {
        id: randomUUID(),
        createdAt: now,
        userId: value.userId,
        issuerId: issuer.id,
        organizationId: issuer.organizationId,
        type: value.type,
        claims,
        assuranceLevel: value.assuranceLevel,
        evidenceReference: seal(
          value.evidenceReference,
          this.config.encryptionKey,
        ),
        evidencePolicy: issuer.policy,
        issuedBy: principal.accountId,
        expiresAt: new Date(
          this.clock() + value.expiresInSeconds * 1000,
        ).toISOString(),
        status: "ACTIVE",
      };
      await tx.insert("credentials", credential);
      await audit(
        tx,
        "credential.issued",
        principal.accountId,
        credential.id,
        {
          type: value.type,
          claimNames: Object.keys(claims),
          assurance: value.assuranceLevel,
        },
        issuer.organizationId,
      );
      return this.safeCredential(credential);
    });
  }
  safeCredential({ evidenceReference, ...credential }: Credential) {
    return { ...credential, evidenceRecorded: !!evidenceReference };
  }
  async list(principal: Principal, query: Query = {}) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      return (
        await tx.list("credentials", {
          ...query,
          where: { userId: principal.accountId },
        })
      ).map((c) => this.safeCredential(c));
    });
  }
  async issued(principal: Principal, issuerId: string, query: Query = {}) {
    return this.db.transaction(async (tx) => {
      const issuer = await tx.get("issuers", issuerId);
      requireThat(issuer, "NOT_FOUND", "Issuer not found", 404);
      await this.canIssue(tx, principal, issuer);
      return (
        await tx.list("credentials", { ...query, where: { issuerId } })
      ).map((c) => this.safeCredential(c));
    });
  }
  async revoke(principal: Principal, id: string, reason: string) {
    return this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock()),
        credential = await tx.get("credentials", id);
      requireThat(credential, "NOT_FOUND", "Credential not found", 404);
      const issuer = await tx.get("issuers", credential.issuerId);
      requireThat(issuer, "NOT_FOUND", "Issuer not found", 404);
      if (
        user.roles.includes("IDENTITY_ADMIN") ||
        user.roles.includes("SECURITY_ADMIN")
      )
        await requireMfa(tx, principal);
      else await this.canIssue(tx, principal, issuer);
      credential.status = "REVOKED";
      credential.revokedAt = new Date(this.clock()).toISOString();
      credential.revocationReason = z.string().min(5).max(1000).parse(reason);
      await tx.put("credentials", credential);
      await audit(
        tx,
        "credential.revoked",
        user.id,
        id,
        { reason },
        credential.organizationId,
      );
      return this.safeCredential(credential);
    });
  }
}
