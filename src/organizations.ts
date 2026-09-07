import { randomUUID } from "node:crypto";
import { z } from "zod";
import { authorize, type Principal } from "./accounts.js";
import type { Database, Transaction } from "./repository.js";
import { requireThat } from "./errors.js";
import { effectivePlan, type Plan } from "./catalog.js";
import { audit } from "./audit.js";
import { canonicalEmail } from "./security.js";

export async function organizationPermission(
  tx: Transaction,
  principal: Principal,
  organizationId: string,
  permitted: ("OWNER" | "ISSUER" | "VERIFIER" | "MEMBER")[],
  now = Date.now(),
) {
  await authorize(tx, principal, [], now);
  const organization = await tx.get("organizations", organizationId),
    member = await tx.get(
      "memberships",
      `${organizationId}:${principal.accountId}`,
    );
  requireThat(
    organization?.status === "ACTIVE" &&
      member &&
      permitted.includes(member.role),
    "FORBIDDEN",
    "This organization operation is not permitted",
    403,
  );
  return organization;
}
export async function requireMfa(tx: Transaction, principal: Principal) {
  const account = await tx.get("accounts", principal.accountId),
    session = await tx.get("sessions", principal.sessionId);
  requireThat(
    account?.mfaSecret && session?.mfaVerified,
    "MFA_REQUIRED",
    "Enable MFA and sign in with an authenticator or recovery code",
    403,
  );
}
export class OrganizationService {
  constructor(
    private db: Database,
    private plans: Plan[],
    private clock = () => Date.now(),
  ) {}
  async list(principal: Principal) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      const memberships = await tx.list("memberships", {
        where: { userId: principal.accountId },
        limit: 100,
      });
      const result = [];
      for (const m of memberships) {
        const organization = await tx.get("organizations", m.organizationId);
        if (organization) result.push({ ...organization, role: m.role });
      }
      return result;
    });
  }
  async create(principal: Principal, name: string) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      await requireMfa(tx, principal);
      const { plan } = await effectivePlan(
        tx,
        principal.accountId,
        this.plans,
        new Date(this.clock()).toISOString(),
      );
      requireThat(
        plan.id === "business",
        "PLAN_REQUIRED",
        "Organization workspaces require the Business plan",
        403,
      );
      requireThat(
        (await tx.count("organizations", {
          ownerId: principal.accountId,
          status: "ACTIVE",
        })) < 1,
        "ORGANIZATION_LIMIT",
        "One active organization is included per Business owner",
      );
      const now = new Date(this.clock()).toISOString(),
        organization = {
          id: randomUUID(),
          createdAt: now,
          name: z.string().min(2).max(120).parse(name),
          ownerId: principal.accountId,
          status: "ACTIVE" as const,
        };
      await tx.insert("organizations", organization);
      await tx.insert("memberships", {
        id: `${organization.id}:${principal.accountId}`,
        createdAt: now,
        organizationId: organization.id,
        userId: principal.accountId,
        role: "OWNER",
      });
      await audit(
        tx,
        "organization.created",
        principal.accountId,
        organization.id,
        {},
        organization.id,
      );
      return organization;
    });
  }
  async members(principal: Principal, organizationId: string) {
    return this.db.transaction(async (tx) => {
      await organizationPermission(
        tx,
        principal,
        organizationId,
        ["OWNER"],
        this.clock(),
      );
      const rows = await tx.list("memberships", {
        where: { organizationId },
        limit: 100,
      });
      return Promise.all(
        rows.map(async (m) => ({
          ...m,
          email: (await tx.get("accounts", m.userId))?.email,
        })),
      );
    });
  }
  async addMember(
    principal: Principal,
    organizationId: string,
    input: { email: string; role: "ISSUER" | "VERIFIER" | "MEMBER" },
  ) {
    return this.db.transaction(async (tx) => {
      const org = await organizationPermission(
        tx,
        principal,
        organizationId,
        ["OWNER"],
        this.clock(),
      );
      await requireMfa(tx, principal);
      const { plan } = await effectivePlan(
        tx,
        org.ownerId,
        this.plans,
        new Date(this.clock()).toISOString(),
      );
      requireThat(
        plan.id === "business",
        "PLAN_REQUIRED",
        "An active Business plan is required",
        403,
      );
      requireThat(
        (await tx.count("memberships", { organizationId })) <
          plan.limits.teamMembers,
        "QUOTA_EXCEEDED",
        "The organization member limit has been reached",
        429,
      );
      const user = (
        await tx.list("accounts", {
          where: {
            email: canonicalEmail(input.email),
            status: "ACTIVE",
            emailVerified: true,
          },
          limit: 1,
        })
      )[0];
      requireThat(
        user,
        "NOT_FOUND",
        "Ask the member to create and verify their account first",
        404,
      );
      requireThat(
        (await tx.count("memberships", { userId: user.id })) < 50,
        "MEMBERSHIP_LIMIT",
        "Account belongs to the maximum number of workspaces",
        429,
      );
      const member = {
        id: `${organizationId}:${user.id}`,
        createdAt: new Date(this.clock()).toISOString(),
        organizationId,
        userId: user.id,
        role: input.role,
      };
      await tx.insert("memberships", member);
      await audit(
        tx,
        "organization.member_added",
        principal.accountId,
        user.id,
        { role: input.role },
        organizationId,
      );
      return member;
    });
  }
  async removeMember(
    principal: Principal,
    organizationId: string,
    userId: string,
  ) {
    return this.db.transaction(async (tx) => {
      await organizationPermission(
        tx,
        principal,
        organizationId,
        ["OWNER"],
        this.clock(),
      );
      await requireMfa(tx, principal);
      const member = await tx.get("memberships", `${organizationId}:${userId}`);
      requireThat(
        member && member.role !== "OWNER",
        "INVALID_MEMBER",
        "Transfer ownership before removing an owner",
      );
      await tx.delete("memberships", member.id);
      await audit(
        tx,
        "organization.member_removed",
        principal.accountId,
        userId,
        {},
        organizationId,
      );
      return { removed: true };
    });
  }
  async transfer(principal: Principal, organizationId: string, userId: string) {
    return this.db.transaction(async (tx) => {
      const org = await organizationPermission(
        tx,
        principal,
        organizationId,
        ["OWNER"],
        this.clock(),
      );
      await requireMfa(tx, principal);
      const member = await tx.get("memberships", `${organizationId}:${userId}`),
        target = await tx.get("accounts", userId);
      const { plan } = await effectivePlan(
        tx,
        userId,
        this.plans,
        new Date(this.clock()).toISOString(),
      );
      requireThat(
        member &&
          target?.status === "ACTIVE" &&
          target.emailVerified &&
          target.mfaSecret &&
          plan.id === "business",
        "INVALID_OWNER",
        "New owner must be a verified member with MFA and an active Business plan",
      );
      requireThat(
        !(await tx.count("organizations", {
          ownerId: userId,
          status: "ACTIVE",
        })),
        "ORGANIZATION_LIMIT",
        "The new owner already owns an active organization",
      );
      const previous = (await tx.get(
        "memberships",
        `${organizationId}:${principal.accountId}`,
      ))!;
      previous.role = "MEMBER";
      member.role = "OWNER";
      org.ownerId = userId;
      for (const issuer of await tx.list("issuers", {
        where: { organizationId },
        limit: 1000,
      })) {
        issuer.ownerId = userId;
        issuer.version++;
        await tx.put("issuers", issuer);
      }
      for (const verifier of await tx.list("verifiers", {
        where: { organizationId },
        limit: 1000,
      })) {
        verifier.ownerId = userId;
        verifier.version++;
        await tx.put("verifiers", verifier);
      }
      await tx.put("organizations", org);
      await tx.put("memberships", previous);
      await tx.put("memberships", member);
      await audit(
        tx,
        "organization.owner_transferred",
        principal.accountId,
        userId,
        {},
        organizationId,
      );
      return org;
    });
  }
  async leave(principal: Principal, organizationId: string) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      const member = await tx.get(
        "memberships",
        `${organizationId}:${principal.accountId}`,
      );
      requireThat(
        member && member.role !== "OWNER",
        "INVALID_MEMBER",
        "Owners must transfer or close the workspace before leaving",
      );
      await tx.delete("memberships", member.id);
      await audit(
        tx,
        "organization.member_left",
        principal.accountId,
        principal.accountId,
        {},
        organizationId,
      );
      return { left: true };
    });
  }
  async close(principal: Principal, organizationId: string) {
    return this.db.transaction(async (tx) => {
      const org = await organizationPermission(
        tx,
        principal,
        organizationId,
        ["OWNER"],
        this.clock(),
      );
      await requireMfa(tx, principal);
      org.status = "SUSPENDED";
      await tx.put("organizations", org);
      await audit(
        tx,
        "organization.closed",
        principal.accountId,
        organizationId,
        {},
        organizationId,
      );
      return { closed: true };
    });
  }
  async audit(
    principal: Principal,
    organizationId: string,
    cursor?: string,
    limit = 50,
  ) {
    return this.db.transaction(async (tx) => {
      await organizationPermission(
        tx,
        principal,
        organizationId,
        ["OWNER"],
        this.clock(),
      );
      return tx.list("audit", { where: { organizationId }, cursor, limit });
    });
  }
}
