import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Database, Transaction, Query } from "./repository.js";
import {
  type Account,
  type Role,
  type Session,
  publicAccount,
  roles,
} from "./models.js";
import type { Config } from "./config.js";
import { AppError, requireThat } from "./errors.js";
import { audit } from "./audit.js";
import {
  canonicalEmail,
  digest,
  equal,
  hashPassword,
  newTotpSecret,
  seal,
  secret,
  unseal,
  verifyPassword,
  verifyTotp,
} from "./security.js";

export type Principal = { accountId: string; sessionId: string };
export const passwordSchema = z
  .string()
  .min(12)
  .max(128)
  .refine(
    (p) =>
      ![
        "passwordpassword",
        "password123456",
        "123456789012",
        "qwertyuiop123",
      ].includes(p.toLowerCase()),
    "Choose a less predictable password",
  );
export const registrationSchema = z
  .object({ email: z.email().max(254), password: passwordSchema })
  .strict();
export async function activeAccount(
  tx: Transaction,
  id: string,
  verified = true,
) {
  const account = await tx.get("accounts", id);
  requireThat(
    account && account.status === "ACTIVE",
    "UNAUTHORIZED",
    "Sign in with an active account",
    401,
  );
  requireThat(
    !verified || account.emailVerified,
    "EMAIL_VERIFICATION_REQUIRED",
    "Verify your email address first",
    403,
  );
  return account;
}
export async function authorize(
  tx: Transaction,
  principal: Principal,
  required: Role[] = [],
  now = Date.now(),
  verified = true,
) {
  const account = await activeAccount(tx, principal.accountId, verified),
    session = await tx.get("sessions", principal.sessionId);
  requireThat(
    session &&
      session.userId === account.id &&
      Date.parse(session.expiresAt) > now &&
      session.authVersion === account.authVersion,
    "UNAUTHORIZED",
    "Your session has expired; sign in again",
    401,
  );
  requireThat(
    !required.length || account.roles.some((role) => required.includes(role)),
    "FORBIDDEN",
    "This operation is not permitted for your account",
    403,
  );
  if (required.length)
    requireThat(
      account.mfaSecret && session.mfaVerified,
      "MFA_REQUIRED",
      "Sign in with multifactor authentication for staff operations",
      403,
    );
  return account;
}
async function removeSessions(tx: Transaction, userId: string) {
  for (;;) {
    const rows = await tx.list("sessions", { where: { userId }, limit: 200 });
    if (!rows.length) return;
    for (const row of rows) await tx.delete("sessions", row.id);
  }
}
export class AccountService {
  constructor(
    public db: Database,
    public config: Config,
    public clock = () => Date.now(),
  ) {}
  private now() {
    return new Date(this.clock()).toISOString();
  }
  private async challenge(
    tx: Transaction,
    user: Account,
    kind: "EMAIL" | "PASSWORD",
  ) {
    const value = secret(),
      now = this.now(),
      id = randomUUID();
    for (const previous of await tx.list("challenges", {
      where: { userId: user.id, kind },
      limit: 100,
    }))
      await tx.delete("challenges", previous.id);
    await tx.insert("challenges", {
      id,
      createdAt: now,
      userId: user.id,
      kind,
      tokenHash: digest(value),
      expiresAt: new Date(this.clock() + 30 * 60000).toISOString(),
    });
    const url = new URL("/site/", this.config.siteUrl);
    url.hash = `${kind === "EMAIL" ? "verify" : "reset"}=${value}`;
    const content = seal(
      JSON.stringify({
        to: user.email,
        subject:
          kind === "EMAIL"
            ? "Verify your PrivateID email"
            : "Reset your PrivateID password",
        text: `Open this link within 30 minutes: ${url}. If you did not request this, ignore this email.`,
      }),
      this.config.encryptionKey,
    );
    await tx.insert("mail", {
      id: randomUUID(),
      createdAt: now,
      userId: user.id,
      content,
      status: "PENDING",
      attempts: 0,
      nextAttemptAt: now,
    });
  }
  async register(input: unknown) {
    const value = registrationSchema.parse(input),
      email = canonicalEmail(value.email),
      passwordHash = await hashPassword(value.password),
      now = this.now();
    return this.db.transaction(async (tx) => {
      requireThat(
        !(await tx.list("accounts", { where: { email }, limit: 1 })).length,
        "CONFLICT",
        "An account with this email already exists",
        409,
      );
      const account: Account = {
        id: randomUUID(),
        createdAt: now,
        email,
        passwordHash,
        status: "ACTIVE",
        roles: ["USER"],
        emailVerified: false,
        authVersion: 1,
        recoveryHashes: [],
      };
      await tx.insert("accounts", account);
      await this.challenge(tx, account, "EMAIL");
      await audit(
        tx,
        "account.created",
        account.id,
        account.id,
        {},
        undefined,
        "SUCCESS",
        now,
      );
      return publicAccount(account);
    });
  }
  async verifyEmail(token: string) {
    return this.db.transaction(async (tx) => {
      const challenge = (
        await tx.list("challenges", {
          where: { tokenHash: digest(token), kind: "EMAIL" },
          limit: 1,
        })
      )[0];
      requireThat(
        challenge && challenge.expiresAt > this.now(),
        "INVALID_CHALLENGE",
        "The verification link is invalid or expired",
      );
      const user = await activeAccount(tx, challenge.userId, false);
      user.emailVerified = true;
      await tx.put("accounts", user);
      await tx.delete("challenges", challenge.id);
      await audit(tx, "email.verified", user.id, user.id);
      return { verified: true };
    });
  }
  async requestChallenge(emailValue: string, kind: "EMAIL" | "PASSWORD") {
    await this.db.transaction(async (tx) => {
      const user = (
        await tx.list("accounts", {
          where: { email: canonicalEmail(emailValue), status: "ACTIVE" },
          limit: 1,
        })
      )[0];
      if (user && (kind !== "EMAIL" || !user.emailVerified))
        await this.challenge(tx, user, kind);
    });
    return {
      message:
        "If the account is eligible, a link will be sent to its email address.",
    };
  }
  private consumeMfa(user: Account, code?: string) {
    if (!user.mfaSecret) return false;
    requireThat(
      code,
      "MFA_REQUIRED",
      "Enter an authenticator or recovery code",
      401,
    );
    const step = verifyTotp(
      unseal(user.mfaSecret, this.config.encryptionKey),
      code,
      this.clock(),
      user.mfaLastStep,
    );
    if (step !== undefined) {
      user.mfaLastStep = step;
      return true;
    }
    const hash = digest(code.replaceAll(" ", "")),
      index = user.recoveryHashes.findIndex((x) => equal(x, hash));
    requireThat(
      index >= 0,
      "INVALID_MFA",
      "The authenticator or recovery code is invalid",
      401,
    );
    user.recoveryHashes.splice(index, 1);
    return true;
  }
  async login(input: {
    email: string;
    password: string;
    code?: string;
    device?: string;
  }) {
    const email = canonicalEmail(input.email);
    const found = await this.db.transaction(
      async (tx) =>
        (await tx.list("accounts", { where: { email }, limit: 1 }))[0],
    );
    const valid = await verifyPassword(input.password, found?.passwordHash);
    if (!found || !valid || found.status !== "ACTIVE") {
      await this.db.transaction((tx) =>
        audit(
          tx,
          "login.failed",
          undefined,
          undefined,
          {
            accountFingerprint: digest(this.config.subjectSecret + email).slice(
              0,
              16,
            ),
          },
          undefined,
          "FAILURE",
        ),
      );
      throw new AppError(
        "INVALID_CREDENTIALS",
        "Email or password is incorrect",
        401,
      );
    }
    return this.db.transaction(async (tx) => {
      const user = await activeAccount(tx, found.id, false);
      requireThat(
        user.passwordHash === found.passwordHash,
        "INVALID_CREDENTIALS",
        "Credentials changed; sign in again",
        401,
      );
      const mfaVerified = this.consumeMfa(user, input.code);
      requireThat(
        !user.roles.some((r) => r !== "USER") || mfaVerified,
        "MFA_REQUIRED",
        "Staff accounts require multifactor authentication",
        401,
      );
      const now = this.now(),
        token = secret(),
        csrfToken = secret();
      for (const expired of await tx.list("sessions", {
        where: { userId: user.id },
        before: { field: "expiresAt", value: now },
        limit: 100,
      }))
        await tx.delete("sessions", expired.id);
      requireThat(
        (await tx.count("sessions", { userId: user.id })) < 20,
        "SESSION_LIMIT",
        "Revoke an existing session before opening another",
        429,
      );
      const session: Session = {
        id: randomUUID(),
        createdAt: now,
        userId: user.id,
        tokenHash: digest(token),
        csrfHash: digest(csrfToken),
        expiresAt: new Date(
          this.clock() + this.config.sessionHours * 3600000,
        ).toISOString(),
        authVersion: user.authVersion,
        lastSeenAt: now,
        device: (input.device ?? "Unknown device").slice(0, 160),
        mfaVerified,
      };
      await tx.put("accounts", user);
      await tx.insert("sessions", session);
      await audit(tx, "login.succeeded", user.id, session.id);
      return {
        accessToken: token,
        csrfToken,
        expiresAt: session.expiresAt,
        user: publicAccount(user),
      };
    });
  }
  async authenticate(token: string) {
    requireThat(
      token && token.length <= 200,
      "UNAUTHORIZED",
      "Sign in to continue",
      401,
    );
    return this.db.transaction(async (tx) => {
      const session = (
        await tx.list("sessions", {
          where: { tokenHash: digest(token) },
          limit: 1,
        })
      )[0];
      requireThat(
        session,
        "UNAUTHORIZED",
        "Your session is invalid; sign in again",
        401,
      );
      const principal = { accountId: session.userId, sessionId: session.id },
        account = await authorize(tx, principal, [], this.clock(), false);
      if (Date.parse(session.lastSeenAt) + 60000 < this.clock()) {
        session.lastSeenAt = this.now();
        await tx.put("sessions", session);
      }
      return { principal, account: publicAccount(account), session };
    });
  }
  async rotateCsrf(principal: Principal) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock(), false);
      const session = (await tx.get("sessions", principal.sessionId))!,
        token = secret();
      session.csrfHash = digest(token);
      await tx.put("sessions", session);
      return token;
    });
  }
  async sessions(principal: Principal) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock(), false);
      return (
        await tx.list("sessions", {
          where: { userId: principal.accountId },
          limit: 100,
        })
      )
        .filter((s) => s.expiresAt > this.now())
        .map((s) => ({
          id: s.id,
          createdAt: s.createdAt,
          expiresAt: s.expiresAt,
          lastSeenAt: s.lastSeenAt,
          device: s.device,
          current: s.id === principal.sessionId,
        }));
    });
  }
  async revokeSession(principal: Principal, id: string) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock(), false);
      const session = await tx.get("sessions", id);
      requireThat(
        session?.userId === principal.accountId,
        "NOT_FOUND",
        "Session not found",
        404,
      );
      await tx.delete("sessions", id);
      await audit(tx, "session.revoked", principal.accountId, id);
      return { revoked: true };
    });
  }
  async startMfa(principal: Principal, password: string) {
    const found = await this.db.transaction((tx) =>
      authorize(tx, principal, [], this.clock()),
    );
    requireThat(
      await verifyPassword(password, found.passwordHash),
      "INVALID_CREDENTIALS",
      "Password is incorrect",
      401,
    );
    return this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock());
      requireThat(
        !user.mfaSecret,
        "MFA_ALREADY_ENABLED",
        "MFA is already enabled",
        409,
      );
      const value = newTotpSecret();
      requireThat(
        user.passwordHash === found.passwordHash,
        "CONFLICT",
        "Password changed; retry setup",
        409,
      );
      user.mfaPending = seal(value, this.config.encryptionKey);
      user.mfaPendingExpiresAt = new Date(this.clock() + 600000).toISOString();
      await tx.put("accounts", user);
      return {
        secret: value,
        uri: `otpauth://totp/PrivateID:${encodeURIComponent(user.email)}?secret=${value}&issuer=PrivateID&algorithm=SHA1&digits=6&period=30`,
      };
    });
  }
  async confirmMfa(principal: Principal, code: string) {
    return this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock());
      requireThat(
        user.mfaPending && (user.mfaPendingExpiresAt ?? "") > this.now(),
        "MFA_NOT_STARTED",
        "Start MFA setup first; setup expires after ten minutes",
      );
      const step = verifyTotp(
        unseal(user.mfaPending, this.config.encryptionKey),
        code,
        this.clock(),
      );
      requireThat(
        step !== undefined,
        "INVALID_MFA",
        "The authenticator code is invalid",
      );
      user.mfaSecret = user.mfaPending;
      delete user.mfaPending;
      delete user.mfaPendingExpiresAt;
      user.mfaLastStep = step;
      const recoveryCodes = Array.from({ length: 10 }, () =>
        secret().slice(0, 20),
      );
      user.recoveryHashes = recoveryCodes.map(digest);
      await tx.put("accounts", user);
      const session = (await tx.get("sessions", principal.sessionId))!;
      session.mfaVerified = true;
      await tx.put("sessions", session);
      await audit(tx, "mfa.enabled", user.id, user.id);
      return { recoveryCodes };
    });
  }
  async resetPassword(token: string, password: string, code?: string) {
    const passwordHash = await hashPassword(passwordSchema.parse(password));
    return this.db.transaction(async (tx) => {
      const challenge = (
        await tx.list("challenges", {
          where: { tokenHash: digest(token), kind: "PASSWORD" },
          limit: 1,
        })
      )[0];
      requireThat(
        challenge && challenge.expiresAt > this.now(),
        "INVALID_CHALLENGE",
        "The reset link is invalid or expired",
      );
      const user = await activeAccount(tx, challenge.userId, false);
      this.consumeMfa(user, code);
      user.passwordHash = passwordHash;
      user.authVersion++;
      await tx.put("accounts", user);
      await removeSessions(tx, user.id);
      await tx.delete("challenges", challenge.id);
      await audit(tx, "password.reset", user.id, user.id);
      return { reset: true };
    });
  }
  async changePassword(
    principal: Principal,
    currentPassword: string,
    newPassword: string,
    code?: string,
  ) {
    const user = await this.db.transaction((tx) =>
      authorize(tx, principal, [], this.clock()),
    );
    requireThat(
      await verifyPassword(currentPassword, user.passwordHash),
      "INVALID_CREDENTIALS",
      "Password is incorrect",
      401,
    );
    const passwordHash = await hashPassword(passwordSchema.parse(newPassword));
    return this.db.transaction(async (tx) => {
      const current = await authorize(tx, principal, [], this.clock());
      requireThat(
        current.passwordHash === user.passwordHash,
        "CONFLICT",
        "Credentials changed",
        409,
      );
      this.consumeMfa(current, code);
      current.passwordHash = passwordHash;
      current.authVersion++;
      await tx.put("accounts", current);
      await removeSessions(tx, current.id);
      await audit(tx, "password.changed", current.id, current.id);
      return { changed: true, signInAgain: true };
    });
  }
  async setStatus(
    principal: Principal,
    id: string,
    status: "ACTIVE" | "SUSPENDED",
    reason: string,
  ) {
    return this.db.transaction(async (tx) => {
      await authorize(
        tx,
        principal,
        ["IDENTITY_ADMIN", "SECURITY_ADMIN"],
        this.clock(),
      );
      const user = await tx.get("accounts", id);
      requireThat(
        user && ["ACTIVE", "SUSPENDED"].includes(user.status),
        "NOT_FOUND",
        "Account not found",
        404,
      );
      requireThat(
        id !== principal.accountId,
        "SELF_SUSPENSION",
        "Ask another administrator to suspend your account",
      );
      if (status === "SUSPENDED" && user.roles.includes("SECURITY_ADMIN"))
        requireThat(
          (
            await tx.list("accounts", {
              where: { status: "ACTIVE" },
              contains: { field: "roles", value: "SECURITY_ADMIN" },
              limit: 2,
            })
          ).length > 1,
          "LAST_ADMIN",
          "The last active security administrator cannot be suspended",
        );
      user.status = status;
      user.authVersion++;
      await tx.put("accounts", user);
      await removeSessions(tx, id);
      await audit(tx, "account.status_changed", principal.accountId, id, {
        status,
        reason,
      });
      return publicAccount(user);
    });
  }
  async grantRoles(
    principal: Principal,
    id: string,
    nextRoles: Role[],
    reason: string,
  ) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, ["SECURITY_ADMIN"], this.clock());
      return this.assignRoles(tx, id, nextRoles, reason, principal.accountId);
    });
  }
  private async assignRoles(
    tx: Transaction,
    id: string,
    nextRoles: Role[],
    reason: string,
    actorId?: string,
  ) {
    const user = await activeAccount(tx, id);
    requireThat(
      !nextRoles.some((r) => r !== "USER") || user.mfaSecret,
      "MFA_REQUIRED",
      "The recipient must verify email and enroll MFA before receiving staff roles",
    );
    const clean = [...new Set(z.array(z.enum(roles)).min(1).parse(nextRoles))];
    if (
      user.roles.includes("SECURITY_ADMIN") &&
      !clean.includes("SECURITY_ADMIN")
    )
      requireThat(
        (
          await tx.list("accounts", {
            where: { status: "ACTIVE" },
            contains: { field: "roles", value: "SECURITY_ADMIN" },
            limit: 2,
          })
        ).length > 1,
        "LAST_ADMIN",
        "The last active security administrator cannot be removed",
      );
    user.roles = clean;
    user.authVersion++;
    await tx.put("accounts", user);
    await removeSessions(tx, id);
    await audit(tx, "account.roles_changed", actorId, id, {
      roles: clean,
      reason,
      source: actorId ? "API" : "OPERATIONAL_CLI",
    });
    return publicAccount(user);
  }
  /** Called only by the local operational CLI, never by an HTTP route. */
  async enrollAdministrator(id: string, nextRoles: Role[], reason: string) {
    return this.db.transaction((tx) =>
      this.assignRoles(tx, id, nextRoles, reason),
    );
  }
  async customers(principal: Principal, query: Query) {
    return this.db.transaction(async (tx) => {
      await authorize(
        tx,
        principal,
        ["IDENTITY_ADMIN", "SECURITY_ADMIN"],
        this.clock(),
      );
      return (await tx.list("accounts", query)).map(publicAccount);
    });
  }
  async requestDeletion(principal: Principal, password: string, code?: string) {
    const found = await this.db.transaction((tx) =>
      authorize(tx, principal, [], this.clock(), false),
    );
    requireThat(
      await verifyPassword(password, found.passwordHash),
      "INVALID_CREDENTIALS",
      "Password is incorrect",
      401,
    );
    return this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock(), false);
      requireThat(
        !user.roles.includes("SECURITY_ADMIN"),
        "ADMIN_DELETION",
        "Transfer security administration and remove the staff role before deletion",
        409,
      );
      requireThat(
        !(
          await tx.list("organizations", {
            where: { ownerId: user.id, status: "ACTIVE" },
            limit: 1,
          })
        ).length,
        "ORGANIZATION_OWNERSHIP",
        "Transfer or close your organizations before deleting the account",
        409,
      );
      requireThat(
        user.passwordHash === found.passwordHash,
        "CONFLICT",
        "Password changed; retry deletion",
        409,
      );
      this.consumeMfa(user, code);
      user.status = "DELETION_PENDING";
      user.deletedAt = this.now();
      user.authVersion++;
      await tx.put("accounts", user);
      await removeSessions(tx, user.id);
      await audit(tx, "account.deletion_requested", user.id, user.id);
      return {
        status: "DELETION_PENDING",
        message:
          "Access is revoked. Billing cancellation and personal-data erasure will be retried until complete.",
      };
    });
  }
}
