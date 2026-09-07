import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import nodemailer from "nodemailer";
import { z } from "zod";
import type { Config } from "./config.js";
import type { Database } from "./repository.js";
import { AppError, requireThat } from "./errors.js";
import { audit } from "./audit.js";
import { digest, unseal } from "./security.js";
import type { BillingService } from "./payments.js";

/** Shared fixed-window limits; hashed identifiers avoid storing source IPs/emails. */
export class AbuseLimiter {
  constructor(
    private db: Database,
    private clock = () => Date.now(),
  ) {}
  async take(key: string, maximum: number, windowMs: number) {
    const allowed = await this.db.transaction(async (tx) => {
      const window = Math.floor(this.clock() / windowMs),
        id = `limit:${digest(key)}:${window}`;
      const old = await tx.get("metadata", id),
        count = Number(old?.value.count ?? 0);
      if (count >= maximum) return false;
      await tx.put("metadata", {
        id,
        createdAt: new Date(this.clock()).toISOString(),
        value: {
          kind: "RATE_LIMIT",
          count: count + 1,
          expiresAt: new Date((window + 1) * windowMs).toISOString(),
        },
      });
      return true;
    });
    requireThat(
      allowed,
      "RATE_LIMITED",
      "Too many attempts. Wait a few minutes before trying again.",
      429,
    );
  }
}

export class BackgroundJobs {
  private running?: Promise<void>;
  private timer?: ReturnType<typeof setInterval>;
  private transport;
  constructor(
    private db: Database,
    private config: Config,
    private billing: BillingService,
    private report: (event: string, code?: string) => void = () => {},
    private clock = () => Date.now(),
  ) {
    this.transport = config.smtpUrl
      ? nodemailer.createTransport(
          {
            url: config.smtpUrl,
            connectionTimeout: 10000,
            greetingTimeout: 10000,
            socketTimeout: 20000,
            ...(config.mode === "production"
              ? { requireTLS: true, tls: { rejectUnauthorized: true } }
              : {}),
          },
          { from: config.mailFrom },
        )
      : undefined;
  }
  private now() {
    return new Date(this.clock()).toISOString();
  }
  private async lease(id: string, work: () => Promise<void>) {
    const token = randomUUID();
    const claimed = await this.db.transaction(async (tx) => {
      const old = await tx.get("metadata", id);
      if (old && String(old.value.until) > this.now()) return false;
      await tx.put("metadata", {
        id,
        createdAt: this.now(),
        value: { token, until: new Date(this.clock() + 300000).toISOString() },
      });
      return true;
    });
    if (!claimed) return;
    try {
      await work();
    } finally {
      await this.db.transaction(async (tx) => {
        const old = await tx.get("metadata", id);
        if (old?.value.token === token) await tx.delete("metadata", id);
      });
    }
  }
  async deliverMail() {
    const messages = await this.db.transaction((tx) =>
      tx.list("mail", {
        where: { status: "PENDING" },
        before: { field: "nextAttemptAt", value: this.now() },
        limit: 10,
      }),
    );
    for (const message of messages)
      await this.lease(`mail-lease:${message.id}`, async () => {
        const current = await this.db.transaction((tx) =>
          tx.get("mail", message.id),
        );
        if (current?.status !== "PENDING") return;
        try {
          const content = z
            .object({ to: z.email(), subject: z.string(), text: z.string() })
            .strict()
            .parse(
              JSON.parse(unseal(current.content, this.config.encryptionKey)),
            );
          const user = await this.db.transaction((tx) =>
            tx.get("accounts", current.userId),
          );
          if (
            user?.status === "ACTIVE" &&
            Date.parse(current.createdAt) + 1800000 > this.clock()
          ) {
            if (this.transport)
              await this.transport.sendMail({
                ...content,
                messageId: `<${current.id}@privateid>`,
                from: this.config.mailFrom,
              });
            else {
              requireThat(
                this.config.mode !== "production",
                "MAIL_CONFIGURATION",
                "Production mail transport is unavailable",
                503,
              );
              await mkdir(this.config.mailDirectory, {
                recursive: true,
                mode: 0o700,
              });
              await writeFile(
                resolve(this.config.mailDirectory, `${current.id}.json`),
                JSON.stringify(content, null, 2),
                { mode: 0o600 },
              );
            }
          }
          await this.db.transaction(async (tx) => {
            const row = await tx.get("mail", current.id);
            if (row) {
              row.status = "SENT";
              row.content = "";
              row.attempts++;
              await tx.put("mail", row);
            }
          });
        } catch (error) {
          await this.db.transaction(async (tx) => {
            const row = await tx.get("mail", current.id);
            if (row) {
              row.attempts++;
              row.status = row.attempts >= 8 ? "FAILED" : "PENDING";
              row.nextAttemptAt = new Date(
                this.clock() + 10000 * 2 ** row.attempts,
              ).toISOString();
              await tx.put("mail", row);
            }
          });
          this.report(
            "mail.delivery_failed",
            error instanceof AppError ? error.code : "TRANSPORT_FAILURE",
          );
        }
      });
  }
  async eraseAccounts() {
    const accounts = await this.db.transaction((tx) =>
      tx.list("accounts", { where: { status: "DELETION_PENDING" }, limit: 10 }),
    );
    for (const account of accounts)
      await this.lease(`erase:${account.id}`, async () => {
        try {
          // Wait out any provider request that started before access was revoked.
          if (Date.parse(account.deletedAt!) + 300000 > this.clock()) return;
          await this.billing.cancelForDeletion(account.id);
          await this.db.transaction(async (tx) => {
            const user = await tx.get("accounts", account.id);
            if (user?.status !== "DELETION_PENDING") return;
            let remaining = false;
            for (const table of [
              "sessions",
              "challenges",
              "mail",
              "requests",
              "access",
              "memberships",
            ] as const) {
              const rows = await tx.list(table, {
                where: { userId: user.id },
                limit: 100,
              });
              for (const row of rows) await tx.delete(table, row.id);
              remaining ||= rows.length === 100;
            }
            for (const credential of await tx.list("credentials", {
              where: { userId: user.id },
              limit: 100,
            }))
              await tx.delete("credentials", credential.id);
            remaining ||=
              (await tx.count("credentials", { userId: user.id })) > 0;
            for (const issuer of await tx.list("issuers", {
              where: { ownerId: user.id },
              limit: 1000,
            })) {
              issuer.status = "REVOKED";
              issuer.version++;
              issuer.issuerName = "Withdrawn issuer";
              issuer.policy =
                "Issuer account deleted; authority permanently withdrawn.";
              issuer.reason = "Account deleted";
              await tx.put("issuers", issuer);
            }
            for (const client of await tx.list("verifiers", {
              where: { ownerId: user.id },
              limit: 1000,
            })) {
              client.status = "REVOKED";
              client.version++;
              client.name = "Withdrawn verifier";
              client.purpose = "Verifier account deleted";
              client.redirectUris = ["https://deleted.invalid/"];
              delete client.secretHash;
              await tx.put("verifiers", client);
            }
            for (const org of await tx.list("organizations", {
              where: { ownerId: user.id, status: "SUSPENDED" },
              limit: 1000,
            })) {
              org.name = "Closed organization";
              await tx.put("organizations", org);
            }
            if (remaining) return;
            user.email = `${user.id}@deleted.invalid`;
            user.passwordHash = "";
            user.emailVerified = false;
            user.roles = ["USER"];
            user.recoveryHashes = [];
            user.status = "DELETED";
            delete user.mfaSecret;
            delete user.mfaPending;
            delete user.mfaPendingExpiresAt;
            delete user.mfaLastStep;
            await tx.put("accounts", user);
            await audit(tx, "account.erased", undefined, user.id, {
              retained: [
                "pseudonymous accounting references",
                "time-limited security audit",
              ],
            });
          });
        } catch (error) {
          this.report(
            "account.erasure_retry",
            error instanceof AppError ? error.code : "DEPENDENCY_FAILURE",
          );
        }
      });
  }
  async retain() {
    await this.db.transaction(async (tx) => {
      const now = this.now(),
        before = (days: number) =>
          new Date(this.clock() - days * 86400000).toISOString();
      for (const table of ["sessions", "challenges"] as const)
        for (const row of await tx.list(table, {
          before: { field: "expiresAt", value: now },
          limit: 100,
        }))
          await tx.delete(table, row.id);
      for (const row of await tx.list("mail", {
        before: { field: "createdAt", value: before(1) },
        limit: 100,
      }))
        await tx.delete("mail", row.id);
      for (const row of await tx.list("metadata", {
        where: { "value.kind": "RATE_LIMIT" },
        before: { field: "createdAt", value: before(1) },
        limit: 100,
      }))
        await tx.delete("metadata", row.id);
      for (const credential of await tx.list("credentials", {
        where: { status: "ACTIVE" },
        before: { field: "expiresAt", value: now },
        limit: 100,
      })) {
        credential.status = "EXPIRED";
        await tx.put("credentials", credential);
      }
      for (const status of ["EXPIRED", "REVOKED"] as const)
        for (const credential of await tx.list("credentials", {
          where: { status },
          before: {
            field: status === "REVOKED" ? "revokedAt" : "expiresAt",
            value: before(30),
          },
          limit: 100,
        })) {
          credential.status = "REDACTED";
          credential.claims = {};
          credential.evidenceReference = "";
          credential.evidencePolicy = "Retention period ended";
          credential.redactedAt = now;
          await tx.put("credentials", credential);
        }
      for (const status of ["PENDING", "ISSUED"] as const)
        for (const request of await tx.list("requests", {
          where: { status },
          before: { field: "expiresAt", value: now },
          limit: 100,
        })) {
          request.status = "EXPIRED";
          delete request.codeHash;
          delete request.proofHash;
          await tx.put("requests", request);
        }
      for (const request of await tx.list("requests", {
        before: {
          field: "createdAt",
          value: before(this.config.retentionDays),
        },
        limit: 100,
      }))
        await tx.delete("requests", request.id);
      for (const status of ["APPLIED", "IGNORED"] as const)
        for (const event of await tx.list("billing_events", {
          where: { status },
          before: { field: "createdAt", value: before(30) },
          limit: 100,
        }))
          await tx.delete("billing_events", event.id);
      for (const user of await tx.list("accounts", {
        where: { status: "DELETED" },
        before: { field: "deletedAt", value: before(730) },
        limit: 10,
      })) {
        for (const table of [
          "invoices",
          "refunds",
          "disputes",
          "subscriptions",
          "usage",
          "checkouts",
        ] as const)
          for (const row of await tx.list(table, {
            where: { accountId: user.id },
            limit: 100,
          }))
            await tx.delete(table, row.id);
        // A customer mapping remains only while linked accounting records are retained.
        if (
          !(await tx.count("invoices", { accountId: user.id })) &&
          !(await tx.count("subscriptions", { accountId: user.id }))
        )
          await tx.delete("billing_customers", user.id);
      }
    });
  }
  async tick() {
    for (const [name, work] of [
      ["mail", () => this.deliverMail()],
      ["billing", () => this.billing.processDue()],
      ["reconcile", () => this.billing.scheduleReconciliation()],
      ["erasure", () => this.eraseAccounts()],
      ["retention", () => this.retain()],
    ] as const) {
      try {
        await work();
      } catch (error) {
        this.report(
          `worker.${name}_failed`,
          error instanceof AppError ? error.code : "DEPENDENCY_FAILURE",
        );
      }
    }
    await this.db.transaction((tx) =>
      tx.put("metadata", {
        id: "worker-heartbeat",
        createdAt: this.now(),
        value: { updatedAt: this.now() },
      }),
    );
  }
  start() {
    const run = () => {
      if (!this.running)
        this.running = this.tick()
          .catch(() => this.report("worker.tick_failed"))
          .finally(() => {
            this.running = undefined;
          });
    };
    this.timer = setInterval(run, 1000);
    this.timer.unref();
    run();
  }
  async stop() {
    if (this.timer) clearInterval(this.timer);
    await this.running;
    this.transport?.close();
  }
}
