import { writeFile } from "node:fs/promises";
import type { Pool } from "pg";
import { z } from "zod";
import type { Config } from "./config.js";
import { canonicalEmail, seal } from "./security.js";
import { requireThat } from "./errors.js";
import { PostgresDatabase } from "./repository.js";
import { audit } from "./audit.js";

export async function assertCutoverComplete(pool: Pool) {
  const result = await pool.query(
    "SELECT EXISTS(SELECT 1 FROM runtime_state WHERE payload <> '{}'::jsonb) OR EXISTS(SELECT 1 FROM billing_customers) OR EXISTS(SELECT 1 FROM users) AS legacy",
  );
  requireThat(
    !result.rows[0].legacy,
    "LEGACY_CUTOVER_REQUIRED",
    "Legacy data detected. Stop all old instances and run the documented archived cutover before starting v2.",
    503,
  );
}

/** Offline, explicit migration; legacy assurance, admin grants, and bearer proofs are never trusted. */
export async function importLegacy(
  pool: Pool,
  config: Config,
  archivePath: string,
) {
  const client = await pool.connect();
  try {
    await client.query(
      "SELECT pg_advisory_lock(hashtext('privateid-legacy-cutover'))",
    );
    requireThat(
      !(await client.query("SELECT 1 FROM users LIMIT 1")).rowCount,
      "ALTERNATE_LEGACY_SCHEMA",
      "Manually populated legacy normalized identity tables require a reviewed mapping; no data was changed",
    );
    const snapshot = (
      await client.query("SELECT payload FROM runtime_state WHERE id=true")
    ).rows[0]?.payload;
    const customers = (await client.query("SELECT * FROM billing_customers"))
      .rows;
    const subscriptions = (await client.query("SELECT * FROM subscriptions"))
      .rows;
    const payments = (await client.query("SELECT * FROM payments")).rows;
    requireThat(
      snapshot || customers.length,
      "NO_LEGACY_DATA",
      "There is no legacy data to import",
    );
    const encoded = JSON.stringify({
      format: "privateid-legacy-v1",
      exportedAt: new Date().toISOString(),
      snapshot,
      customers,
      subscriptions,
      payments,
    });
    requireThat(
      Buffer.byteLength(encoded) <= 50 * 1024 * 1024,
      "IMPORT_SIZE",
      "Legacy archive exceeds the 50 MiB offline migration limit; use a reviewed batch migration",
    );
    await writeFile(archivePath, seal(encoded, config.encryptionKey), {
      flag: "wx",
      mode: 0o600,
    });
    const user = z.object({
      id: z.uuid(),
      email: z.email(),
      passwordHash: z.string().regex(/^[^:]+:[a-f0-9]{128}$/),
      accountValid: z.boolean(),
    });
    const users = z
      .array(z.tuple([z.string(), user]))
      .parse(snapshot?.users ?? [])
      .map(([, value]) => value);
    const db = new PostgresDatabase(pool),
      now = new Date().toISOString();
    await db.transaction(async (tx) => {
      requireThat(
        (await tx.count("accounts")) === 0,
        "NONEMPTY_TARGET",
        "Legacy import requires an empty v2 account database",
      );
      for (const value of users)
        await tx.insert("accounts", {
          id: value.id,
          createdAt: now,
          email: canonicalEmail(value.email),
          passwordHash: value.passwordHash,
          emailVerified: false,
          status: value.accountValid ? "ACTIVE" : "SUSPENDED",
          roles: ["USER"],
          authVersion: 1,
          recoveryHashes: [],
        });
      for (const customer of customers) {
        requireThat(
          users.some((u) => u.id === customer.account_id),
          "ORPHAN_BILLING_CUSTOMER",
          "Reconcile orphan billing accounts before cutover",
        );
        await tx.insert("billing_customers", {
          id: customer.account_id,
          accountId: customer.account_id,
          createdAt: now,
          stripeCustomerId: customer.stripe_customer_id,
        });
      }
      await tx.insert("metadata", {
        id: "legacy-cutover",
        createdAt: now,
        value: {
          accounts: users.length,
          customers: customers.length,
          invalidated: [
            "sessions",
            "proofs",
            "unverified assurance",
            "administrator grants",
            "unreviewed applications",
          ],
        },
      });
      await audit(tx, "migration.legacy_imported", undefined, undefined, {
        accounts: users.length,
        customers: customers.length,
      });
    });
    // Marking the input as consumed occurs only after the v2 transaction committed.
    // If this step fails, startup still refuses traffic; resume with finalize-cutover.
    await finalizeCutover(pool);
    return {
      accounts: users.length,
      customers: customers.length,
      archivePath,
      message:
        "Users must verify email. Issuers, applications, and staff must be enrolled again. Billing will reconcile from the provider.",
    };
  } finally {
    await client
      .query("SELECT pg_advisory_unlock(hashtext('privateid-legacy-cutover'))")
      .catch(() => {});
    client.release();
  }
}
export async function finalizeCutover(pool: Pool) {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    requireThat(
      (await c.query("SELECT 1 FROM pid_metadata WHERE id='legacy-cutover'"))
        .rowCount,
      "NO_COMMITTED_IMPORT",
      "No successful import exists",
    );
    // The archive preserves the baseline; obsolete personal data must not remain in live tables.
    for (const table of [
      "runtime_state",
      "billing_customers",
      "subscriptions",
      "payments",
      "stripe_events",
    ])
      await c.query(`DELETE FROM ${table}`);
    await c.query("COMMIT");
  } catch (error) {
    await c.query("ROLLBACK");
    throw error;
  } finally {
    c.release();
  }
}
