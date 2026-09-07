import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPool, migrate, verifyMigrations } from "../src/database.js";
import { PostgresDatabase } from "../src/repository.js";
import { assertCutoverComplete, importLegacy } from "../src/legacy.js";
import { testConfig } from "../src/config.js";
import { hashPassword, unseal } from "../src/security.js";
const url = process.env.TEST_DATABASE_URL;
test(
  "legacy cutover archives inputs, invalidates old authority, preserves billing mappings, and guards startup",
  { skip: !url },
  async (t) => {
    const admin = createPool(url),
      name = `privateid_cutover_${randomUUID().replaceAll("-", "")}`;
    await admin.query(`CREATE DATABASE ${name}`);
    const target = new URL(url!);
    target.pathname = `/${name}`;
    const pool = createPool(target.href),
      db = new PostgresDatabase(pool);
    const directory = await mkdtemp(join(tmpdir(), "privateid-cutover-"));
    t.after(async () => {
      await db.close();
      await admin.query(`DROP DATABASE ${name}`);
      await admin.end();
      await rm(directory, { recursive: true, force: true });
    });
    await migrate(pool);
    await verifyMigrations(pool);
    const id = randomUUID(),
      passwordHash = await hashPassword("legacy synthetic password"),
      snapshot = {
        users: [
          [
            id,
            {
              id,
              email: "legacy@synthetic.test",
              passwordHash,
              accountValid: true,
              emailVerified: true,
              roles: ["SECURITY_ADMIN"],
              identityVerified: true,
            },
          ],
        ],
        sessions: [["raw-old-token", { userId: id }]],
        requests: [],
        credentials: [],
      };
    await pool.query("INSERT INTO runtime_state(id,payload) VALUES(true,$1)", [
      snapshot,
    ]);
    await pool.query(
      "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
      [id, "cus_legacy_test"],
    );
    await assert.rejects(assertCutoverComplete(pool));
    const config = testConfig(),
      archive = join(directory, "legacy.archive");
    await importLegacy(pool, config, archive);
    await assertCutoverComplete(pool);
    const account = (await db.transaction((tx) => tx.get("accounts", id)))!;
    assert.equal(account.emailVerified, false);
    assert.deepEqual(account.roles, ["USER"]);
    assert.equal(account.passwordHash, passwordHash);
    assert.equal("identityVerified" in account, false);
    assert.equal(await db.transaction((tx) => tx.count("sessions")), 0);
    assert.equal(
      (await db.transaction((tx) => tx.get("billing_customers", id)))
        ?.stripeCustomerId,
      "cus_legacy_test",
    );
    const encrypted = await readFile(archive, "utf8");
    assert.ok(!encrypted.includes("raw-old-token"));
    assert.equal(
      JSON.parse(unseal(encrypted, config.encryptionKey)).snapshot
        .sessions[0][0],
      "raw-old-token",
    );
    await pool.query(
      "UPDATE schema_migrations SET checksum='changed' WHERE name='007_operations.sql'",
    );
    await assert.rejects(verifyMigrations(pool), /Apply and verify migration/);
  },
);
