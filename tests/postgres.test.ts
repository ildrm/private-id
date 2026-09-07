import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createPool, migrate } from "../src/database.js";
import { PostgresDatabase } from "../src/repository.js";
import { createServices } from "../src/services.js";
import { testConfig } from "../src/config.js";
import { createUser } from "./helpers.js";
import { audit } from "../src/audit.js";
const url = process.env.TEST_DATABASE_URL;
test(
  "PostgreSQL: migrations, row isolation, rollback recovery, constraints, and shared authorization",
  { skip: !url },
  async (t) => {
    const pool = createPool(url),
      otherPool = createPool(url),
      db = new PostgresDatabase(pool),
      otherDb = new PostgresDatabase(otherPool);
    t.after(async () => {
      await db.close();
      await otherDb.close();
    });
    await migrate(pool);
    await migrate(pool);
    const services = await createServices(db, testConfig()),
      other = await createServices(otherDb, testConfig()),
      tag = randomUUID();
    const [a, b] = await Promise.all([
      createUser(services.accounts, `pg-a-${tag}@synthetic.test`),
      createUser(other.accounts, `pg-b-${tag}@synthetic.test`),
    ]);
    assert.equal(
      (await other.accounts.authenticate(a.login.accessToken)).principal
        .accountId,
      a.user.id,
    );
    const invoice = {
      id: `in-${tag}`,
      createdAt: new Date().toISOString(),
      accountId: b.user.id,
      amountPaid: 0,
      amountDue: 1200,
      currency: "USD",
      status: "open",
      updatedAt: new Date().toISOString(),
      providerUpdatedAt: 1,
    };
    await db.transaction((tx) => tx.put("invoices", invoice));
    await otherDb.transaction((tx) =>
      tx.put("invoices", {
        ...invoice,
        status: "paid",
        amountPaid: 1200,
        providerUpdatedAt: 2,
      }),
    );
    assert.equal(
      (await db.transaction((tx) => tx.get("invoices", invoice.id)))
        ?.amountPaid,
      1200,
    );
    const same = `pg-race-${tag}@synthetic.test`;
    const results = await Promise.allSettled([
      services.accounts.register({
        email: same.toUpperCase(),
        password: "unique database password",
      }),
      other.accounts.register({
        email: same,
        password: "unique database password",
      }),
    ]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    assert.equal(
      await db.transaction((tx) => tx.count("accounts", { email: same })),
      1,
    );
    await assert.rejects(
      db.transaction(async (tx) => {
        await tx.put("metadata", {
          id: tag,
          createdAt: new Date().toISOString(),
          value: { rollback: true },
        });
        throw new Error("fail before commit");
      }),
    );
    assert.equal(
      await db.transaction((tx) => tx.get("metadata", tag)),
      undefined,
    );
    await db.transaction((tx) =>
      tx.put("metadata", {
        id: tag,
        createdAt: new Date().toISOString(),
        value: { kind: "TEST", recovered: true },
      }),
    );
    assert.equal(
      (
        await otherDb.transaction((tx) =>
          tx.list("metadata", { where: { "value.kind": "TEST" } }),
        )
      ).some((m) => m.id === tag),
      true,
    );
    await other.accounts.revokeSession(a.principal, a.principal.sessionId);
    await assert.rejects(services.accounts.authenticate(a.login.accessToken));
    const row = await db.transaction(async (tx) => {
      await audit(tx, "test.immutable", b.user.id);
      return (
        await tx.list("audit", {
          where: { actorId: b.user.id, event: "test.immutable" },
          limit: 1,
        })
      )[0];
    });
    await assert.rejects(
      pool.query("UPDATE pid_audit SET data=data WHERE id=$1", [row.id]),
      /append-only/,
    );
    await assert.rejects(
      pool.query("DELETE FROM pid_audit WHERE id=$1", [row.id]),
      /append-only/,
    );
    await assert.rejects(
      pool.query("INSERT INTO pid_sessions(id,data) VALUES($1,$2::jsonb)", [
        "orphan-" + tag,
        JSON.stringify({ id: "orphan-" + tag, userId: "missing-account" }),
      ]),
      /foreign key/,
    );
  },
);
test(
  "PostgreSQL: concurrent proof redemption across independent pools succeeds exactly once",
  { skip: !url },
  async (t) => {
    const pool = createPool(url),
      otherPool = createPool(url),
      db = new PostgresDatabase(pool),
      db2 = new PostgresDatabase(otherPool);
    t.after(async () => {
      await db.close();
      await db2.close();
    });
    await migrate(pool);
    const s = await createServices(db, testConfig()),
      s2 = await createServices(db2, testConfig()),
      tag = randomUUID(),
      customer = await createUser(s.accounts, `redeem-${tag}@synthetic.test`);
    const { digest } = await import("../src/security.js");
    const clientId = `pg-${tag}`;
    await db.transaction((tx) =>
      tx.insert("verifiers", {
        id: clientId,
        createdAt: new Date().toISOString(),
        name: "Synthetic PostgreSQL client",
        redirectUris: ["http://localhost:3002/callback"],
        allowedClaims: ["account_valid"],
        environment: "SANDBOX",
        status: "ACTIVE",
        version: 1,
        purpose: "PostgreSQL transaction regression test",
        secretHash: digest("test-only-client-secret"),
      }),
    );
    const request = await s.proofs.create(customer.principal, {
        clientId,
        requestedClaims: ["account_valid"],
      }),
      issued = await s.proofs.decide(customer.principal, request.id, true);
    const results = await Promise.allSettled([
      s.proofs.verify(issued.proof!, clientId, "test-only-client-secret"),
      s2.proofs.verify(issued.proof!, clientId, "test-only-client-secret"),
    ]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    assert.equal(
      (await db.transaction((tx) => tx.get("requests", request.id)))?.status,
      "REDEEMED",
    );
  },
);
