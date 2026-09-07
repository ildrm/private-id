import test from "node:test";
import assert from "node:assert/strict";
import { MemoryDatabase } from "../src/repository.js";
import { AccountService } from "../src/accounts.js";
import { testConfig, loadConfig } from "../src/config.js";
import { audit } from "../src/audit.js";
import { totp, unseal } from "../src/security.js";

async function setup() {
  const db = new MemoryDatabase(),
    config = testConfig(),
    accounts = new AccountService(db, config);
  const user = await accounts.register({
    email: "member@example.test",
    password: "a unique test password",
  });
  const mail = await db.transaction((tx) => tx.list("mail"));
  const text = JSON.parse(unseal(mail[0].content, config.encryptionKey))
    .text as string;
  const token = text.match(/verify=([A-Za-z0-9_-]+)/)![1];
  await accounts.verifyEmail(token);
  const login = await accounts.login({
    email: user.email,
    password: "a unique test password",
  });
  const auth = await accounts.authenticate(login.accessToken);
  return { db, config, accounts, user, login, principal: auth.principal };
}
test("failed commits roll back and do not poison later transactions", async () => {
  const db = new MemoryDatabase();
  db.failNextCommit = true;
  await assert.rejects(
    db.transaction((tx) =>
      tx.insert("metadata", {
        id: "a",
        createdAt: new Date().toISOString(),
        value: {},
      }),
    ),
  );
  assert.equal(
    await db.transaction((tx) => tx.get("metadata", "a")),
    undefined,
  );
  await db.transaction((tx) =>
    tx.insert("metadata", {
      id: "b",
      createdAt: new Date().toISOString(),
      value: {},
    }),
  );
  assert.ok(await db.transaction((tx) => tx.get("metadata", "b")));
});
test("concurrent registration creates one canonical email and public input cannot grant roles", async () => {
  const db = new MemoryDatabase(),
    a = new AccountService(db, testConfig());
  const input = {
    email: "same@example.test",
    password: "a unique test password",
  };
  const results = await Promise.allSettled([
    a.register(input),
    a.register({ ...input, email: "SAME@example.test" }),
  ]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(await db.transaction((tx) => tx.count("accounts")), 1);
  await assert.rejects(
    a.register({
      ...input,
      email: "other@example.test",
      roles: ["SECURITY_ADMIN"],
    }),
  );
});
test("session management returns IDs that cannot authenticate, and revocation works", async () => {
  const { accounts, principal, login } = await setup();
  const sessions = await accounts.sessions(principal);
  assert.notEqual(sessions[0].id, login.accessToken);
  await assert.rejects(accounts.authenticate(sessions[0].id));
  await accounts.revokeSession(principal, sessions[0].id);
  await assert.rejects(accounts.authenticate(login.accessToken));
});
test("email challenges are single-use and MFA is required before operational enrollment", async () => {
  const { accounts, principal, user, db } = await setup();
  await assert.rejects(
    accounts.enrollAdministrator(
      user.id,
      ["USER", "SECURITY_ADMIN"],
      "Initial enrollment",
    ),
  );
  const mfa = await accounts.startMfa(principal, "a unique test password");
  const codes = await accounts.confirmMfa(
    principal,
    totp(mfa.secret, Math.floor(Date.now() / 30000)),
  );
  assert.equal(codes.recoveryCodes.length, 10);
  await accounts.enrollAdministrator(
    user.id,
    ["USER", "SECURITY_ADMIN"],
    "Initial enrollment",
  );
  await assert.rejects(
    accounts.login({ email: user.email, password: "a unique test password" }),
  );
  const login = await accounts.login({
    email: user.email,
    password: "a unique test password",
    code: codes.recoveryCodes[0],
  });
  assert.ok(login.accessToken);
  await assert.rejects(
    accounts.login({
      email: user.email,
      password: "a unique test password",
      code: codes.recoveryCodes[0],
    }),
  );
  const events = await db.transaction((tx) => tx.list("audit"));
  assert.ok(events.some((e) => e.event === "account.roles_changed"));
});
test("audit history cannot be rewritten through a repository", async () => {
  const db = new MemoryDatabase();
  await db.transaction((tx) => audit(tx, "test.event"));
  const row = (await db.transaction((tx) => tx.list("audit")))[0];
  await assert.rejects(
    db.transaction((tx) => tx.put("audit", { ...row, event: "changed" })),
  );
  await assert.rejects(db.transaction((tx) => tx.delete("audit", row.id)));
});
test("production configuration rejects development defaults and obsolete bootstrap", () => {
  assert.throws(() => loadConfig({ NODE_ENV: "production" }));
  assert.throws(
    () =>
      loadConfig({ PRIVATEID_BOOTSTRAP_ADMIN_EMAILS: "admin@example.test" }),
    /bootstrap/,
  );
});
