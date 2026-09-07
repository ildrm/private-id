import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MemoryDatabase } from "../src/repository.js";
import { testConfig } from "../src/config.js";
import { createServices } from "../src/services.js";
import { BackgroundJobs, AbuseLimiter } from "../src/jobs.js";
import { createUser, testPassword } from "./helpers.js";
test("outbox delivers development challenges without retaining plaintext in database", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "privateid-mail-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let now = Date.now();
  const db = new MemoryDatabase(),
    config = testConfig({ mailDirectory: directory }),
    s = await createServices(db, config, undefined, () => now),
    jobs = new BackgroundJobs(db, config, s.billing, undefined, () => now);
  await s.accounts.register({
    email: "mail@synthetic.test",
    password: testPassword,
  });
  now += 1000;
  await jobs.deliverMail();
  const files = await readdir(directory);
  assert.equal(files.length, 1);
  assert.match(await readFile(join(directory, files[0]), "utf8"), /verify=/);
  const row = (await db.transaction((tx) => tx.list("mail")))[0];
  assert.equal(row.status, "SENT");
  assert.equal(row.content, "");
  await jobs.deliverMail();
  assert.equal((await readdir(directory)).length, 1);
});
test("deletion revokes access immediately and erases secrets after the safety interval", async () => {
  let now = Date.now();
  const db = new MemoryDatabase(),
    config = testConfig(),
    s = await createServices(db, config, undefined, () => now),
    jobs = new BackgroundJobs(db, config, s.billing, undefined, () => now);
  const customer = await createUser(s.accounts, "erase@synthetic.test");
  await s.accounts.requestDeletion(customer.principal, testPassword);
  await assert.rejects(s.accounts.authenticate(customer.login.accessToken));
  await jobs.eraseAccounts();
  assert.equal(
    (await db.transaction((tx) => tx.get("accounts", customer.user.id)))
      ?.status,
    "DELETION_PENDING",
  );
  now += 301000;
  await jobs.eraseAccounts();
  const user = (await db.transaction((tx) =>
    tx.get("accounts", customer.user.id),
  ))!;
  assert.equal(user.status, "DELETED");
  assert.equal(user.passwordHash, "");
  assert.ok(user.email.endsWith("@deleted.invalid"));
  assert.equal(
    await db.transaction((tx) => tx.count("mail", { userId: user.id })),
    0,
  );
});
test("abuse limit is shared between instances and expires without permanent lockout", async () => {
  let now = Date.now();
  const db = new MemoryDatabase(),
    a = new AbuseLimiter(db, () => now),
    b = new AbuseLimiter(db, () => now);
  await a.take("account:test", 2, 60000);
  await b.take("account:test", 2, 60000);
  await assert.rejects(a.take("account:test", 2, 60000));
  now += 60001;
  await b.take("account:test", 2, 60000);
});
