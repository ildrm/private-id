import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import staticPlugin from "@fastify/static";
import { createServices } from "../src/services.js";
import { buildApp } from "../src/app.js";
import { testConfig } from "../src/config.js";
import { MemoryDatabase, PostgresDatabase } from "../src/repository.js";
import { createPool, migrate } from "../src/database.js";
import { createUser, testPassword } from "./helpers.js";
import { digest, unseal } from "../src/security.js";
const config = testConfig({
  siteUrl: "http://127.0.0.1:3197",
  allowedOrigins: ["http://127.0.0.1:3197"],
});
const pool = process.env.TEST_DATABASE_URL
  ? createPool(process.env.TEST_DATABASE_URL)
  : undefined;
if (pool) await migrate(pool);
const db = pool ? new PostgresDatabase(pool) : new MemoryDatabase(),
  s = await createServices(db, config),
  tag = randomUUID();
const customer = await createUser(s.accounts, `browser-${tag}@synthetic.test`),
  clientId = `browser-${tag}`,
  clientSecret = "synthetic-browser-client-secret";
await db.transaction((tx) =>
  tx.insert("verifiers", {
    id: clientId,
    createdAt: new Date().toISOString(),
    name: "Browser test verifier",
    purpose: "Test minimal account disclosure with explicit consent.",
    allowedClaims: ["account_valid"],
    redirectUris: ["http://localhost:3002/callback"],
    environment: "SANDBOX",
    status: "ACTIVE",
    version: 1,
    secretHash: digest(clientSecret),
  }),
);
await mkdir(".data", { recursive: true });
await writeFile(
  ".data/browser-fixture.json",
  JSON.stringify({
    email: customer.user.email,
    password: testPassword,
    clientId,
    clientSecret,
  }),
  { mode: 0o600 },
);
const app = await buildApp(s);
// Test-only mailbox endpoint; this file is excluded from production compilation.
app.get("/__test__/challenge/:email", async (req) => {
  const email = (req.params as { email: string }).email;
  if (!email.endsWith("@synthetic.test"))
    throw new Error("Synthetic tests only");
  return db.transaction(async (tx) => {
    const user = (await tx.list("accounts", { where: { email }, limit: 1 }))[0];
    const messages = await tx.list("mail", {
      where: { userId: user.id },
      limit: 100,
    });
    return messages.map((m) =>
      JSON.parse(unseal(m.content, config.encryptionKey)),
    );
  });
});
await app.register(staticPlugin, {
  root: resolve("web-dist"),
  prefix: "/site/",
});
app.addHook("onClose", async () => db.close());
process.once("SIGTERM", () => app.close());
process.once("SIGINT", () => app.close());
await app.listen({ host: "127.0.0.1", port: 3197 });
