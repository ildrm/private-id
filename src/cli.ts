import { generateKeyPairSync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import { loadConfig, testConfig } from "./config.js";
import { createPool, migrate } from "./database.js";
import { PostgresDatabase } from "./repository.js";
import { AccountService } from "./accounts.js";
import { roles } from "./models.js";
import {
  importLegacy,
  finalizeCutover,
  assertCutoverComplete,
} from "./legacy.js";
import { seed } from "./seed.js";
import { requireThat } from "./errors.js";
const [command, ...args] = process.argv.slice(2);
const flag = (name: string) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
if (command === "keygen") {
  const directory = resolve(flag("--directory") ?? ".data/keys");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  await writeFile(
    resolve(directory, "signing-private.pem"),
    privateKey.export({ format: "pem", type: "pkcs8" }),
    { mode: 0o600, flag: "wx" },
  );
  await writeFile(
    resolve(directory, "signing-public.pem"),
    publicKey.export({ format: "pem", type: "spki" }),
    { mode: 0o644, flag: "wx" },
  );
  console.log(
    JSON.stringify({
      directory,
      message:
        "Mount the private key as a secret and assign a unique signing key ID.",
    }),
  );
} else {
  // These offline DB operations neither sign proofs nor decrypt identity data.
  // They intentionally require no application signing/SMTP secrets.
  const databaseOnly = [
    "migrate",
    "retention",
    "enroll-admin",
    "finalize-cutover",
  ].includes(command);
  const config = databaseOnly
      ? testConfig({
          databaseUrl: process.env.DATABASE_URL,
          auditRetentionDays: z.coerce
            .number()
            .int()
            .min(30)
            .max(3650)
            .parse(process.env.AUDIT_RETENTION_DAYS ?? 365),
        })
      : loadConfig(),
    pool = createPool(config.databaseUrl),
    db = new PostgresDatabase(pool);
  try {
    if (command === "migrate") {
      await migrate(pool);
      console.log("Migrations applied and checksums verified.");
    } else if (command === "import-legacy") {
      requireThat(
        args.includes("--acknowledge-invalidations") && flag("--archive"),
        "ARGUMENTS",
        "Provide --archive PATH --acknowledge-invalidations after stopping old instances and backing up the database",
      );
      await migrate(pool);
      console.log(
        JSON.stringify(await importLegacy(pool, config, flag("--archive")!)),
      );
    } else if (command === "finalize-cutover") {
      await finalizeCutover(pool);
      console.log("Previously committed cutover finalized.");
    } else if (command === "enroll-admin") {
      await assertCutoverComplete(pool);
      const id = z.string().min(1).parse(flag("--account")),
        next = z.array(z.enum(roles)).min(1).parse(flag("--roles")?.split(",")),
        reason = z.string().min(10).max(1000).parse(flag("--reason"));
      console.log(
        JSON.stringify(
          await new AccountService(db, config).enrollAdministrator(
            id,
            next,
            reason,
          ),
        ),
      );
    } else if (command === "seed") {
      await migrate(pool);
      await assertCutoverComplete(pool);
      console.log(JSON.stringify(await seed(db, config)));
    } else if (command === "retention") {
      const cutoff = new Date(
        Date.now() - Math.max(30, config.auditRetentionDays) * 86400000,
      ).toISOString();
      console.log(
        JSON.stringify({
          cutoff,
          removed: (
            await pool.query(
              "SELECT privateid_purge_audit($1::timestamptz,1000) AS removed",
              [cutoff],
            )
          ).rows[0].removed,
        }),
      );
    } else
      throw new Error(
        "Usage: cli.ts migrate | keygen | seed | enroll-admin --account ID --roles USER,SECURITY_ADMIN --reason TEXT | import-legacy --archive PATH --acknowledge-invalidations | finalize-cutover | retention",
      );
  } finally {
    await db.close();
  }
}
