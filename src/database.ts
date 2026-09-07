import { readFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { Pool } from "pg";
import { requireThat } from "./errors.js";

export function createPool(url = process.env.DATABASE_URL): Pool {
  requireThat(url, "CONFIGURATION", "DATABASE_URL is required");
  const max = Number(process.env.DATABASE_POOL_SIZE ?? 10);
  requireThat(
    Number.isInteger(max) && max > 0 && max <= 100,
    "CONFIGURATION",
    "DATABASE_POOL_SIZE must be between 1 and 100",
  );
  const pool = new Pool({
    connectionString: url,
    max,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    statement_timeout: 10000,
    query_timeout: 12000,
    idle_in_transaction_session_timeout: 15000,
    ssl:
      process.env.DATABASE_SSL === "true"
        ? { rejectUnauthorized: true }
        : undefined,
  });
  pool.on("error", (error) =>
    console.error(
      JSON.stringify({ event: "database.pool_error", name: error.name }),
    ),
  );
  return pool;
}
export async function migrate(
  pool: Pool,
  directory = resolve(process.cwd(), "migrations"),
) {
  const client = await pool.connect();
  try {
    await client.query(
      "SELECT pg_advisory_lock(hashtext('privateid-schema-migrations'))",
    );
    await client.query(
      "CREATE TABLE IF NOT EXISTS schema_migrations(name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now(), checksum text)",
    );
    await client.query(
      "ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text",
    );
    for (const name of (await readdir(directory))
      .filter((x) => x.endsWith(".sql"))
      .sort()) {
      const sql = await readFile(resolve(directory, name), "utf8"),
        checksum = createHash("sha256").update(sql).digest("hex");
      const exists = await client.query(
        "SELECT checksum FROM schema_migrations WHERE name=$1",
        [name],
      );
      if (exists.rowCount) {
        requireThat(
          !exists.rows[0].checksum || exists.rows[0].checksum === checksum,
          "MIGRATION_CHANGED",
          `Applied migration changed: ${name}`,
        );
        if (!exists.rows[0].checksum)
          await client.query(
            "UPDATE schema_migrations SET checksum=$1 WHERE name=$2",
            [checksum, name],
          );
        continue;
      }
      try {
        await client.query("BEGIN");
        await client.query(sql);
        await client.query(
          "INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)",
          [name, checksum],
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    }
  } finally {
    await client
      .query(
        "SELECT pg_advisory_unlock(hashtext('privateid-schema-migrations'))",
      )
      .catch(() => undefined);
    client.release();
  }
}

/** Read-only verification for restricted production runtime connections. */
export async function verifyMigrations(
  pool: Pool,
  directory = resolve(process.cwd(), "migrations"),
) {
  const rows = (
    await pool.query("SELECT name, checksum FROM schema_migrations")
  ).rows;
  for (const name of (await readdir(directory))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    const checksum = createHash("sha256")
      .update(await readFile(resolve(directory, name), "utf8"))
      .digest("hex");
    requireThat(
      rows.some((row) => row.name === name && row.checksum === checksum),
      "MIGRATION_REQUIRED",
      `Apply and verify migration ${name} with the migrator role before starting`,
      503,
    );
  }
}
