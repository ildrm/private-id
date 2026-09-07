import type { Config } from "./config.js";
import { createPool, migrate, verifyMigrations } from "./database.js";
import { PostgresDatabase } from "./repository.js";
import { assertCutoverComplete } from "./legacy.js";
import { requireThat } from "./errors.js";
export async function openDatabase(config: Config) {
  requireThat(
    config.databaseUrl,
    "CONFIGURATION",
    "DATABASE_URL is required; memory storage is restricted to tests",
  );
  const pool = createPool(config.databaseUrl);
  try {
    if (config.mode !== "production") await migrate(pool);
    else {
      await verifyMigrations(pool);
      requireThat(
        (
          await pool.query(
            "SELECT 1 FROM schema_migrations WHERE name='007_operations.sql'",
          )
        ).rowCount,
        "MIGRATION_REQUIRED",
        "Apply migrations with the separate migrator role before starting",
      );
      const permissions = (
        await pool.query(
          "SELECT EXISTS (SELECT 1 FROM unnest(ARRAY[current_user,session_user]) AS roles(name) WHERE has_table_privilege(name, 'pid_audit', 'UPDATE') OR has_table_privilege(name, 'pid_audit', 'DELETE') OR has_function_privilege(name, 'privateid_purge_audit(timestamptz,integer)', 'EXECUTE') OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname=name AND rolsuper)) AS unsafe",
        )
      ).rows[0];
      requireThat(
        !permissions.unsafe,
        "DATABASE_PRIVILEGES",
        "Production runtime must use a restricted role without audit modification or retention privileges",
      );
    }
    await assertCutoverComplete(pool);
    return new PostgresDatabase(pool);
  } catch (error) {
    await pool.end();
    throw error;
  }
}
