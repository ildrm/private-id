import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Pool } from 'pg';
export function createPool(url = process.env.DATABASE_URL) {
    if (!url)
        throw new Error('DATABASE_URL is required');
    return new Pool({ connectionString: url, max: Number(process.env.DATABASE_POOL_SIZE ?? 10), ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: true } : undefined });
}
export async function migrate(pool, directory = resolve(process.cwd(), 'migrations')) {
    await pool.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    for (const name of (await readdir(directory)).filter(x => x.endsWith('.sql')).sort()) {
        const exists = await pool.query('SELECT 1 FROM schema_migrations WHERE name=$1', [name]);
        if (exists.rowCount)
            continue;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(await readFile(resolve(directory, name), 'utf8'));
            await client.query('INSERT INTO schema_migrations(name) VALUES($1)', [name]);
            await client.query('COMMIT');
        }
        catch (error) {
            await client.query('ROLLBACK');
            throw error;
        }
        finally {
            client.release();
        }
    }
}
