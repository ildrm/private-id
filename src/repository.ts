import type { Pool, PoolClient } from "pg";
import { recordSchemas, type Records, type Table } from "./models.js";
import { AppError, requireThat, unavailable } from "./errors.js";
export type Filter = Record<string, string | number | boolean | null>;
export type Query = {
  where?: Filter;
  organizationId?: string;
  limit?: number;
  cursor?: string;
  before?: { field: string; value: string };
  contains?: { field: string; value: string };
};
export interface Transaction {
  get<K extends Table>(table: K, id: string): Promise<Records[K] | undefined>;
  list<K extends Table>(table: K, query?: Query): Promise<Records[K][]>;
  count(table: Table, where?: Filter): Promise<number>;
  insert<K extends Table>(table: K, value: Records[K]): Promise<void>;
  put<K extends Table>(table: K, value: Records[K]): Promise<void>;
  delete(table: Table, id: string): Promise<void>;
}
export interface Database {
  transaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T>;
  health(): Promise<boolean>;
  close(): Promise<void>;
}
function parse<K extends Table>(table: K, value: unknown): Records[K] {
  const result = recordSchemas[table].safeParse(value);
  if (!result.success)
    throw new AppError(
      "RECORD_CONTRACT",
      "A stored record could not be validated",
      500,
    );
  return result.data as Records[K];
}
const tableName = (table: Table) => {
  requireThat(
    Object.hasOwn(recordSchemas, table),
    "INVALID_TABLE",
    "Unknown repository",
  );
  return `pid_${table}`;
};
function clauses(query: Query, params: unknown[]) {
  const parts: string[] = [];
  if (query.where && Object.keys(query.where).length) {
    params.push(
      JSON.stringify(
        Object.fromEntries(
          Object.entries(query.where).map(([key, value]) =>
            key.includes(".")
              ? [key.split(".")[0], { [key.split(".")[1]]: value }]
              : [key, value],
          ),
        ),
      ),
    );
    parts.push(`data @> $${params.length}::jsonb`);
  }
  if (query.cursor) {
    params.push(query.cursor);
    parts.push(`id > $${params.length}`);
  }
  if (query.before) {
    params.push(query.before.field, query.before.value);
    parts.push(`data->>$${params.length - 1} < $${params.length}`);
  }
  if (query.contains) {
    params.push(query.contains.field, JSON.stringify([query.contains.value]));
    parts.push(`data->$${params.length - 1} @> $${params.length}::jsonb`);
  }
  return parts.length ? ` WHERE ${parts.join(" AND ")}` : "";
}
class PostgresTransaction implements Transaction {
  constructor(private client: PoolClient) {}
  async get<K extends Table>(table: K, id: string) {
    const r = await this.client.query(
      `SELECT data FROM ${tableName(table)} WHERE id=$1 FOR UPDATE`,
      [id],
    );
    return r.rows[0] ? parse(table, r.rows[0].data) : undefined;
  }
  async list<K extends Table>(table: K, query: Query = {}) {
    const limit = query.limit ?? 50;
    requireThat(
      Number.isInteger(limit) && limit > 0 && limit <= 1000,
      "INVALID_LIMIT",
      "Page size is outside the permitted range",
    );
    const params: unknown[] = [];
    const where = clauses(query, params);
    params.push(limit);
    const r = await this.client.query(
      `SELECT data FROM ${tableName(table)}${where} ORDER BY id LIMIT $${params.length}`,
      params,
    );
    return r.rows.map((row) => parse(table, row.data));
  }
  async count(table: Table, where: Filter = {}) {
    const params: unknown[] = [];
    const condition = clauses({ where }, params);
    const r = await this.client.query(
      `SELECT count(*)::int AS count FROM ${tableName(table)}${condition}`,
      params,
    );
    return Number(r.rows[0].count);
  }
  async insert<K extends Table>(table: K, value: Records[K]) {
    const clean = parse(table, value);
    await this.client.query(
      `INSERT INTO ${tableName(table)}(id,data) VALUES($1,$2::jsonb)`,
      [clean.id, JSON.stringify(clean)],
    );
  }
  async put<K extends Table>(table: K, value: Records[K]) {
    requireThat(
      table !== "audit",
      "IMMUTABLE_AUDIT",
      "Audit records cannot be modified",
      403,
    );
    const clean = parse(table, value);
    await this.client.query(
      `INSERT INTO ${tableName(table)}(id,data) VALUES($1,$2::jsonb) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`,
      [clean.id, JSON.stringify(clean)],
    );
  }
  async delete(table: Table, id: string) {
    requireThat(
      table !== "audit",
      "IMMUTABLE_AUDIT",
      "Audit retention is an operational task",
      403,
    );
    await this.client.query(`DELETE FROM ${tableName(table)} WHERE id=$1`, [
      id,
    ]);
  }
}
export class PostgresDatabase implements Database {
  constructor(public readonly pool: Pool) {}
  async transaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    for (let attempt = 0; attempt < 4; attempt++) {
      const client = await this.pool.connect();
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const result = await work(new PostgresTransaction(client));
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        const code =
          error && typeof error === "object" && "code" in error
            ? String(error.code)
            : "";
        if (["40001", "40P01"].includes(code)) {
          if (attempt < 3) continue;
          throw unavailable("Concurrent change; retry the request");
        }
        if (code === "23505")
          throw new AppError(
            "CONFLICT",
            "A record with this identifier already exists",
            409,
          );
        throw error;
      } finally {
        client.release();
      }
    }
    throw unavailable(
      "Concurrent changes could not be committed; retry the request",
    );
  }
  async health() {
    try {
      await this.pool.query("SELECT 1");
      return true;
    } catch {
      return false;
    }
  }
  async close() {
    await this.pool.end();
  }
}
type MemoryState = { [K in Table]: Map<string, Records[K]> };
function emptyState(): MemoryState {
  return Object.fromEntries(
    Object.keys(recordSchemas).map((k) => [k, new Map()]),
  ) as MemoryState;
}
export class MemoryDatabase implements Database {
  private state = emptyState();
  private pending: Promise<unknown> = Promise.resolve();
  /** Test-only fault injection happens before publishing a transaction. */
  failNextCommit = false;
  async transaction<T>(work: (tx: Transaction) => Promise<T>): Promise<T> {
    const operation = this.pending
      .catch(() => undefined)
      .then(async () => {
        const state = structuredClone(this.state);
        const matches = (value: unknown, where: Filter = {}) =>
          Object.entries(where).every(
            ([k, v]) =>
              (k.includes(".")
                ? (
                    (value as Record<string, unknown>)[
                      k.split(".")[0]
                    ] as Record<string, unknown>
                  )?.[k.split(".")[1]]
                : (value as Record<string, unknown>)[k]) === v,
          );
        const save = async <K extends Table>(
          table: K,
          value: Records[K],
          insert: boolean,
        ) => {
          const clean = parse(table, value),
            map = state[table] as Map<string, Records[K]>;
          requireThat(
            !(insert && map.has(clean.id)),
            "CONFLICT",
            "A record with this identifier already exists",
            409,
          );
          requireThat(
            table !== "audit" || insert,
            "IMMUTABLE_AUDIT",
            "Audit records cannot be modified",
            403,
          );
          const unique =
            table === "accounts"
              ? "email"
              : table === "sessions"
                ? "tokenHash"
                : table === "billing_customers"
                  ? "stripeCustomerId"
                  : undefined;
          if (unique)
            for (const existing of map.values())
              requireThat(
                existing.id === clean.id ||
                  (existing as Record<string, unknown>)[unique] !==
                    (clean as Record<string, unknown>)[unique],
                "CONFLICT",
                "A record with this identifier already exists",
                409,
              );
          map.set(clean.id, structuredClone(clean));
        };
        const tx: Transaction = {
          get: async <K extends Table>(table: K, id: string) =>
            structuredClone(state[table].get(id)) as Records[K] | undefined,
          list: async <K extends Table>(table: K, query: Query = {}) => {
            const limit = query.limit ?? 50;
            requireThat(
              limit > 0 && limit <= 1000,
              "INVALID_LIMIT",
              "Page size is outside the permitted range",
            );
            return structuredClone(
              [...state[table].values()]
                .filter(
                  (x) =>
                    matches(x, query.where) &&
                    (!query.cursor || x.id > query.cursor) &&
                    (!query.before ||
                      String(
                        (x as Record<string, unknown>)[query.before.field],
                      ) < query.before.value) &&
                    (!query.contains ||
                      (
                        (x as Record<string, unknown>)[query.contains.field] as
                          string[] | undefined
                      )?.includes(query.contains.value)),
                )
                .sort((a, b) => a.id.localeCompare(b.id))
                .slice(0, limit),
            ) as Records[K][];
          },
          count: async (table, where) =>
            [...state[table].values()].filter((x) => matches(x, where)).length,
          insert: (table, value) => save(table, value, true),
          put: (table, value) => save(table, value, false),
          delete: async (table, id) => {
            requireThat(
              table !== "audit",
              "IMMUTABLE_AUDIT",
              "Audit records cannot be deleted",
              403,
            );
            state[table].delete(id);
          },
        };
        const result = await work(tx);
        if (this.failNextCommit) {
          this.failNextCommit = false;
          throw unavailable("Injected commit failure");
        }
        this.state = state;
        return structuredClone(result);
      });
    this.pending = operation.catch(() => undefined);
    return operation;
  }
  async health() {
    return true;
  }
  async close() {
    await this.pending;
  }
}
