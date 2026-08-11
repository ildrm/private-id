export class PostgresStateStore {
    pool;
    constructor(pool) {
        this.pool = pool;
    }
    async load() { const r = await this.pool.query('SELECT payload FROM runtime_state WHERE id=true'); return r.rowCount ? r.rows[0].payload : undefined; }
    async save(state) { await this.pool.query("INSERT INTO runtime_state(id,payload)VALUES(true,$1::jsonb) ON CONFLICT(id)DO UPDATE SET payload=EXCLUDED.payload,version=runtime_state.version+1,updated_at=now()", [JSON.stringify(state)]); }
}
