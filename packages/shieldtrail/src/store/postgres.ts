import pg from 'pg';
import type { GuardEvent } from '../types.js';
import type { EventStore } from './memory.js';

export type PostgresStoreOptions = (pg.PoolConfig | { pool: pg.Pool }) & { table?: string };

/** Events as JSONB plus the columns the dashboard filters on. Requires the `pg` package. */
export class PostgresStore implements EventStore {
  readonly pool: pg.Pool;
  private readonly table: string;

  constructor(opts: PostgresStoreOptions = {}) {
    const { table = 'shieldtrail_events', ...rest } = opts;
    if (!/^[a-z_][a-z0-9_]{0,62}$/.test(table)) throw new Error(`invalid table name: ${table}`);
    this.table = table;
    this.pool = 'pool' in rest ? rest.pool : new pg.Pool(rest);
  }

  async init(): Promise<void> {
    await this.pool.query(`
      create table if not exists ${this.table} (
        id text primary key,
        trace_id text not null,
        seq bigint not null,
        ts timestamptz not null,
        kind text not null,
        actor text not null,
        target text not null,
        action text,
        event jsonb not null
      );
      create index if not exists ${this.table}_trace_idx on ${this.table} (trace_id, seq);
      create index if not exists ${this.table}_ts_idx on ${this.table} (ts desc);`);
  }

  async add(e: GuardEvent): Promise<void> {
    await this.pool.query(
      `insert into ${this.table} (id, trace_id, seq, ts, kind, actor, target, action, event)
       values ($1, $2, $3, to_timestamp($4 / 1000.0), $5, $6, $7, $8, $9) on conflict (id) do nothing`,
      [e.id, e.traceId, e.seq, e.ts, e.kind, e.actor, e.target, e.decision?.action ?? null, e],
    );
  }

  async list(traceId?: string): Promise<GuardEvent[]> {
    const { rows } = traceId
      ? await this.pool.query(`select event from ${this.table} where trace_id = $1 order by seq, ts`, [traceId])
      : await this.pool.query(`select event from ${this.table} order by ts, seq`);
    return rows.map((r) => r.event);
  }

  async traces(limit = 100): Promise<string[]> {
    const { rows } = await this.pool.query(`select trace_id from ${this.table} group by trace_id order by max(ts) desc limit $1`, [limit]);
    return rows.map((r) => r.trace_id);
  }

  close(): Promise<void> {
    return this.pool.end();
  }
}
