import { describe, expect, it } from 'vitest';
import { PostgresStore } from '../src/store/postgres.js';
import { recordAttack } from './helpers/scenario.js';

const url = process.env.GUARDPULSE_PG_URL;

describe.skipIf(!url)('PostgresStore', () => {
  it('stores and reads back chains', async () => {
    const store = new PostgresStore({ connectionString: url, table: `gp_test_${Date.now()}` });
    try {
      await store.init();
      const { guard, trace } = await recordAttack({ store });
      const events = await store.list(trace.traceId);
      expect(events.map((e) => e.kind)).toEqual(['task', 'context', 'tool_call', 'http']);
      expect(await store.traces()).toEqual([trace.traceId]);
      const chain = await guard.chain(trace.traceId);
      expect(chain.wouldBlock).toBe(true);
      await store.add(events[0]); // duplicate id is ignored
      expect(await store.list()).toHaveLength(4);
      await store.pool.query(`drop table ${(store as unknown as { table: string }).table}`);
    } finally {
      await store.close();
    }
  });

  it('refuses unsafe table names', () => {
    expect(() => new PostgresStore({ table: 'x; drop table users' })).toThrow('invalid table name');
  });
});
