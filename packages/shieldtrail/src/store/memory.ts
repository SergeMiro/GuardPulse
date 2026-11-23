import type { GuardEvent } from '../types.js';

export interface EventStore {
  add(event: GuardEvent): Promise<void>;
  /** Events of one trace, or all events when traceId is omitted. */
  list(traceId?: string): Promise<GuardEvent[]>;
  /** Trace ids, most recent first. */
  traces(limit?: number): Promise<string[]>;
}

export class MemoryStore implements EventStore {
  private events: GuardEvent[] = [];

  /** Keeps the most recent `maxEvents` (default 100 000); use PostgresStore to keep everything. */
  constructor(private readonly maxEvents = 100_000) {}

  async add(event: GuardEvent): Promise<void> {
    this.events.push(event);
    if (this.events.length > this.maxEvents) this.events.splice(0, this.events.length - this.maxEvents);
  }

  async list(traceId?: string): Promise<GuardEvent[]> {
    return traceId ? this.events.filter((e) => e.traceId === traceId) : [...this.events];
  }

  async traces(limit = 100): Promise<string[]> {
    const seen = new Set<string>();
    for (let i = this.events.length - 1; i >= 0 && seen.size < limit; i--) seen.add(this.events[i].traceId);
    return [...seen];
  }
}
