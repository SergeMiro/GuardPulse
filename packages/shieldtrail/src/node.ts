import { AsyncLocalStorage } from 'node:async_hooks';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTraceContext, ShieldTrail, type GuardOptions, type Trace } from './guard.js';
import { parsePolicy, PolicyError } from './policy.js';
import type { Policy } from './types.js';

// one store per process, even when a dev server loads this module twice (hot reload)
const g = globalThis as typeof globalThis & { [k: symbol]: unknown };
const ALS = Symbol.for('shieldtrail.als');
const als = (g[ALS] ??= new AsyncLocalStorage<Trace>()) as AsyncLocalStorage<Trace>;
setTraceContext({ run: (trace, fn) => als.run(trace, fn), get: () => als.getStore() });

const WRAPPED = Symbol.for('shieldtrail.fetch');

/**
 * Routes global fetch through the current trace: calls made inside trace.run() / trace.tool() are
 * checked by the policy, every other call passes through untouched. Installed once per process.
 */
export function interceptFetch(): void {
  const current = g.fetch as typeof fetch & { [WRAPPED]?: true };
  if (current[WRAPPED]) return;
  const original = current;
  const wrapped = ((input: string | URL | Request, init?: RequestInit) => {
    const trace = als.getStore();
    if (!trace) return original(input, init);
    // leave the trace context so trace.fetch's own call reaches the real fetch
    return als.exit(() => trace.fetch(input, init));
  }) as typeof fetch & { [WRAPPED]?: true };
  wrapped[WRAPPED] = true;
  g.fetch = wrapped;
}

export const POLICY_FILE = 'shieldtrail.policy.json';

/**
 * Reads and validates the policy file. The default file is optional (undefined when absent); a path
 * given explicitly must exist. Errors name the file and the place in it.
 */
export function loadPolicy(path?: string): Policy | undefined {
  const file = resolve(path ?? POLICY_FILE);
  if (!existsSync(file)) {
    if (path) throw new PolicyError(`${file}: file not found`);
    return undefined;
  }
  try {
    return parsePolicy(JSON.parse(readFileSync(file, 'utf8')));
  } catch (err) {
    throw new PolicyError(`${file}: ${(err as Error).message}`, { cause: err });
  }
}

/** Writes a policy back (validated first, so a bad edit never lands on disk). */
export function savePolicy(policy: Policy, path = POLICY_FILE): void {
  parsePolicy(JSON.parse(JSON.stringify(policy)));
  writeFileSync(resolve(path), `${JSON.stringify(policy, null, 2)}\n`);
}

export interface NodeGuardOptions extends GuardOptions {
  /** Policy file to read, default `shieldtrail.policy.json` in the working directory; false to skip. */
  policyFile?: string | false;
  /** Check every fetch made inside trace.run() / trace.tool(), default true. */
  interceptFetch?: boolean;
}

/**
 * createGuard for servers: reads `shieldtrail.policy.json` when present. Options passed in code win
 * over the file, so the file can hold rules while code holds secrets (canaries, exporters).
 */
export function createGuard(options: NodeGuardOptions = {}): ShieldTrail {
  const { policyFile, interceptFetch: intercept = true, ...rest } = options;
  if (intercept) interceptFetch();
  const file = policyFile === false ? undefined : loadPolicy(policyFile);
  return new ShieldTrail({
    ...rest,
    mode: rest.mode ?? file?.mode,
    rules: rest.rules ?? file?.rules,
    allowedDomains: rest.allowedDomains ?? file?.allowedDomains,
    budget: rest.budget ?? file?.budget,
  });
}

export * from './index.js';
