import { AsyncLocalStorage } from 'node:async_hooks';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTraceContext, ShieldTrail, type GuardOptions, type Trace } from './guard.js';
import { parsePolicy, PolicyError } from './policy.js';
import type { Mode, Policy } from './types.js';

// one store per process, even when a dev server loads this module twice (hot reload)
const g = globalThis as typeof globalThis & { [k: symbol]: unknown };
const ALS = Symbol.for('shieldtrail.als');
const als = (g[ALS] ??= new AsyncLocalStorage<Trace>()) as AsyncLocalStorage<Trace>;
setTraceContext({ run: (trace, fn) => als.run(trace, fn), exit: (fn) => als.exit(fn), get: () => als.getStore() });

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

/**
 * Switches one rule's mode in the policy file (creating the file if needed) without rewriting the
 * rest of it: only `ruleModes` changes, so hand-written rules and comments-as-ids stay as they are.
 */
export function setRuleMode(ruleId: string, mode: Mode, path?: string): Policy {
  const file = resolve(path ?? POLICY_FILE);
  const raw = existsSync(file) ? (JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>) : {};
  raw.ruleModes = { ...((raw.ruleModes as Record<string, Mode> | undefined) ?? {}), [ruleId]: mode };
  const parsed = parsePolicy(raw); // never write a file the next start could not read
  writeFileSync(file, `${JSON.stringify(raw, null, 2)}\n`);
  return parsed;
}

export interface NodeGuardOptions extends GuardOptions {
  /** Policy file to read, default `shieldtrail.policy.json` in the working directory; false to skip. */
  policyFile?: string | false;
  /** Check every fetch made inside trace.run() / trace.tool(), default true. */
  interceptFetch?: boolean;
  /**
   * Dev panel and local dashboard on http://127.0.0.1:4320, default on when NODE_ENV is 'development'
   * and off otherwise (never in production). Add the panel to your pages with
   * `<script src="http://127.0.0.1:4320/panel.js" async></script>`.
   */
  devtools?: boolean | { port?: number };
}

export const DEVTOOLS_PORT = 4320;

interface DevtoolsHolder {
  guard: ShieldTrail;
  url?: string;
  starting?: Promise<void>;
}
const DEVTOOLS = Symbol.for('shieldtrail.devtools');

/**
 * Starts the dev panel server once per process. A hot-reloaded module creates a new guard: the server
 * then serves that one, and the new guard keeps the previous store so the history survives the reload.
 */
function startDevtools(guard: ShieldTrail, port: number, policyFile: string | false | undefined, onError: (e: unknown) => void): void {
  const holder = g[DEVTOOLS] as DevtoolsHolder | undefined;
  guard.interactive = true;
  if (holder) {
    holder.guard = guard;
    return;
  }
  const next: DevtoolsHolder = { guard };
  g[DEVTOOLS] = next;
  next.starting = import('./collector.js')
    .then(({ startCollector }) =>
      startCollector({
        port,
        guard: () => next.guard,
        // policyFile: false = the app keeps its policy in code, so a switch only lasts until restart
        devtools: { onRuleMode: policyFile === false ? undefined : (id, mode) => void setRuleMode(id, mode, policyFile) },
      }),
    )
    .then(({ url }) => {
      next.url = url;
      console.log(`ShieldTrail dev panel: ${url}  (add <script src="${url}/panel.js" async></script> to your layout)`);
    })
    .catch((err) => {
      // e.g. the port is taken by another dev server: the app keeps running without the panel
      onError(err);
      console.warn(`ShieldTrail dev panel not started: ${(err as Error).message}`);
    });
}

/** The running dev panel, for tests and tooling. */
export async function devtoolsUrl(): Promise<string | undefined> {
  const holder = g[DEVTOOLS] as DevtoolsHolder | undefined;
  await holder?.starting;
  return holder?.url;
}

/**
 * createGuard for servers: reads `shieldtrail.policy.json` when present. Options passed in code win
 * over the file, so the file can hold rules while code holds secrets (canaries, exporters).
 */
export function createGuard(options: NodeGuardOptions = {}): ShieldTrail {
  const { policyFile, interceptFetch: intercept = true, devtools = process.env.NODE_ENV === 'development', ...rest } = options;
  if (intercept) interceptFetch();
  const file = policyFile === false ? undefined : loadPolicy(policyFile);
  const previous = devtools ? (g[DEVTOOLS] as DevtoolsHolder | undefined)?.guard : undefined;
  const guard = new ShieldTrail({
    ...rest,
    store: rest.store ?? previous?.store,
    mode: rest.mode ?? file?.mode,
    rules: rest.rules ?? file?.rules,
    allowedDomains: rest.allowedDomains ?? file?.allowedDomains,
    budget: rest.budget ?? file?.budget,
  });
  if (devtools) {
    const port = typeof devtools === 'object' && devtools.port !== undefined ? devtools.port : DEVTOOLS_PORT;
    startDevtools(guard, port, policyFile, (e) => rest.onError?.(e));
  }
  return guard;
}

export * from './index.js';
