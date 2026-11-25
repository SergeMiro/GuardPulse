import { AsyncLocalStorage } from 'node:async_hooks';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTraceContext, ShieldTrail, type GuardOptions, type Trace } from './guard.js';
import { applyRuleModes, defaultRules, parsePolicy, PolicyError } from './policy.js';
import type { Mode, Policy } from './types.js';

// one store per process, even when a dev server loads this module twice (hot reload)
const g = globalThis as typeof globalThis & { [k: symbol]: unknown };
const ALS = Symbol.for('shieldtrail.als');
const als = (g[ALS] ??= new AsyncLocalStorage<Trace>()) as AsyncLocalStorage<Trace>;
const INTERCEPT = Symbol.for('shieldtrail.intercept');
setTraceContext({
  run: (trace, fn) => {
    // next dev puts its own fetch back after a server-code edit: re-wrap whenever a task starts work
    if (g[INTERCEPT]) interceptFetch();
    return als.run(trace, fn);
  },
  exit: (fn) => als.exit(fn),
  get: () => als.getStore(),
});

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
 * Absolute path of a policy file. The comment tells Next.js (Turbopack) not to trace the whole project
 * for this run-time path: the file is read at run time, or imported and passed as `policy`.
 */
const policyPath = (path?: string) => resolve(/* turbopackIgnore: true */ process.cwd(), path ?? POLICY_FILE);

/**
 * Reads and validates the policy file. The default file is optional (undefined when absent); a path
 * given explicitly must exist. Errors name the file and the place in it.
 */
export function loadPolicy(path?: string): Policy | undefined {
  const file = policyPath(path);
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
  writeFileSync(policyPath(path), `${JSON.stringify(policy, null, 2)}\n`);
}

/**
 * Switches one rule's mode in the policy file (creating the file if needed) without rewriting the
 * rest of it: only `ruleModes` changes, so hand-written rules and comments-as-ids stay as they are.
 */
export function setRuleMode(ruleId: string, mode: Mode, path?: string): Policy {
  const file = policyPath(path);
  const raw = existsSync(file) ? (JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>) : {};
  raw.ruleModes = { ...((raw.ruleModes as Record<string, Mode> | undefined) ?? {}), [ruleId]: mode };
  const parsed = parsePolicy(raw); // never write a file the next start could not read
  writeFileSync(file, `${JSON.stringify(raw, null, 2)}\n`);
  return parsed;
}

export interface NodeGuardOptions extends GuardOptions {
  /**
   * The policy itself, e.g. `import policy from './shieldtrail.policy.json'`. Use this in bundled or
   * serverless deployments (Next.js standalone, Vercel): the bundler ships an imported file, while a
   * file read at run time from the working directory may not be there. Validated like the file.
   */
  policy?: unknown;
  /**
   * Policy file, default `shieldtrail.policy.json` in the working directory: read when `policy` is
   * not given, and where the dev panel saves its rule switches. false = neither.
   */
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
  /** Every guard of the process (one per agent, or a new one after a hot reload); weak, so old ones can go. */
  refs: Array<WeakRef<ShieldTrail>>;
  url?: string;
  starting?: Promise<void>;
}
const DEVTOOLS = Symbol.for('shieldtrail.devtools');

const liveGuards = (h: DevtoolsHolder): ShieldTrail[] => {
  h.refs = h.refs.filter((r) => r.deref() !== undefined);
  return h.refs.map((r) => r.deref()!);
};

/**
 * Starts the dev panel server once per process. Every guard created afterwards joins it: the panel
 * shows the approvals of all of them, the kill switch stops all of them (and the ones created later),
 * and a guard created after a hot reload keeps the previous store, so the history survives.
 */
function startDevtools(guard: ShieldTrail, port: number, policyFile: string | false | undefined, onError: (e: unknown) => void): void {
  const holder = g[DEVTOOLS] as DevtoolsHolder | undefined;
  guard.interactive = true;
  if (holder) {
    const halted = liveGuards(holder).find((x) => x.halted)?.halted;
    if (halted) guard.halt(halted);
    holder.refs.push(new WeakRef(guard));
    return;
  }
  const next: DevtoolsHolder = { refs: [new WeakRef(guard)] };
  g[DEVTOOLS] = next;
  const all = () => liveGuards(next);
  next.starting = import('./collector.js')
    .then(({ startCollector }) =>
      startCollector({
        port,
        guard: () => all().at(-1) ?? guard,
        devtools: {
          guards: all,
          // policyFile: false = the app keeps its policy in code, so a switch only lasts until restart
          onRuleMode: policyFile === false ? undefined : (id, mode) => void setRuleMode(id, mode, policyFile),
        },
      }),
    )
    .then(({ url }) => {
      next.url = url;
      console.log(`ShieldTrail dev panel: ${url}  (add <script src="${url}/panel.js" async></script> to your layout)`);
    })
    .catch((err) => {
      // e.g. the port is taken by another dev server: the app keeps running without the panel, nobody
      // can answer 'ask' steps (so they are blocked at once), and the next createGuard tries again
      for (const x of all()) x.interactive = false;
      if (g[DEVTOOLS] === next) delete g[DEVTOOLS];
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

let warnedNoPolicy = false;

/**
 * createGuard for servers: takes the policy from `policy` or `shieldtrail.policy.json`. Options passed
 * in code win over the policy, so the file can hold rules while code holds secrets (canaries,
 * exporters); `ruleModes` (the panel's switches) apply to rules from code too.
 */
export function createGuard(options: NodeGuardOptions = {}): ShieldTrail {
  const { policy, policyFile, interceptFetch: intercept = true, devtools = process.env.NODE_ENV === 'development', ...rest } = options;
  if (intercept) {
    g[INTERCEPT] = true;
    interceptFetch();
  }
  let file: Policy | undefined;
  if (policy !== undefined) {
    try {
      file = parsePolicy(policy);
    } catch (err) {
      throw new PolicyError(`policy option: ${(err as Error).message}`, { cause: err });
    }
  } else if (policyFile !== false) file = loadPolicy(policyFile);
  if (!file && !rest.rules && process.env.NODE_ENV === 'production' && !warnedNoPolicy) {
    warnedNoPolicy = true;
    console.warn(
      `ShieldTrail: no policy found (${policyPath(typeof policyFile === 'string' ? policyFile : undefined)}) and no rules in code, ` +
        'so the built-in rules run in shadow mode. In a bundled deployment, import the file and pass it: createGuard({ policy }).',
    );
  }
  const holder = devtools ? (g[DEVTOOLS] as DevtoolsHolder | undefined) : undefined;
  const previous = holder ? liveGuards(holder).at(-1) : undefined;
  const ruleSet = rest.rules ?? file?.rules ?? (file?.ruleModes ? defaultRules : undefined);
  const guard = new ShieldTrail({
    ...rest,
    store: rest.store ?? previous?.store,
    mode: rest.mode ?? file?.mode,
    rules: ruleSet && applyRuleModes(ruleSet, file?.ruleModes),
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
