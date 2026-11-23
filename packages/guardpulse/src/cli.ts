#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { replay, type ReplayOptions, shadowReport } from './replay.js';
import type { GuardEvent } from './types.js';

const USAGE = `guardpulse — attack chain intelligence for AI agents

  guardpulse replay <events.jsonl> --policy <policy.json> [--json]
      Re-run recorded events through a policy. Exit code 1 when the policy would stop
      traffic that was allowed when it was recorded (use it as a pre-release gate).
  guardpulse report <events.jsonl> [--json]
      Shadow-mode report: what enforce mode would have blocked, grouped by rule.
  guardpulse collector [--port 4319] [--pg <postgres-url>] [--token <secret>]
      Start the HTTP collector the dashboard reads from.

policy.json: { "mode": "enforce", "allowedDomains": ["api.acme.com"], "rules": [...] }`;

async function readEvents(path: string): Promise<GuardEvent[]> {
  const text = (await readFile(path, 'utf8')).trim();
  if (text.startsWith('[')) return JSON.parse(text);
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

const flag = (argv: string[], name: string) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

export async function runCli(argv: string[], out: (line: string) => void = console.log): Promise<number> {
  const [command, file] = argv;
  const json = argv.includes('--json');

  if (command === 'replay' && file) {
    const policyPath = flag(argv, '--policy');
    const policy: ReplayOptions = policyPath ? JSON.parse(await readFile(policyPath, 'utf8')) : {};
    const result = replay(await readEvents(file), policy);
    if (json) out(JSON.stringify({ changed: result.changed, newlyStopped: result.newlyStopped, newlyAllowed: result.newlyAllowed }, null, 2));
    else {
      out(`${result.decisions.length} events replayed, ${result.changed.length} decisions changed`);
      for (const d of result.newlyStopped) out(`  + STOP  ${d.kind} ${d.target}  (${d.before ?? 'none'} → ${d.after}, rule ${d.ruleId})`);
      for (const d of result.newlyAllowed) out(`  - PASS  ${d.kind} ${d.target}  (${d.before} → ${d.after})`);
    }
    return result.newlyStopped.length > 0 ? 1 : 0;
  }

  if (command === 'report' && file) {
    const report = shadowReport(await readEvents(file));
    if (json) out(JSON.stringify(report, null, 2));
    else {
      out(`${report.events} events in ${report.traces} traces, ${report.blocked} blocked`);
      out(report.wouldBlock.length ? 'Enforce mode would have blocked:' : 'Enforce mode would not have blocked anything.');
      for (const g of report.wouldBlock) out(`  ${g.ruleId}: ${g.count} × (${g.targets.join(', ')})`);
      for (const g of report.alerts) out(`  alert ${g.ruleId}: ${g.count}`);
    }
    return 0;
  }

  if (command === 'collector') {
    const { startCollector } = await import('./collector.js');
    const pg = flag(argv, '--pg');
    const store = pg ? new (await import('./store/postgres.js')).PostgresStore({ connectionString: pg }) : undefined;
    if (store) await store.init();
    const { url } = await startCollector({ port: Number(flag(argv, '--port') ?? 4319), store, token: flag(argv, '--token') });
    out(`GuardPulse collector listening on ${url}`);
    return new Promise(() => {}); // runs until killed
  }

  out(USAGE);
  return command === 'help' || command === '--help' ? 0 : 2;
}

// realpath: npm installs bins as symlinks
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  runCli(process.argv.slice(2)).then((code) => process.exit(code));
}
