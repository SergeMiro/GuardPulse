#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { auditRules } from './audit.js';
import { loadPolicy, POLICY_FILE } from './node.js';
import { defaultRules } from './policy.js';
import { replay, shadowReport } from './replay.js';
import { renderReport } from './report.js';
import type { GuardEvent } from './types.js';

const USAGE = `shieldtrail — attack chain intelligence for AI agents

  shieldtrail check [events.jsonl] [--policy <file>] [--json]
      Validate the policy file. With recorded events: which rules work, which never fire,
      and which are hidden behind an earlier rule. Exit code 1 on an invalid policy.
  shieldtrail replay <events.jsonl> [--policy <file>] [--json]
      Re-run recorded events through a policy. Exit code 1 when the policy would stop
      traffic that was allowed when it was recorded (use it as a pre-release gate).
  shieldtrail report <events.jsonl> [--json] [--html report.html]
      Shadow-mode report: what enforce mode would have blocked, grouped by rule.
      --html writes a self-contained incident report to share with a security team.
  shieldtrail collector [--port 4319] [--pg <postgres-url>] [--token <secret>] [--allow-origin <url,...>]
      Start the HTTP collector the dashboard reads from. Browser access is limited to the
      hosted dashboard and http://localhost:3000 unless --allow-origin lists other origins.

The policy defaults to ./${POLICY_FILE}:
  { "mode": "shadow", "allowedDomains": ["api.acme.com"], "rules": [{ "id": "…", "match": {…}, "action": "block" }, "defaults"] }`;

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

  if (command === 'check') {
    let policy;
    try {
      policy = loadPolicy(flag(argv, '--policy'));
    } catch (err) {
      out(`✗ ${(err as Error).message}`);
      return 1;
    }
    const events = file && !file.startsWith('--') ? await readEvents(file) : undefined;
    const rules = policy?.rules ?? defaultRules;
    const unknownModes = Object.keys(policy?.ruleModes ?? {}).filter((id) => !rules.some((r) => r.id === id));
    if (unknownModes.length) out(`! ruleModes names rules this file does not define: ${unknownModes.join(', ')} (fine if they come from code)`);
    if (!events) {
      out(policy ? `✓ policy is valid: ${rules.length} rules, mode ${policy.mode ?? 'shadow'}` : `No ${flag(argv, '--policy') ?? POLICY_FILE}: the built-in rules apply.`);
      return 0;
    }
    const stats = auditRules(events, { mode: policy?.mode, rules, allowedDomains: policy?.allowedDomains, budget: policy?.budget });
    if (json) out(JSON.stringify(stats, null, 2));
    else {
      out(`${rules.length} rules checked against ${events.length} recorded events`);
      for (const s of stats) {
        const note = s.verdict === 'active' ? `decided ${s.decided}×` : s.verdict === 'shadowed' ? `matches ${s.matched}× but "${s.shadowedBy}" always decides first: move it up or remove it` : 'never matched: check its pattern, or keep it for traffic not recorded yet';
        out(`  ${s.verdict.padEnd(8)} ${s.ruleId}  ${note}`);
      }
    }
    return 0;
  }

  if (command === 'replay' && file) {
    const policy = loadPolicy(flag(argv, '--policy')) ?? {};
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
    const events = await readEvents(file);
    const html = flag(argv, '--html');
    if (html) {
      await writeFile(html, renderReport(events));
      out(`HTML report written to ${html}`);
    }
    const report = shadowReport(events);
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
    const { url } = await startCollector({ port: Number(flag(argv, '--port') ?? 4319), store, token: flag(argv, '--token'), allowOrigins: flag(argv, '--allow-origin')?.split(',').map((o) => o.trim()) });
    out(`ShieldTrail collector listening on ${url}`);
    return new Promise(() => {}); // runs until killed
  }

  out(USAGE);
  return command === 'help' || command === '--help' ? 0 : 2;
}

// realpath: npm installs bins as symlinks
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  runCli(process.argv.slice(2)).then((code) => process.exit(code));
}
