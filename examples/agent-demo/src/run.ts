/** npm run demo -- --mode enforce [--collector http://127.0.0.1:4319] [--out events.jsonl] */
import { writeFile } from 'node:fs/promises';
import { collectorExporter } from 'guardpulse';
import { type DemoMode, runScenario } from './scenario.js';

const arg = (name: string) => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const mode = (arg('--mode') ?? 'enforce') as DemoMode;
if (!['off', 'shadow', 'enforce'].includes(mode)) throw new Error(`--mode must be off | shadow | enforce, got ${mode}`);

const COLOR = { ok: '\x1b[32m', alert: '\x1b[33m', would_block: '\x1b[35m', blocked: '\x1b[31m', leaked: '\x1b[41;97m' } as const;
const collector = arg('--collector');

console.log(`\nGuardPulse demo — mode: ${mode === 'off' ? 'without GuardPulse' : mode}\n`);
const result = await runScenario(mode, {
  exporters: collector ? [collectorExporter(collector)] : undefined,
  onStep: (s) => console.log(`${COLOR[s.status]}${s.status.toUpperCase().padEnd(11)}\x1b[0m ${s.n}. ${s.title}\n            ${s.detail}`),
});

console.log(`\nData that reached the attacker: ${result.leaked.length ? `\x1b[31m${result.leaked[0].body.length} bytes\x1b[0m` : 'none'}`);
if (result.chain) {
  console.log(`\nAttack chain ${result.chain.traceId} — severity ${result.chain.severity}`);
  result.chain.narrative.forEach((line, i) => console.log(`  ${i + 1}. ${line}`));
  console.log(`\nSecurity Autopilot drift:`);
  result.drift.forEach((f) => console.log(`  • ${f.message}${f.suggestedRule ? `  → suggested rule ${f.suggestedRule.id}` : ''}`));
}
const out = arg('--out');
if (out && result.guard) {
  await writeFile(out, (await result.guard.store.list()).map((e) => JSON.stringify(e)).join('\n'));
  console.log(`\nEvents written to ${out} — try: npx guardpulse replay ${out} --policy policy.json`);
}
