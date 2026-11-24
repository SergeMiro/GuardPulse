import { buildChain, type Chain } from './chain.js';
import { maxSeverity, severityRank } from './detectors.js';
import { shadowReport } from './replay.js';
import type { GuardEvent, Severity } from './types.js';

const esc = (v: unknown) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const COLOR: Record<Severity, string> = { low: '#0f7f52', medium: '#a35f00', high: '#d2491f', critical: '#cf2631' };

/**
 * A self-contained HTML incident report (no scripts, no external assets) to send to a security
 * team: risk rating, what enforce mode would block, the chains that matter, findings, timeline.
 * Browser-safe: the dashboard renders the same report.
 */
export function renderReport(events: GuardEvent[], opts: { title?: string; generatedAt?: Date } = {}): string {
  const byTrace = new Map<string, GuardEvent[]>();
  for (const e of events) byTrace.set(e.traceId, [...(byTrace.get(e.traceId) ?? []), e]);
  const chains: Chain[] = [...byTrace.values()].map(buildChain).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.startedAt - a.startedAt);
  const shadow = shadowReport(events);
  const risk = maxSeverity(chains.map((c) => c.severity)) ?? 'low';
  const notable = chains.filter((c) => c.blocked || c.wouldBlock || severityRank(c.severity) >= severityRank('medium'));
  const findings = new Map<string, number>();
  for (const e of events) for (const f of e.findings) findings.set(f.type, (findings.get(f.type) ?? 0) + 1);
  const generated = (opts.generatedAt ?? new Date()).toISOString().replace('T', ' ').slice(0, 16);
  const title = opts.title ?? 'ShieldTrail incident report';

  const verdict = (c: Chain) => (c.blocked ? 'BLOCKED' : c.wouldBlock ? 'WOULD BLOCK' : c.severity.toUpperCase());
  const chainHtml = notable
    .slice(0, 50)
    .map((c) => {
      const stopped = c.events.find((e) => e.decision?.action === 'block' || e.decision?.action === 'would_block');
      return `<section class="chain">
  <h3><span class="sev" style="background:${COLOR[c.severity]}">${verdict(c)}</span> ${esc(c.actor)} — ${esc(c.task ?? 'task')}</h3>
  <p class="muted">trace ${esc(c.traceId)} · ${new Date(c.startedAt).toISOString()} · ${c.events.length} steps</p>
  <ol>${c.narrative.map((l) => `<li>${esc(l)}</li>`).join('')}</ol>
  ${stopped?.decision?.recommendation ? `<p><b>Advice:</b> ${esc(stopped.decision.recommendation)}</p>` : ''}
</section>`;
    })
    .join('\n');

  const rows = (list: Array<{ ruleId: string; count: number; targets: string[] }>) =>
    list.length ? list.map((g) => `<tr><td>${esc(g.ruleId)}</td><td>${g.count}</td><td>${g.targets.map(esc).join('<br>')}</td></tr>`).join('') : '<tr><td colspan="3" class="muted">Nothing</td></tr>';

  const timeline = [...events]
    .sort((a, b) => a.ts - b.ts || a.seq - b.seq)
    .filter((e) => e.decision?.action !== 'allow' || e.findings.length)
    .slice(-300)
    .map((e) => `<tr><td>${new Date(e.ts).toISOString().slice(11, 19)}</td><td>${esc(e.actor)}</td><td>${esc(e.kind)}</td><td class="mono">${esc(e.target)}</td><td>${esc(e.decision?.action ?? '')}</td><td>${esc(e.decision?.ruleId ?? '')}</td></tr>`)
    .join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
body{font:15px/1.55 system-ui,-apple-system,'Segoe UI',sans-serif;color:#15151f;background:#fff;max-width:1000px;margin:0 auto;padding:32px 20px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 10px;border-bottom:1px solid #e2e2ee;padding-bottom:6px}h3{font-size:15px;margin:0 0 4px}
.muted{color:#6a6a85;font-size:13px}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0}.kpi{border:1px solid #e2e2ee;border-radius:10px;padding:10px 12px}.kpi b{display:block;font-size:20px}
.sev{display:inline-block;color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;font-weight:700;letter-spacing:.04em}
.chain{border:1px solid #e2e2ee;border-radius:12px;padding:14px 16px;margin:12px 0}.chain ol{margin:8px 0;padding-left:20px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #eee;vertical-align:top}th{background:#f6f6fb;font-weight:600}
@media print{body{padding:0}.chain{break-inside:avoid}}
</style></head><body>
<h1>${esc(title)}</h1>
<p class="muted">Generated ${esc(generated)} UTC by ShieldTrail · ${events.length} events</p>
<p>Overall risk: <span class="sev" style="background:${COLOR[risk]}">${risk.toUpperCase()}</span></p>
<div class="kpis">
<div class="kpi"><span class="muted">Agent tasks</span><b>${chains.length}</b></div>
<div class="kpi"><span class="muted">Blocked</span><b>${chains.filter((c) => c.blocked).length}</b></div>
<div class="kpi"><span class="muted">Would block</span><b>${chains.filter((c) => c.wouldBlock).length}</b></div>
<div class="kpi"><span class="muted">Critical</span><b>${chains.filter((c) => c.severity === 'critical').length}</b></div>
<div class="kpi"><span class="muted">Alerts</span><b>${shadow.alerts.reduce((n, g) => n + g.count, 0)}</b></div>
</div>
<h2>Tasks that need attention</h2>
${chainHtml || '<p class="muted">No task needs attention.</p>'}
<h2>What blocking mode would have stopped</h2>
<table><tr><th>Rule</th><th>Count</th><th>Targets</th></tr>${rows(shadow.wouldBlock)}</table>
<h2>Alerts</h2>
<table><tr><th>Rule</th><th>Count</th><th>Targets</th></tr>${rows(shadow.alerts)}</table>
<h2>Findings by type</h2>
<table><tr><th>Finding</th><th>Count</th></tr>${[...findings].sort((a, b) => b[1] - a[1]).map(([t, n]) => `<tr><td class="mono">${esc(t)}</td><td>${n}</td></tr>`).join('') || '<tr><td colspan="2" class="muted">None</td></tr>'}</table>
<h2>Timeline of notable steps</h2>
<table><tr><th>Time</th><th>Agent</th><th>Kind</th><th>Target</th><th>Decision</th><th>Rule</th></tr>${timeline || '<tr><td colspan="6" class="muted">None</td></tr>'}</table>
<p class="muted" style="margin-top:30px">Secrets were redacted before storage. Report generated by ShieldTrail — https://github.com/SergeMiro/ShieldTrail</p>
</body></html>`;
}
