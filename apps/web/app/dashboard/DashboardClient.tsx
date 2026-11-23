'use client';
import { buildChain, type Chain, createGuard, type GuardEvent, shadowReport, type ShadowReport } from 'shieldtrail';
import { runScenario } from 'shieldtrail-agent-demo';
import { useCallback, useEffect, useState } from 'react';
import { ChainGraph } from '../components/ChainGraph';

type Summary = Omit<Chain, 'events' | 'nodes' | 'edges'> & { events: number };

/** Demo traffic: the attack in enforce and shadow mode plus a few clean and noisy traces. */
async function demoData(): Promise<{ chains: Chain[]; report: ShadowReport }> {
  const attacks = await Promise.all([runScenario('enforce'), runScenario('shadow')]);
  const guard = createGuard({ mode: 'shadow', allowedDomains: ['api.helpdesk.local', 'api.stripe.com'], fetch: (async () => new Response('{}')) as typeof fetch });
  const billing = guard.startTrace({ agent: 'billing-bot', task: 'Sync invoices', allowedTools: ['invoices.*'] });
  await billing.tool('invoices.list', {}, () => [{ id: 1 }]);
  await billing.fetch('https://api.stripe.com/v1/invoices');
  await billing.fetch('https://hooks.partner-erp.io/sync', { method: 'POST', body: '{"count":1}' });
  const kb = guard.startTrace({ agent: 'kb-writer', task: 'Draft FAQ', allowedTools: ['docs.*'] });
  await kb.context({ source: 'https://docs.helpdesk.local/faq', text: 'How to reset a password: open settings, then security.', untrusted: false });
  await kb.tool('docs.write', { title: 'Password reset' }, () => ({ ok: true }));
  await kb.error(new TypeError('Cannot read properties of undefined (reading "slug")'));
  const own = await guard.chains();
  const chains = [...attacks.map((a) => a.chain!), ...own];
  const events: GuardEvent[] = chains.flatMap((c) => c.events);
  return { chains, report: shadowReport(events) };
}

export function DashboardClient() {
  const [api, setApi] = useState('');
  const [draft, setDraft] = useState('http://127.0.0.1:4319');
  const [chains, setChains] = useState<Summary[]>([]);
  const [full, setFull] = useState<Record<string, Chain>>({});
  const [report, setReport] = useState<ShadowReport | null>(null);
  const [selected, setSelected] = useState<string>('');
  const [error, setError] = useState('');

  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get('api');
    if (q) {
      setApi(q);
      setDraft(q);
    }
  }, []);

  const load = useCallback(async () => {
    try {
      if (!api) {
        const d = await demoData();
        setFull(Object.fromEntries(d.chains.map((c) => [c.traceId, c])));
        setChains(d.chains.map(({ events, nodes, edges, ...s }) => ({ ...s, events: events.length })));
        setReport(d.report);
        setSelected((s) => s || d.chains[0].traceId);
      } else {
        const [list, rep] = await Promise.all([fetch(`${api}/v1/chains`).then((r) => r.json()), fetch(`${api}/v1/report`).then((r) => r.json())]);
        setChains(list);
        setReport(rep);
        setSelected((s) => s || list[0]?.traceId || '');
      }
      setError('');
    } catch (err) {
      setError(`Cannot reach ${api}: ${(err as Error).message}`);
    }
  }, [api]);

  useEffect(() => {
    load();
    if (!api) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [api, load]);

  useEffect(() => {
    if (!api || !selected) return;
    fetch(`${api}/v1/chains/${selected}`)
      .then((r) => r.json())
      .then((c: Chain) => setFull((f) => ({ ...f, [c.traceId]: c })))
      .catch(() => undefined);
  }, [api, selected, chains]);

  const chain = full[selected];
  const count = (pred: (c: Summary) => boolean) => chains.filter(pred).length;

  return (
    <>
      <div className="src" style={{ marginBottom: 18 }}>
        <span className="dot" style={{ background: api ? (error ? 'var(--red)' : 'var(--green)') : 'var(--violet)' }} />
        {api ? `collector ${api}` : 'demo data (generated in your browser)'}
        <form
          style={{ display: 'flex', gap: 8, marginLeft: 'auto', flexWrap: 'wrap' }}
          onSubmit={(e) => {
            e.preventDefault();
            setSelected('');
            setApi(draft.replace(/\/$/, ''));
          }}
        >
          <label htmlFor="api" className="skip">Collector URL</label>
          <input id="api" value={draft} onChange={(e) => setDraft(e.target.value)} />
          <button className="btn btn-ghost btn-sm" type="submit">Connect</button>
          {api && (
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => { setSelected(''); setApi(''); }}>
              Demo data
            </button>
          )}
        </form>
      </div>
      {error && <p className="leak-box" style={{ margin: '0 0 18px' }}>{error}</p>}

      <div className="dash-kpis">
        <div className="kpi"><small>Traces</small><b>{chains.length}</b></div>
        <div className="kpi"><small>Blocked</small><b style={{ color: 'var(--red)' }}>{count((c) => c.blocked)}</b></div>
        <div className="kpi"><small>Would block (shadow)</small><b style={{ color: 'var(--amber)' }}>{count((c) => c.wouldBlock)}</b></div>
        <div className="kpi"><small>Critical chains</small><b className="sev-critical">{count((c) => c.severity === 'critical')}</b></div>
      </div>

      <div className="dash-grid">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="panel">
            <div className="panel-h"><span>chains</span><span>{chains.length}</span></div>
            <div className="chain-list">
              {chains.map((c) => (
                <button key={c.traceId} className="chain-row" aria-current={c.traceId === selected} onClick={() => setSelected(c.traceId)}>
                  <span className="who">{c.actor}</span>
                  <span className={`sev-${c.severity}`} style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>
                    {c.blocked ? 'BLOCKED' : c.wouldBlock ? 'WOULD BLOCK' : c.severity}
                  </span>
                  <small>{c.task ?? '—'}</small>
                  <small>{c.events} ev</small>
                </button>
              ))}
            </div>
          </div>
          <div className="panel">
            <div className="panel-h"><span>shadow report</span><span>{report?.events ?? 0} events</span></div>
            <div className="panel-b" style={{ fontSize: 14 }}>
              <h4 style={{ margin: '0 0 8px', fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--dim)' }}>ENFORCE WOULD HAVE BLOCKED</h4>
              {report?.wouldBlock.length ? report.wouldBlock.map((g) => (
                <div key={g.ruleId} className="drift"><b style={{ color: 'var(--amber)' }}>{g.ruleId}</b> × {g.count}<br /><small style={{ color: 'var(--muted)' }}>{g.targets.join(', ')}</small></div>
              )) : <p style={{ color: 'var(--muted)', margin: 0 }}>Nothing.</p>}
              <h4 style={{ margin: '14px 0 8px', fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--dim)' }}>ALERTS</h4>
              {report?.alerts.map((g) => (
                <div key={g.ruleId} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', color: '#d4d4e6' }}><span>{g.ruleId}</span><span>{g.count}</span></div>
              ))}
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-h">
            <span>{chain ? `${chain.actor} · ${chain.task ?? ''}` : 'select a chain'}</span>
            {chain && <span className={`sev-${chain.severity}`}>{chain.severity}</span>}
          </div>
          <div className="graph-wrap">{chain ? <ChainGraph chain={chain} /> : <div className="graph-empty">No chain selected.</div>}</div>
          {chain && (
            <div className="story" style={{ gridTemplateColumns: '1fr' }}>
              <div>
                <h4>Decisions</h4>
                <div className="table-wrap">
                  <table>
                    <thead><tr><th scope="col">#</th><th scope="col">Event</th><th scope="col">Decision</th><th scope="col">Rule / findings</th></tr></thead>
                    <tbody>
                      {chain.events.map((e) => (
                        <tr key={e.id}>
                          <td>{e.seq}</td>
                          <td style={{ fontFamily: 'var(--mono)', fontSize: 12.5 }}>{e.kind} · {e.target}</td>
                          <td><span className={`status st-${e.decision?.action === 'block' ? 'blocked' : e.decision?.action === 'would_block' ? 'would_block' : e.decision?.action === 'alert' ? 'alert' : 'ok'}`}>{e.decision?.action ?? '—'}</span></td>
                          <td style={{ color: 'var(--muted)' }}>{e.decision?.ruleId ?? ''} {e.findings.map((f) => f.message).join(' · ')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
