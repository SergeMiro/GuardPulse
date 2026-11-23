'use client';
import { type DemoMode, type DemoResult, runScenario, type Step } from 'shieldtrail-agent-demo';
import { useCallback, useEffect, useRef, useState } from 'react';
import { ChainGraph } from '../components/ChainGraph';

const MODES: Array<{ id: DemoMode; label: string; note: string }> = [
  { id: 'off', label: 'Without\nShieldTrail', note: 'The agent calls tools and the network directly. Nothing is correlated, nothing is stopped.' },
  { id: 'shadow', label: 'Shadow\nmode', note: 'ShieldTrail watches and records what it would block. Production traffic is not touched.' },
  { id: 'enforce', label: 'Enforce\nmode', note: 'The exfiltration step is blocked. Everything else, including the reply to the customer, keeps working.' },
];

const STATUS_LABEL: Record<Step['status'], string> = { ok: 'ok', alert: 'alert', would_block: 'would block', blocked: 'blocked', leaked: 'leaked' };

export function DemoClient() {
  const [mode, setMode] = useState<DemoMode>('enforce');
  const [steps, setSteps] = useState<Step[]>([]);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [running, setRunning] = useState(false);
  const timers = useRef<number[]>([]);

  const run = useCallback(async (m: DemoMode, animate = true) => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setRunning(true);
    setResult(null);
    setSteps([]);
    const r = await runScenario(m);
    const delay = animate ? 520 : 0;
    r.steps.forEach((s, i) => timers.current.push(window.setTimeout(() => setSteps((prev) => [...prev, s]), delay * (i + 1))));
    timers.current.push(
      window.setTimeout(() => {
        setResult(r);
        setRunning(false);
      }, delay * (r.steps.length + 1)),
    );
  }, []);

  useEffect(() => {
    run('enforce', false);
    return () => timers.current.forEach(clearTimeout);
  }, [run]);

  const chain = result?.chain;
  const stopped = chain?.events.find((e) => e.decision && ['block', 'would_block'].includes(e.decision.action));
  const outcome = !result ? '…' : result.leaked.length ? (chain?.wouldBlock ? 'LEAKED*' : 'LEAKED') : 'BLOCKED';

  const graphPanel = (
    <div className="panel">
      <div className="panel-h">
        <span>attack chain {chain ? `· trace ${chain.traceId.slice(0, 12)}…` : ''}</span>
        <span>
          <span style={{ color: '#ff3d7f' }}>━ taint</span> &nbsp; <span style={{ color: '#ffb547' }}>━ data</span> &nbsp; <span style={{ color: '#6a6a88' }}>━ sequence</span>
        </span>
      </div>
      <div className="graph-wrap">
        {chain ? (
          <ChainGraph chain={chain} />
        ) : (
          <div className="graph-empty">
            {result?.mode === 'off' ? (
              <div>
                <strong>No chain. No alert. No evidence.</strong>
                Without ShieldTrail the four steps are unrelated log lines — if they are logged at all.
              </div>
            ) : (
              <div>{running ? 'Agent is working…' : 'Run the scenario to see the chain.'}</div>
            )}
          </div>
        )}
      </div>
      <div className="verdict">
        <div className="kpi">
          <small>Outcome</small>
          <b style={{ color: outcome === 'BLOCKED' ? 'var(--green)' : 'var(--red)' }}>{outcome}</b>
        </div>
        <div className="kpi">
          <small>Severity</small>
          <b className={chain ? `sev-${chain.severity}` : ''}>{chain?.severity ?? (result ? 'unknown' : '…')}</b>
        </div>
        <div className="kpi">
          <small>Events linked</small>
          <b>{chain?.events.length ?? 0}</b>
        </div>
        <div className="kpi">
          <small>Leaked</small>
          <b style={{ color: result?.leaked.length ? 'var(--red)' : 'var(--green)' }}>{result ? `${result.leaked.reduce((n, l) => n + l.body.length, 0)} B` : '…'}</b>
        </div>
      </div>
      {result?.leaked.length ? (
        <div className="leak-box">
          <b>Received by exfil.attacker.dev{chain?.wouldBlock ? ' — *shadow mode: ShieldTrail recorded “would block”' : ''}:</b>
          <br />
          {result.leaked[0].body}
        </div>
      ) : null}
    </div>
  );

  return (
    <div className="demo-stack">
      <div className="panel panel-b demo-controls">
        <div className="seg" role="group" aria-label="Mode">
          {MODES.map((m) => (
            <button key={m.id} data-mode={m.id} aria-pressed={mode === m.id} onClick={() => setMode(m.id)} style={{ whiteSpace: 'pre-line' }}>
              {m.label}
            </button>
          ))}
        </div>
        <p className="mode-note">{MODES.find((m) => m.id === mode)!.note}</p>
        <button className="btn btn-primary btn-run" onClick={() => run(mode)} disabled={running}>
          {running ? 'Agent running…' : 'Run the attack ▶'}
        </button>
      </div>

      {graphPanel}

      <div className="demo-bottom">
        <div className="panel">
          <div className="panel-h">
            <span>agent log · ticket #4521</span>
            <span style={{ color: running ? 'var(--amber)' : 'var(--green)' }}>{running ? '● running' : '● done'}</span>
          </div>
          <div className="panel-b">
            <div className="log" aria-live="polite" style={{ marginTop: 0 }}>
              {steps.map((s) => (
                <div key={s.n} className="log-item">
                  <span className={`status st-${s.status}`}>{STATUS_LABEL[s.status]}</span>
                  <div>
                    <b>{s.n}. {s.title}</b>
                    <span>{s.detail}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-h"><span>investigation</span><span>{chain ? chain.severity : ''}</span></div>
          {chain ? (
            <div className="story">
              <div>
                <h4>What happened</h4>
                <ol>
                  {chain.narrative.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ol>
                {stopped?.decision?.recommendation && (
                  <>
                    <h4 style={{ marginTop: 18 }}>Recommendation</h4>
                    <p style={{ margin: 0, fontSize: 14, color: '#d4d4e6' }}>{stopped.decision.recommendation}</p>
                  </>
                )}
              </div>
              <div>
                <h4>Security Autopilot · drift vs baseline</h4>
                {result!.drift.map((f) => (
                  <div key={f.message} className="drift">
                    <span className={`sev-${f.severity}`}>●</span> {f.message}
                    {f.suggestedRule && (
                      <details>
                        <summary>suggested rule</summary>
                        <pre>{JSON.stringify(f.suggestedRule, null, 2)}</pre>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="panel-b" style={{ color: 'var(--muted)', margin: 0 }}>
              {result?.mode === 'off' ? 'Nothing to investigate: no events were recorded.' : 'Waiting for the run to finish…'}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
