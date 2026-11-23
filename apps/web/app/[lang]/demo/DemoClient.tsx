'use client';
import { type DemoMode, type DemoResult, HIDDEN_INSTRUCTION, runScenario, type StepKey } from 'shieldtrail-agent-demo';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ChainGraph } from '../../components/ChainGraph';
import { dicts, type Lang } from '../../i18n';

const MODES: DemoMode[] = ['off', 'shadow', 'enforce'];
const MODE_COLOR = { off: 'var(--red)', shadow: '#ffb547', enforce: 'var(--green)' };
const STEP_KEYS: StepKey[] = ['ticket', 'attachment', 'injection', 'query', 'exfil', 'reply'];
const STEP_MS = 1100;

export function DemoClient({ lang }: { lang: Lang }) {
  const t = dicts[lang].demo;
  const [mode, setMode] = useState<DemoMode>('enforce');
  const [result, setResult] = useState<DemoResult | null>(null);
  const [shown, setShown] = useState(0);
  const timers = useRef<number[]>([]);
  const stop = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  };
  useEffect(() => stop, []);

  const playing = result !== null && shown < result.steps.length;
  const done = result !== null && shown >= result.steps.length;

  const play = async () => {
    stop();
    setShown(0);
    const r = await runScenario(mode);
    setResult(r);
    r.steps.forEach((_, i) => timers.current.push(window.setTimeout(() => setShown(i + 1), STEP_MS * (i + 0.4))));
  };

  const choose = (m: DemoMode) => {
    stop();
    setMode(m);
    setResult(null);
    setShown(0);
  };

  const chain = result?.chain;
  const { visibleIds, currentId } = useMemo(() => {
    if (!result?.chain) return { visibleIds: undefined, currentId: undefined };
    const ids = new Set<string>([result.chain.events[0].id]); // the task node
    result.steps.slice(0, shown).forEach((s) => s.eventId && ids.add(s.eventId));
    return { visibleIds: ids, currentId: shown > 0 ? result.steps[shown - 1].eventId : undefined };
  }, [result, shown]);

  const detail = (key: StepKey) => {
    const s = t.steps[key] as Record<string, string>;
    return s[mode] ?? (mode === 'off' ? s.off : s.on);
  };
  const leakedBytes = result?.leaked.reduce((n, l) => n + l.body.length, 0) ?? 0;
  const outcome = !done ? '…' : mode === 'enforce' ? t.outcome.blocked : mode === 'shadow' ? t.outcome.recorded : t.outcome.leaked;

  return (
    <>
      <h2 className="sr">{t.storyTitle}</h2>
      <div className="story-grid">
        {t.story.map((s, i) => (
          <div key={s.k} className="story-card">
            <small>{s.k}</small>
            <p>{s.t}</p>
            {i === 1 && <div className="hidden-text">“{HIDDEN_INSTRUCTION}”</div>}
          </div>
        ))}
      </div>

      <p className="step-label">{t.modeTitle}</p>
      <div className="modes" role="group" aria-label={t.modeTitle}>
        {MODES.map((m) => (
          <button key={m} type="button" className="mode-card" aria-pressed={mode === m} onClick={() => choose(m)}>
            <b>
              <i className="dot" style={{ background: MODE_COLOR[m] }} />
              {t.modes[m].name}
            </b>
            <span>{t.modes[m].desc}</span>
          </button>
        ))}
        <button type="button" className="btn btn-primary btn-lg" onClick={play} disabled={playing}>
          {playing ? t.playing : done ? `↻ ${t.replay}` : `▶ ${t.play}`}
        </button>
      </div>

      {done && (
        <div className={`result result-${mode}`} role="status">
          <div className="big" aria-hidden="true">{mode === 'enforce' ? '✓' : mode === 'shadow' ? '◐' : '✕'}</div>
          <div>
            <h2>{t.result[mode].title}</h2>
            <p>{t.result[mode].text}</p>
            <small>{t.result.tryNext}</small>
          </div>
        </div>
      )}

      <div className="player">
        <div className="panel">
          <div className="panel-h">
            <span>{t.stepsTitle}</span>
            <span>{Math.min(shown, 6)}/6</span>
          </div>
          <ol className="steps-list">
            {STEP_KEYS.map((key, i) => {
              const step = result?.steps[i];
              const isDone = step !== undefined && i < shown;
              return (
                <li key={key} className={`step-item${isDone ? ' done' : ''}${isDone && i === shown - 1 ? ' current' : ''}`}>
                  <span className="num">{i + 1}</span>
                  <div>
                    <b>
                      {t.steps[key].title}
                      {isDone && <span className={`status st-${step.status}`}>{t.status[step.status]}</span>}
                    </b>
                    {isDone && <p>{detail(key)}</p>}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>

        <div className="panel">
          <div className="panel-h">
            <span>{t.graphTitle}</span>
            {chain && <span>trace {chain.traceId.slice(0, 10)}…</span>}
          </div>
          <div className="graph-wrap">
            {chain ? (
              <ChainGraph chain={chain} visibleIds={visibleIds} currentId={currentId} />
            ) : (
              <div className="graph-empty">{result?.mode === 'off' ? t.graphEmptyOff : t.graphEmptyIdle}</div>
            )}
          </div>
          {done && (
            <div className="kpis">
              <div className="kpi">
                <small>{t.kpi.outcome}</small>
                <b style={{ color: mode === 'enforce' ? 'var(--green)' : 'var(--red)' }}>{outcome}</b>
              </div>
              <div className="kpi">
                <small>{t.kpi.severity}</small>
                <b className={chain ? `sev-${chain.severity}` : ''}>{chain?.severity ?? '—'}</b>
              </div>
              <div className="kpi">
                <small>{t.kpi.events}</small>
                <b>{chain?.events.length ?? 0}</b>
              </div>
              <div className="kpi">
                <small>{t.kpi.leaked}</small>
                <b style={{ color: leakedBytes ? 'var(--red)' : 'var(--green)' }}>{leakedBytes} B</b>
              </div>
            </div>
          )}
          {done && leakedBytes > 0 && (
            <div className="leak-box">
              <b>{t.leakedLabel}</b>
              <br />
              {result!.leaked[0].body}
            </div>
          )}
          <div className="legend" aria-label={t.legendTitle}>
            {t.legend.map(([cls, text]) => (
              <span key={cls}>
                <i className={`lg-${cls}`} />
                {text}
              </span>
            ))}
          </div>
        </div>
      </div>

      {done && chain && (
        <details className="details">
          <summary>{t.detailsTitle}</summary>
          <div className="details-body">
            <div>
              <h3>{t.narrative}</h3>
              <ol>
                {chain.narrative.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ol>
              {chain.events.find((e) => e.decision?.recommendation && e.decision.action !== 'allow' && e.decision.action !== 'alert')?.decision?.recommendation && (
                <>
                  <h3 style={{ marginTop: 18 }}>{t.recommendation}</h3>
                  <p style={{ margin: 0, fontSize: 14 }}>
                    {chain.events.find((e) => e.decision?.action === 'block' || e.decision?.action === 'would_block')?.decision?.recommendation}
                  </p>
                </>
              )}
            </div>
            <div>
              <h3>{t.drift}</h3>
              {result!.drift.map((f) => (
                <div key={f.message} className="drift">
                  <span className={`sev-${f.severity}`}>●</span> {f.message}
                  {f.suggestedRule && (
                    <details>
                      <summary>{t.suggested}</summary>
                      <pre>{JSON.stringify(f.suggestedRule, null, 2)}</pre>
                    </details>
                  )}
                </div>
              ))}
            </div>
          </div>
        </details>
      )}
      {!(done && chain) && <div style={{ height: 50 }} />}
    </>
  );
}
