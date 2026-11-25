'use client';
import { type DemoMode, type DemoResult, HIDDEN_INSTRUCTION, runScenario, type StepKey } from 'shieldtrail-agent-demo';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ChainGraph } from '../../components/ChainGraph';
import { dicts, type Lang } from '../../i18n';

// Two choices only: the difference is the whole point. Watch-only mode is explained on the other pages.
type Choice = Extract<DemoMode, 'off' | 'enforce'>;
const STEP_KEYS: StepKey[] = ['ticket', 'attachment', 'injection', 'query', 'exfil', 'reply'];
const STEP_MS = 1000;
const ICON: Record<string, string> = { ok: '✓', alert: '!', would_block: '!', blocked: '✕', leaked: '✕' };

/** The stolen rows as a person reads them ("ana@shop.com — 4111 1111 1111 1111"), raw text otherwise. */
function leakRows(body: string): string[] {
  try {
    const rows = JSON.parse(body);
    if (Array.isArray(rows)) return rows.map((r) => (r && typeof r === 'object' ? Object.values(r).join(' — ') : String(r)));
  } catch {
    // not JSON: show it as it was sent
  }
  return [body];
}

export function DemoClient({ lang }: { lang: Lang }) {
  const t = dicts[lang].demo;
  const [mode, setMode] = useState<Choice | null>(null);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [shown, setShown] = useState(0);
  const [graphOpen, setGraphOpen] = useState(false);
  const timers = useRef<number[]>([]);
  const stop = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  };
  useEffect(() => stop, []);

  const playing = result !== null && shown < result.steps.length;
  const done = result !== null && shown >= result.steps.length;

  const play = async (m: Choice) => {
    stop();
    setMode(m);
    setResult(null);
    setShown(0);
    const r = await runScenario(m);
    setResult(r);
    r.steps.forEach((_, i) => timers.current.push(window.setTimeout(() => setShown(i + 1), STEP_MS * (i + 0.5))));
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
    return s[mode ?? 'off'] ?? (mode === 'enforce' ? s.on : s.off);
  };
  const other: Choice = mode === 'enforce' ? 'off' : 'enforce';
  const advice = chain?.events.find((e) => e.decision?.action === 'block')?.decision?.recommendation;

  return (
    <>
      <div className="demo-setup">
        <p>
          <b>{t.story[0].k}.</b> {t.story[0].t}
        </p>
        <p>
          <b>{t.story[1].k}.</b> {t.story[1].t}
        </p>
        <blockquote className="hidden-text">“{HIDDEN_INSTRUCTION}”</blockquote>
        <p>
          <b>{t.story[2].k}.</b> {t.story[2].t}
        </p>
      </div>

      <p className="demo-ask">{t.choose}</p>
      <div className="demo-choice" role="group" aria-label={t.choose}>
        {(['off', 'enforce'] as Choice[]).map((m) => (
          <button key={m} type="button" className={`choice choice-${m}`} aria-pressed={mode === m} disabled={playing} onClick={() => play(m)}>
            <span aria-hidden="true">▶</span>
            <b>{m === 'off' ? t.btnOff : t.btnOn}</b>
            <small>{m === 'off' ? t.modes.off.desc : t.modes.enforce.desc}</small>
          </button>
        ))}
      </div>

      <ol className="tl" aria-live="polite">
        {STEP_KEYS.map((key, i) => {
          const step = result?.steps[i];
          const isDone = step !== undefined && i < shown;
          const status = isDone ? step.status : 'todo';
          return (
            <li key={key} className={`tl-step tl-${status}${isDone && i === shown - 1 ? ' tl-current' : ''}`}>
              <span className="tl-icon" aria-hidden="true">{isDone ? ICON[step.status] : i + 1}</span>
              <div className="tl-body">
                <div className="tl-title">
                  <b>{t.steps[key].title}</b>
                  {isDone && <span className={`status st-${step.status}`}>{t.status[step.status]}</span>}
                </div>
                {isDone && <p>{detail(key)}</p>}
                {isDone && step.status === 'leaked' && result!.leaked[0] && (
                  <div className="leak-box">
                    <b>{t.leakedLabel}</b>
                    <ul className="leak-rows">
                      {leakRows(result!.leaked[0].body).map((r) => (
                        <li key={r}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ol>

      {!mode && <p className="demo-hint">{t.idle}</p>}

      {done && mode && (
        <div className={`result result-${mode}`} role="status">
          <div className="big" aria-hidden="true">{mode === 'enforce' ? '✓' : '✕'}</div>
          <div>
            <h2>{t.result[mode].title}</h2>
            <p>{t.result[mode].text}</p>
            <button type="button" className="btn btn-ghost" style={{ marginTop: 12 }} onClick={() => play(other)}>
              {mode === 'off' ? t.compareOn : t.compareOff}
            </button>
          </div>
        </div>
      )}

      {done && chain && (
        <details className="details" onToggle={(e) => setGraphOpen((e.target as HTMLDetailsElement).open)}>
          <summary>{t.detailsTitle}</summary>
          <p className="muted-small">{t.detailsLead}</p>
          <div className="panel">
            <div className="graph-wrap">{graphOpen && <ChainGraph chain={chain} visibleIds={visibleIds} currentId={currentId} />}</div>
            <div className="legend" aria-label={t.legendTitle}>
              {t.legend.map(([cls, text]) => (
                <span key={cls}>
                  <i className={`lg-${cls}`} />
                  {text}
                </span>
              ))}
            </div>
          </div>
          <div className="details-body">
            <div>
              <h3>{t.narrative}</h3>
              <ol>
                {chain.narrative.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ol>
              {advice && (
                <>
                  <h3 style={{ marginTop: 18 }}>{t.recommendation}</h3>
                  <p style={{ margin: 0, fontSize: 14 }}>{advice}</p>
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
      <div style={{ height: 60 }} />
    </>
  );
}
