'use client';
import { useState } from 'react';
import type { Dict } from '../i18n';

/** The hero's attack chain: three alerts, then the step that is blocked (or would be, in watch-only mode). */
export function AttackConsole({ t }: { t: Dict['home']['console'] }) {
  const [mode, setMode] = useState<'shadow' | 'enforce'>('enforce');
  const last = t.steps.length - 1;
  return (
    <div className="console">
      <div className="console-head">
        <div className="console-title">
          <span>{t.trace}</span>
          <b>{t.task}</b>
        </div>
        <div className="seg" role="group" aria-label={t.modeLabel}>
          {(['shadow', 'enforce'] as const).map((m) => (
            <button key={m} type="button" aria-pressed={mode === m} onClick={() => setMode(m)}>
              {t.modes[m]}
            </button>
          ))}
        </div>
      </div>
      <ol className="console-steps">
        {t.steps.map((s, i) => {
          const kind = i < last ? 'alert' : mode === 'enforce' ? 'blocked' : 'would';
          return (
            <li key={s.code} className={`cstep cstep-${kind}`}>
              <span className="cstep-n">{i + 1}</span>
              <div>
                <code>{s.code}</code>
                <span>{s.why}</span>
              </div>
              <span className="ctag">{t.tags[kind]}</span>
            </li>
          );
        })}
      </ol>
      <div className="console-foot">
        <span className={`dot dot-${mode}`} aria-hidden="true" />
        <span>{mode === 'enforce' ? t.footEnforce : t.footShadow}</span>
      </div>
    </div>
  );
}
