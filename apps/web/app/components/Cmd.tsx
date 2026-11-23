'use client';
import { useState } from 'react';

/** A copyable shell command block. */
export function Cmd({ code, label, copy, copied }: { code: string; label?: string; copy: string; copied: string }) {
  const [done, setDone] = useState(false);
  return (
    <>
      {label && <span className="cmd-label">{label}</span>}
      <div className="cmd">
        <pre>
          {code.split('\n').map((line, i) => (
            <span key={i}>
              {line.startsWith('#') ? <span className="c-com">{line}</span> : <><span className="c-prompt">$ </span>{line}</>}
              {'\n'}
            </span>
          ))}
        </pre>
        <button
          type="button"
          className="copy-btn"
          onClick={() =>
            navigator.clipboard?.writeText(code).then(() => {
              setDone(true);
              setTimeout(() => setDone(false), 1400);
            })
          }
        >
          {done ? copied : copy}
        </button>
      </div>
    </>
  );
}
