'use client';
import { useState } from 'react';

export function CodeTabs({ tabs }: { tabs: Array<{ label: string; code: React.ReactNode; raw: string }> }) {
  const [active, setActive] = useState(0);
  const [copied, setCopied] = useState(false);
  return (
    <div className="tabs">
      <div className="tablist" role="tablist" aria-label="Code examples">
        {tabs.map((t, i) => (
          <button key={t.label} role="tab" className="tab" aria-selected={i === active} onClick={() => setActive(i)}>
            {t.label}
          </button>
        ))}
        <button
          className="tab copy"
          onClick={() => {
            navigator.clipboard?.writeText(tabs[active].raw).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1400);
            });
          }}
        >
          {copied ? 'COPIED' : 'COPY'}
        </button>
      </div>
      <pre role="tabpanel">{tabs[active].code}</pre>
    </div>
  );
}
