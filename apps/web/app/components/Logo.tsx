/** A shield with a trail of linked events inside: the last one, in red, is the step that gets stopped. */
export function LogoMark({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" aria-hidden="true" className="logo-mark">
      <path d="M20 3 34 8.5V19c0 9-6 15.5-14 18-8-2.5-14-9-14-18V8.5Z" fill="var(--pulse-soft)" stroke="var(--pulse)" strokeWidth="2.4" strokeLinejoin="round" />
      <path d="M12.5 25 17 17.5l5.5 5L27 14" fill="none" stroke="var(--dim)" strokeWidth="1.6" strokeDasharray="2 2.2" strokeLinecap="round" />
      <circle cx="12.5" cy="25" r="2.2" fill="var(--pulse)" />
      <circle cx="17" cy="17.5" r="2.2" fill="var(--pulse)" />
      <circle cx="22.5" cy="22.5" r="2.2" fill="var(--pulse)" />
      <circle cx="27" cy="14" r="5" fill="none" stroke="var(--red)" strokeOpacity="0.4" strokeWidth="1.4" />
      <circle cx="27" cy="14" r="2.8" fill="var(--red)" />
    </svg>
  );
}
