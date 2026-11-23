/** A shield with a trail of linked events inside: the last one is the step that gets stopped. */
export function LogoMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <linearGradient id="st-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#ff3d7f" />
          <stop offset="1" stopColor="#8b5cf6" />
        </linearGradient>
      </defs>
      <path d="M16 2.5 27 7v8.2c0 6.9-4.6 12.2-11 14.3C9.6 27.4 5 22.1 5 15.2V7z" fill="none" stroke="url(#st-g)" strokeWidth="2.2" strokeLinejoin="round" />
      <path d="M10.5 20.5 14 13.5l3.5 5 4-8" fill="none" stroke="currentColor" strokeOpacity="0.55" strokeWidth="1.6" strokeDasharray="2 2" strokeLinecap="round" />
      <circle cx="10.5" cy="20.5" r="1.9" fill="#8b5cf6" />
      <circle cx="14" cy="13.5" r="1.9" fill="#8b5cf6" />
      <circle cx="17.5" cy="18.5" r="1.9" fill="#ff3d7f" />
      <circle cx="21.5" cy="10.5" r="2.5" fill="#ff3d7f" />
    </svg>
  );
}
