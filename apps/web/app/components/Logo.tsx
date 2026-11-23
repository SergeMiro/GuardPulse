export function LogoMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <linearGradient id="gp-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#ff3d7f" />
          <stop offset="1" stopColor="#8b5cf6" />
        </linearGradient>
      </defs>
      <path d="M16 2.5 27 7v8.2c0 6.9-4.6 12.2-11 14.3C9.6 27.4 5 22.1 5 15.2V7z" fill="none" stroke="url(#gp-g)" strokeWidth="2.2" strokeLinejoin="round" />
      <path d="M8.5 16.5h4l2-4.5 3 9 2.2-4.5h3.8" fill="none" stroke="#ff3d7f" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
