'use client';
import { useEffect, useRef } from 'react';

/** Drifting nodes; now and then a pulse runs along an edge, like an event travelling a chain. */
export function TrailField() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current!;
    const ctx = canvas.getContext('2d')!;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let w = 0;
    let h = 0;
    let raf = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const colors = ['#ff3d7f', '#8b5cf6', '#ffb547', '#46d9ff'];
    type P = { x: number; y: number; vx: number; vy: number; r: number; c: string };
    let pts: P[] = [];
    const pulses: Array<{ a: number; b: number; t: number; c: string }> = [];

    const resize = () => {
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = Math.round(Math.min(46, (w * h) / 26000));
      pts = Array.from({ length: n }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.18,
        r: Math.random() * 2 + 1.2,
        c: colors[Math.floor(Math.random() * colors.length)],
      }));
    };

    const frame = () => {
      ctx.clearRect(0, 0, w, h);
      for (const p of pts) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
      }
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const d = Math.hypot(pts[i].x - pts[j].x, pts[i].y - pts[j].y);
          if (d < 150) {
            ctx.strokeStyle = `rgba(150,140,220,${0.12 * (1 - d / 150)})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(pts[i].x, pts[i].y);
            ctx.lineTo(pts[j].x, pts[j].y);
            ctx.stroke();
            if (pulses.length < 6 && Math.random() < 0.0008) pulses.push({ a: i, b: j, t: 0, c: Math.random() < 0.7 ? '#ff3d7f' : '#8b5cf6' });
          }
        }
      }
      for (let k = pulses.length - 1; k >= 0; k--) {
        const q = pulses[k];
        q.t += 0.012;
        const A = pts[q.a];
        const B = pts[q.b];
        if (!A || !B || q.t >= 1) {
          pulses.splice(k, 1);
          continue;
        }
        const x = A.x + (B.x - A.x) * q.t;
        const y = A.y + (B.y - A.y) * q.t;
        ctx.fillStyle = q.c;
        ctx.shadowColor = q.c;
        ctx.shadowBlur = 12;
        ctx.beginPath();
        ctx.arc(x, y, 2.4, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
      for (const p of pts) {
        ctx.fillStyle = p.c;
        ctx.globalAlpha = 0.75;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 0.25;
        ctx.strokeStyle = p.c;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r + 4, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = 1;
      }
      if (!reduce) raf = requestAnimationFrame(frame);
    };

    resize();
    frame();
    window.addEventListener('resize', resize);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return <canvas ref={ref} className="trail-field" aria-hidden="true" />;
}
