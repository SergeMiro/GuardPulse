// Embeds src/panel.js into src/panel-source.ts, so the dev server can serve it even when a bundler
// (Next.js, Turbopack, webpack) moves the package code away from its files. Run by `npm run build`.
import { readFileSync, writeFileSync } from 'node:fs';

const js = readFileSync(new URL('../src/panel.js', import.meta.url), 'utf8');
writeFileSync(
  new URL('../src/panel-source.ts', import.meta.url),
  `// Generated from src/panel.js by scripts/embed-panel.mjs. Do not edit.\nexport const PANEL_JS = ${JSON.stringify(js)};\n`,
);
