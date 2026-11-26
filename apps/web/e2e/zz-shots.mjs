import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
const OUT = fileURLToPath(new URL('../out', import.meta.url));
const T = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' };
const srv = createServer((req, res) => {
  let f = join(OUT, decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/ShieldTrail/, ''));
  if (!existsSync(f)) return res.writeHead(404).end();
  if (statSync(f).isDirectory()) f = join(f, 'index.html');
  res.writeHead(200, { 'content-type': T[extname(f)] ?? 'application/octet-stream' });
  createReadStream(f).pipe(res);
}).listen(0, '127.0.0.1');
await new Promise((r) => srv.once('listening', r));
const base = `http://127.0.0.1:${srv.address().port}/ShieldTrail`;
const dir = process.argv[2];
const jobs = JSON.parse(process.argv[3]);
const b = await chromium.launch({ channel: 'chrome' });
for (const [name, path, scheme, w] of jobs) {
  const p = await b.newPage({ viewport: { width: w, height: 900 }, colorScheme: scheme });
  await p.goto(base + path); await p.waitForTimeout(700);
  await p.screenshot({ path: `${dir}/${name}.png`, fullPage: true });
  await p.close();
}
await b.close(); srv.close(); console.log('done');
