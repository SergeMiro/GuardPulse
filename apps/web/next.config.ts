import { fileURLToPath } from 'node:url';
import type { NextConfig } from 'next';

const config: NextConfig = {
  output: 'export',
  // GitHub Pages serves the site under /ShieldTrail
  basePath: process.env.PAGES_BASE_PATH ?? '/ShieldTrail',
  trailingSlash: true,
  images: { unoptimized: true },
  transpilePackages: ['shieldtrail-agent-demo'],
  turbopack: { root: fileURLToPath(new URL('../..', import.meta.url)) },
};

export default config;
