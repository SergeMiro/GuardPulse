import { fileURLToPath } from 'node:url';
import type { NextConfig } from 'next';

const config: NextConfig = {
  output: 'export',
  // GitHub Pages serves the site under /GuardPulse
  basePath: process.env.PAGES_BASE_PATH ?? '',
  trailingSlash: true,
  images: { unoptimized: true },
  transpilePackages: ['guardpulse-agent-demo'],
  turbopack: { root: fileURLToPath(new URL('../..', import.meta.url)) },
};

export default config;
