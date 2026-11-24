import { fileURLToPath } from 'node:url';
import type { NextConfig } from 'next';

const config: NextConfig = {
  // keep ShieldTrail a normal Node package: one instance per process and its dev panel files on disk
  serverExternalPackages: ['shieldtrail'],
  turbopack: { root: fileURLToPath(new URL('../..', import.meta.url)) },
};

export default config;
