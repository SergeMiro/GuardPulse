import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  // tests run against the SDK source, no build step needed
  resolve: { alias: { shieldtrail: fileURLToPath(new URL('./packages/shieldtrail/src/index.ts', import.meta.url)) } },
  test: { include: ['packages/*/test/**/*.test.ts', 'examples/*/test/**/*.test.ts'] },
});
