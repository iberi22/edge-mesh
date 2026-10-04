import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.toml' },
      miniflare: {
        bindings: {
          MESH_ENTITLEMENT_SECRET: 'test-secret-do-not-use',
          ALLOWED_ORIGINS: '*.swal.network,http://localhost:*',
        },
      },
    }),
  ],
});
