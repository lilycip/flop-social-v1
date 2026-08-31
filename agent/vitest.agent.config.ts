import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    include: ["test/**/*.agent.spec.ts"],
    exclude: ["**/node_modules/**"],
    poolOptions: {
      workers: {
        isolatedStorage: true,
        wrangler: { configPath: "./wrangler.agent.test.jsonc" },
        miniflare: { bindings: { TEST_MODE: "1" } },
      },
    },
  },
});
