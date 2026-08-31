import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    include: ["test/**/*.spec.ts"],
    exclude: ["test/**/*.prod.spec.ts", "test/**/*.agent.spec.ts", "**/node_modules/**"],
    poolOptions: {
      workers: {
        isolatedStorage: true,
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: { bindings: { TEST_MODE: "1" } },
      },
    },
  },
});
