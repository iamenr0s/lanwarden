import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { codecovVitePlugin } from "@codecov/vite-plugin";
import { defineConfig } from "vitest/config";

// This file runs in Node, but the UI code is typed for the browser only (no @types/node), so declare just what we use.
declare const process: { env: Record<string, string | undefined> };

// Dev: `npm run dev` serves the UI on :5173 and proxies /api to the backend on :8080.
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    // Bundle analysis: only in a build that has the upload token (CI). Boolean() because an unset GitHub secret
    // arrives as an empty string, not undefined. Must stay last. Telemetry off, like semgrep's --metrics=off.
    codecovVitePlugin({
      enableBundleAnalysis: Boolean(process.env.CODECOV_TOKEN),
      bundleName: "lanwarden-frontend",
      uploadToken: process.env.CODECOV_TOKEN,
      telemetry: false,
    }),
  ],
  server: { proxy: { "/api": "http://127.0.0.1:8080" } },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test-setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/test-setup.ts", "src/test-utils.tsx","src/**/*.d.ts", "src/types/**"],
    },
  },
});
