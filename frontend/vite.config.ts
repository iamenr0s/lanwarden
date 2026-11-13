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
    //
    // package.json "overrides" exist only for this plugin (2.0.1, the latest; every @codecov package shares its core):
    //  - "@codecov/vite-plugin".vite: it declares Vite 4-6 but works on our Vite 8 (checked: builds, stats upload).
    //  - "zod": its core pins zod 3.x, which `npm audit` flags (GHSA-mrhx-c7xc-m3w5, fixed in 4.6.6); zod 4 still
    //    validates its options and uploads fine.
    // Remove both overrides once a newer plugin release supports Vite 8 and zod >= 4.6.6. If this ever breaks, CI's
    // build step logs "[codecov] Successfully uploaded stats for bundle: ..." on success: look for that line.
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
