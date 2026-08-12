/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// CVM console dev server. Backend (caspar serve) runs on :2027 and owns
// /api/v1; the build output is mounted there at /app in production, so
// base is relative and the dev proxy mirrors the same path prefix.
export default defineConfig({
  plugins: [react()],
  base: "/app/",
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:2027",
    },
  },
  build: {
    outDir: "dist",
    // Off because dist/ is committed: the console must work straight from a
    // clone, with no Node toolchain, and sourcemaps are 2.9 MB of the 3.6 MB
    // build while being useful only to someone editing the React source —
    // who can rebuild locally with `npm run build -- --sourcemap`.
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split the heavy, rarely-changing vendors out of the app bundle.
        // Recharts is by far the largest and is only needed by two views, so
        // it caches independently of application code.
        manualChunks: {
          charts: ["recharts"],
          react: ["react", "react-dom", "react-router-dom"],
          query: ["@tanstack/react-query"],
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test/setup.ts",
    // dist/ contains the built bundle; without this, a stale build's JS gets
    // picked up as if it were source.
    exclude: ["node_modules/**", "dist/**"],
  },
});
