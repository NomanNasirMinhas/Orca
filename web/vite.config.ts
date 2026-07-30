import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// Relative base so the built assets load correctly when embedded and served
// from the Go binary at any path. Dev server proxies the API to `orca serve`.
export default defineConfig({
  plugins: [vue()],
  base: "./",
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8666",
    },
  },
});
