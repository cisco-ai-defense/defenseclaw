import { defineConfig } from "vite";
import { resolve } from "node:path";

export default defineConfig({
  root: __dirname,
  base: "/",
  build: {
    outDir: resolve(__dirname, "../internal/dashboard/dist"),
    emptyOutDir: true,
    target: "es2022",
    sourcemap: false,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  server: {
    port: 18971,
    proxy: {
      "/health": "http://127.0.0.1:18970",
      "/status": "http://127.0.0.1:18970",
      "/alerts": "http://127.0.0.1:18970",
      "/skills": "http://127.0.0.1:18970",
      "/mcps": "http://127.0.0.1:18970",
      "/tools": "http://127.0.0.1:18970",
      "/v1": "http://127.0.0.1:18970",
      "/api": "http://127.0.0.1:18970",
    },
  },
});
