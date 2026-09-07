import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  root: "web",
  base: "/site/",
  build: { outDir: "../web-dist", emptyOutDir: true },
  server: {
    host: "127.0.0.1",
    port: 3101,
    strictPort: true,
    proxy: {
      "/api": "http://127.0.0.1:3001",
      "/openapi.json": "http://127.0.0.1:3001",
      "/.well-known": "http://127.0.0.1:3001",
    },
  },
});
