import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Forward /api/* to FastAPI without rewriting — same paths in dev and prod
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
