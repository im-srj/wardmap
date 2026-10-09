import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed, predictable port for the dev server.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
});
