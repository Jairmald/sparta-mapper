import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server pinned to 5173 to match the CORS origins allowed in api/main.py.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
});
