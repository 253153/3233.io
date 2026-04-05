import { defineConfig } from "vite";

export default defineConfig({
  appType: "spa",
  server: {
    proxy: {
      "/v1": "http://127.0.0.1:3233",
    },
  },
});
