import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "happy-dom",
    globals: false,
    include: ["src/**/*.test.ts"],
    setupFiles: ["./src/test-setup.ts"],
    reporters: ["default"],
  },
});
