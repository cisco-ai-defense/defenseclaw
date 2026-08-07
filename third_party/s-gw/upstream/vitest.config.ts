import os from "node:os";
import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/fixtures/**"],
    setupFiles: ["tests/setup.ts"],
    restoreMocks: true,
    env: {
      SGW_DISABLE_UPDATE_CHECK: "1",
      SGW_DISABLE_KEYCHAIN: "1",
      SGW_DISABLE_ONEPASSWORD_BACKUP: "1",
      SGW_TEST_MODE: "1",
      SGW_TEST_LIVE_HOME: path.join(os.homedir(), ".s-gw")
    }
  }
});
