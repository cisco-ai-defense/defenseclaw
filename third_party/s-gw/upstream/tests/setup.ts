import { randomBytes } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, beforeEach } from "vitest";

const originalEnvironment = {
  TEMP: process.env.TEMP,
  TMP: process.env.TMP,
  SGW_TEST_HOME_ROOT: process.env.SGW_TEST_HOME_ROOT,
  SGW_HOME: process.env.SGW_HOME,
  SGW_RECOVERY_HOME: process.env.SGW_RECOVERY_HOME,
  SGW_LOGIN_SESSION_ID: process.env.SGW_LOGIN_SESSION_ID
};
const windowsTestRoot = makeWindowsTestRoot();
const testHomeRoot = windowsTestRoot || path.resolve(os.tmpdir());
if (windowsTestRoot) {
  process.env.TEMP = windowsTestRoot;
  process.env.TMP = windowsTestRoot;
}
const suiteHome = path.join(testHomeRoot, `sgw-vitest-${testPathSuffix()}`);
const suiteRecoveryHome = `${suiteHome}-recovery`;

function useDisposableHomes(): void {
  process.env.SGW_TEST_MODE = "1";
  process.env.SGW_TEST_HOME_ROOT = testHomeRoot;
  process.env.SGW_HOME = suiteHome;
  process.env.SGW_RECOVERY_HOME = suiteRecoveryHome;
  process.env.SGW_LOGIN_SESSION_ID = "vitest-login-session";
}

useDisposableHomes();
beforeAll(() => {
  if (windowsTestRoot) {
    mkdirSync(path.dirname(windowsTestRoot), { recursive: true });
    mkdirSync(windowsTestRoot, { mode: 0o700 });
  }
  mkdirSync(suiteHome, { mode: 0o700 });
});
beforeEach(useDisposableHomes);

afterAll(() => {
  rmSync(suiteHome, { recursive: true, force: true });
  rmSync(suiteRecoveryHome, { recursive: true, force: true });
  if (windowsTestRoot) {
    rmSync(windowsTestRoot, { recursive: true, force: true });
  }
  for (const [name, value] of Object.entries(originalEnvironment)) {
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
});

function makeWindowsTestRoot(): string | undefined {
  if (process.platform !== "win32") return undefined;

  const localAppData = process.env.LOCALAPPDATA?.trim()
    || path.join(os.homedir(), "AppData", "Local");
  const tempParent = path.join(localAppData, "Temp");
  return path.join(tempParent, `sgw-vitest-root-${testPathSuffix()}`);
}

function testPathSuffix(): string {
  return randomBytes(5).toString("base64url").slice(0, 6);
}
