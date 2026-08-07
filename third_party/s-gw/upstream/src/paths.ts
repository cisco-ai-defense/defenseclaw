import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { trustedWindowsSystemExecutableSync, windowsSystemEnvironment } from "./windows-system.js";

export const MASTER_KEYCHAIN_SERVICE = "com.s-gw.sgw.master-passphrase";
export const SECRET_KEYCHAIN_SERVICE = "com.s-gw.sgw.secret";

let windowsLoginSessionCached = false;
let cachedWindowsLoginSession: string | undefined;

export function expandHome(inputPath: string): string {
  if (inputPath === "~") {
    return os.homedir();
  }

  if (inputPath.startsWith("~/")) {
    return path.join(os.homedir(), inputPath.slice(2));
  }

  return inputPath;
}

export function getSgwHome(): string {
  const configuredHome = process.env.SGW_HOME?.trim();
  if (isTestMode() && !configuredHome) {
    throw new Error("Refusing to use s-gw while tests are running without an explicit SGW_HOME.");
  }

  const home = path.resolve(expandHome(configuredHome || "~/.s-gw"));
  assertIsolatedTestHome(home);
  return home;
}

export function getSgwInstanceKey(home = getSgwHome()): string {
  const user = os.userInfo();
  const identity = {
    platform: process.platform,
    user: {
      username: user.username,
      home: instancePath(user.homedir),
      uid: user.uid,
      gid: user.gid
    },
    home: instancePath(home),
    recoveryHome: instancePath(getSgwRecoveryHome(home)),
    keychainService: process.env.SGW_KEYCHAIN_SERVICE || MASTER_KEYCHAIN_SERVICE,
    keychainAccount: process.env.SGW_KEYCHAIN_ACCOUNT || user.username || "local-user",
    secretBackend: environmentValue("SGW_SECRET_BACKEND").toLowerCase(),
    secretKeychainService: process.env.SGW_SECRET_KEYCHAIN_SERVICE || SECRET_KEYCHAIN_SERVICE
  };
  return createHash("sha256").update(JSON.stringify(identity)).digest("hex");
}

export function getSgwLoginSessionId(): string | undefined {
  const override = process.env.SGW_LOGIN_SESSION_ID?.trim();
  if (override) {
    if (!isTestMode()) {
      throw new Error("SGW_LOGIN_SESSION_ID is restricted to isolated s-gw tests.");
    }
    return override.slice(0, 160);
  }

  const user = os.userInfo();
  const native = process.platform === "linux"
    ? linuxLoginSessionId(user.uid)
    : process.platform === "darwin"
      ? macLoginSessionId(user.uid)
      : process.platform === "win32"
        ? windowsLoginSessionId()
        : undefined;
  if (!native) return undefined;

  const parts = [process.platform, String(user.uid), user.username, native];
  return createHash("sha256").update(parts.join("\0")).digest("base64url").slice(0, 32);
}

function linuxLoginSessionId(uid: number): string | undefined {
  if (!Number.isInteger(uid) || uid < 0) return undefined;
  const loginctl = ["/usr/bin/loginctl", "/bin/loginctl"].find(existsSync);
  if (loginctl) {
    const current = linuxSessionIdentity(loginctl, "self", uid);
    if (current) return current;
  }
  return linuxAuditSessionIdentity(uid);
}

function linuxSessionIdentity(loginctl: string, requested: string, uid: number): string | undefined {
  const output = runLoginctl(loginctl, ["show-session", requested, "--no-pager"]);
  if (!output) return undefined;
  const fields = parseKeyValueOutput(output);
  const session = fields.get("Id") || (requested === "self" ? "" : requested);
  const started = fields.get("TimestampMonotonic") || "";
  const boot = linuxBootId();
  if (fields.get("User") !== String(uid)
    || !validLoginSessionName(session)
    || !boot
    || !/^\d+$/u.test(started)) {
    return undefined;
  }
  return `logind:${boot}:${session}:${started}`;
}

function runLoginctl(command: string, args: string[]): string | undefined {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 2_000
  });
  if (result.status !== 0 || result.error) return undefined;
  return result.stdout;
}

function parseKeyValueOutput(value: string): Map<string, string> {
  const fields = new Map<string, string>();
  for (const line of value.split(/\r?\n/)) {
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    fields.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return fields;
}

function validLoginSessionName(value: string): boolean {
  return /^[A-Za-z0-9_.-]{1,128}$/u.test(value);
}

function linuxBootId(): string | undefined {
  try {
    const value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
    return /^[0-9a-f-]{16,64}$/u.test(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function linuxAuditSessionIdentity(uid: number): string | undefined {
  try {
    const loginUid = readFileSync("/proc/self/loginuid", "utf8").trim();
    const session = readFileSync("/proc/self/sessionid", "utf8").trim();
    const boot = linuxBootId();
    if (loginUid !== String(uid)
      || !boot
      || !validNativeSessionNumber(session)) {
      return undefined;
    }
    return `audit:${boot}:${loginUid}:${session}`;
  } catch {
    return undefined;
  }
}

function macLoginSessionId(uid: number): string | undefined {
  const boot = macBootSessionId();
  if (!boot) return undefined;

  const result = spawnSync("/usr/bin/id", ["-A"], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 2_000
  });
  if (result.status !== 0 || result.error) return undefined;
  const fields = parseKeyValueOutput(result.stdout);
  const auditUid = fields.get("auid") || "";
  const auditSession = fields.get("asid") || "";
  if (auditUid !== String(uid) || !validNativeSessionNumber(auditSession)) return undefined;
  return `audit:${boot}:${auditUid}:${auditSession}`;
}

function validNativeSessionNumber(value: string): boolean {
  if (!/^\d{1,10}$/u.test(value)) return false;
  const session = Number(value);
  return Number.isSafeInteger(session) && session > 0 && session < 0xffffffff;
}

function macBootSessionId(): string | undefined {
  const result = spawnSync("/usr/sbin/sysctl", ["-n", "kern.bootsessionuuid"], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 2_000
  });
  if (result.status !== 0 || result.error) return undefined;
  const value = result.stdout.trim().toLowerCase();
  return /^[0-9a-f-]{16,64}$/u.test(value) ? value : undefined;
}

function windowsLoginSessionId(): string | undefined {
  if (windowsLoginSessionCached) return cachedWindowsLoginSession;

  let command: string;
  let env: NodeJS.ProcessEnv;
  try {
    command = trustedWindowsSystemExecutableSync("whoami.exe");
    env = windowsSystemEnvironment();
  } catch {
    windowsLoginSessionCached = true;
    return undefined;
  }
  const result = spawnSync(command, ["/logonid"], {
    encoding: "utf8",
    env,
    shell: false,
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 2_000,
    windowsHide: true
  });
  cachedWindowsLoginSession = result.status === 0 && !result.error
    ? /S-1-5-5-\d+-\d+/iu.exec(result.stdout)?.[0].toLowerCase()
    : undefined;
  windowsLoginSessionCached = true;
  return cachedWindowsLoginSession;
}

function instancePath(inputPath: string): string {
  return path.resolve(expandHome(inputPath));
}

function environmentValue(name: string): string {
  return process.env[name]?.trim() || "";
}

export function getSgwRecoveryHome(home = getSgwHome()): string {
  assertIsolatedTestHome(home);
  const configuredRecoveryHome = process.env.SGW_RECOVERY_HOME?.trim();
  if (isTestMode() && !configuredRecoveryHome) {
    throw new Error("Refusing to use s-gw while tests are running without an explicit SGW_RECOVERY_HOME.");
  }

  const recoveryHome = path.resolve(expandHome(configuredRecoveryHome || `${home}-recovery`));
  assertIsolatedTestRecoveryHome(recoveryHome);
  if (pathsOverlap(home, recoveryHome)) {
    throw new Error(`s-gw recovery home must be outside the primary ledger home: ${recoveryHome}`);
  }
  return recoveryHome;
}

function pathsOverlap(left: string, right: string): boolean {
  const normalizedLeft = canonicalPath(left);
  const normalizedRight = canonicalPath(right);
  if (normalizedLeft === normalizedRight) {
    return true;
  }
  return normalizedLeft.startsWith(`${normalizedRight}${path.sep}`)
    || normalizedRight.startsWith(`${normalizedLeft}${path.sep}`);
}

export function getStorePath(home = getSgwHome()): string {
  assertIsolatedTestHome(home);
  return path.join(home, "store.json");
}

export async function ensureSgwHome(home = getSgwHome()): Promise<void> {
  assertIsolatedTestHome(home);
  await mkdir(home, { recursive: true, mode: 0o700 });
}

function isTestMode(): boolean {
  return process.env.SGW_TEST_MODE === "1";
}

function assertIsolatedTestHome(home: string): void {
  if (!isTestMode()) return;
  requireTestEnvironmentPath("SGW_HOME");
  assertIsolatedTestPath(home, "s-gw home");
}

function assertIsolatedTestRecoveryHome(recoveryHome: string): void {
  if (!isTestMode()) return;
  requireTestEnvironmentPath("SGW_RECOVERY_HOME");
  assertIsolatedTestPath(recoveryHome, "s-gw recovery home");
}

function requireTestEnvironmentPath(name: "SGW_HOME" | "SGW_RECOVERY_HOME"): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Refusing to use s-gw while tests are running without an explicit ${name}.`);
  }
  return value;
}

function assertIsolatedTestPath(inputPath: string, label: string): void {
  const testRoot = canonicalTestRoot();
  const candidate = canonicalPath(inputPath);
  if (!isInside(candidate, testRoot)) {
    throw new Error(`Refusing to use a ${label} outside SGW_TEST_HOME_ROOT while tests are running: ${inputPath}`);
  }

  for (const protectedPath of protectedTestPaths()) {
    if (pathsOverlap(candidate, protectedPath)) {
      throw new Error(`Refusing to use the live ${label} while tests are running: ${inputPath}`);
    }
  }
}

function canonicalTestRoot(): string {
  const configuredRoot = process.env.SGW_TEST_HOME_ROOT?.trim();
  if (!configuredRoot) {
    throw new Error("Refusing to use s-gw while tests are running without SGW_TEST_HOME_ROOT.");
  }

  const root = canonicalPath(configuredRoot);
  const systemTemp = canonicalPath(os.tmpdir());
  if (!isInside(root, systemTemp)) {
    throw new Error(`Refusing to use an SGW_TEST_HOME_ROOT outside the system temporary directory: ${configuredRoot}`);
  }
  return root;
}

function protectedTestPaths(): string[] {
  const configuredLiveHome = process.env.SGW_TEST_LIVE_HOME?.trim();
  const defaultLiveHome = configuredLiveHome || path.join(os.homedir(), ".s-gw");
  const configuredLiveRecoveryHome = process.env.SGW_TEST_LIVE_RECOVERY_HOME?.trim();
  const paths = [
    defaultLiveHome,
    `${defaultLiveHome}-recovery`,
    configuredLiveRecoveryHome
  ].filter((value): value is string => Boolean(value));
  return [...new Set(paths.map(canonicalPath))];
}

function canonicalPath(inputPath: string): string {
  const absolute = path.resolve(expandHome(inputPath));
  const missing: string[] = [];
  let current = absolute;

  while (true) {
    try {
      const resolved = realpathSync.native(current);
      return missing.length === 0 ? resolved : path.join(resolved, ...missing.reverse());
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        throw new Error(`Cannot verify s-gw test path isolation for ${absolute}.`);
      }

      if (isDanglingSymlink(current)) {
        throw new Error(`Refusing to use a symlinked s-gw test path: ${absolute}`);
      }

      const parent = path.dirname(current);
      if (parent === current) {
        throw new Error(`Cannot verify s-gw test path isolation for ${absolute}.`);
      }
      missing.push(path.basename(current));
      current = parent;
    }
  }
}

function isDanglingSymlink(inputPath: string): boolean {
  try {
    return lstatSync(inputPath).isSymbolicLink();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      return false;
    }
    throw new Error(`Cannot verify s-gw test path isolation for ${inputPath}.`);
  }
}

function isInside(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}
