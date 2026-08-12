import { lstatSync, realpathSync, type BigIntStats } from "node:fs";
import path from "node:path";

const WINDOWS_GLOBAL_SYSTEM_ROOT = String.raw`\\?\GLOBALROOT\SystemRoot`;
const WINDOWS_DEVICE_PREFIX = "\\\\?\\";

export function trustedWindowsSystemRootSync(): string {
  if (path.sep !== "\\") return simulatedWindowsSystemRoot();

  let normalRoot = "";
  try {
    normalRoot = realpathSync.native(WINDOWS_GLOBAL_SYSTEM_ROOT);
  } catch {
    // Fail below without consulting ambient environment variables.
  }
  if (!normalLocalWindowsPath(normalRoot)) {
    throw new Error("The kernel-anchored Windows system directory did not resolve to a normal local drive path.");
  }
  normalRoot = path.normalize(normalRoot);

  assertSameWindowsIdentity(normalRoot, WINDOWS_GLOBAL_SYSTEM_ROOT, "directory");
  assertSameWindowsIdentity(
    path.join(normalRoot, "System32"),
    path.join(WINDOWS_GLOBAL_SYSTEM_ROOT, "System32"),
    "directory"
  );
  assertSameWindowsIdentity(
    path.join(normalRoot, "System32", "kernel32.dll"),
    path.join(WINDOWS_GLOBAL_SYSTEM_ROOT, "System32", "kernel32.dll"),
    "file"
  );
  return normalRoot;
}

export function trustedWindowsSystemExecutableSync(...parts: string[]): string {
  const systemRoot = trustedWindowsSystemRootSync();
  const system32 = path.join(systemRoot, "System32");
  const requested = path.join(system32, ...parts);
  let candidate = "";
  try {
    candidate = path.sep === "\\" ? realpathSync.native(requested) : realpathSync(requested);
  } catch {
    // Fail below without attempting PATH fallback.
  }
  const relative = path.relative(system32, candidate);
  if (!candidate || !parts.length || !relative || relative.startsWith(`..${path.sep}`) ||
      relative === ".." || path.isAbsolute(relative) ||
      (path.sep === "\\" && !normalLocalWindowsPath(candidate))) {
    throw new Error("Trusted Windows system executable path validation failed.");
  }
  trustedWindowsPathInfo(candidate, "file");

  if (path.sep === "\\") {
    const kernelCandidate = path.join(WINDOWS_GLOBAL_SYSTEM_ROOT, "System32", ...parts);
    assertSameWindowsIdentity(candidate, kernelCandidate, "file");
    return candidate;
  }

  if (!sameWindowsPath(candidate, requested)) {
    throw new Error("Trusted Windows system executable path validation failed.");
  }
  return candidate;
}

export function trustedWindowsPowerShellSync(): string {
  return trustedWindowsSystemExecutableSync("WindowsPowerShell", "v1.0", "powershell.exe");
}

export function windowsSystemEnvironment(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const systemRoot = trustedWindowsSystemRootSync();
  const env: NodeJS.ProcessEnv = {
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
    PATH: `${path.join(systemRoot, "System32")};${systemRoot}`
  };
  for (const key of [
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE"
  ]) {
    const value = optionalWindowsEnvironmentValue(key);
    if (value) env[key] = value;
  }
  for (const [key, value] of Object.entries(extra)) {
    if (value === undefined) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)
      || value.length > 8_192
      || /[\0\r\n]/.test(value)) {
      throw new Error(`Invalid bounded Windows child environment value: ${key}`);
    }
    if (["PATH", "SYSTEMROOT", "WINDIR"].includes(key.toUpperCase())) {
      throw new Error(`Windows child environment cannot override trusted ${key}.`);
    }
    env[key] = value;
  }
  return env;
}

function simulatedWindowsSystemRoot(): string {
  if (process.env.SGW_TEST_MODE !== "1") {
    throw new Error("A simulated Windows system directory is allowed only in isolated test mode.");
  }
  const systemRoot = requiredWindowsEnvironmentPath("SystemRoot");
  const winDir = requiredWindowsEnvironmentPath("WINDIR");
  if (!sameWindowsPath(systemRoot, winDir)) {
    throw new Error("Windows SystemRoot and WINDIR identify conflicting system directories.");
  }

  const resolvedRoot = path.resolve(systemRoot);
  let realRoot = "";
  try {
    realRoot = realpathSync(resolvedRoot);
  } catch {
    // Fail below.
  }
  if (!realRoot || !sameWindowsPath(realRoot, resolvedRoot)) {
    throw new Error("The simulated Windows system directory could not be validated.");
  }
  return realRoot;
}

function requiredWindowsEnvironmentPath(name: "SystemRoot" | "WINDIR"): string {
  const value = optionalWindowsEnvironmentValue(name);
  if (!value) throw new Error(`Windows ${name} is required for trusted system paths.`);
  return value;
}

function optionalWindowsEnvironmentValue(name: string): string | undefined {
  const values: string[] = [];
  for (const [key, raw] of Object.entries(process.env)) {
    if (key.toLowerCase() !== name.toLowerCase() || raw === undefined) continue;
    const value = raw.trim();
    if (!value) throw new Error(`Windows ${name} contains an empty environment value.`);
    values.push(value);
  }
  if (values.length === 0) return undefined;
  if (values.some((value) => !sameWindowsPath(value, values[0]))) {
    throw new Error(`Windows ${name} contains conflicting case-insensitive environment values.`);
  }
  return values[0];
}

function assertSameWindowsIdentity(normalPath: string, kernelPath: string, kind: "directory" | "file"): void {
  const normalBefore = trustedWindowsPathInfo(normalPath, kind);
  const kernelBefore = trustedWindowsPathInfo(kernelPath, kind);
  const normalAfter = trustedWindowsPathInfo(normalPath, kind);
  const kernelAfter = trustedWindowsPathInfo(kernelPath, kind);
  if (!sameFileIdentity(normalBefore, normalAfter) || !sameFileIdentity(kernelBefore, kernelAfter) ||
      !sameFileIdentity(normalBefore, kernelBefore)) {
    throw new Error("Windows system path does not match the kernel-anchored system directory.");
  }
}

function trustedWindowsPathInfo(input: string, kind: "directory" | "file"): BigIntStats {
  let info: BigIntStats;
  try {
    info = lstatSync(input, { bigint: true });
  } catch {
    throw new Error("A required trusted Windows system path is unavailable.");
  }
  if (info.isSymbolicLink() || (kind === "directory" ? !info.isDirectory() : !info.isFile())) {
    throw new Error("A required trusted Windows system path has an invalid file type.");
  }
  return info;
}

function sameFileIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev !== 0n && left.ino !== 0n && right.dev !== 0n && right.ino !== 0n &&
    left.dev === right.dev && left.ino === right.ino;
}

function normalLocalWindowsPath(input: string): boolean {
  return /^[A-Za-z]:\\/u.test(input) && !input.startsWith(WINDOWS_DEVICE_PREFIX);
}

function sameWindowsPath(left: string, right: string): boolean {
  return path.normalize(left).replace(/[\\/]+$/, "").toLowerCase()
    === path.normalize(right).replace(/[\\/]+$/, "").toLowerCase();
}
