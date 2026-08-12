import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  accessSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync
} from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  getSgwHome,
  getSgwInstanceKey,
  getSgwRecoveryHome,
  getStorePath,
  MASTER_KEYCHAIN_SERVICE,
  SECRET_KEYCHAIN_SERVICE
} from "./paths.js";
import {
  isInstalledMacAppLocation,
  isSelfContainedMacApp,
  resolveSelfContainedMacRuntime
} from "./self-contained-runtime.js";
import { unlockStatus } from "./unlock.js";
import { CURRENT_VERSION } from "./version.js";
import {
  applyWindowsStartupConfig,
  installWindowsStartupShortcut,
  installedWindowsStartupConfig,
  uninstallWindowsStartupShortcut,
  windowsStartupShortcutStatus,
  type WindowsStartupConfig,
  type WindowsStartupShortcutStatus
} from "./windows-startup.js";
import { trustedWindowsPowerShellSync, windowsSystemEnvironment } from "./windows-system.js";

export const consoleLabel = "com.s-gw.sgw.console";
export const menuBarLabel = "com.s-gw.sgw.menubar";
export const systemdUnitName = "s-gw.service";

const defaultWindowsProcessInspectionTimeoutMs = 15_000;
const maxWindowsProcessInspectionTestTimeoutMs = 120_000;
const defaultWindowsHelperLaunchTimeoutMs = 15_000;
const defaultWindowsHelperCleanupTimeoutMs = 10_000;
const maxWindowsHelperOperationTestTimeoutMs = 120_000;

export interface PackageLayout {
  packageRoot: string;
  nodePath: string;
  isSelfContainedMacApp: boolean;
  standaloneMacAppInstalled: boolean;
  cliPath: string;
  mcpPath: string;
  keychainHelperPath: string;
  packagedMacAppPath: string;
  packagedMacAppBinaryPath: string;
  installedMacAppPath: string;
  macAppPath: string;
  macAppBinaryPath: string;
  menuBarAppPath: string;
  menuBarBinaryPath: string;
  windowsClientScriptPath: string;
  windowsClientLauncherPath: string;
  windowsHelperScriptPath: string;
  windowsHelperBootstrapPath: string;
  windowsHelperLauncherPath: string;
  windowsCredentialHelperPath: string;
}

export interface LaunchAgentStatus {
  label: string;
  plistPath: string;
  installed: boolean;
  loaded: boolean;
}

export interface SystemdUserServiceStatus {
  unit: string;
  unitPath: string;
  installed: boolean;
  loaded: boolean;
  enabled: boolean;
  active: boolean;
  state: string;
  subState: string;
  mainPid?: number;
  error?: string;
}

interface LaunchAgentDefinition {
  label: string;
  programArguments: string[];
  environment: Record<string, string>;
  runAtLoad: boolean;
  keepAlive: boolean;
  stdoutPath: string;
  stderrPath: string;
  limitToAqua?: boolean;
}

export interface ServiceInstallOptions {
  port?: number;
  start?: boolean;
}

export interface MenuBarOptions {
  consoleUrl?: string;
  port?: number;
  start?: boolean;
  show?: boolean;
  notify?: boolean;
  countMode?: MenuBarCountMode;
}

export interface WindowsSurfaceScope extends MenuBarOptions {
  cliPath?: string;
  nodePath?: string;
}

export type MenuBarCountMode = "pending" | "credentials" | "none";

export interface MacAppProcessInfo {
  pid: number;
  source: "record" | "process-list";
  alive: boolean;
  recordPath?: string;
  bundleIdentifier?: string;
  bundlePath?: string;
  executablePath?: string;
  command?: string;
  startedAt?: string;
  updatedAt?: string;
  otherPids?: number[];
}

export interface MacAppOpenResult {
  appPath: string;
  consoleUrl: string;
  reusedExisting: boolean;
  process?: MacAppProcessInfo;
}

export interface MacAppInstallResult {
  appPath: string;
  sourcePath: string;
  changed: boolean;
}

export interface MacAppInstallOptions {
  applicationsDir?: string;
  registerCliPath?: boolean;
}

export interface WindowsOpenResult {
  scriptPath: string;
  launcherPath: string;
  consoleUrl: string;
  pid?: number;
  reusedExisting?: boolean;
}

export interface WindowsHelperProcess {
  pid: number;
  ownerSid: string;
  sessionId: number;
  instanceKey: string;
  exactPath: boolean;
}

interface WindowsHelperCleanupTarget {
  launchNonce: string;
  pid?: number;
  startedAtUtcTicks?: string;
}

interface WindowsHelperLaunch extends WindowsHelperCleanupTarget {
  pid: number;
  startedAtUtcTicks: string;
}

interface WindowsConsoleListenerProcess {
  pid: number;
  ownerSid: string;
  sessionId: number;
  exactNode: boolean;
  exactCli: boolean;
  exactArguments: boolean;
}

export interface WindowsStoppedSurfaces {
  pids: number[];
  console: boolean;
  helper: boolean;
  client: boolean;
}

export interface WindowsRestartResult {
  console?: WindowsOpenResult;
  helper?: WindowsOpenResult;
  client?: WindowsOpenResult;
}

export interface WindowsLoginServiceStatus extends WindowsStartupShortcutStatus {
  active: boolean;
  helperActive: boolean;
  consoleUrl?: string;
  consolePid?: number;
  stopped?: WindowsStoppedSurfaces;
}

export function getPackageLayout(): PackageLayout {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const packageRoot = path.basename(here) === "dist" ? path.dirname(here) : path.dirname(here);
  const nativeTarget = `${process.platform}-${process.arch}`;
  const runtime = resolveSelfContainedMacRuntime(packageRoot);
  const packagedMacAppPath = runtime?.appPath || path.join(packageRoot, "dist", "s-gw.app");
  const standaloneAppPath = runtime ? undefined : findInstalledSelfContainedMacApp();
  const installedMacAppPath = runtime?.appPath || standaloneAppPath || path.join(macApplicationsDirectory(), "s-gw.app");
  const macAppPath = runtime?.appPath || (existsSync(installedMacAppPath) ? installedMacAppPath : packagedMacAppPath);
  const menuBarAppPath = runtime?.menuBarAppPath || path.join(packageRoot, "dist", "s-gw Menu Bar.app");

  return {
    packageRoot,
    nodePath: runtime?.nodePath || process.execPath,
    isSelfContainedMacApp: runtime !== undefined,
    standaloneMacAppInstalled: runtime !== undefined || standaloneAppPath !== undefined,
    cliPath: runtime?.cliPath || path.join(packageRoot, "dist", "cli.js"),
    mcpPath: runtime?.mcpPath || path.join(packageRoot, "dist", "mcp-server.js"),
    keychainHelperPath: path.join(packageRoot, "dist", "native", nativeTarget, "s-gw-keychain-helper"),
    packagedMacAppPath,
    packagedMacAppBinaryPath: macAppBinaryPath(packagedMacAppPath),
    installedMacAppPath,
    macAppPath,
    macAppBinaryPath: macAppBinaryPath(macAppPath),
    menuBarAppPath,
    menuBarBinaryPath: path.join(
      menuBarAppPath,
      "Contents",
      "MacOS",
      "s-gw-menu-bar-helper"
    ),
    windowsClientScriptPath: path.join(packageRoot, "dist", "windows", "s-gw-client.ps1"),
    windowsClientLauncherPath: path.join(packageRoot, "dist", "windows", "s-gw-client.cmd"),
    windowsHelperScriptPath: path.join(packageRoot, "dist", "windows", "s-gw-helper.ps1"),
    windowsHelperBootstrapPath: path.join(packageRoot, "dist", "windows", "s-gw-helper-bootstrap.ps1"),
    windowsHelperLauncherPath: path.join(packageRoot, "dist", "windows", "s-gw-helper.cmd"),
    windowsCredentialHelperPath: path.join(packageRoot, "dist", "windows", "s-gw-credential.ps1")
  };
}

export function packageHealth(port = 8718) {
  const layout = getPackageLayout();
  const unlock = unlockStatus();
  const cli = pathStatus(layout.cliPath);
  const mcp = pathStatus(layout.mcpPath);

  // "Ready" means a fresh user could actually store and redeem a secret: the CLI/MCP
  // entry points exist and there is some unlock source. Without this, `status` looked
  // healthy (every path exists) even when the encrypted ledger could not be unlocked.
  const unlockConfigured = unlock.activeSource !== "none";
  const ready = unlockConfigured && cli.exists && mcp.exists;

  return {
    version: CURRENT_VERSION,
    packageRoot: layout.packageRoot,
    selfContainedMacApp: layout.isSelfContainedMacApp,
    nodePath: pathStatus(layout.nodePath),
    ready,
    readiness: buildReadiness({ unlockConfigured, cli: cli.exists, mcp: mcp.exists }),
    cliPath: cli,
    mcpPath: mcp,
    keychainHelperPath: pathStatus(layout.keychainHelperPath),
    packagedMacAppPath: pathStatus(layout.packagedMacAppPath),
    installedMacAppPath: pathStatus(layout.installedMacAppPath),
    macAppPath: pathStatus(layout.macAppPath),
    macAppBinaryPath: pathStatus(layout.macAppBinaryPath),
    menuBarAppPath: pathStatus(layout.menuBarAppPath),
    menuBarBinaryPath: pathStatus(layout.menuBarBinaryPath),
    windowsClientScriptPath: pathStatus(layout.windowsClientScriptPath),
    windowsClientLauncherPath: pathStatus(layout.windowsClientLauncherPath),
    windowsHelperScriptPath: pathStatus(layout.windowsHelperScriptPath),
    windowsHelperBootstrapPath: pathStatus(layout.windowsHelperBootstrapPath),
    windowsHelperLauncherPath: pathStatus(layout.windowsHelperLauncherPath),
    windowsCredentialHelperPath: pathStatus(layout.windowsCredentialHelperPath),
    storePath: getStorePath(),
    consoleUrl: consoleUrl(port),
    unlock,
    launchAgents: {
      console: launchAgentStatus("console"),
      menuBar: launchAgentStatus("menubar")
    },
    systemdService: process.platform === "linux" ? safeSystemdUserServiceStatus() : undefined
  };
}

export interface ReadinessVerdict {
  ok: boolean;
  summary: string;
  blockers: string[];
}

// Console/native surfaces share this so the "not ready" wording stays identical
// everywhere. The console process is, by definition, running from a built package,
// so it only needs to report unlock readiness.
export function readinessForUnlock(unlockConfigured: boolean): ReadinessVerdict {
  return buildReadiness({ unlockConfigured, cli: true, mcp: true });
}

function buildReadiness(checks: { unlockConfigured: boolean; cli: boolean; mcp: boolean }): ReadinessVerdict {
  const blockers: string[] = [];
  if (!checks.cli || !checks.mcp) {
    blockers.push("Build artifacts are missing. Run `npm run build` (or reinstall the package).");
  }
  if (!checks.unlockConfigured) {
    blockers.push(
      "No local unlock material. Run `s-gw setup`, or `s-gw unlock keychain set --value-stdin`, or set SGW_MASTER_PASSPHRASE."
    );
  }

  const ok = blockers.length === 0;
  return {
    ok,
    summary: ok ? "s-gw is ready to store and redeem secrets." : "s-gw is not ready yet.",
    blockers
  };
}

export async function installConsoleLaunchAgent(options: ServiceInstallOptions = {}): Promise<LaunchAgentStatus> {
  requireMac("launchd service install");
  assertMacRuntimeForManagedSurfaces();
  assertMacBackgroundUnlock();
  const port = options.port || 8718;
  const plistPath = launchAgentPath(consoleLabel);
  const logs = await ensureLogDir();
  await writeFile(plistPath, buildConsoleLaunchAgentPlist(port, logs), { mode: 0o644 });

  if (options.start) {
    startLaunchAgent(consoleLabel, plistPath);
  }

  return launchAgentStatus("console");
}

export async function uninstallConsoleLaunchAgent(): Promise<LaunchAgentStatus> {
  requireMac("launchd service uninstall");
  stopLaunchAgent(consoleLabel);
  await rm(launchAgentPath(consoleLabel), { force: true });
  return launchAgentStatus("console");
}

export async function installMenuBarLaunchAgent(options: MenuBarOptions = {}): Promise<LaunchAgentStatus> {
  requireMac("menu-bar install");
  assertMacRuntimeForManagedSurfaces();
  assertMacBackgroundUnlock();
  assertMenuBarExists();
  const plistPath = launchAgentPath(menuBarLabel);
  const logs = await ensureLogDir();
  await writeFile(plistPath, buildMenuBarLaunchAgentPlist(options, logs), { mode: 0o644 });

  if (options.start) {
    startLaunchAgent(menuBarLabel, plistPath);
  }

  return launchAgentStatus("menubar");
}

export async function uninstallMenuBarLaunchAgent(): Promise<LaunchAgentStatus> {
  requireMac("menu-bar uninstall");
  stopLaunchAgent(menuBarLabel);
  await rm(launchAgentPath(menuBarLabel), { force: true });
  return launchAgentStatus("menubar");
}

export function startInstalledLaunchAgent(kind: "console" | "menubar"): LaunchAgentStatus {
  requireMac("launch-agent start");
  assertMacRuntimeForManagedSurfaces();
  assertMacBackgroundUnlock();
  const label = kind === "console" ? consoleLabel : menuBarLabel;
  const plistPath = launchAgentPath(label);
  if (!existsSync(plistPath)) {
    throw new Error(`LaunchAgent is not installed: ${plistPath}`);
  }

  startLaunchAgent(label, plistPath);
  return launchAgentStatus(kind);
}

export async function refreshMacRuntimeServices(): Promise<{
  console: LaunchAgentStatus;
  menuBar: LaunchAgentStatus;
}> {
  requireMac("macOS runtime refresh");
  assertMacRuntimeForManagedSurfaces();
  assertMacBackgroundUnlock();
  const console = launchAgentStatus("console");
  const menuBar = launchAgentStatus("menubar");
  return {
    console: await refreshConsoleLaunchAgent(console),
    menuBar: await refreshMenuBarLaunchAgent(menuBar)
  };
}

export function stopInstalledLaunchAgent(kind: "console" | "menubar"): LaunchAgentStatus {
  requireMac("launch-agent stop");
  stopLaunchAgent(kind === "console" ? consoleLabel : menuBarLabel);
  return launchAgentStatus(kind);
}

export async function installSystemdUserService(
  options: ServiceInstallOptions = {}
): Promise<SystemdUserServiceStatus> {
  requireLinux("systemd user service install");
  assertLinuxServiceUnlock();
  const unitPath = systemdUserServicePath();
  const sgwHome = getSgwHome();
  const recoveryHome = getSgwRecoveryHome(sgwHome);
  await mkdir(path.dirname(unitPath), { recursive: true, mode: 0o700 });
  assertSafeSystemdUnitDirectory(unitPath);
  await mkdir(path.join(sgwHome, "logs"), { recursive: true, mode: 0o700 });
  await mkdir(recoveryHome, { recursive: true, mode: 0o700 });
  assertSafeSystemdUnitTarget(unitPath);

  const staging = `${unitPath}.install-${process.pid}-${Date.now()}`;
  try {
    await writeFile(staging, buildSystemdUserUnit(options.port || 8718), { mode: 0o600 });
    renameSync(staging, unitPath);
  } finally {
    await rm(staging, { force: true });
  }

  runSystemctl(["daemon-reload"]);
  runSystemctl(["enable", systemdUnitName]);
  if (options.start) runSystemctl(["restart", systemdUnitName]);
  const status = systemdUserServiceStatus();
  if (options.start && !status.active) {
    throw new Error(`systemd started ${systemdUnitName}, but it is not active (${status.state}/${status.subState}).`);
  }
  return status;
}

export function startInstalledSystemdUserService(): SystemdUserServiceStatus {
  requireLinux("systemd user service start");
  assertLinuxServiceUnlock();
  const unitPath = systemdUserServicePath();
  if (!existsSync(unitPath)) {
    throw new Error(`systemd user service is not installed: ${unitPath}`);
  }
  runSystemctl(["start", systemdUnitName]);
  const status = systemdUserServiceStatus();
  if (!status.active) {
    throw new Error(`systemd did not keep ${systemdUnitName} active (${status.state}/${status.subState}).`);
  }
  return status;
}

export function stopInstalledSystemdUserService(): SystemdUserServiceStatus {
  requireLinux("systemd user service stop");
  if (existsSync(systemdUserServicePath())) {
    runSystemctl(["stop", systemdUnitName]);
  }
  return systemdUserServiceStatus();
}

export async function uninstallSystemdUserService(): Promise<SystemdUserServiceStatus> {
  requireLinux("systemd user service uninstall");
  const unitPath = systemdUserServicePath();
  runSystemctl(["disable", "--now", systemdUnitName], true);
  if (existsSync(unitPath)) {
    assertSafeSystemdUnitTarget(unitPath);
    await rm(unitPath, { force: true });
  }
  runSystemctl(["daemon-reload"]);
  runSystemctl(["reset-failed", systemdUnitName], true);
  return systemdUserServiceStatus();
}

export function systemdUserServiceStatus(): SystemdUserServiceStatus {
  requireLinux("systemd user service status");
  const unitPath = systemdUserServicePath();
  if (!existsSync(unitPath)) return emptySystemdUserServiceStatus(unitPath);

  const output = runSystemctl([
    "show",
    systemdUnitName,
    "--property=LoadState",
    "--property=UnitFileState",
    "--property=ActiveState",
    "--property=SubState",
    "--property=MainPID",
    "--no-pager"
  ]);
  const fields = new Map<string, string>();
  for (const line of output.split(/\r?\n/)) {
    const separator = line.indexOf("=");
    if (separator > 0) fields.set(line.slice(0, separator), line.slice(separator + 1));
  }
  const mainPid = Number(fields.get("MainPID"));
  const state = fields.get("ActiveState") || "unknown";
  return {
    unit: systemdUnitName,
    unitPath,
    installed: true,
    loaded: fields.get("LoadState") === "loaded",
    enabled: fields.get("UnitFileState") === "enabled",
    active: state === "active",
    state,
    subState: fields.get("SubState") || "unknown",
    ...(Number.isInteger(mainPid) && mainPid > 0 ? { mainPid } : {})
  };
}

export function buildSystemdUserUnit(port = 8718): string {
  const layout = getPackageLayout();
  const sgwHome = getSgwHome();
  const recoveryHome = getSgwRecoveryHome(sgwHome);
  const runtimeDir = process.env.XDG_RUNTIME_DIR?.trim()
    || (typeof process.getuid === "function" ? `/run/user/${process.getuid()}` : undefined);
  const dbusAddress = process.env.DBUS_SESSION_BUS_ADDRESS?.trim()
    || (runtimeDir ? `unix:path=${runtimeDir}/bus` : undefined);
  const username = os.userInfo().username;
  const env: Record<string, string> = {
    HOME: os.homedir(),
    LANG: "C.UTF-8",
    LOGNAME: username,
    PATH: "/usr/local/bin:/usr/bin:/bin",
    SGW_DISABLE_UPDATE_CHECK: "1",
    SGW_HOME: sgwHome,
    SGW_RECOVERY_HOME: recoveryHome,
    USER: username
  };
  if (runtimeDir) env.XDG_RUNTIME_DIR = runtimeDir;
  if (dbusAddress) env.DBUS_SESSION_BUS_ADDRESS = dbusAddress;
  for (const key of ["SGW_KEYCHAIN_SERVICE", "SGW_KEYCHAIN_ACCOUNT", "SGW_SECRET_KEYCHAIN_SERVICE"] as const) {
    const value = boundedAuthorityValue(key, process.env[key]);
    if (value) env[key] = value;
  }
  copyNormalizedAuthorityEnum(env, "SGW_SECRET_BACKEND", process.env.SGW_SECRET_BACKEND, ["local", "keychain"]);
  copyNormalizedAuthorityEnum(env, "SGW_EXECUTION_ENGINE", process.env.SGW_EXECUTION_ENGINE, [
    "auto",
    "rust",
    "typescript"
  ]);
  const args = [
    "/usr/bin/env",
    "-i",
    ...Object.entries(env)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => `${key}=${value}`),
    layout.nodePath,
    layout.cliPath,
    "console",
    "--host",
    "127.0.0.1",
    "--port",
    String(port),
    "--no-open"
  ];

  return `[Unit]
Description=s-gw local credential console
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=exec
ExecStartPre=${["/usr/bin/test", "-x", layout.nodePath].map(systemdExecQuote).join(" ")}
ExecStartPre=${["/usr/bin/test", "-r", layout.cliPath].map(systemdExecQuote).join(" ")}
ExecStart=${args.map(systemdExecQuote).join(" ")}
UnsetEnvironment=SGW_MASTER_PASSPHRASE
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${systemdDirectiveQuote(sgwHome)} ${systemdDirectiveQuote(recoveryHome)}
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=graphical-session.target
`;
}

async function refreshConsoleLaunchAgent(status: LaunchAgentStatus): Promise<LaunchAgentStatus> {
  if (!status.installed) return status;

  const args = launchAgentProgramArguments(status.plistPath);
  const env = launchAgentEnvironment(status.plistPath);
  const port = numberAfter(args, "--port") || 8718;
  const logs = await ensureLogDir(env.SGW_HOME);
  if (status.loaded) stopLaunchAgent(consoleLabel);
  await writeFile(status.plistPath, buildConsoleLaunchAgentPlist(port, logs, env), { mode: 0o644 });
  if (status.loaded) startLaunchAgent(consoleLabel, status.plistPath);
  return launchAgentStatus("console");
}

async function refreshMenuBarLaunchAgent(status: LaunchAgentStatus): Promise<LaunchAgentStatus> {
  if (!status.installed) return status;

  const args = launchAgentProgramArguments(status.plistPath);
  const env = launchAgentEnvironment(status.plistPath);
  const logs = await ensureLogDir(env.SGW_HOME);
  if (status.loaded) stopLaunchAgent(menuBarLabel);
  await writeFile(status.plistPath, buildMenuBarLaunchAgentPlist({
    consoleUrl: env.SGW_CONSOLE_URL,
    countMode: normalizeMenuBarCountMode(env.SGW_MENU_BAR_COUNT_MODE),
    notify: !args.includes("--no-notify")
  }, logs, env), { mode: 0o644 });
  if (status.loaded) startLaunchAgent(menuBarLabel, status.plistPath);
  return launchAgentStatus("menubar");
}

function launchAgentProgramArguments(plistPath: string): string[] {
  const plist = readLaunchAgentPlist(plistPath);
  const match = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(plist);
  if (!match) return [];
  return [...match[1].matchAll(/<string>([\s\S]*?)<\/string>/g)].map((item) => xmlUnescape(item[1]));
}

function launchAgentEnvironment(plistPath: string): Record<string, string> {
  const plist = readLaunchAgentPlist(plistPath);
  const match = /<key>EnvironmentVariables<\/key>\s*<dict>([\s\S]*?)<\/dict>/.exec(plist);
  if (!match) return {};

  const env: Record<string, string> = {};
  for (const item of match[1].matchAll(/<key>([\s\S]*?)<\/key>\s*<string>([\s\S]*?)<\/string>/g)) {
    env[xmlUnescape(item[1])] = xmlUnescape(item[2]);
  }
  return env;
}

function readLaunchAgentPlist(plistPath: string): string {
  try {
    return readFileSync(plistPath, "utf8");
  } catch {
    return "";
  }
}

function numberAfter(values: string[], flag: string): number | undefined {
  const index = values.indexOf(flag);
  if (index === -1) return undefined;
  const value = Number(values[index + 1]);
  return Number.isInteger(value) && value > 0 && value <= 65_535 ? value : undefined;
}

export function stopMacApp(): MacAppProcessInfo | undefined {
  requireMac("macOS app stop");
  if (process.env.SGW_SKIP_APP_STOP === "1") return undefined;

  const script = [
    "ObjC.import('AppKit')",
    "const apps = $.NSRunningApplication.runningApplicationsWithBundleIdentifier('com.s-gw.sgw.app')",
    "const pids = []",
    "for (let i = 0; i < apps.count; i += 1) {",
    "  const app = apps.objectAtIndex(i)",
    "  pids.push(Number(app.processIdentifier))",
    "  app.terminate",
    "}",
    "JSON.stringify(pids)"
  ].join("\n");
  const result = spawnSync("/usr/bin/osascript", ["-l", "JavaScript", "-e", script], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Could not close the running s-gw macOS app.");
  }

  const parsed = JSON.parse(result.stdout.trim() || "[]") as unknown;
  const pids = Array.isArray(parsed)
    ? parsed.filter((pid): pid is number => Number.isInteger(pid) && pid > 0)
    : [];
  if (pids.length === 0) return undefined;
  for (const pid of pids) waitForPidToExit(pid);
  if (pids.some(isPidAlive)) {
    throw new Error("The s-gw macOS app is still running. Close it and retry the update.");
  }
  return {
    pid: pids[0],
    source: "process-list",
    alive: false,
    bundleIdentifier: "com.s-gw.sgw.app",
    otherPids: pids.slice(1)
  };
}

export function stopWindowsSurfaces(options: WindowsSurfaceScope = {}): WindowsStoppedSurfaces {
  requireWindows("Windows surface stop");
  const layout = getPackageLayout();
  const endpoint = windowsConsoleEndpoint(options);
  const cliPath = path.resolve(options.cliPath || layout.cliPath);
  const nodePath = path.resolve(options.nodePath || layout.nodePath);
  const windowsScripts = path.join(path.dirname(cliPath), "windows");
  const helperPath = path.join(windowsScripts, "s-gw-helper.ps1");
  const clientPath = path.join(windowsScripts, "s-gw-client.ps1");
  const instanceKey = getSgwInstanceKey();
  const helperInstanceKey = windowsHelperInstanceKey(endpoint.baseUrl);
  const powershell = trustedWindowsPowerShellSync();
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$stopped = @()",
    "$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$currentSessionId = [int](Get-Process -Id $PID).SessionId",
    "$consoleAuthorityMatches = $false",
    "try {",
    "  $health = Invoke-RestMethod -Method Get -Uri $env:SGW_STOP_HEALTH_URL -TimeoutSec 1",
    "  $consoleAuthorityMatches = $health.ok -eq $true -and [string]$health.name -eq 's-gw' -and [string]$health.instanceKey -ceq $env:SGW_STOP_INSTANCE_KEY",
    "} catch {}",
    "$cliPattern = '(?i)(?:^|\\s)\"?' + [regex]::Escape($env:SGW_STOP_CLI_PATH) + '\"?(?:\\s|$)'",
    "$helperPattern = '(?i)(?:^|\\s)-File(?:\\s+|:)\"?' + [regex]::Escape($env:SGW_STOP_HELPER_PATH) + '\"?(?:\\s|$)'",
    "$clientPattern = '(?i)(?:^|\\s)-File(?:\\s+|:)\"?' + [regex]::Escape($env:SGW_STOP_CLIENT_PATH) + '\"?(?:\\s|$)'",
    "$portPattern = '(?i)(?:^|\\s)(?:--port|-Port)(?:\\s+|:|=)\"?' + [regex]::Escape($env:SGW_STOP_PORT) + '\"?(?:\\s|$)'",
    "$anyPortPattern = '(?i)(?:^|\\s)(?:--port|-Port)(?:\\s+|:|=)'",
    "$hostPattern = '(?i)(?:^|\\s)--host(?:\\s+|:|=)\"?127\\.0\\.0\\.1\"?(?:\\s|$)'",
    "$anyHostPattern = '(?i)(?:^|\\s)--host(?:\\s+|:|=)'",
    "$helperInstancePattern = '(?i)(?:^|\\s)-InstanceKey(?:\\s+|:)\"?' + [regex]::Escape($env:SGW_STOP_HELPER_INSTANCE_KEY) + '\"?(?:\\s|$)'",
    "$clientInstancePattern = '(?i)(?:^|\\s)-InstanceKey(?:\\s+|:)\"?' + [regex]::Escape($env:SGW_STOP_INSTANCE_KEY) + '\"?(?:\\s|$)'",
    "$nodeName = [IO.Path]::GetFileName($env:SGW_STOP_NODE_PATH).Replace(\"'\", \"''\")",
    "$powerShellName = [IO.Path]::GetFileName($env:SGW_STOP_POWERSHELL_PATH).Replace(\"'\", \"''\")",
    "$processFilter = \"Name = '$nodeName' OR Name = '$powerShellName'\"",
    "Get-CimInstance Win32_Process -Filter $processFilter | ForEach-Object {",
    "  $line = [string]$_.CommandLine",
    "  if (-not $line -or [int]$_.ProcessId -eq $PID -or [int]$_.SessionId -ne $currentSessionId) { return }",
    "  $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction SilentlyContinue",
    "  if ($null -eq $owner -or $owner.ReturnValue -ne 0 -or [string]$owner.Sid -ne $currentSid) { return }",
    "  $exactNode = $false",
    "  $exactPowerShell = $false",
    "  try {",
    "    $executable = [IO.Path]::GetFullPath([string]$_.ExecutablePath)",
    "    $exactNode = [string]::Equals($executable, [IO.Path]::GetFullPath($env:SGW_STOP_NODE_PATH), [StringComparison]::OrdinalIgnoreCase)",
    "    $exactPowerShell = [string]::Equals($executable, [IO.Path]::GetFullPath($env:SGW_STOP_POWERSHELL_PATH), [StringComparison]::OrdinalIgnoreCase)",
    "  } catch {}",
    "  $portMatches = $line -match $portPattern -or ($env:SGW_STOP_PORT -eq '8718' -and $line -notmatch $anyPortPattern)",
    "  $hostMatches = $line -match $hostPattern -or $line -notmatch $anyHostPattern",
    "  $kind = ''",
    "  if ($exactPowerShell -and $line -match $helperPattern -and $line -match $helperInstancePattern -and $portMatches) {",
    "    $kind = 'helper'",
    "  } elseif ($exactPowerShell -and $line -match $clientPattern -and $line -match $clientInstancePattern -and $portMatches) {",
    "    $kind = 'client'",
    "  } elseif ($consoleAuthorityMatches -and $exactNode -and $line -match $cliPattern -and $line -match '(?i)(?:^|\\s)console(?:\\s|$)' -and $portMatches -and $hostMatches) {",
    "    $kind = 'console'",
    "  }",
    "  if (-not $kind) { return }",
    "  $pidToStop = [int]$_.ProcessId",
    "  $creationDate = [string]$_.CreationDate",
    "  $expectedLine = $line",
    "  $expectedExecutable = [string]$_.ExecutablePath",
    "  $fresh = Get-CimInstance Win32_Process -Filter \"ProcessId = $pidToStop\" -ErrorAction SilentlyContinue",
    "  if ($null -ne $fresh) {",
    "    $freshOwner = Invoke-CimMethod -InputObject $fresh -MethodName GetOwnerSid -ErrorAction SilentlyContinue",
    "    if ([string]$fresh.CreationDate -ne $creationDate -or [int]$fresh.SessionId -ne $currentSessionId -or [string]$fresh.CommandLine -ne $expectedLine -or [string]$fresh.ExecutablePath -ne $expectedExecutable -or $null -eq $freshOwner -or $freshOwner.ReturnValue -ne 0 -or [string]$freshOwner.Sid -ne $currentSid) {",
    "      throw \"s-gw process $pidToStop changed before it could be stopped.\"",
    "    }",
    "    try {",
    "      $termination = Invoke-CimMethod -InputObject $fresh -MethodName Terminate -ErrorAction Stop",
    "      if ($termination.ReturnValue -ne 0) { throw \"s-gw process $pidToStop returned termination code $($termination.ReturnValue).\" }",
    "    } catch {",
    "      if ($null -ne (Get-Process -Id $pidToStop -ErrorAction SilentlyContinue)) { throw }",
    "    }",
    "  }",
    "  for ($attempt = 0; $attempt -lt 50; $attempt += 1) {",
    "    if ($null -eq (Get-Process -Id $pidToStop -ErrorAction SilentlyContinue)) { break }",
    "    Start-Sleep -Milliseconds 50",
    "  }",
    "  if ($null -ne (Get-Process -Id $pidToStop -ErrorAction SilentlyContinue)) { throw \"s-gw process $pidToStop did not stop.\" }",
    "  $stopped += [PSCustomObject]@{ pid = $pidToStop; kind = $kind }",
    "}",
    "$stopped | ConvertTo-Json -Compress"
  ].join("\n");
  const result = spawnSync(powershell, ["-NoProfile", "-Command", script], {
    cwd: path.dirname(powershell),
    encoding: "utf8",
    env: windowsBackgroundEnvironment(endpoint.baseUrl, {
      SGW_STOP_CLI_PATH: cliPath,
      SGW_STOP_CLIENT_PATH: clientPath,
      SGW_STOP_HEALTH_URL: new URL("api/health", endpoint.baseUrl).toString(),
      SGW_STOP_HELPER_INSTANCE_KEY: helperInstanceKey,
      SGW_STOP_HELPER_PATH: helperPath,
      SGW_STOP_INSTANCE_KEY: instanceKey,
      SGW_STOP_NODE_PATH: nodePath,
      SGW_STOP_PORT: String(endpoint.port),
      SGW_STOP_POWERSHELL_PATH: powershell
    }),
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Could not stop the running s-gw Windows surfaces.");
  }
  if (!result.stdout.trim()) return { pids: [], console: false, helper: false, client: false };
  const parsed = JSON.parse(result.stdout) as unknown;
  const entries = (Array.isArray(parsed) ? parsed : [parsed]).filter((entry): entry is { pid: number; kind: string } => {
    if (!entry || typeof entry !== "object") return false;
    const item = entry as { pid?: unknown; kind?: unknown };
    return typeof item.pid === "number"
      && Number.isInteger(item.pid)
      && item.pid > 0
      && ["client", "console", "helper"].includes(String(item.kind));
  });
  return {
    pids: entries.map((entry) => entry.pid),
    console: entries.some((entry) => entry.kind === "console"),
    helper: entries.some((entry) => entry.kind === "helper"),
    client: entries.some((entry) => entry.kind === "client")
  };
}

export function startWindowsConsole(options: MenuBarOptions = {}): WindowsOpenResult {
  requireWindows("Windows console start");
  assertWindowsBackgroundUnlock();
  return spawnWindowsConsole(options).result;
}

function spawnWindowsConsole(options: MenuBarOptions): { child: ChildProcess; result: WindowsOpenResult } {
  requireWindows("Windows console start");
  const layout = getPackageLayout();
  const { port, url } = windowsConsoleEndpoint(options);
  const child = spawn(process.execPath, [
    layout.cliPath,
    "console",
    "--host",
    "127.0.0.1",
    "--port",
    String(port),
    "--no-open"
  ], {
    detached: true,
    env: windowsEnvironment(url),
    stdio: "ignore",
    windowsHide: true
  });
  child.unref();
  return {
    child,
    result: {
      scriptPath: layout.cliPath,
      launcherPath: process.execPath,
      consoleUrl: url,
      pid: child.pid
    }
  };
}

export async function ensureWindowsConsole(options: MenuBarOptions = {}): Promise<WindowsOpenResult> {
  return (await ensureWindowsConsoleState(options)).result;
}

async function ensureWindowsConsoleState(
  options: MenuBarOptions,
  unlockVerified = false
): Promise<{ result: WindowsOpenResult; helperPids: number[] }> {
  requireWindows("Windows console start");
  const layout = getPackageLayout();
  const { port, url } = windowsConsoleEndpoint(options);
  const instanceKey = getSgwInstanceKey();
  const helperInstanceKey = windowsHelperInstanceKey(url);
  const health = await windowsConsoleHealth(url);
  if (health.ready) {
    if (health.instanceKey !== instanceKey) {
      throw new Error(`Port ${port} already has an s-gw console for another credential home. Stop it or choose another port.`);
    }
    assertWindowsConsoleListener(port, layout.cliPath);
    const helperPids = findRunningWindowsHelpers(
      layout.windowsHelperScriptPath,
      port,
      url,
      helperInstanceKey
    );
    return {
      result: {
        scriptPath: layout.cliPath,
        launcherPath: process.execPath,
        consoleUrl: url
      },
      helperPids
    };
  }

  findRunningWindowsHelpers(layout.windowsHelperScriptPath, port, url, helperInstanceKey);
  if (!unlockVerified) assertWindowsBackgroundUnlock();
  const started = spawnWindowsConsole({ ...options, port, consoleUrl: url });
  try {
    const listenerPid = await waitForWindowsConsole(url, instanceKey, port, layout.cliPath);
    const helperPids = findRunningWindowsHelpers(
      layout.windowsHelperScriptPath,
      port,
      url,
      helperInstanceKey
    );
    return {
      result: {
        ...started.result,
        pid: listenerPid,
        reusedExisting: listenerPid !== started.child.pid
      },
      helperPids
    };
  } catch (error) {
    try {
      await stopSpawnedWindowsProcess(started.child, "console");
    } catch (cleanupError) {
      throw new Error(`${error instanceof Error ? error.message : String(error)}; ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`);
    }
    const latest = await windowsConsoleHealth(url);
    if (latest.ready && latest.instanceKey !== instanceKey) {
      throw new Error(`Port ${port} became active for another credential home. Stop it or choose another port.`);
    }
    throw error;
  }
}

export async function installWindowsLoginService(options: {
  port?: number;
  start?: boolean;
  tray?: boolean;
} = {}): Promise<WindowsLoginServiceStatus> {
  requireWindows("Windows login startup install");
  assertWindowsBackgroundUnlock();
  const layout = getPackageLayout();
  const port = options.port || 8718;
  const shortcut = await installWindowsStartupShortcut({
    nodePath: layout.nodePath,
    cliPath: layout.cliPath,
    port,
    tray: options.tray === true
  });
  if (options.start) {
    return startWindowsLoginServiceForShortcut(shortcut, undefined, true);
  }
  const config = await installedWindowsStartupConfig(layout.nodePath, layout.cliPath, undefined, shortcut);
  return windowsLoginServiceStatusForConfig(config, shortcut);
}

export async function startInstalledWindowsLoginService(
  expectedPayload?: string
): Promise<WindowsLoginServiceStatus> {
  requireWindows("Windows login startup start");
  const layout = getPackageLayout();
  const shortcut = await windowsStartupShortcutStatus(layout.nodePath, layout.cliPath);
  return startWindowsLoginServiceForShortcut(shortcut, expectedPayload);
}

async function startWindowsLoginServiceForShortcut(
  shortcut: WindowsStartupShortcutStatus,
  expectedPayload?: string,
  unlockVerified = false
): Promise<WindowsLoginServiceStatus> {
  const credentialTestEnvironment = windowsCredentialTestEnvironment();
  const layout = getPackageLayout();
  const config = await installedWindowsStartupConfig(
    layout.nodePath,
    layout.cliPath,
    expectedPayload,
    shortcut
  );
  const restore = applyWindowsStartupConfig(config);
  Object.assign(process.env, credentialTestEnvironment);
  try {
    if (!unlockVerified) assertWindowsBackgroundUnlock();
    await ensureWindowsConsoleState(
      { port: config.port, consoleUrl: consoleUrl(config.port) },
      true
    );
    if (config.tray) {
      await openWindowsHelper({ port: config.port, consoleUrl: consoleUrl(config.port) });
    }
    return await waitForWindowsLoginServiceStatus(config, shortcut);
  } finally {
    restore();
  }
}

async function waitForWindowsLoginServiceStatus(
  config: WindowsStartupConfig,
  shortcut: WindowsStartupShortcutStatus
): Promise<WindowsLoginServiceStatus> {
  let latest = await windowsLoginServiceStatusForConfig(config, shortcut);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (latest.active && (!config.tray || latest.helperActive)) return latest;
    await new Promise((resolve) => setTimeout(resolve, 300));
    latest = await windowsLoginServiceStatusForConfig(config, shortcut);
  }
  if (latest.active && (!config.tray || latest.helperActive)) return latest;
  throw new Error(latest.error || "Windows login startup did not remain active after launch.");
}

export async function stopInstalledWindowsLoginService(): Promise<WindowsLoginServiceStatus> {
  requireWindows("Windows login startup stop");
  const layout = getPackageLayout();
  const shortcut = await windowsStartupShortcutStatus(layout.nodePath, layout.cliPath);
  if (shortcut.installed && !shortcut.managed) {
    throw new Error(shortcut.error || "The existing Windows Startup item is not managed by s-gw.");
  }
  const stopped = stopWindowsSurfacesForShortcut(shortcut);
  if (!shortcut.config) {
    return { ...shortcut, active: false, helperActive: false, stopped };
  }
  return { ...await windowsLoginServiceStatusForConfig(shortcut.config, shortcut), stopped };
}

export async function uninstallWindowsLoginService(): Promise<WindowsLoginServiceStatus> {
  requireWindows("Windows login startup uninstall");
  const layout = getPackageLayout();
  const shortcut = await windowsStartupShortcutStatus(layout.nodePath, layout.cliPath);
  if (shortcut.installed && !shortcut.managed) {
    throw new Error(shortcut.error || "The existing Windows Startup item is not managed by s-gw.");
  }
  stopWindowsSurfacesForShortcut(shortcut);
  const removed = await uninstallWindowsStartupShortcut(layout.nodePath, layout.cliPath, shortcut);
  return { ...removed, active: false, helperActive: false };
}

function stopWindowsSurfacesForShortcut(shortcut: WindowsStartupShortcutStatus): WindowsStoppedSurfaces {
  if (!shortcut.config || !shortcut.targetPath || !shortcut.cliPath) {
    return stopWindowsSurfaces();
  }
  const restore = applyWindowsStartupConfig(shortcut.config);
  try {
    return stopWindowsSurfaces({
      cliPath: shortcut.cliPath,
      consoleUrl: consoleUrl(shortcut.config.port),
      nodePath: shortcut.targetPath,
      port: shortcut.config.port
    });
  } finally {
    restore();
  }
}

export async function windowsLoginServiceStatus(): Promise<WindowsLoginServiceStatus> {
  requireWindows("Windows login startup status");
  const layout = getPackageLayout();
  const shortcut = await windowsStartupShortcutStatus(layout.nodePath, layout.cliPath);
  if (!shortcut.config) {
    return { ...shortcut, active: false, helperActive: false };
  }
  const restore = applyWindowsStartupConfig(shortcut.config);
  try {
    return await windowsLoginServiceStatusForConfig(shortcut.config, shortcut);
  } finally {
    restore();
  }
}

async function windowsLoginServiceStatusForConfig(
  config: WindowsStartupConfig,
  shortcut?: WindowsStartupShortcutStatus
): Promise<WindowsLoginServiceStatus> {
  const layout = getPackageLayout();
  const registration = shortcut || await windowsStartupShortcutStatus(layout.nodePath, layout.cliPath);
  const url = consoleUrl(config.port);
  let active = false;
  let helperActive = false;
  let consolePid: number | undefined;
  let runtimeError: string | undefined;
  try {
    const health = await windowsConsoleHealth(url);
    if (health.ready && health.instanceKey === getSgwInstanceKey()) {
      consolePid = trustedWindowsConsoleListener(config.port, layout.cliPath);
      active = consolePid !== undefined;
    }
    if (config.tray) {
      helperActive = findRunningWindowsHelpers(
        layout.windowsHelperScriptPath,
        config.port,
        url,
        windowsHelperInstanceKey(url)
      ).length === 1;
    }
  } catch (error) {
    runtimeError = error instanceof Error ? error.message : String(error);
  }
  return {
    ...registration,
    active,
    helperActive,
    consoleUrl: url,
    ...(consolePid ? { consolePid } : {}),
    ...((registration.error || runtimeError) ? { error: [registration.error, runtimeError].filter(Boolean).join("; ") } : {})
  };
}

export async function restartWindowsSurfaces(
  stopped: WindowsStoppedSurfaces,
  options: MenuBarOptions = {}
): Promise<WindowsRestartResult> {
  requireWindows("Windows surface restart");
  const result: WindowsRestartResult = {};
  const failures: string[] = [];
  try {
    if (stopped.client) {
      result.client = await openWindowsClient(options);
    } else if (stopped.console) {
      result.console = await ensureWindowsConsole(options);
    }
  } catch (error) {
    failures.push(`console/client: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (stopped.helper) {
    try {
      result.helper = await openWindowsHelper(options);
    } catch (error) {
      failures.push(`helper: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if ((stopped.console || stopped.client) && (result.console || result.client)) {
    try {
      await waitForWindowsConsole(
        windowsConsoleEndpoint(options).url,
        getSgwInstanceKey(),
        windowsConsoleEndpoint(options).port,
        getPackageLayout().cliPath
      );
    } catch (error) {
      failures.push(`console health: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (result.helper) {
    await new Promise((resolve) => setTimeout(resolve, 300));
    if (!result.helper.pid || !isPidAlive(result.helper.pid)) {
      failures.push("helper: process exited during startup");
    }
  }
  if (failures.length > 0) {
    throw new Error(failures.join("; "));
  }
  return result;
}

async function waitForWindowsConsole(url: string, instanceKey: string, port: number, cliPath: string): Promise<number> {
  const healthUrl = new URL("/api/health", url).toString();
  let listenerError: unknown;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const health = await windowsConsoleHealth(url);
    if (health.ready && health.instanceKey === instanceKey) {
      try {
        return assertWindowsConsoleListener(port, cliPath);
      } catch (error) {
        listenerError = error;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (listenerError) throw listenerError;
  throw new Error(`s-gw console did not become healthy for this credential home at ${healthUrl}`);
}

function assertWindowsConsoleListener(port: number, cliPath: string): number {
  const pid = trustedWindowsConsoleListener(port, cliPath);
  if (!pid) {
    throw new Error(`Port ${port} is not owned by this user's s-gw console process. Stop the listener or choose another port.`);
  }
  return pid;
}

function trustedWindowsConsoleListener(port: number, cliPath: string): number | undefined {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$currentSessionId = [int](Get-Process -Id $PID).SessionId",
    "$connections = @(Get-NetTCPConnection -State Listen -LocalPort ([int]$env:SGW_CONSOLE_PORT) | Where-Object { [string]$_.LocalAddress -eq '127.0.0.1' })",
    "$listenerPids = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)",
    "$cliPattern = '(?i)(?:^|\\s)\"?' + [regex]::Escape($env:SGW_CONSOLE_CLI_PATH) + '\"?(?:\\s|$)'",
    "$portPattern = '(?i)(?:^|\\s)--port(?:\\s+|:|=)\"?' + [regex]::Escape($env:SGW_CONSOLE_PORT) + '\"?(?:\\s|$)'",
    "$anyPortPattern = '(?i)(?:^|\\s)--port(?:\\s+|:|=)'",
    "$hostPattern = '(?i)(?:^|\\s)--host(?:\\s+|:|=)\"?127\\.0\\.0\\.1\"?(?:\\s|$)'",
    "$anyHostPattern = '(?i)(?:^|\\s)--host(?:\\s+|:|=)'",
    "$consolePattern = '(?i)(?:^|\\s)console(?:\\s|$)'",
    "$processes = @()",
    "foreach ($listenerPid in $listenerPids) {",
    "  $item = Get-CimInstance Win32_Process -Filter \"ProcessId = $listenerPid\" -ErrorAction SilentlyContinue",
    "  if ($null -eq $item) { continue }",
    "  $owner = Invoke-CimMethod -InputObject $item -MethodName GetOwnerSid -ErrorAction SilentlyContinue",
    "  $ownerSid = if ($null -ne $owner -and $owner.ReturnValue -eq 0) { [string]$owner.Sid } else { '' }",
    "  $exactNode = $false",
    "  try { $exactNode = [string]::Equals([IO.Path]::GetFullPath([string]$item.ExecutablePath), [IO.Path]::GetFullPath($env:SGW_CONSOLE_NODE_PATH), [StringComparison]::OrdinalIgnoreCase) } catch {}",
    "  $line = [string]$item.CommandLine",
    "  $hostMatches = $line -match $hostPattern -or $line -notmatch $anyHostPattern",
    "  $portMatches = $line -match $portPattern -or ($env:SGW_CONSOLE_PORT -eq '8718' -and $line -notmatch $anyPortPattern)",
    "  $processes += [PSCustomObject]@{ pid = [int]$item.ProcessId; ownerSid = $ownerSid; sessionId = [int]$item.SessionId; exactNode = $exactNode; exactCli = [bool]($line -match $cliPattern); exactArguments = [bool]($line -match $consolePattern -and $hostMatches -and $portMatches) }",
    "}",
    "[PSCustomObject]@{ currentSid = $currentSid; currentSessionId = $currentSessionId; processes = $processes } | ConvertTo-Json -Depth 3 -Compress"
  ].join("\n");
  const powershell = trustedWindowsPowerShellSync();
  const result = spawnSync(powershell, ["-NoProfile", "-Command", script], {
    cwd: path.dirname(powershell),
    encoding: "utf8",
    env: windowsEnvironment(consoleUrl(port), {
      SGW_CONSOLE_PORT: String(port),
      SGW_CONSOLE_CLI_PATH: cliPath,
      SGW_CONSOLE_NODE_PATH: process.execPath
    }),
    stdio: ["ignore", "pipe", "pipe"],
    timeout: windowsProcessInspectionTimeoutMs(),
    windowsHide: true
  });
  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      throw new Error(`Timed out inspecting the Windows listener on port ${port}.`);
    }
    throw new Error(`Could not inspect the Windows listener on port ${port}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error((result.stderr || "").trim() || `Could not inspect the Windows listener on port ${port}.`);
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(result.stdout) as Record<string, unknown>;
  } catch {
    throw new Error(`Could not parse the Windows listener on port ${port}.`);
  }
  const currentSid = typeof payload.currentSid === "string" ? payload.currentSid.toLowerCase() : "";
  const currentSessionId = Number(payload.currentSessionId);
  const rawProcesses = Array.isArray(payload.processes)
    ? payload.processes
    : payload.processes ? [payload.processes] : [];
  const processes = rawProcesses.flatMap((value): WindowsConsoleListenerProcess[] => {
    if (!value || typeof value !== "object") return [];
    const item = value as Record<string, unknown>;
    const pid = Number(item.pid);
    const sessionId = Number(item.sessionId);
    if (!Number.isInteger(pid) || pid <= 0 || !Number.isInteger(sessionId)) return [];
    return [{
      pid,
      ownerSid: typeof item.ownerSid === "string" ? item.ownerSid : "",
      sessionId,
      exactNode: item.exactNode === true,
      exactCli: item.exactCli === true,
      exactArguments: item.exactArguments === true
    }];
  });
  if (processes.length !== 1 || !currentSid || !Number.isInteger(currentSessionId)) return undefined;
  const listener = processes[0];
  if (
    listener.ownerSid.toLowerCase() !== currentSid
    || listener.sessionId !== currentSessionId
    || !listener.exactNode
    || !listener.exactCli
    || !listener.exactArguments
  ) return undefined;
  return listener.pid;
}

async function windowsConsoleHealth(url: string): Promise<{ ready: boolean; instanceKey?: string }> {
  const healthUrl = new URL("/api/health", url).toString();
  try {
    const response = await fetch(healthUrl, { signal: AbortSignal.timeout(500) });
    if (!response.ok) return { ready: false };
    const payload = await response.json() as Record<string, unknown>;
    return {
      ready: payload.ok === true && payload.name === "s-gw",
      instanceKey: typeof payload.instanceKey === "string" ? payload.instanceKey : undefined
    };
  } catch {
    return { ready: false };
  }
}

export function launchAgentStatus(kind: "console" | "menubar"): LaunchAgentStatus {
  const label = kind === "console" ? consoleLabel : menuBarLabel;
  const plistPath = launchAgentPath(label);

  return {
    label,
    plistPath,
    installed: existsSync(plistPath),
    loaded: process.platform === "darwin" ? isLaunchAgentLoaded(label) : false
  };
}

export function openMenuBarHelper(options: MenuBarOptions = {}): { appPath: string; consoleUrl: string } {
  requireMac("menu-bar open");
  assertMacRuntimeForManagedSurfaces();
  assertMenuBarExists();
  const layout = getPackageLayout();
  const url = options.consoleUrl || consoleUrl(options.port || 8718);
  const env = menuBarEnvironment(url, options.countMode);
  const args: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    args.push("--env", `${key}=${value}`);
  }

  args.push(layout.menuBarAppPath, "--args");
  if (options.show) {
    args.push("--show-on-launch");
  }
  if (options.notify !== false) {
    args.push("--notify-on-launch");
  } else {
    args.push("--no-notify");
  }

  const result = spawnSync("/usr/bin/open", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Failed to open s-gw menu-bar helper.");
  }

  return { appPath: layout.menuBarAppPath, consoleUrl: url };
}

export function openMacApp(options: MenuBarOptions = {}): MacAppOpenResult {
  requireMac("mac app open");
  installMacAppBundle();
  assertMacAppExists();
  const layout = getPackageLayout();
  const url = options.consoleUrl || consoleUrl(options.port || 8718);

  const existing = existingMacAppProcess(layout);
  if (existing) {
    focusMacAppProcess(existing, layout.macAppPath);
    return {
      appPath: layout.macAppPath,
      consoleUrl: url,
      reusedExisting: true,
      process: existing
    };
  }

  const env = menuBarEnvironment(url);
  const args: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    args.push("--env", `${key}=${value}`);
  }

  args.push(layout.macAppPath);
  const result = spawnSync("/usr/bin/open", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Failed to open s-gw macOS app.");
  }

  return { appPath: layout.macAppPath, consoleUrl: url, reusedExisting: false };
}

export function installMacAppBundle(options: MacAppInstallOptions = {}): MacAppInstallResult {
  requireMac("mac app install");
  const layout = getPackageLayout();
  assertMacRuntimeForManagedSurfaces(layout);
  const sourcePath = layout.packagedMacAppPath;
  const sourceBinary = layout.packagedMacAppBinaryPath;
  if (!existsSync(sourcePath) || !existsSync(sourceBinary)) {
    throw new Error(`Packaged macOS app is missing. Expected app bundle at ${sourcePath}`);
  }
  assertMacExecutableCompatible(sourceBinary, "macOS app");

  if (layout.isSelfContainedMacApp) {
    return { appPath: sourcePath, sourcePath, changed: false };
  }

  const applicationsDir = path.resolve(options.applicationsDir || macApplicationsDirectory());
  const appPath = path.join(applicationsDir, "s-gw.app");
  const registerCliPath = options.registerCliPath !== false
    && process.env.SGW_SKIP_MAC_APP_CLI_REGISTRATION !== "1";
  if (isSelfContainedMacApp(appPath)) {
    return { appPath, sourcePath, changed: false };
  }

  if (path.resolve(sourcePath) === path.resolve(appPath)) {
    if (registerCliPath) registerMacAppCliPath(layout.cliPath);
    return { appPath, sourcePath, changed: false };
  }

  mkdirSync(applicationsDir, { recursive: true });
  if (sameMacAppBundle(sourcePath, appPath)) {
    if (registerCliPath) registerMacAppCliPath(layout.cliPath);
    return { appPath, sourcePath, changed: false };
  }

  const suffix = `${process.pid}-${Date.now()}`;
  const stagingPath = path.join(applicationsDir, `.s-gw.app.install-${suffix}`);
  const backupPath = path.join(applicationsDir, `.s-gw.app.backup-${suffix}`);
  rmSync(stagingPath, { recursive: true, force: true });
  rmSync(backupPath, { recursive: true, force: true });

  const copied = spawnSync("/usr/bin/ditto", [sourcePath, stagingPath], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (copied.status !== 0) {
    rmSync(stagingPath, { recursive: true, force: true });
    throw new Error(copied.stderr.trim() || `Could not copy s-gw to ${applicationsDir}.`);
  }
  assertMacExecutableCompatible(macAppBinaryPath(stagingPath), "installed macOS app");

  let movedExisting = false;
  try {
    if (existsSync(appPath)) {
      renameSync(appPath, backupPath);
      movedExisting = true;
    }
    renameSync(stagingPath, appPath);
    rmSync(backupPath, { recursive: true, force: true });
  } catch (error) {
    rmSync(stagingPath, { recursive: true, force: true });
    if (movedExisting && !existsSync(appPath) && existsSync(backupPath)) {
      renameSync(backupPath, appPath);
    }
    throw new Error(`Could not install s-gw in ${applicationsDir}: ${error instanceof Error ? error.message : String(error)}`);
  }

  if (registerCliPath) registerMacAppCliPath(layout.cliPath);
  return { appPath, sourcePath, changed: true };
}

export async function openWindowsClient(options: MenuBarOptions = {}): Promise<WindowsOpenResult> {
  requireWindows("Windows client open");
  assertWindowsClientExists();
  const layout = getPackageLayout();
  const { port, url } = windowsConsoleEndpoint(options);
  const instanceKey = getSgwInstanceKey();
  await ensureWindowsConsole({ ...options, port, consoleUrl: url });
  const powershell = trustedWindowsPowerShellSync();
  const result = spawnSync(
    powershell,
    [
      "-NoProfile",
      "-Sta",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      layout.windowsClientScriptPath,
      "-Port",
      String(port),
      "-ConsoleUrl",
      url,
      "-InstanceKey",
      instanceKey,
      "-NoStart"
    ],
    {
      cwd: path.dirname(powershell),
      encoding: "utf8",
      env: windowsEnvironment(url),
      stdio: ["ignore", "pipe", "pipe"]
    }
  );

  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || "Failed to open s-gw Windows client.");
  }

  return {
    scriptPath: layout.windowsClientScriptPath,
    launcherPath: layout.windowsClientLauncherPath,
    consoleUrl: url
  };
}

export async function openWindowsHelper(options: MenuBarOptions = {}): Promise<WindowsOpenResult> {
  requireWindows("Windows helper open");
  assertWindowsHelperExists();
  const layout = getPackageLayout();
  const endpoint = windowsConsoleEndpoint(options);
  const port = endpoint.port;
  const url = endpoint.baseUrl;
  const consoleState = await ensureWindowsConsoleState({ ...options, port, consoleUrl: url });
  const instanceKey = windowsHelperInstanceKey(url);
  const existingPid = consoleState.helperPids[0];
  if (existingPid) {
    return {
      scriptPath: layout.windowsHelperScriptPath,
      launcherPath: layout.windowsHelperLauncherPath,
      consoleUrl: url,
      pid: existingPid,
      reusedExisting: true
    };
  }

  assertWindowsBackgroundUnlock();
  const launched = launchWindowsHelper(
    layout.windowsHelperBootstrapPath,
    layout.windowsHelperScriptPath,
    port,
    url,
    instanceKey
  );
  let pid: number;
  try {
    pid = waitForWindowsHelper(layout.windowsHelperScriptPath, port, url, instanceKey);
  } catch (error) {
    try {
      stopLaunchedWindowsHelper(launched, layout.windowsHelperScriptPath, port, url, instanceKey);
    } catch (cleanupError) {
      throw new Error(`${error instanceof Error ? error.message : String(error)}; ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`);
    }
    throw error;
  }

  return {
    scriptPath: layout.windowsHelperScriptPath,
    launcherPath: layout.windowsHelperLauncherPath,
    consoleUrl: url,
    pid,
    reusedExisting: pid !== launched.pid
  };
}

function launchWindowsHelper(
  bootstrapPath: string,
  scriptPath: string,
  port: number,
  url: string,
  instanceKey: string
): WindowsHelperLaunch {
  const launchNonce = randomBytes(32).toString("hex");
  const powershell = trustedWindowsPowerShellSync();
  const result = spawnSync(
    powershell,
    [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      bootstrapPath,
      "-HelperPath",
      scriptPath,
      "-Port",
      String(port),
      "-ConsoleUrl",
      url,
      "-InstanceKey",
      instanceKey,
      "-LaunchNonce",
      launchNonce
    ],
    {
      cwd: path.dirname(powershell),
      encoding: "utf8",
      env: windowsEnvironment(url),
      maxBuffer: 64 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: windowsHelperOperationTimeoutMs(defaultWindowsHelperLaunchTimeoutMs),
      windowsHide: true
    }
  );
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";
  let failure: Error | undefined;
  let payload: Record<string, unknown> | undefined;
  if (result.error) {
    failure = new Error(`Could not launch the s-gw Windows helper: ${result.error.message}`);
  } else if (result.status !== 0) {
    failure = new Error(stderr.trim() || stdout.trim() || "Could not launch the s-gw Windows helper.");
  } else {
    try {
      payload = JSON.parse(stdout) as Record<string, unknown>;
    } catch {
      failure = new Error("Could not parse the s-gw Windows helper launch result.");
    }
  }

  const pid = Number(payload?.pid);
  const startedAtUtcTicks = typeof payload?.startedAtUtcTicks === "string" ? payload.startedAtUtcTicks : "";
  const returnedNonce = typeof payload?.launchNonce === "string" ? payload.launchNonce : "";
  if (!failure && (
    !Number.isInteger(pid)
    || pid <= 0
    || !/^\d{17,19}$/.test(startedAtUtcTicks)
    || returnedNonce !== launchNonce
  )) {
    failure = new Error("The s-gw Windows helper launch result was invalid.");
  }
  if (failure) {
    try {
      stopLaunchedWindowsHelper({ launchNonce }, scriptPath, port, url, instanceKey);
    } catch (cleanupError) {
      throw new Error(`${failure.message}; ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`);
    }
    throw failure;
  }
  return { pid, startedAtUtcTicks, launchNonce };
}

function stopLaunchedWindowsHelper(
  launched: WindowsHelperCleanupTarget,
  scriptPath: string,
  port: number,
  url: string,
  instanceKey: string
): void {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$currentSessionId = [int](Get-Process -Id $PID).SessionId",
    "$expectedPid = if ($env:SGW_HELPER_LAUNCHED_PID) { [int]$env:SGW_HELPER_LAUNCHED_PID } else { 0 }",
    "$expectedTicks = [string]$env:SGW_HELPER_LAUNCHED_TICKS",
    "$portPattern = '(?i)(?:^|\\s)-Port(?:\\s+|:)\"?' + [regex]::Escape($env:SGW_HELPER_PORT) + '\"?(?:\\s|$)'",
    "$exactPathPattern = '(?i)(?:^|\\s)-File(?:\\s+|:)\"?' + [regex]::Escape($env:SGW_HELPER_SCRIPT_PATH) + '\"?(?:\\s|$)'",
    "$instancePattern = '(?i)(?:^|\\s)-InstanceKey(?:\\s+|:)\"?([a-f0-9]{64})\"?(?:\\s|$)'",
    "$noncePattern = '(?i)(?:^|\\s)-LaunchNonce(?:\\s+|:)\"?([a-f0-9]{64})\"?(?:\\s|$)'",
    "$powerShellName = [IO.Path]::GetFileName($env:SGW_HELPER_POWERSHELL_PATH).Replace(\"'\", \"''\")",
    "$processFilter = \"Name = '$powerShellName'\"",
    "$candidates = @()",
    "for ($attempt = 0; $attempt -lt 5; $attempt += 1) {",
    "  $candidates = @()",
    "  Get-CimInstance Win32_Process -Filter $processFilter | ForEach-Object {",
    "    $line = [string]$_.CommandLine",
    "    $instanceMatch = [regex]::Match($line, $instancePattern)",
    "    $nonceMatch = [regex]::Match($line, $noncePattern)",
    "    if ($line -notmatch $portPattern -or $line -notmatch $exactPathPattern -or -not $instanceMatch.Success -or -not $nonceMatch.Success) { return }",
    "    if ([string]$instanceMatch.Groups[1].Value -ine $env:SGW_HELPER_INSTANCE_KEY -or [string]$nonceMatch.Groups[1].Value -ine $env:SGW_HELPER_LAUNCH_NONCE) { return }",
    "    if ($expectedPid -gt 0 -and [int]$_.ProcessId -ne $expectedPid) { return }",
    "    if ([int]$_.SessionId -ne $currentSessionId) { return }",
    "    $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction SilentlyContinue",
    "    if ($null -eq $owner -or $owner.ReturnValue -ne 0 -or [string]$owner.Sid -ne $currentSid) { return }",
    "    $process = Get-Process -Id ([int]$_.ProcessId) -ErrorAction SilentlyContinue",
    "    if ($null -eq $process) { return }",
    "    $startTicks = [string]$process.StartTime.ToUniversalTime().Ticks",
    "    if ($expectedTicks -and $startTicks -ne $expectedTicks) { throw 'The launched s-gw helper PID was reused.' }",
    "    $candidates += [PSCustomObject]@{ pid = [int]$_.ProcessId; creationDate = [string]$_.CreationDate; commandLine = $line; startTicks = $startTicks }",
    "  }",
    "  if ((@($candidates) | Measure-Object).Count -gt 0) { break }",
    "  Start-Sleep -Milliseconds 100",
    "}",
    "$candidateCount = (@($candidates) | Measure-Object).Count",
    "if ($candidateCount -eq 0) { exit 0 }",
    "if ($candidateCount -ne 1) { throw 'More than one s-gw helper matched the launch nonce.' }",
    "$record = @($candidates)[0]",
    "$targetPid = [int]$record.pid",
    "$fresh = Get-CimInstance Win32_Process -Filter \"ProcessId = $targetPid\" -ErrorAction SilentlyContinue",
    "if ($null -eq $fresh) { exit 0 }",
    "$freshProcess = Get-Process -Id $targetPid -ErrorAction SilentlyContinue",
    "$freshOwner = Invoke-CimMethod -InputObject $fresh -MethodName GetOwnerSid -ErrorAction SilentlyContinue",
    "if ($null -eq $freshProcess -or [string]$freshProcess.StartTime.ToUniversalTime().Ticks -ne [string]$record.startTicks -or [string]$fresh.CreationDate -ne [string]$record.creationDate -or [string]$fresh.CommandLine -ne [string]$record.commandLine -or [int]$fresh.SessionId -ne $currentSessionId -or $null -eq $freshOwner -or $freshOwner.ReturnValue -ne 0 -or [string]$freshOwner.Sid -ne $currentSid) { throw 'The launched s-gw helper changed before cleanup.' }",
    "$termination = Invoke-CimMethod -InputObject $fresh -MethodName Terminate -ErrorAction Stop",
    "if ($termination.ReturnValue -ne 0) { throw \"The launched s-gw helper returned termination code $($termination.ReturnValue).\" }",
    "for ($attempt = 0; $attempt -lt 50; $attempt += 1) {",
    "  if ($null -eq (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) { exit 0 }",
    "  Start-Sleep -Milliseconds 50",
    "}",
    "throw 'The launched s-gw helper did not stop.'"
  ].join("\n");
  const powershell = trustedWindowsPowerShellSync();
  const result = spawnSync(powershell, ["-NoProfile", "-Command", script], {
    cwd: path.dirname(powershell),
    encoding: "utf8",
    env: windowsEnvironment(url, {
      SGW_HELPER_INSTANCE_KEY: instanceKey,
      SGW_HELPER_LAUNCH_NONCE: launched.launchNonce,
      SGW_HELPER_LAUNCHED_PID: launched.pid ? String(launched.pid) : "",
      SGW_HELPER_LAUNCHED_TICKS: launched.startedAtUtcTicks || "",
      SGW_HELPER_PORT: String(port),
      SGW_HELPER_POWERSHELL_PATH: powershell,
      SGW_HELPER_SCRIPT_PATH: scriptPath
    }),
    stdio: ["ignore", "pipe", "pipe"],
    timeout: windowsHelperOperationTimeoutMs(defaultWindowsHelperCleanupTimeoutMs),
    windowsHide: true
  });
  if (result.error) {
    throw new Error(`Could not clean up the launched s-gw Windows helper: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error((result.stderr || "").trim() || "Could not clean up the launched s-gw Windows helper.");
  }
}

async function stopSpawnedWindowsProcess(child: ChildProcess, label: string): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;

  let onExit: (() => void) | undefined;
  const exited = new Promise<boolean>((resolve) => {
    onExit = () => resolve(true);
    child.once("exit", onExit);
    setTimeout(() => resolve(false), 2500).unref();
  });
  try {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill();
    if (!await exited && child.exitCode === null && child.signalCode === null) {
      throw new Error(`spawned s-gw Windows ${label} did not exit`);
    }
  } finally {
    if (onExit) child.removeListener("exit", onExit);
  }
}

function findRunningWindowsHelpers(scriptPath: string, port: number, url: string, instanceKey: string): number[] {
  return inspectRunningWindowsHelpers(scriptPath, port, url, instanceKey, false);
}

function inspectRunningWindowsHelpers(
  scriptPath: string,
  port: number,
  url: string,
  instanceKey: string,
  settle: boolean
): number[] {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$currentSessionId = [int](Get-Process -Id $PID).SessionId",
    "$portPattern = '(?i)(?:^|\\s)-Port(?:\\s+|:)\"?' + [regex]::Escape($env:SGW_HELPER_PORT) + '\"?(?:\\s|$)'",
    "$anyPortPattern = '(?i)(?:^|\\s)-Port(?:\\s+|:)'",
    "$helperPattern = '(?i)(?:^|\\s)-File(?:\\s+|:)(?:\"[^\"]*[\\\\/]|[^\\s\"]*[\\\\/])?s-gw-helper\\.ps1\"?(?:\\s|$)'",
    "$exactPathPattern = '(?i)(?:^|\\s)-File(?:\\s+|:)\"?' + [regex]::Escape($env:SGW_HELPER_SCRIPT_PATH) + '\"?(?:\\s|$)'",
    "$instancePattern = '(?i)(?:^|\\s)-InstanceKey(?:\\s+|:)\"?([a-f0-9]{64})\"?(?:\\s|$)'",
    "$powerShellName = [IO.Path]::GetFileName($env:SGW_HELPER_POWERSHELL_PATH).Replace(\"'\", \"''\")",
    "$processFilter = \"Name = '$powerShellName'\"",
    "$settle = $env:SGW_HELPER_SETTLE -eq '1'",
    "$clock = [Diagnostics.Stopwatch]::StartNew()",
    "$previousPid = 0",
    "$stable = $false",
    "$helperProcesses = @()",
    "do {",
    "  $helperProcesses = @()",
    "  Get-CimInstance Win32_Process -Filter $processFilter | ForEach-Object {",
    "    $line = [string]$_.CommandLine",
    "    if (-not $line -or $line -notmatch $helperPattern) { return }",
    "    $processInstanceKey = if ($line -match $instancePattern) { [string]$Matches[1] } else { '' }",
    "    $usesDefaultPort = $env:SGW_HELPER_PORT -eq '8718' -and $line -notmatch $anyPortPattern",
    "    if ($line -notmatch $portPattern -and -not $usesDefaultPort) { return }",
    "    $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction SilentlyContinue",
    "    if ($null -eq $owner -or $owner.ReturnValue -ne 0) { return }",
    "    $helperProcesses += [PSCustomObject]@{ pid = [int]$_.ProcessId; ownerSid = [string]$owner.Sid; sessionId = [int]$_.SessionId; instanceKey = $processInstanceKey; exactPath = [bool]($line -match $exactPathPattern) }",
    "  }",
    "  if (-not $settle) { break }",
    "  $sessionProcesses = @($helperProcesses | Where-Object { [string]$_.ownerSid -ieq $currentSid -and [int]$_.sessionId -eq $currentSessionId })",
    "  $matching = @($sessionProcesses | Where-Object { $_.exactPath -eq $true -and [string]$_.instanceKey -ieq $env:SGW_HELPER_INSTANCE_KEY })",
    "  if ($sessionProcesses.Count -ne $matching.Count) { break }",
    "  if ($sessionProcesses.Count -eq 1 -and $matching.Count -eq 1) {",
    "    $matchingPid = [int]$matching[0].pid",
    "    if ($matchingPid -eq $previousPid) { $stable = $true; break }",
    "    $previousPid = $matchingPid",
    "  } else {",
    "    $previousPid = 0",
    "  }",
    "  if ($clock.ElapsedMilliseconds -ge 10000) { break }",
    "  Start-Sleep -Milliseconds 100",
    "} while ($true)",
    "[PSCustomObject]@{ currentSid = $currentSid; currentSessionId = $currentSessionId; processes = $helperProcesses; stable = $stable } | ConvertTo-Json -Depth 3 -Compress"
  ].join("\n");
  const powershell = trustedWindowsPowerShellSync();
  const result = spawnSync(powershell, ["-NoProfile", "-Command", script], {
    cwd: path.dirname(powershell),
    encoding: "utf8",
    env: windowsEnvironment(url, {
      SGW_HELPER_INSTANCE_KEY: instanceKey,
      SGW_HELPER_PORT: String(port),
      SGW_HELPER_POWERSHELL_PATH: powershell,
      SGW_HELPER_SCRIPT_PATH: scriptPath,
      SGW_HELPER_SETTLE: settle ? "1" : "0"
    }),
    stdio: ["ignore", "pipe", "pipe"],
    timeout: windowsProcessInspectionTimeoutMs(),
    windowsHide: true
  });
  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      throw new Error("Timed out inspecting the running s-gw Windows helper.");
    }
    throw new Error(`Could not inspect the running s-gw Windows helper: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error((result.stderr || "").trim() || "Could not inspect the running s-gw Windows helper.");
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(result.stdout) as Record<string, unknown>;
  } catch {
    throw new Error("Could not parse the running s-gw Windows helper process list.");
  }
  const currentSid = typeof payload.currentSid === "string" ? payload.currentSid : "";
  const currentSessionId = Number(payload.currentSessionId);
  const rawProcesses = Array.isArray(payload.processes)
    ? payload.processes
    : payload.processes ? [payload.processes] : [];
  const processes = rawProcesses.flatMap((item) => windowsHelperProcess(item));
  const sessionProcesses = selectWindowsHelperProcesses(processes, currentSid, currentSessionId);
  const conflicts = sessionProcesses.filter((item) => !item.exactPath || item.instanceKey.toLowerCase() !== instanceKey);
  if (conflicts.length > 0) {
    throw new Error(`Another s-gw Windows helper is already running in this session for port ${port}. Run s-gw stop before changing installation or credential authority.`);
  }
  const pids = sessionProcesses.map((item) => item.pid).sort((a, b) => a - b);
  if (settle && payload.stable !== true) {
    throw new Error(`s-gw Windows helper did not settle to one process; found ${pids.length}.`);
  }
  return pids;
}

function waitForWindowsHelper(scriptPath: string, port: number, url: string, instanceKey: string): number {
  return inspectRunningWindowsHelpers(scriptPath, port, url, instanceKey, true)[0];
}

export function windowsProcessInspectionTimeoutMs(): number {
  if (process.env.SGW_TEST_MODE !== "1") return defaultWindowsProcessInspectionTimeoutMs;
  const configured = Number(process.env.SGW_WINDOWS_PROCESS_INSPECTION_TIMEOUT_MS);
  return Number.isInteger(configured) && configured > 0 && configured <= maxWindowsProcessInspectionTestTimeoutMs
    ? configured
    : defaultWindowsProcessInspectionTimeoutMs;
}

export function windowsHelperOperationTimeoutMs(defaultTimeoutMs = defaultWindowsHelperLaunchTimeoutMs): number {
  if (process.env.SGW_TEST_MODE !== "1") return defaultTimeoutMs;
  const configured = Number(process.env.SGW_WINDOWS_HELPER_OPERATION_TIMEOUT_MS);
  return Number.isInteger(configured) && configured > 0 && configured <= maxWindowsHelperOperationTestTimeoutMs
    ? configured
    : defaultTimeoutMs;
}

function windowsHelperInstanceKey(url: string): string {
  const normalizedUrl = new URL("/", url).toString();
  return createHash("sha256")
    .update(`${getSgwInstanceKey()}\n${normalizedUrl}`)
    .digest("hex");
}

function windowsConsoleEndpoint(options: MenuBarOptions): { port: number; url: string; baseUrl: string } {
  const port = options.port || 8718;
  const rawUrl = options.consoleUrl || consoleUrl(port);
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid Windows console URL: ${rawUrl}`);
  }
  if (parsed.protocol !== "http:") {
    throw new Error("The Windows console URL must use http on the local machine.");
  }
  if (!["127.0.0.1", "localhost"].includes(parsed.hostname.toLowerCase()) || parsed.username || parsed.password) {
    throw new Error("The Windows console URL must use 127.0.0.1 or localhost without credentials.");
  }
  const urlPort = Number(parsed.port || 80);
  if (urlPort !== port) {
    throw new Error(`The Windows console URL port ${urlPort} must match --port ${port}.`);
  }
  return {
    port,
    url: parsed.toString(),
    baseUrl: new URL("/", parsed).toString()
  };
}

export function selectWindowsHelperPid(
  processes: WindowsHelperProcess[],
  currentSid: string,
  currentSessionId: number
): number | undefined {
  return selectWindowsHelperProcesses(processes, currentSid, currentSessionId)[0]?.pid;
}

function selectWindowsHelperProcesses(
  processes: WindowsHelperProcess[],
  currentSid: string,
  currentSessionId: number
): WindowsHelperProcess[] {
  if (!currentSid || !Number.isInteger(currentSessionId)) return [];
  const sid = currentSid.toLowerCase();
  return processes
    .filter((item) => item.ownerSid.toLowerCase() === sid && item.sessionId === currentSessionId)
    .sort((a, b) => a.pid - b.pid);
}

function windowsHelperProcess(value: unknown): WindowsHelperProcess[] {
  if (!value || typeof value !== "object") return [];
  const item = value as Record<string, unknown>;
  const pid = Number(item.pid);
  const ownerSid = typeof item.ownerSid === "string" ? item.ownerSid : "";
  const sessionId = Number(item.sessionId);
  const instanceKey = typeof item.instanceKey === "string" ? item.instanceKey : "";
  const exactPath = item.exactPath === true;
  if (!Number.isInteger(pid) || pid <= 0 || !ownerSid || !Number.isInteger(sessionId)) return [];
  return [{ pid, ownerSid, sessionId, instanceKey, exactPath }];
}

export function macAppProcessRecordPath(): string {
  return path.join(os.homedir(), "Library", "Application Support", "s-gw", "s-gw-app.process.json");
}

function existingMacAppProcess(layout: PackageLayout): MacAppProcessInfo | undefined {
  const record = readMacAppProcessRecord();
  if (record?.alive) {
    return record;
  }

  return findRunningMacAppProcess(layout);
}

function readMacAppProcessRecord(): MacAppProcessInfo | undefined {
  const recordPath = macAppProcessRecordPath();
  if (!existsSync(recordPath)) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(readFileSync(recordPath, "utf8")) as Record<string, unknown>;
    const pid = Number(parsed.pid);
    if (!Number.isInteger(pid) || pid <= 0) {
      return undefined;
    }

    return {
      pid,
      source: "record",
      alive: isPidAlive(pid),
      recordPath,
      bundleIdentifier: stringValue(parsed.bundleIdentifier),
      bundlePath: stringValue(parsed.bundlePath),
      executablePath: stringValue(parsed.executablePath),
      startedAt: stringValue(parsed.startedAt),
      updatedAt: stringValue(parsed.updatedAt)
    };
  } catch {
    return undefined;
  }
}

function findRunningMacAppProcess(layout: PackageLayout): MacAppProcessInfo | undefined {
  const result = spawnSync("/usr/bin/pgrep", ["-x", "s-gw"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) {
    return undefined;
  }

  const pids = result.stdout
    .split(/\s+/)
    .map((item) => Number(item.trim()))
    .filter((pid) => Number.isInteger(pid) && pid > 0 && isPidAlive(pid));
  if (pids.length === 0) {
    return undefined;
  }

  const candidates = pids.map((pid) => ({
    pid,
    command: commandForPid(pid)
  }));
  const selected = candidates.find((item) => commandMatchesPath(item.command, layout.macAppBinaryPath)) || candidates[0];

  return {
    pid: selected.pid,
    source: "process-list",
    alive: true,
    bundleIdentifier: "com.s-gw.sgw.app",
    bundlePath: layout.macAppPath,
    executablePath: layout.macAppBinaryPath,
    command: selected.command,
    otherPids: candidates
      .filter((item) => item.pid !== selected.pid)
      .map((item) => item.pid)
  };
}

function focusMacAppProcess(app: MacAppProcessInfo, appPath: string): void {
  if (postOpenMainWindowNotification()) {
    return;
  }

  if (app.bundleIdentifier) {
    const byBundle = spawnSync("/usr/bin/open", ["-b", app.bundleIdentifier], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
    if (byBundle.status === 0) {
      return;
    }
  }

  const byPath = spawnSync("/usr/bin/open", [appPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (byPath.status !== 0) {
    throw new Error(byPath.stderr.trim() || "Failed to focus running s-gw macOS app.");
  }
}

function postOpenMainWindowNotification(): boolean {
  const script = [
    "ObjC.import('Foundation')",
    "$.NSDistributedNotificationCenter.defaultCenter.postNotificationNameObjectUserInfoDeliverImmediately(",
    "  'com.s-gw.sgw.openMainWindow', null, null, true",
    ")"
  ].join("\n");
  const result = spawnSync("/usr/bin/osascript", ["-l", "JavaScript", "-e", script], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  return result.status === 0;
}

function commandForPid(pid: number): string | undefined {
  const result = spawnSync("/bin/ps", ["-p", String(pid), "-o", "command="], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status !== 0) {
    return undefined;
  }

  return result.stdout.trim() || undefined;
}

function commandMatchesPath(command: string | undefined, targetPath: string): boolean {
  return command === targetPath || command?.startsWith(`${targetPath} `) === true;
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function waitForPidToExit(pid: number): void {
  const flag = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; i < 40; i += 1) {
    if (!isPidAlive(pid)) return;
    Atomics.wait(flag, 0, 0, 50);
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

export function buildConsoleLaunchAgentPlist(
  port: number,
  logsDir: string,
  inheritedEnvironment: Record<string, string> = {}
): string {
  const layout = getPackageLayout();
  return buildLaunchAgentPlist({
    label: consoleLabel,
    programArguments: [
      layout.nodePath,
      layout.cliPath,
      "console",
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--no-open"
    ],
    environment: launchdBaseEnvironment(inheritedEnvironment),
    runAtLoad: true,
    keepAlive: true,
    stdoutPath: path.join(logsDir, "console.log"),
    stderrPath: path.join(logsDir, "console.err.log")
  });
}

export function buildMenuBarLaunchAgentPlist(
  options: MenuBarOptions,
  logsDir: string,
  inheritedEnvironment: Record<string, string> = {}
): string {
  const layout = getPackageLayout();
  const args = [layout.menuBarBinaryPath];
  if (options.notify !== false) {
    args.push("--notify-on-launch");
  } else {
    args.push("--no-notify");
  }

  return buildLaunchAgentPlist({
    label: menuBarLabel,
    programArguments: args,
    environment: menuBarEnvironment(options.consoleUrl || consoleUrl(options.port || 8718), options.countMode, inheritedEnvironment),
    runAtLoad: true,
    keepAlive: true,
    stdoutPath: path.join(logsDir, "menubar.log"),
    stderrPath: path.join(logsDir, "menubar.err.log"),
    limitToAqua: true
  });
}

function buildLaunchAgentPlist(definition: LaunchAgentDefinition): string {
  const envPairs = Object.entries(definition.environment)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `    <key>${xmlEscape(key)}</key>\n    <string>${xmlEscape(value)}</string>`)
    .join("\n");
  const programArgs = definition.programArguments
    .map((item) => `    <string>${xmlEscape(item)}</string>`)
    .join("\n");
  const aqua = definition.limitToAqua
    ? "  <key>LimitLoadToSessionType</key>\n  <string>Aqua</string>\n"
    : "";

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${xmlEscape(definition.label)}</string>
  <key>ProgramArguments</key>
  <array>
${programArgs}
  </array>
  <key>EnvironmentVariables</key>
  <dict>
${envPairs}
  </dict>
  <key>RunAtLoad</key>
  <${definition.runAtLoad ? "true" : "false"}/>
  <key>KeepAlive</key>
  <${definition.keepAlive ? "true" : "false"}/>
${aqua}  <key>StandardOutPath</key>
  <string>${xmlEscape(definition.stdoutPath)}</string>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(definition.stderrPath)}</string>
</dict>
</plist>
`;
}

function startLaunchAgent(label: string, plistPath: string): void {
  stopLaunchAgent(label);
  runLaunchctl(["bootstrap", launchdDomain(), plistPath]);
}

function stopLaunchAgent(label: string): void {
  const plistPath = launchAgentPath(label);
  if (existsSync(plistPath)) {
    spawnSync("/bin/launchctl", ["bootout", launchdDomain(), plistPath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
  }

  spawnSync("/bin/launchctl", ["bootout", `${launchdDomain()}/${label}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  waitForLaunchAgentToUnload(label);
}

function runLaunchctl(args: string[]): void {
  const result = spawnSync("/bin/launchctl", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `launchctl ${args.join(" ")} failed.`);
  }
}

function isLaunchAgentLoaded(label: string): boolean {
  const result = spawnSync("/bin/launchctl", ["print", `${launchdDomain()}/${label}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  return result.status === 0;
}

function waitForLaunchAgentToUnload(label: string): void {
  const flag = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; i < 20; i += 1) {
    if (!isLaunchAgentLoaded(label)) {
      return;
    }
    Atomics.wait(flag, 0, 0, 50);
  }
}

function launchdDomain(): string {
  return `gui/${process.getuid?.() ?? os.userInfo().uid}`;
}

function launchAgentPath(label: string): string {
  return path.join(os.homedir(), "Library", "LaunchAgents", `${label}.plist`);
}

export function systemdUserServicePath(): string {
  return path.join(systemdUserConfigRoot(), "systemd", "user", systemdUnitName);
}

function systemdUserConfigRoot(): string {
  const configHome = process.env.XDG_CONFIG_HOME?.trim();
  return configHome ? path.resolve(configHome) : path.join(os.homedir(), ".config");
}

function safeSystemdUserServiceStatus(): SystemdUserServiceStatus {
  try {
    return systemdUserServiceStatus();
  } catch (error) {
    return {
      ...emptySystemdUserServiceStatus(systemdUserServicePath()),
      installed: existsSync(systemdUserServicePath()),
      state: "unavailable",
      subState: "unknown",
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function emptySystemdUserServiceStatus(unitPath: string): SystemdUserServiceStatus {
  return {
    unit: systemdUnitName,
    unitPath,
    installed: false,
    loaded: false,
    enabled: false,
    active: false,
    state: "inactive",
    subState: "dead"
  };
}

function assertLinuxServiceUnlock(): void {
  const source = unlockStatus().activeSource;
  if (source === "linux-secret-service") return;
  if (source === "env") {
    throw new Error(
      "The Linux systemd service will not persist SGW_MASTER_PASSPHRASE. " +
      "Unset it and run `s-gw setup` with an unlocked Secret Service, or run `s-gw console` in this foreground session."
    );
  }
  throw new Error(
    "The Linux systemd service needs an unlocked Secret Service. " +
    "Install libsecret-tools and run `s-gw setup`, or use SGW_MASTER_PASSPHRASE with `s-gw console` for a foreground session."
  );
}

function assertSafeSystemdUnitTarget(unitPath: string): void {
  if (!existsSync(unitPath)) return;
  const info = lstatSync(unitPath);
  const uid = typeof process.getuid === "function" ? process.getuid() : info.uid;
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== uid || (info.mode & 0o022) !== 0) {
    throw new Error(`Refusing to replace an unsafe systemd user unit: ${unitPath}`);
  }
}

function assertSafeSystemdUnitDirectory(unitPath: string): void {
  const root = systemdUserConfigRoot();
  const directories = [root, path.join(root, "systemd"), path.dirname(unitPath)];
  const uid = typeof process.getuid === "function" ? process.getuid() : os.userInfo().uid;
  for (const directory of directories) {
    const info = lstatSync(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== uid || (info.mode & 0o022) !== 0) {
      throw new Error(`Refusing to install a systemd user unit through an unsafe directory: ${directory}`);
    }
  }
}

function systemdExecQuote(value: string): string {
  return quoteSystemdValue(value, true);
}

function systemdDirectiveQuote(value: string): string {
  return quoteSystemdValue(value, false);
}

function quoteSystemdValue(value: string, escapeDollar: boolean): string {
  if (/[\0\r\n]/.test(value)) {
    throw new Error("systemd service paths and environment values cannot contain line breaks.");
  }
  let escaped = value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("%", "%%");
  if (escapeDollar) escaped = escaped.replaceAll("$", () => "$$");
  return `"${escaped}"`;
}

function runSystemctl(args: string[], allowFailure = false): string {
  const command = systemctlPath();
  const result = spawnSync(command, ["--user", ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) {
    const detail = result.stderr.trim() || result.stdout.trim();
    throw new Error(
      detail || `systemctl --user ${args.join(" ")} failed. Confirm that this user has an active systemd session.`
    );
  }
  return result.stdout;
}

function systemctlPath(): string {
  if (process.env.SGW_TEST_MODE === "1" && process.env.SGW_SYSTEMCTL) {
    return path.resolve(process.env.SGW_SYSTEMCTL);
  }
  if (existsSync("/usr/bin/systemctl")) return "/usr/bin/systemctl";
  if (existsSync("/bin/systemctl")) return "/bin/systemctl";
  throw new Error("systemctl is unavailable; s-gw needs a systemd user session for its Linux background service.");
}

async function ensureLogDir(sgwHome?: string): Promise<string> {
  const logs = path.join(path.resolve(sgwHome || getSgwHome()), "logs");
  await mkdir(logs, { recursive: true, mode: 0o700 });
  await mkdir(path.dirname(launchAgentPath(consoleLabel)), { recursive: true });
  return logs;
}

function launchdBaseEnvironment(inherited: Record<string, string> = {}): Record<string, string> {
  const layout = getPackageLayout();
  const inheritedHome = boundedAuthorityValue("SGW_HOME", inherited.SGW_HOME);
  const sgwHome = absoluteAuthorityPath("SGW_HOME", inheritedHome || getSgwHome());
  const inheritedRecovery = boundedAuthorityValue("SGW_RECOVERY_HOME", inherited.SGW_RECOVERY_HOME);
  const recoveryHome = absoluteAuthorityPath(
    "SGW_RECOVERY_HOME",
    inheritedRecovery || getSgwRecoveryHome(sgwHome)
  );
  if (authorityPathsOverlap(sgwHome, recoveryHome)) {
    throw new Error("SGW_HOME and SGW_RECOVERY_HOME must not overlap in a managed service.");
  }
  const env: Record<string, string> = {
    PATH: inherited.PATH || process.env.PATH || "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
    SGW_HOME: sgwHome,
    SGW_KEYCHAIN_ACCOUNT: boundedAuthorityValue(
      "SGW_KEYCHAIN_ACCOUNT",
      inherited.SGW_KEYCHAIN_ACCOUNT || process.env.SGW_KEYCHAIN_ACCOUNT
    ) || os.userInfo().username || "local-user",
    SGW_KEYCHAIN_SERVICE: boundedAuthorityValue(
      "SGW_KEYCHAIN_SERVICE",
      inherited.SGW_KEYCHAIN_SERVICE || process.env.SGW_KEYCHAIN_SERVICE
    ) || MASTER_KEYCHAIN_SERVICE,
    SGW_NODE_PATH: layout.nodePath,
    SGW_RECOVERY_HOME: recoveryHome,
    SGW_SECRET_KEYCHAIN_SERVICE: boundedAuthorityValue(
      "SGW_SECRET_KEYCHAIN_SERVICE",
      inherited.SGW_SECRET_KEYCHAIN_SERVICE || process.env.SGW_SECRET_KEYCHAIN_SERVICE
    ) || SECRET_KEYCHAIN_SERVICE
  };
  copyNormalizedAuthorityEnum(
    env,
    "SGW_SECRET_BACKEND",
    inherited.SGW_SECRET_BACKEND || process.env.SGW_SECRET_BACKEND,
    ["local", "keychain"]
  );
  copyNormalizedAuthorityEnum(
    env,
    "SGW_EXECUTION_ENGINE",
    inherited.SGW_EXECUTION_ENGINE || process.env.SGW_EXECUTION_ENGINE,
    ["auto", "rust", "typescript"]
  );
  return env;
}

export function normalizeMenuBarCountMode(value?: string): MenuBarCountMode | undefined {
  if (!value) {
    return undefined;
  }

  switch (value.trim().toLowerCase()) {
    case "pending":
    case "approval":
    case "approvals":
    case "authorization":
    case "authorizations":
    case "auth":
      return "pending";
    case "credential":
    case "credentials":
    case "secret":
    case "secrets":
    case "handle":
    case "handles":
      return "credentials";
    case "none":
    case "off":
    case "hide":
    case "hidden":
      return "none";
    default:
      throw new Error("--count must be pending, credentials, or none.");
  }
}

function menuBarEnvironment(
  url: string,
  countMode?: MenuBarCountMode,
  inheritedEnvironment: Record<string, string> = {}
): Record<string, string> {
  const layout = getPackageLayout();
  const env: Record<string, string> = {
    ...launchdBaseEnvironment(inheritedEnvironment),
    SGW_REPO_ROOT: layout.packageRoot,
    SGW_CLI_PATH: layout.cliPath,
    SGW_CONSOLE_URL: url,
    SGW_APP_PATH: layout.macAppPath
  };

  if (countMode) {
    env.SGW_MENU_BAR_COUNT_MODE = countMode;
  }

  return env;
}

export function windowsBackgroundEnvironment(
  url: string,
  extra: NodeJS.ProcessEnv = {}
): NodeJS.ProcessEnv {
  const layout = getPackageLayout();
  const authority: NodeJS.ProcessEnv = {
    SGW_DISABLE_UPDATE_CHECK: "1",
    SGW_EXECUTION_ENGINE: process.env.SGW_EXECUTION_ENGINE || "",
    SGW_HOME: getSgwHome(),
    SGW_RECOVERY_HOME: getSgwRecoveryHome(),
    SGW_KEYCHAIN_SERVICE: process.env.SGW_KEYCHAIN_SERVICE || "com.s-gw.sgw.master-passphrase",
    SGW_KEYCHAIN_ACCOUNT: process.env.SGW_KEYCHAIN_ACCOUNT || os.userInfo().username || "local-user",
    SGW_SECRET_KEYCHAIN_SERVICE: process.env.SGW_SECRET_KEYCHAIN_SERVICE || "com.s-gw.sgw.secret",
    SGW_SECRET_BACKEND: process.env.SGW_SECRET_BACKEND || "",
    SGW_NODE_PATH: process.execPath,
    SGW_CLI_PATH: layout.cliPath,
    SGW_CONSOLE_URL: url,
    SGW_APP_PATH: layout.windowsClientLauncherPath
  };
  for (const [key, value] of Object.entries(extra)) {
    if (Object.prototype.hasOwnProperty.call(authority, key)) {
      throw new Error(`Windows background environment cannot override ${key}.`);
    }
    authority[key] = value;
  }
  return windowsSystemEnvironment(authority);
}

function windowsEnvironment(url: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return windowsBackgroundEnvironment(url, {
    ...windowsCredentialTestEnvironment(),
    ...extra
  });
}

function windowsCredentialTestEnvironment(): NodeJS.ProcessEnv {
  const helper = process.env.SGW_WINDOWS_CREDENTIAL_HELPER?.trim();
  if (process.env.SGW_TEST_MODE !== "1" || !helper) return {};
  const testRoot = process.env.SGW_TEST_HOME_ROOT?.trim();
  if (!testRoot) {
    throw new Error("SGW_TEST_HOME_ROOT is required for the isolated Windows credential fixture.");
  }
  return {
    SGW_TEST_MODE: "1",
    SGW_TEST_HOME_ROOT: path.resolve(testRoot),
    SGW_WINDOWS_CREDENTIAL_HELPER: path.resolve(helper)
  };
}

export function assertMacBackgroundUnlock(): void {
  const unlock = unlockStatus();
  if (unlock.envConfigured) {
    throw new Error(
      "macOS background startup will not persist or inherit SGW_MASTER_PASSPHRASE. " +
      "Unset it and run `s-gw setup` with macOS Keychain, or run `s-gw console` in this foreground session."
    );
  }
  if (unlock.activeSource !== "macos-keychain") {
    throw new Error(
      "macOS background startup requires configured Keychain unlock material. " +
      "Run `s-gw setup`, or use `s-gw console` in the foreground."
    );
  }
}

function assertWindowsBackgroundUnlock(): void {
  const unlock = unlockStatus();
  if (unlock.envConfigured) {
    throw new Error(
      "Windows background startup will not persist or inherit SGW_MASTER_PASSPHRASE. " +
      "Unset it and run `s-gw setup` with Windows Credential Manager, or run `s-gw console` in this foreground session."
    );
  }
  if (!unlock.keychain.configured) {
    throw new Error(
      "Windows background startup requires configured Windows Credential Manager unlock material. " +
      "SGW_MASTER_PASSPHRASE is never inherited by background children; run `s-gw setup`, or use `s-gw console` in the foreground."
    );
  }
}

function boundedAuthorityValue(name: string, value: string | undefined): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (value.length > 4_096 || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new Error(`Invalid ${name} value for a managed service.`);
  }
  return value;
}

function absoluteAuthorityPath(name: string, value: string): string {
  if (!path.isAbsolute(value)) {
    throw new Error(`${name} must be an absolute path for a managed service.`);
  }
  return path.resolve(value);
}

function authorityPathsOverlap(left: string, right: string): boolean {
  const relative = path.relative(path.resolve(left), path.resolve(right));
  if (!relative) return true;
  if (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)) return true;
  const reverse = path.relative(path.resolve(right), path.resolve(left));
  return reverse !== ".." && !reverse.startsWith(`..${path.sep}`) && !path.isAbsolute(reverse);
}

function copyNormalizedAuthorityEnum(
  target: Record<string, string>,
  name: string,
  value: string | undefined,
  allowed: readonly string[]
): void {
  const checked = boundedAuthorityValue(name, value);
  if (!checked) return;
  const normalized = checked.trim().toLowerCase();
  if (!normalized || !allowed.includes(normalized)) {
    throw new Error(`Unsupported ${name} value: ${checked}`);
  }
  target[name] = normalized;
}

function consoleUrl(port: number): string {
  return `http://127.0.0.1:${port}/`;
}

function pathStatus(filePath: string) {
  return {
    path: filePath,
    exists: existsSync(filePath)
  };
}

function macApplicationsDirectory(): string {
  const override = process.env.SGW_APPLICATIONS_DIR?.trim();
  if (override) return path.resolve(override);

  if (process.platform === "darwin") {
    try {
      accessSync("/Applications", constants.W_OK);
      return "/Applications";
    } catch {
      // Standard users can still keep a normal app bundle under their home directory.
    }
  }
  return path.join(os.homedir(), "Applications");
}

function findInstalledSelfContainedMacApp(): string | undefined {
  const override = process.env.SGW_APPLICATIONS_DIR?.trim();
  if (process.env.SGW_TEST_MODE === "1" && !override) {
    // Tests must not inherit a developer's real /Applications state.
    return undefined;
  }
  if (override) {
    const candidate = path.resolve(override, "s-gw.app");
    return isSelfContainedMacApp(candidate) ? candidate : undefined;
  }

  const candidates = [
    path.join(macApplicationsDirectory(), "s-gw.app"),
    "/Applications/s-gw.app",
    path.join(os.homedir(), "Applications", "s-gw.app")
  ];

  for (const candidate of new Set(candidates.map((item) => path.resolve(item)))) {
    if (isSelfContainedMacApp(candidate)) return candidate;
  }

  return undefined;
}

export function assertMacRuntimeForManagedSurfaces(
  layout: Pick<PackageLayout, "isSelfContainedMacApp" | "standaloneMacAppInstalled" | "macAppPath"> = getPackageLayout()
): void {
  if (layout.isSelfContainedMacApp) {
    if (!isInstalledMacAppLocation(layout.macAppPath)) {
      throw new Error("Move s-gw.app to /Applications or ~/Applications before setup. Services and agent connections cannot safely run from a mounted disk image, App Translocation path, or other temporary location.");
    }
    return;
  }

  if (layout.standaloneMacAppInstalled) {
    throw new Error("A self-contained s-gw.app is already installed. Open that app to manage s-gw services, the menu bar, agents, or updates.");
  }
}

function macAppBinaryPath(appPath: string): string {
  return path.join(appPath, "Contents", "MacOS", "s-gw");
}

function sameMacAppBundle(sourcePath: string, installedPath: string): boolean {
  if (!existsSync(installedPath)) return false;
  const checkedFiles = [
    path.join("Contents", "Info.plist"),
    path.join("Contents", "MacOS", "s-gw"),
    path.join("Contents", "Resources", "AppIcon.icns"),
    path.join("Contents", "Resources", "MenuBarTemplate.png")
  ];

  try {
    for (const relativePath of checkedFiles) {
      const source = path.join(sourcePath, relativePath);
      const installed = path.join(installedPath, relativePath);
      if (!existsSync(source) || !existsSync(installed) || fileSHA256(source) !== fileSHA256(installed)) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

function fileSHA256(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function registerMacAppCliPath(cliPath: string): void {
  const result = spawnSync(
    "/usr/bin/defaults",
    ["write", "com.s-gw.sgw.app", "sgwBinaryPath", "-string", cliPath],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Could not save the s-gw CLI path for the macOS app.");
  }
}

function assertMenuBarExists(): void {
  const layout = getPackageLayout();
  if (!existsSync(layout.menuBarAppPath) || !existsSync(layout.menuBarBinaryPath)) {
    throw new Error(`Menu-bar helper is missing. Expected app bundle at ${layout.menuBarAppPath}`);
  }
  assertMacExecutableCompatible(layout.menuBarBinaryPath, "menu-bar helper");
}

function assertMacAppExists(): void {
  const layout = getPackageLayout();
  if (!existsSync(layout.macAppPath) || !existsSync(layout.macAppBinaryPath)) {
    throw new Error(`macOS app is missing. Expected app bundle at ${layout.macAppPath}`);
  }
  assertMacExecutableCompatible(layout.macAppBinaryPath, "macOS app");
}

function assertMacExecutableCompatible(binaryPath: string, label: string): void {
  if (process.platform !== "darwin") return;
  const arch = process.arch === "x64" ? "x86_64" : process.arch;
  const check = spawnSync("/usr/bin/lipo", [binaryPath, "-verify_arch", arch], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (check.status === 0) return;
  throw new Error(
    `The packaged ${label} is not compatible with darwin-${process.arch}. ` +
    "Public npm and DMG releases currently include Apple Silicon native surfaces; Intel Macs must build them from source."
  );
}

function assertWindowsClientExists(): void {
  const layout = getPackageLayout();
  if (!existsSync(layout.windowsClientScriptPath)) {
    throw new Error(`Windows client is missing. Expected script at ${layout.windowsClientScriptPath}`);
  }
}

function assertWindowsHelperExists(): void {
  const layout = getPackageLayout();
  if (!existsSync(layout.windowsHelperScriptPath)) {
    throw new Error(`Windows helper is missing. Expected script at ${layout.windowsHelperScriptPath}`);
  }
  if (!existsSync(layout.windowsHelperBootstrapPath)) {
    throw new Error(`Windows helper bootstrap is missing. Expected script at ${layout.windowsHelperBootstrapPath}`);
  }
}

function requireMac(action: string): void {
  if (process.platform !== "darwin") {
    throw new Error(`${action} is only available on macOS.`);
  }
}

function requireLinux(action: string): void {
  if (process.platform !== "linux") {
    throw new Error(`${action} is only available on Linux.`);
  }
}

function requireWindows(action: string): void {
  if (process.platform !== "win32") {
    throw new Error(`${action} is only available on Windows.`);
  }
}

function xmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function xmlUnescape(value: string): string {
  return value
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&amp;", "&");
}
