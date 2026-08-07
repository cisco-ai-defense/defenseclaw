import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  applyEdits,
  createScanner,
  findNodeAtLocation,
  modify,
  parse as parseJsonc,
  parseTree,
  printParseErrorCode,
  SyntaxKind,
  type ParseError
} from "jsonc-parser";
import { agentProfiles, renderAgentMcpSnippet, resolveAgentProfile, type AgentProfile } from "./agents.js";
import { getPackageLayout } from "./install.js";

export type AgentIntegrationState = "not-detected" | "manual" | "available" | "partial" | "installed" | "conflict";
export type AgentResourceState = "unsupported" | "missing" | "installed" | "existing" | "conflict";

export interface AgentResourceStatus {
  state: AgentResourceState;
  path?: string;
  owned: boolean;
  message?: string;
}

export interface AgentIntegrationStatus {
  agentId: string;
  displayName: string;
  detected: boolean;
  eligible: boolean;
  state: AgentIntegrationState;
  mcp: AgentResourceStatus;
  skill: AgentResourceStatus;
  reason?: string;
  plannedChanges: Array<"mcp" | "skill">;
}

export interface AgentIntegrationResult extends AgentIntegrationStatus {
  action: "install" | "uninstall";
  changed: boolean;
  dryRun: boolean;
  backups: string[];
}

export interface AgentIntegrationOptions {
  homeDir?: string;
  pathEnv?: string;
  sgwHome?: string;
  agentIds?: string[];
  dryRun?: boolean;
  skillSourcePath?: string;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  mcpServerPath?: string;
  lockTimeoutMs?: number;
}

type JsonContainer = "mcpServers" | "mcp" | "servers";

interface AgentAdapter {
  id: string;
  commands: string[];
  configPath: (homeDir: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform) => string;
  configKind: "json" | "jsonc" | "toml";
  jsonContainer?: JsonContainer;
  skillPath?: (homeDir: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform) => string;
}

interface OwnedResource {
  path: string;
  kind: "json-entry" | "toml-block" | "skill";
  fingerprint: string;
  parentCreated?: boolean;
}

interface AgentOwnership {
  mcp?: OwnedResource;
  skill?: OwnedResource;
  updatedAt: string;
}

interface AgentManifest {
  version: 1;
  agents: Record<string, AgentOwnership>;
}

interface AgentIntegrationLockOwner {
  pid: number;
  startedAt: number;
  token: string;
}

interface AgentIntegrationLockState {
  markerPath?: string;
  owner?: AgentIntegrationLockOwner;
  modifiedAt: number;
}

interface WorkContext {
  homeDir: string;
  pathEnv: string;
  sgwHome: string;
  mcpEnv: Record<string, string>;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  includeSystemApps: boolean;
  mcpCommand: string;
  mcpArgs: string[];
  skillSourcePath: string;
  manifestPath: string;
  manifest: AgentManifest;
  manifestError?: string;
}

interface JsonConfigInfo {
  state: AgentResourceState;
  entry?: Record<string, unknown>;
  document?: Record<string, unknown>;
  message?: string;
}

interface TomlSection {
  start: number;
  end: number;
  text: string;
  command?: string;
  args: string[];
  managed: boolean;
}

const managedStart = "# >>> s-gw managed MCP server";
const managedEnd = "# <<< s-gw managed MCP server";
const agentLockTimeoutMs = 35_000;
const staleAgentLockMs = 30_000;
const agentLockPollMs = 25;
const agentLockFileRetryMs = 1_000;
const managedAuthorityEnvKeys = [
  "SGW_HOME",
  "SGW_RECOVERY_HOME",
  "SGW_KEYCHAIN_SERVICE",
  "SGW_KEYCHAIN_ACCOUNT",
  "SGW_SECRET_KEYCHAIN_SERVICE",
  "SGW_SECRET_BACKEND",
  "SGW_EXECUTION_ENGINE"
] as const;
type ManagedAuthorityEnvKey = typeof managedAuthorityEnvKeys[number];

function envPath(value: string | undefined, fallback: string): string {
  const configured = value?.trim();
  return path.resolve(configured || fallback);
}

function codexHome(homeDir: string, env: NodeJS.ProcessEnv): string {
  return envPath(env.CODEX_HOME, path.join(homeDir, ".codex"));
}

function geminiHome(homeDir: string, env: NodeJS.ProcessEnv): string {
  const root = envPath(env.GEMINI_CLI_HOME, homeDir);
  return path.join(root, ".gemini");
}

function copilotHome(homeDir: string, env: NodeJS.ProcessEnv): string {
  return envPath(env.COPILOT_HOME, path.join(homeDir, ".copilot"));
}

function openCodeConfigFile(dir: string): string {
  const jsonc = path.join(dir, "opencode.jsonc");
  if (existsSync(jsonc)) return jsonc;
  const json = path.join(dir, "opencode.json");
  return existsSync(json) ? json : jsonc;
}

function openCodeConfig(homeDir: string, env: NodeJS.ProcessEnv): string {
  if (env.OPENCODE_CONFIG_DIR?.trim()) {
    return openCodeConfigFile(envPath(env.OPENCODE_CONFIG_DIR, ""));
  }
  if (env.OPENCODE_CONFIG?.trim()) return envPath(env.OPENCODE_CONFIG, "");
  const root = envPath(env.XDG_CONFIG_HOME, path.join(homeDir, ".config"));
  return openCodeConfigFile(path.join(root, "opencode"));
}

function openCodeSkill(homeDir: string, env: NodeJS.ProcessEnv): string {
  const root = env.OPENCODE_CONFIG_DIR?.trim()
    ? envPath(env.OPENCODE_CONFIG_DIR, "")
    : path.join(envPath(env.XDG_CONFIG_HOME, path.join(homeDir, ".config")), "opencode");
  return path.join(root, "skills", "s-gw", "SKILL.md");
}

function vscodeConfig(homeDir: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string {
  let userData: string;
  if (platform === "win32") {
    userData = envPath(env.APPDATA, path.join(homeDir, "AppData", "Roaming"));
  } else if (platform === "darwin") {
    userData = path.join(homeDir, "Library", "Application Support");
  } else {
    userData = envPath(env.XDG_CONFIG_HOME, path.join(homeDir, ".config"));
  }
  return path.join(userData, "Code", "User", "mcp.json");
}

const adapters: AgentAdapter[] = [
  {
    id: "claudecode",
    commands: ["claude"],
    configPath: (homeDir) => path.join(homeDir, ".claude.json"),
    configKind: "json",
    jsonContainer: "mcpServers",
    skillPath: (homeDir) => path.join(homeDir, ".claude", "skills", "s-gw", "SKILL.md")
  },
  {
    id: "codex",
    commands: ["codex"],
    configPath: (homeDir, env) => path.join(codexHome(homeDir, env), "config.toml"),
    configKind: "toml",
    skillPath: (homeDir, env) => path.join(codexHome(homeDir, env), "skills", "s-gw", "SKILL.md")
  },
  {
    id: "cursor",
    commands: ["cursor", "cursor-agent"],
    configPath: (homeDir) => path.join(homeDir, ".cursor", "mcp.json"),
    configKind: "json",
    jsonContainer: "mcpServers",
    skillPath: (homeDir) => path.join(homeDir, ".cursor", "skills", "s-gw", "SKILL.md")
  },
  {
    id: "geminicli",
    commands: ["gemini"],
    configPath: (homeDir, env) => path.join(geminiHome(homeDir, env), "settings.json"),
    configKind: "json",
    jsonContainer: "mcpServers",
    skillPath: (homeDir, env) => path.join(geminiHome(homeDir, env), "skills", "s-gw", "SKILL.md")
  },
  {
    id: "copilot",
    commands: ["copilot"],
    configPath: (homeDir, env) => path.join(copilotHome(homeDir, env), "mcp-config.json"),
    configKind: "json",
    jsonContainer: "mcpServers",
    skillPath: (homeDir, env) => path.join(copilotHome(homeDir, env), "skills", "s-gw", "SKILL.md")
  },
  {
    id: "opencode",
    commands: ["opencode"],
    configPath: (homeDir, env) => openCodeConfig(homeDir, env),
    configKind: "jsonc",
    jsonContainer: "mcp",
    skillPath: (homeDir, env) => openCodeSkill(homeDir, env)
  },
  {
    id: "vscode",
    commands: ["code"],
    configPath: (homeDir, env, platform) => vscodeConfig(homeDir, env, platform),
    configKind: "jsonc",
    jsonContainer: "servers",
    skillPath: (homeDir) => path.join(homeDir, ".agents", "skills", "s-gw", "SKILL.md")
  }
];

const commandNames: Record<string, string[]> = {
  openclaw: ["openclaw"],
  zeptoclaw: ["zeptoclaw"],
  claudecode: ["claude"],
  codex: ["codex"],
  hermes: ["hermes"],
  cursor: ["cursor", "cursor-agent"],
  windsurf: ["windsurf"],
  geminicli: ["gemini"],
  copilot: ["copilot"],
  openhands: ["openhands"],
  antigravity: ["agy", "antigravity"],
  opencode: ["opencode"],
  omnigent: ["omnigent"],
  vscode: ["code"]
};

export function agentIntegrationStatus(options: AgentIntegrationOptions = {}): AgentIntegrationStatus[] {
  const ctx = loadContext(options);
  const profiles = selectedProfiles(options.agentIds);
  return profiles.map((profile) => statusForProfile(profile, ctx));
}

export function installAgentIntegrations(options: AgentIntegrationOptions = {}): AgentIntegrationResult[] {
  if (options.dryRun) return installAgentIntegrationsUnlocked(options);
  return withAgentIntegrationLock(options, () => installAgentIntegrationsUnlocked(options));
}

export function refreshManagedAgentIntegrations(options: AgentIntegrationOptions = {}): AgentIntegrationResult[] {
  if (options.dryRun) return refreshManagedAgentIntegrationsUnlocked(options);
  return withAgentIntegrationLock(options, () => refreshManagedAgentIntegrationsUnlocked(options));
}

function refreshManagedAgentIntegrationsUnlocked(options: AgentIntegrationOptions): AgentIntegrationResult[] {
  const ctx = loadContext(options);
  if (ctx.manifestError) {
    throw new Error(`Cannot refresh managed agent integrations: ${ctx.manifestError}`);
  }

  const agentIds = Object.keys(ctx.manifest.agents);
  if (agentIds.length === 0) return [];

  const results: AgentIntegrationResult[] = [];
  for (const agentId of agentIds) {
    const current = loadContext(options);
    const managedEnv = managedAgentAuthorityEnv(current, agentId);
    const sgwHome = managedEnv.SGW_HOME || options.sgwHome;
    const env = { ...(options.env || process.env), ...managedEnv };
    results.push(...installAgentIntegrationsUnlocked({ ...options, agentIds: [agentId], env, sgwHome }));
  }
  return results;
}

function installAgentIntegrationsUnlocked(options: AgentIntegrationOptions): AgentIntegrationResult[] {
  const ctx = loadContext(options);
  const explicit = Boolean(options.agentIds?.length);
  const profiles = selectedProfiles(options.agentIds);
  const results: AgentIntegrationResult[] = [];

  for (const profile of profiles) {
    const status = statusForProfile(profile, ctx);
    if (!explicit && !status.detected) continue;

    if (!status.eligible || status.state === "conflict" || status.mcp.state === "conflict" ||
      status.skill.state === "conflict" || (!explicit && status.state === "not-detected")) {
      const blocked = status.state === "conflict" ||
        (status.mcp.state !== "conflict" && status.skill.state !== "conflict")
        ? status
        : {
            ...status,
            state: "conflict" as const,
            reason: status.mcp.message || status.skill.message || status.reason
          };
      results.push(asResult(blocked, "install", false, Boolean(options.dryRun), []));
      continue;
    }

    if (options.dryRun) {
      results.push(asResult(status, "install", false, true, []));
      continue;
    }

    results.push(installOne(profile, ctx));
  }

  return results;
}

export function uninstallAgentIntegrations(options: AgentIntegrationOptions = {}): AgentIntegrationResult[] {
  if (options.dryRun) return uninstallAgentIntegrationsUnlocked(options);
  return withAgentIntegrationLock(options, () => uninstallAgentIntegrationsUnlocked(options));
}

function uninstallAgentIntegrationsUnlocked(options: AgentIntegrationOptions): AgentIntegrationResult[] {
  const ctx = loadContext(options);
  const ids = options.agentIds?.length
    ? options.agentIds
    : ctx.manifestError ? agentProfiles.map((profile) => profile.id) : Object.keys(ctx.manifest.agents);
  const profiles = selectedProfiles(ids);
  const results: AgentIntegrationResult[] = [];

  for (const profile of profiles) {
    const status = statusForProfile(profile, ctx);
    const owned = ctx.manifest.agents[profile.id];
    if (!owned) {
      results.push(asResult(status, "uninstall", false, Boolean(options.dryRun), []));
      continue;
    }

    const conflict = uninstallConflict(profile, ctx, owned);
    if (conflict) {
      results.push(asResult({ ...status, state: "conflict", reason: conflict }, "uninstall", false, Boolean(options.dryRun), []));
      continue;
    }

    if (options.dryRun) {
      const plannedChanges: Array<"mcp" | "skill"> = [];
      if (owned.mcp) plannedChanges.push("mcp");
      if (owned.skill) plannedChanges.push("skill");
      results.push(asResult({ ...status, plannedChanges }, "uninstall", false, true, []));
      continue;
    }

    results.push(uninstallOne(profile, ctx, owned));
  }

  return results;
}

function loadContext(options: AgentIntegrationOptions): WorkContext {
  const env = options.env || process.env;
  const platform = options.platform || process.platform;
  const homeDir = integrationHome(options);
  const mcpEnv = mcpAuthorityEnvironment(options);
  const pathEnv = options.pathEnv ?? env.PATH ?? "";
  const manifestPath = path.join(homeDir, ".s-gw", "agent-integrations.json");
  const layout = getPackageLayout();
  const mcpServerPath = path.resolve(options.mcpServerPath || layout.mcpPath);
  const mcpLaunch = resolvePackagedMcpCommand(layout, { platform, pathEnv, env, mcpServerPath });
  let manifest: AgentManifest = { version: 1, agents: {} };
  let manifestError: string | undefined;
  try {
    manifest = readManifest(manifestPath);
  } catch (error) {
    manifestError = error instanceof Error ? error.message : String(error);
  }
  return {
    homeDir,
    pathEnv,
    sgwHome: mcpEnv.SGW_HOME,
    mcpEnv,
    env,
    platform,
    includeSystemApps: !options.homeDir,
    mcpCommand: mcpLaunch.command,
    mcpArgs: mcpLaunch.args,
    skillSourcePath: options.skillSourcePath || fileURLToPath(new URL("../skills/s-gw/SKILL.md", import.meta.url)),
    manifestPath,
    manifest,
    manifestError
  };
}

export function resolvePackagedMcpCommand(
  layout: Pick<ReturnType<typeof getPackageLayout>, "isSelfContainedMacApp" | "nodePath">,
  options: {
    platform: NodeJS.Platform;
    pathEnv: string;
    env: NodeJS.ProcessEnv;
    mcpServerPath: string;
  }
): { command: string; args: string[] } {
  const bundledMacMcp = options.platform === "darwin" && layout.isSelfContainedMacApp;
  if (options.platform === "win32" || bundledMacMcp) {
    return {
      command: bundledMacMcp ? layout.nodePath : path.resolve(process.execPath),
      args: [options.mcpServerPath]
    };
  }

  return {
    command: commandPath("s-gw-mcp", options.pathEnv, options.platform, options.env) || "s-gw-mcp",
    args: []
  };
}

function integrationHome(options: AgentIntegrationOptions): string {
  const env = options.env || process.env;
  return path.resolve(options.homeDir || env.HOME || env.USERPROFILE || os.homedir());
}

function withAgentIntegrationLock<T>(options: AgentIntegrationOptions, body: () => T): T {
  const homeDir = integrationHome(options);
  mkdirSync(homeDir, { recursive: true, mode: 0o700 });
  const lockPath = path.join(homeDir, ".s-gw-agent-integrations.lock");
  const owner: AgentIntegrationLockOwner = {
    pid: process.pid,
    startedAt: Date.now(),
    token: randomUUID()
  };
  const markerName = agentLockMarkerName(owner.token);
  const started = Date.now();
  const timeoutMs = options.lockTimeoutMs ?? agentLockTimeoutMs;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
    throw new Error("Agent integration lock timeout must be a non-negative number.");
  }
  const waiter = new Int32Array(new SharedArrayBuffer(4));

  while (!publishAgentIntegrationLock(lockPath, markerName, owner)) {
    if (Date.now() - started >= timeoutMs) {
      throw new Error(`Timed out waiting for the agent integration lock at ${lockPath}. Another install or uninstall may still be running.`);
    }
    if (removeAbandonedAgentLock(lockPath)) continue;
    Atomics.wait(waiter, 0, 0, agentLockPollMs);
  }

  try {
    return body();
  } finally {
    releaseAgentIntegrationLock(lockPath, markerName);
  }
}

function publishAgentIntegrationLock(
  lockPath: string,
  markerName: string,
  owner: AgentIntegrationLockOwner
): boolean {
  const tmpPath = `${lockPath}.tmp-${process.pid}-${owner.token}`;
  const markerPath = path.join(tmpPath, markerName);
  let markerFd: number | undefined;
  try {
    mkdirSync(tmpPath, { mode: 0o700 });
    markerFd = openSync(markerPath, "wx", 0o600);
    writeFileSync(markerFd, `${JSON.stringify(owner)}\n`);
    fsyncSync(markerFd);
    closeSync(markerFd);
    markerFd = undefined;

    try {
      renameSync(tmpPath, lockPath);
      return true;
    } catch (error) {
      if (isNodeError(error) && (error.code === "EEXIST" || error.code === "ENOTEMPTY")) return false;
      if (process.platform === "win32" && isNodeError(error) && (error.code === "EPERM" || error.code === "EACCES")) {
        return false;
      }
      if (isNodeError(error) && (error.code === "EPERM" || error.code === "EACCES") && existsSync(lockPath)) return false;
      throw error;
    }
  } finally {
    if (markerFd !== undefined) closeSync(markerFd);
    if (!tryUnlink(markerPath) && existsSync(tmpPath)) {
      throw new Error(`Could not remove the temporary agent integration lock marker at ${markerPath}.`);
    }
    if (!tryRmdir(tmpPath) && existsSync(tmpPath)) {
      throw new Error(`Could not remove the temporary agent integration lock directory at ${tmpPath}.`);
    }
  }
}

function inspectAgentIntegrationLock(lockPath: string): AgentIntegrationLockState {
  const lockInfo = lstatSync(lockPath);
  if (lockInfo.isSymbolicLink() || !lockInfo.isDirectory()) {
    throw new Error(`${lockPath} is not a regular directory. s-gw refuses to remove it.`);
  }

  const entries = readdirSync(lockPath);
  if (entries.length === 0) return { modifiedAt: lockInfo.mtimeMs };
  if (entries.length > 1) {
    throw new Error(`${lockPath} contains unexpected files. s-gw refuses to remove it.`);
  }

  const markerName = entries[0];
  const markerPath = path.join(lockPath, markerName);
  const marker = readRegularFileSnapshot(markerPath);
  const parsed = readAgentLockOwner(marker.content.toString("utf8"));
  const owner = parsed && markerName === agentLockMarkerName(parsed.token) ? parsed : undefined;
  return {
    markerPath,
    owner,
    modifiedAt: Math.max(lockInfo.mtimeMs, marker.modifiedAt)
  };
}

function removeAbandonedAgentLock(lockPath: string): boolean {
  let state: AgentIntegrationLockState;
  try {
    state = inspectAgentIntegrationLock(lockPath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return true;
    if (process.platform === "win32" && isNodeError(error) && (error.code === "EPERM" || error.code === "EACCES")) {
      return false;
    }
    throw error;
  }

  if (state.owner) {
    if (state.owner.pid === process.pid) {
      throw new Error(`The current process already owns the agent integration lock at ${lockPath}.`);
    }
    if (processIsAlive(state.owner.pid)) return false;
  } else if (Date.now() - state.modifiedAt <= staleAgentLockMs) {
    return false;
  }

  // The marker name belongs to this generation, so an old cleaner cannot unlink a replacement.
  if (state.markerPath && !tryUnlink(state.markerPath)) return false;
  return tryRmdir(lockPath);
}

function readAgentLockOwner(contents: string): AgentIntegrationLockOwner | undefined {
  try {
    const value = JSON.parse(contents) as Partial<AgentIntegrationLockOwner>;
    if (!Number.isSafeInteger(value.pid) || (value.pid || 0) <= 0) return undefined;
    if (!Number.isFinite(value.startedAt) || (value.startedAt || 0) <= 0) return undefined;
    if (typeof value.token !== "string" || !value.token) return undefined;
    return value as AgentIntegrationLockOwner;
  } catch {
    return undefined;
  }
}

function agentLockMarkerName(token: string): string {
  return `owner-${token}.json`;
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return isNodeError(error) && error.code === "EPERM";
  }
}

function releaseAgentIntegrationLock(lockPath: string, markerName: string): void {
  const markerPath = path.join(lockPath, markerName);
  if (!tryUnlink(markerPath)) {
    throw new Error(`Could not release the agent integration lock marker at ${markerPath}.`);
  }
  if (tryRmdir(lockPath)) return;

  try {
    if (readdirSync(lockPath).length > 0) return;
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`Could not release the agent integration lock directory at ${lockPath}.`);
}

function tryUnlink(filePath: string): boolean {
  const started = Date.now();
  const waiter = new Int32Array(new SharedArrayBuffer(4));
  while (true) {
    try {
      unlinkSync(filePath);
      return true;
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return true;
      if (!isWindowsLockAccessError(error)) throw error;
      if (Date.now() - started >= agentLockFileRetryMs) return false;
      Atomics.wait(waiter, 0, 0, agentLockPollMs);
    }
  }
}

function tryRmdir(dirPath: string): boolean {
  const started = Date.now();
  const waiter = new Int32Array(new SharedArrayBuffer(4));
  while (true) {
    try {
      rmdirSync(dirPath);
      return true;
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return true;
      if (isNodeError(error) && (error.code === "ENOTEMPTY" || error.code === "EEXIST")) return false;
      if (!isWindowsLockAccessError(error)) throw error;

      try {
        if (readdirSync(dirPath).length > 0) return false;
      } catch (readError) {
        if (isNodeError(readError) && readError.code === "ENOENT") return true;
        if (!isWindowsLockAccessError(readError)) throw readError;
      }
      if (Date.now() - started >= agentLockFileRetryMs) return false;
      Atomics.wait(waiter, 0, 0, agentLockPollMs);
    }
  }
}

function isWindowsLockAccessError(error: unknown): boolean {
  return process.platform === "win32" && isNodeError(error) &&
    (error.code === "EPERM" || error.code === "EACCES");
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function selectedProfiles(ids?: string[]): AgentProfile[] {
  if (!ids?.length) return agentProfiles;
  const profiles: AgentProfile[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    const profile = resolveAgentProfile(id);
    if (seen.has(profile.id)) continue;
    profiles.push(profile);
    seen.add(profile.id);
  }
  return profiles;
}

function statusForProfile(profile: AgentProfile, ctx: WorkContext): AgentIntegrationStatus {
  const adapter = adapters.find((candidate) => candidate.id === profile.id);
  const ownership = ctx.manifest.agents[profile.id];
  const detected = Boolean(ownership) || detectProfile(profile, adapter, ctx);

  if (!adapter) {
    const manualProfile = profile.mcp.status === "manual" || profile.mcp.writeMode === "manual";
    const reason = manualProfile
      ? "This profile remains snippet-only because s-gw does not have a safe automatic merge for its config format."
      : "This agent does not have a safe user-level automatic registration target. Use the generated MCP snippet.";
    return {
      agentId: profile.id,
      displayName: profile.displayName,
      detected,
      eligible: false,
      state: detected ? "manual" : "not-detected",
      mcp: { state: "unsupported", owned: false, message: reason },
      skill: { state: "unsupported", owned: false },
      reason,
      plannedChanges: []
    };
  }

  const mcp = mcpStatus(profile, adapter, ctx, ownership?.mcp);
  const skill = skillStatus(adapter, ctx, ownership?.skill);
  if (ctx.manifestError) {
    return {
      agentId: profile.id,
      displayName: profile.displayName,
      detected,
      eligible: true,
      state: "conflict",
      mcp,
      skill,
      reason: ctx.manifestError,
      plannedChanges: []
    };
  }
  const plannedChanges: Array<"mcp" | "skill"> = [];
  if (mcp.state === "missing") plannedChanges.push("mcp");
  if (skill.state === "missing") plannedChanges.push("skill");

  let state: AgentIntegrationState = "available";
  let reason: string | undefined;
  if (!detected) {
    state = "not-detected";
  } else if (mcp.state === "conflict" || skill.state === "conflict") {
    state = "conflict";
    reason = mcp.message || skill.message;
  } else if (resourceReady(mcp) && resourceReady(skill)) {
    state = "installed";
  } else if (resourceReady(mcp) || resourceReady(skill)) {
    state = "partial";
  }

  return {
    agentId: profile.id,
    displayName: profile.displayName,
    detected,
    eligible: true,
    state,
    mcp,
    skill,
    reason,
    plannedChanges
  };
}

export function mcpAuthorityEnvironment(
  options: Pick<AgentIntegrationOptions, "homeDir" | "sgwHome" | "env"> = {}
): Record<string, string> {
  const env = options.env || process.env;
  const homeDir = integrationHome(options);
  const result: Record<string, string> = {
    SGW_HOME: resolveManagedAuthorityPath(
      "SGW_HOME",
      options.sgwHome || env.SGW_HOME,
      path.join(homeDir, ".s-gw"),
      homeDir
    )
  };
  const recoveryHome = optionalManagedAuthorityValue("SGW_RECOVERY_HOME", env.SGW_RECOVERY_HOME);
  if (recoveryHome) {
    result.SGW_RECOVERY_HOME = resolveManagedAuthorityPath(
      "SGW_RECOVERY_HOME",
      recoveryHome,
      "",
      homeDir
    );
  }

  for (const key of ["SGW_KEYCHAIN_SERVICE", "SGW_KEYCHAIN_ACCOUNT", "SGW_SECRET_KEYCHAIN_SERVICE"] as const) {
    const value = optionalManagedAuthorityValue(key, env[key]);
    if (value) result[key] = value;
  }

  const backend = optionalManagedAuthorityValue("SGW_SECRET_BACKEND", env.SGW_SECRET_BACKEND);
  if (backend) {
    const normalized = backend.trim().toLowerCase();
    if (normalized !== "local" && normalized !== "keychain") {
      throw new Error(`Unsupported SGW_SECRET_BACKEND value: ${backend}`);
    }
    result.SGW_SECRET_BACKEND = normalized;
  }

  const engine = optionalManagedAuthorityValue("SGW_EXECUTION_ENGINE", env.SGW_EXECUTION_ENGINE);
  if (engine) {
    const normalized = engine.trim().toLowerCase();
    if (normalized !== "auto" && normalized !== "rust" && normalized !== "typescript") {
      throw new Error(`Unsupported SGW_EXECUTION_ENGINE value: ${engine}`);
    }
    result.SGW_EXECUTION_ENGINE = normalized;
  }
  return result;
}

function optionalManagedAuthorityValue(
  key: ManagedAuthorityEnvKey,
  value: string | undefined
): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (value.length > 4_096 || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new Error(`Invalid ${key} value for a managed agent integration.`);
  }
  return value.trim() ? value : undefined;
}

function resolveManagedAuthorityPath(
  key: "SGW_HOME" | "SGW_RECOVERY_HOME",
  value: string | undefined,
  fallback: string,
  homeDir: string
): string {
  const checked = optionalManagedAuthorityValue(key, value);
  if (!checked) return path.resolve(fallback);

  const configured = checked.trim();
  if (configured === "~") return path.resolve(homeDir);
  if (configured.startsWith("~/") || configured.startsWith("~\\")) {
    return path.resolve(homeDir, configured.slice(2));
  }
  return path.resolve(path.isAbsolute(configured) ? configured : path.join(homeDir, configured));
}

function managedAgentAuthorityEnv(ctx: WorkContext, agentId: string): Record<string, string> {
  const ownership = ctx.manifest.agents[agentId];
  if (!ownership?.mcp) return {};
  const adapter = adapters.find((candidate) => candidate.id === agentId);
  if (!adapter) return {};
  return readManagedAuthorityEnv(adapter, ownership.mcp.path);
}

function readManagedAuthorityEnv(adapter: AgentAdapter, configPath: string): Record<string, string> {
  if (adapter.configKind !== "toml") {
    const info = inspectJsonConfig(configPath, adapter.jsonContainer || "mcpServers", adapter.configKind);
    return authorityEnvFromEntry(info.entry);
  }

  const current = readTextIfPresent(configPath);
  if (!current.value) return {};
  const section = findCodexSection(current.value);
  if (!section) return {};

  const result: Record<string, string> = {};
  for (const key of managedAuthorityEnvKeys) {
    const match = new RegExp(`\\b${key}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*")`).exec(section.text);
    if (!match) continue;
    try {
      const value = JSON.parse(match[1]);
      if (typeof value === "string") result[key] = value;
    } catch {
      // A malformed owned block will be reported as a fingerprint conflict.
    }
  }
  return result;
}

function authorityEnvFromEntry(entry: Record<string, unknown> | undefined): Record<string, string> {
  if (!entry) return {};
  const rawEnv = isPlainObject(entry.env)
    ? entry.env
    : isPlainObject(entry.environment) ? entry.environment : undefined;
  if (!rawEnv) return {};

  const result: Record<string, string> = {};
  for (const key of managedAuthorityEnvKeys) {
    const value = rawEnv[key];
    if (typeof value === "string") result[key] = value;
  }
  return result;
}

function detectProfile(profile: AgentProfile, adapter: AgentAdapter | undefined, ctx: WorkContext): boolean {
  const commands = adapter?.commands || commandNames[profile.id] || [];
  if (commands.some((name) => commandExists(name, ctx))) return true;
  if (desktopAppDetected(profile.id, ctx)) return true;

  if (adapter && existsSync(adapter.configPath(ctx.homeDir, ctx.env, ctx.platform))) return true;

  for (const configPath of profile.mcp.configPaths) {
    const resolved = resolveHomePath(configPath, ctx.homeDir);
    if (resolved && existsSync(resolved)) return true;
  }
  return false;
}

function desktopAppDetected(agentId: string, ctx: WorkContext): boolean {
  if (agentId !== "cursor" && agentId !== "opencode" && agentId !== "vscode") return false;
  const appName = agentId === "cursor"
    ? "Cursor"
    : agentId === "opencode" ? "OpenCode" : "Visual Studio Code";
  const candidates: string[] = [];

  if (ctx.platform === "darwin") {
    candidates.push(path.join(ctx.homeDir, "Applications", `${appName}.app`));
    if (ctx.includeSystemApps) candidates.push(path.join("/Applications", `${appName}.app`));
  } else if (ctx.platform === "win32") {
    const local = envPath(ctx.env.LOCALAPPDATA, path.join(ctx.homeDir, "AppData", "Local"));
    const folder = agentId === "cursor"
      ? "cursor"
      : agentId === "opencode" ? "OpenCode" : "Microsoft VS Code";
    const executable = agentId === "cursor"
      ? "Cursor.exe"
      : agentId === "opencode" ? "OpenCode.exe" : "Code.exe";
    candidates.push(path.join(local, "Programs", folder, executable));
    if (agentId === "opencode") {
      candidates.push(path.join(local, folder, executable));
      const scoop = envPath(ctx.env.SCOOP, path.join(ctx.homeDir, "scoop"));
      candidates.push(path.join(scoop, "apps", "opencode-desktop", "current", executable));
      if (ctx.includeSystemApps && ctx.env.SCOOP_GLOBAL?.trim()) {
        candidates.push(path.join(ctx.env.SCOOP_GLOBAL, "apps", "opencode-desktop", "current", executable));
      }
    }
    if (ctx.includeSystemApps && ctx.env.ProgramFiles?.trim()) {
      candidates.push(path.join(ctx.env.ProgramFiles, folder, executable));
    }
  }

  return candidates.some((candidate) => existsSync(candidate));
}

function commandExists(name: string, ctx: WorkContext): boolean {
  return commandPath(name, ctx.pathEnv, ctx.platform, ctx.env) !== undefined;
}

function commandPath(
  name: string,
  pathEnv: string,
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv
): string | undefined {
  const suffixes = platform === "win32"
    ? (env.PATHEXT || ".EXE;.CMD;.BAT;.COM").split(";")
    : [""];
  const delimiter = platform === "win32" ? ";" : path.delimiter;
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    for (const suffix of suffixes) {
      const candidate = path.join(dir, platform === "win32" ? `${name}${suffix}` : name);
      try {
        const info = statSync(candidate);
        if (!info.isFile()) continue;
        if (platform === "win32" || (info.mode & 0o111) !== 0) return candidate;
      } catch {
        // PATH commonly contains stale directories.
      }
    }
  }
  return undefined;
}

function mcpStatus(
  profile: AgentProfile,
  adapter: AgentAdapter,
  ctx: WorkContext,
  owned: OwnedResource | undefined
): AgentResourceStatus {
  const configPath = adapter.configPath(ctx.homeDir, ctx.env, ctx.platform);
  if (owned && !samePath(owned.path, configPath, ctx.platform)) {
    return { state: "conflict", path: configPath, owned: true, message: "The tracked MCP config path changed. Uninstall the old integration first." };
  }

  if (adapter.configKind !== "toml") {
    const info = inspectJsonConfig(configPath, adapter.jsonContainer || "mcpServers", adapter.configKind);
    if (info.state === "conflict") {
      return { state: "conflict", path: configPath, owned: Boolean(owned), message: info.message };
    }
    if (!info.entry) {
      if (!sgwCommandAvailable(ctx.mcpCommand, ctx.mcpArgs, ctx)) {
        return {
          state: "conflict",
          path: configPath,
          owned: Boolean(owned),
          message: "The packaged s-gw MCP command is not available, so s-gw cannot write a working agent registration."
        };
      }
      return { state: "missing", path: configPath, owned: Boolean(owned) };
    }
    if (!isSgwServerEntry(info.entry)) {
      return {
        state: "conflict",
        path: configPath,
        owned: Boolean(owned),
        message: `${configPath} already has an unrelated 's-gw' MCP server entry. s-gw left it unchanged.`
      };
    }
    if (owned && owned.fingerprint !== fingerprintObject(info.entry)) {
      return {
        state: "conflict",
        path: configPath,
        owned: true,
        message: `${configPath} has changes inside the s-gw-owned MCP entry. Resolve them before installing or uninstalling.`
      };
    }
    if (owned && owned.fingerprint !== fingerprintObject(expectedJsonEntry(profile, ctx))) {
      return { state: "missing", path: configPath, owned: true, message: "The s-gw-owned MCP entry needs to be refreshed." };
    }
    const contractIssue = agentEntryContractIssue(profile.id, info.entry);
    if (contractIssue) {
      return {
        state: "conflict",
        path: configPath,
        owned: Boolean(owned),
        message: `${configPath} ${contractIssue} s-gw left it unchanged.`
      };
    }
    if (!sgwServerEntryAvailable(info.entry, ctx)) {
      return {
        state: "conflict",
        path: configPath,
        owned: Boolean(owned),
        message: `${configPath} points to an s-gw MCP command that is no longer available.`
      };
    }
    return { state: owned ? "installed" : "existing", path: configPath, owned: Boolean(owned) };
  }

  const text = readTextIfPresent(configPath);
  if (text.error) return { state: "conflict", path: configPath, owned: Boolean(owned), message: text.error };
  const section = findCodexSection(text.value || "");
  if (!section) {
    if (!sgwCommandAvailable(ctx.mcpCommand, ctx.mcpArgs, ctx)) {
      return {
        state: "conflict",
        path: configPath,
        owned: Boolean(owned),
        message: "The packaged s-gw MCP command is not available, so s-gw cannot write a working agent registration."
      };
    }
    return { state: "missing", path: configPath, owned: Boolean(owned) };
  }
  if (!isSgwCommand(section.command, section.args)) {
    return {
      state: "conflict",
      path: configPath,
      owned: Boolean(owned),
      message: `${configPath} already has an unrelated [mcp_servers.s-gw] section. s-gw left it unchanged.`
    };
  }
  if (owned && owned.fingerprint !== fingerprintText(section.text)) {
    return {
      state: "conflict",
      path: configPath,
      owned: true,
      message: `${configPath} has changes inside the s-gw-owned MCP block. Resolve them before installing or uninstalling.`
    };
  }
  if (owned && owned.fingerprint !== fingerprintText(codexManagedBlock(profile, ctx))) {
    return { state: "missing", path: configPath, owned: true, message: "The s-gw-owned MCP block needs to be refreshed." };
  }
  if (!sgwCommandAvailable(section.command, section.args, ctx)) {
    return {
      state: "conflict",
      path: configPath,
      owned: Boolean(owned),
      message: `${configPath} points to an s-gw MCP command that is no longer available.`
    };
  }
  return { state: owned ? "installed" : "existing", path: configPath, owned: Boolean(owned) };
}

function skillStatus(adapter: AgentAdapter, ctx: WorkContext, owned: OwnedResource | undefined): AgentResourceStatus {
  if (!adapter.skillPath) return { state: "unsupported", owned: false };
  const skillPath = adapter.skillPath(ctx.homeDir, ctx.env, ctx.platform);
  if (owned && !samePath(owned.path, skillPath, ctx.platform)) {
    return { state: "conflict", path: skillPath, owned: true, message: "The tracked skill path changed. Uninstall the old integration first." };
  }

  const source = readFileSync(ctx.skillSourcePath, "utf8");
  const current = readTextIfPresent(skillPath);
  if (current.error) return { state: "conflict", path: skillPath, owned: Boolean(owned), message: current.error };
  if (current.value === undefined) return { state: "missing", path: skillPath, owned: Boolean(owned) };
  if (owned) {
    if (fingerprintText(current.value) !== owned.fingerprint) {
      return { state: "conflict", path: skillPath, owned: true, message: `${skillPath} has user changes. s-gw left it unchanged.` };
    }
    if (current.value !== source) {
      return { state: "missing", path: skillPath, owned: true, message: "A newer packaged s-gw skill is ready to install." };
    }
    return { state: "installed", path: skillPath, owned: true };
  }
  if (current.value !== source) {
    return {
      state: "conflict",
      path: skillPath,
      owned: false,
      message: `${skillPath} already exists with different content. s-gw left it unchanged.`
    };
  }
  return { state: "existing", path: skillPath, owned: false };
}

function installOne(profile: AgentProfile, ctx: WorkContext): AgentIntegrationResult {
  const adapter = requiredAdapter(profile.id);
  const before = statusForProfile(profile, ctx);
  const backups: string[] = [];
  const rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }> = [];
  const manifestBefore = structuredClone(ctx.manifest);
  let ownershipChanged = false;
  const owned = ctx.manifest.agents[profile.id] || { updatedAt: new Date().toISOString() };

  try {
    if (before.mcp.state === "missing") {
      const installed = installMcp(profile, adapter, ctx, backups, rollbacks);
      owned.mcp = installed;
      ownershipChanged = true;
    }
    if (before.skill.state === "missing" && adapter.skillPath) {
      const installed = installSkill(adapter, ctx, backups, rollbacks);
      owned.skill = installed;
      ownershipChanged = true;
    }

    if (ownershipChanged) {
      rememberFile(ctx.manifestPath, rollbacks);
      owned.updatedAt = new Date().toISOString();
      ctx.manifest.agents[profile.id] = owned;
      writeManifest(ctx.manifestPath, ctx.manifest);
    }
  } catch (error) {
    rollbackFiles(rollbacks);
    ctx.manifest = manifestBefore;
    const failed = statusForProfile(profile, ctx);
    return asResult(
      { ...failed, state: "conflict", reason: error instanceof Error ? error.message : String(error) },
      "install",
      false,
      false,
      backups
    );
  }

  const after = statusForProfile(profile, ctx);
  return asResult(after, "install", ownershipChanged, false, backups);
}

function installMcp(
  profile: AgentProfile,
  adapter: AgentAdapter,
  ctx: WorkContext,
  backups: string[],
  rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }>
): OwnedResource {
  const configPath = adapter.configPath(ctx.homeDir, ctx.env, ctx.platform);
  rememberFile(configPath, rollbacks);
  const mode = currentMode(configPath, 0o600);
  if (existsSync(configPath)) backups.push(backupFile(configPath, ctx.homeDir, profile.id, "mcp"));

  if (adapter.configKind !== "toml") {
    const info = inspectJsonConfig(configPath, adapter.jsonContainer || "mcpServers", adapter.configKind);
    if (info.state === "conflict") throw new Error(info.message);
    const doc = info.document || {};
    const container = adapter.jsonContainer || "mcpServers";
    const parentCreated = !(container in doc);
    const entry = expectedJsonEntry(profile, ctx);
    if (adapter.configKind === "jsonc") {
      const current = existsSync(configPath) ? readFileSync(configPath, "utf8") : "";
      atomicWrite(configPath, updateJsonc(current, [container, "s-gw"], entry), mode);
    } else {
      const servers = isPlainObject(doc[container]) ? doc[container] as Record<string, unknown> : {};
      servers["s-gw"] = entry;
      doc[container] = servers;
      atomicWrite(configPath, `${JSON.stringify(doc, null, 2)}\n`, mode);
    }
    return { path: configPath, kind: "json-entry", fingerprint: fingerprintObject(entry), parentCreated };
  }

  const current = existsSync(configPath) ? readFileSync(configPath, "utf8") : "";
  const block = codexManagedBlock(profile, ctx);
  const ownedSection = ctx.manifest.agents[profile.id]?.mcp ? findCodexSection(current) : undefined;
  if (ownedSection) {
    atomicWrite(
      configPath,
      `${current.slice(0, ownedSection.start)}${block}${current.slice(ownedSection.end)}`,
      mode
    );
    return { path: configPath, kind: "toml-block", fingerprint: fingerprintText(block) };
  }
  const prefix = current.length === 0 ? "" : current.endsWith("\n\n") ? "" : current.endsWith("\n") ? "\n" : "\n\n";
  atomicWrite(configPath, `${current}${prefix}${block}\n`, mode);
  return { path: configPath, kind: "toml-block", fingerprint: fingerprintText(block) };
}

function installSkill(
  adapter: AgentAdapter,
  ctx: WorkContext,
  backups: string[],
  rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }>
): OwnedResource {
  const skillPath = adapter.skillPath?.(ctx.homeDir, ctx.env, ctx.platform);
  if (!skillPath) throw new Error("This agent does not expose a supported user-level skill directory.");
  rememberFile(skillPath, rollbacks);
  if (existsSync(skillPath)) backups.push(backupFile(skillPath, ctx.homeDir, adapter.id, "skill"));
  const content = readFileSync(ctx.skillSourcePath, "utf8");
  atomicWrite(skillPath, content, currentMode(skillPath, 0o644));
  return { path: skillPath, kind: "skill", fingerprint: fingerprintText(content) };
}

function uninstallConflict(profile: AgentProfile, ctx: WorkContext, owned: AgentOwnership): string | undefined {
  const adapter = adapters.find((candidate) => candidate.id === profile.id);
  if (!adapter) return "The owned integration no longer has a supported installer adapter.";

  if (owned.mcp) {
    if (adapter.configKind !== "toml") {
      const info = inspectJsonConfig(
        owned.mcp.path,
        adapter.jsonContainer || "mcpServers",
        adapter.configKind
      );
      if (info.state === "conflict") return info.message;
      if (info.entry && fingerprintObject(info.entry) !== owned.mcp.fingerprint) {
        return `${owned.mcp.path} has changes inside the s-gw-owned MCP entry. It was not removed.`;
      }
    } else {
      const current = readTextIfPresent(owned.mcp.path);
      if (current.error) return current.error;
      const section = findCodexSection(current.value || "");
      if (section && fingerprintText(section.text) !== owned.mcp.fingerprint) {
        return `${owned.mcp.path} has changes inside the s-gw-owned MCP block. It was not removed.`;
      }
    }
  }

  if (owned.skill && existsSync(owned.skill.path)) {
    const current = readTextIfPresent(owned.skill.path);
    if (current.error) return current.error;
    if (current.value !== undefined && fingerprintText(current.value) !== owned.skill.fingerprint) {
      return `${owned.skill.path} has user changes. It was not removed.`;
    }
  }
  return undefined;
}

function uninstallOne(
  profile: AgentProfile,
  ctx: WorkContext,
  owned: AgentOwnership
): AgentIntegrationResult {
  const adapter = requiredAdapter(profile.id);
  const backups: string[] = [];
  const rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }> = [];
  const manifestBefore = structuredClone(ctx.manifest);
  let changed = false;

  try {
    if (owned.mcp && existsSync(owned.mcp.path)) {
      rememberFile(owned.mcp.path, rollbacks);
      backups.push(backupFile(owned.mcp.path, ctx.homeDir, profile.id, "mcp-uninstall"));
      if (adapter.configKind !== "toml") {
        const container = adapter.jsonContainer || "mcpServers";
        const info = inspectJsonConfig(owned.mcp.path, container, adapter.configKind);
        const doc = info.document || {};
        const servers = isPlainObject(doc[container]) ? doc[container] as Record<string, unknown> : {};
        if (adapter.configKind === "jsonc") {
          const current = readFileSync(owned.mcp.path, "utf8");
          const next = removeJsoncEntry(current, container);
          atomicWrite(owned.mcp.path, next, currentMode(owned.mcp.path, 0o600));
        } else {
          delete servers["s-gw"];
          if (Object.keys(servers).length === 0 && owned.mcp.parentCreated) delete doc[container];
          else doc[container] = servers;
          atomicWrite(owned.mcp.path, `${JSON.stringify(doc, null, 2)}\n`, currentMode(owned.mcp.path, 0o600));
        }
      } else {
        const current = readFileSync(owned.mcp.path, "utf8");
        const section = findCodexSection(current);
        if (section) atomicWrite(owned.mcp.path, removeTomlSection(current, section), currentMode(owned.mcp.path, 0o600));
      }
      changed = true;
    }

    if (owned.skill && existsSync(owned.skill.path)) {
      rememberFile(owned.skill.path, rollbacks);
      backups.push(backupFile(owned.skill.path, ctx.homeDir, profile.id, "skill-uninstall"));
      unlinkSync(owned.skill.path);
      removeEmptyDir(path.dirname(owned.skill.path));
      changed = true;
    }

    rememberFile(ctx.manifestPath, rollbacks);
    delete ctx.manifest.agents[profile.id];
    writeManifest(ctx.manifestPath, ctx.manifest);
  } catch (error) {
    rollbackFiles(rollbacks);
    ctx.manifest = manifestBefore;
    const failed = statusForProfile(profile, ctx);
    return asResult(
      { ...failed, state: "conflict", reason: error instanceof Error ? error.message : String(error) },
      "uninstall",
      false,
      false,
      backups
    );
  }

  const after = statusForProfile(profile, ctx);
  return asResult(after, "uninstall", changed, false, backups);
}

function inspectJsonConfig(
  configPath: string,
  container: JsonContainer,
  kind: "json" | "jsonc"
): JsonConfigInfo {
  if (!existsSync(configPath)) return { state: "missing", document: {} };
  const current = readTextIfPresent(configPath);
  if (current.error) return { state: "conflict", message: current.error };

  let parsed: unknown;
  if (kind === "jsonc") {
    const errors: ParseError[] = [];
    parsed = parseJsonc(current.value || "{}", errors, { allowTrailingComma: true });
    if (errors.length > 0) {
      const first = errors[0];
      return {
        state: "conflict",
        message: `${configPath} is not valid JSONC (${printParseErrorCode(first.error)} at offset ${first.offset}). s-gw left it unchanged.`
      };
    }
  } else {
    try {
      parsed = JSON.parse(current.value || "{}");
    } catch (error) {
      return {
        state: "conflict",
        message: `${configPath} is not valid JSON (${error instanceof Error ? error.message : String(error)}). s-gw left it unchanged.`
      };
    }
  }
  if (!isPlainObject(parsed)) return { state: "conflict", message: `${configPath} must contain a JSON object. s-gw left it unchanged.` };

  const rawContainer = parsed[container];
  if (rawContainer !== undefined && !isPlainObject(rawContainer)) {
    return { state: "conflict", message: `${configPath} has a non-object '${container}' value. s-gw left it unchanged.` };
  }
  const servers = rawContainer as Record<string, unknown> | undefined;
  const entry = servers?.["s-gw"];
  if (entry !== undefined && !isPlainObject(entry)) {
    return { state: "conflict", message: `${configPath} has an invalid 's-gw' MCP entry. s-gw left it unchanged.` };
  }
  return { state: entry ? "existing" : "missing", document: parsed, entry: entry as Record<string, unknown> | undefined };
}

function updateJsonc(text: string, jsonPath: string[], value: unknown): string {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const edits = modify(text, jsonPath, value, {
    formattingOptions: { insertSpaces: true, tabSize: 2, eol }
  });
  const next = applyEdits(text, edits);
  return next.endsWith(eol) ? next : `${next}${eol}`;
}

function removeJsoncEntry(text: string, container: JsonContainer): string {
  const tree = parseTree(text, [], { allowTrailingComma: true });
  const value = tree && findNodeAtLocation(tree, [container, "s-gw"]);
  const property = value?.parent;
  const parent = property?.parent;
  if (!property || property.type !== "property" || !parent || parent.type !== "object") return text;

  const siblings = parent.children || [];
  const index = siblings.indexOf(property);
  const nextProperty = siblings[index + 1];
  const previousProperty = siblings[index - 1];
  const afterEnd = nextProperty?.offset ?? parent.offset + parent.length - 1;
  let comma = jsoncCommaOffset(text, property.offset + property.length, afterEnd);
  if (comma === undefined && previousProperty) {
    comma = jsoncCommaOffset(text, previousProperty.offset + previousProperty.length, property.offset);
  }

  const removals = [{ offset: property.offset, length: property.length }];
  if (comma !== undefined) removals.push({ offset: comma, length: 1 });
  removals.sort((left, right) => right.offset - left.offset);

  let next = text;
  for (const edit of removals) {
    next = `${next.slice(0, edit.offset)}${next.slice(edit.offset + edit.length)}`;
  }
  return next;
}

function jsoncCommaOffset(text: string, start: number, end: number): number | undefined {
  const scanner = createScanner(text, false);
  let token = scanner.scan();
  while (token !== SyntaxKind.EOF) {
    const offset = scanner.getTokenOffset();
    if (offset >= end) return undefined;
    if (offset >= start && token === SyntaxKind.CommaToken) return offset;
    token = scanner.scan();
  }
  return undefined;
}

function expectedJsonEntry(profile: AgentProfile, ctx: WorkContext): Record<string, unknown> {
  const adapter = requiredAdapter(profile.id);
  const container = adapter.jsonContainer || "mcpServers";
  const snippet = JSON.parse(renderAgentMcpSnippet(profile.id, {
    command: ctx.mcpCommand,
    args: ctx.mcpArgs,
    env: ctx.mcpEnv
  })) as Record<string, unknown>;
  const servers = snippet[container];
  if (!isPlainObject(servers) || !isPlainObject(servers["s-gw"])) {
    throw new Error(`The ${profile.displayName} MCP snippet is not a supported user-level JSON shape.`);
  }
  return servers["s-gw"] as Record<string, unknown>;
}

function codexManagedBlock(profile: AgentProfile, ctx: WorkContext): string {
  return `${managedStart}\n${renderAgentMcpSnippet(profile.id, {
    command: ctx.mcpCommand,
    args: ctx.mcpArgs,
    env: ctx.mcpEnv
  })}\n${managedEnd}`;
}

function findCodexSection(text: string): TomlSection | undefined {
  const heading = /^\s*\[mcp_servers\.(?:s-gw|"s-gw"|'s-gw')\]\s*(?:#.*)?$/m;
  const match = heading.exec(text);
  if (!match || match.index === undefined) return undefined;

  const lineStart = text.lastIndexOf("\n", match.index - 1) + 1;
  const priorLineEnd = lineStart > 0 ? lineStart - 1 : 0;
  const priorLineStart = lineStart > 0 ? text.lastIndexOf("\n", priorLineEnd - 1) + 1 : 0;
  const priorLine = text.slice(priorLineStart, priorLineEnd).trim();
  const managed = priorLine === managedStart;
  const start = managed ? priorLineStart : lineStart;

  let next = text.length;
  const table = /^\s*\[[^\]]+\]\s*(?:#.*)?$/gm;
  table.lastIndex = match.index + match[0].length;
  const nextTable = table.exec(text);
  if (nextTable?.index !== undefined) next = nextTable.index;

  if (managed) {
    const marker = text.indexOf(managedEnd, match.index + match[0].length);
    if (marker !== -1 && marker < next) {
      const markerEnd = text.indexOf("\n", marker);
      next = markerEnd === -1 ? text.length : markerEnd;
    }
  }

  const sectionText = text.slice(start, next).trimEnd();
  const body = text.slice(lineStart, next);
  const command = tomlStringValue(body, "command");
  const args = tomlStringArray(body, "args");
  return { start, end: next, text: sectionText, command, args, managed };
}

function tomlStringValue(text: string, key: string): string | undefined {
  const match = new RegExp(`^\\s*${key}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*")\\s*(?:#.*)?$`, "m").exec(text);
  if (!match) return undefined;
  try {
    return JSON.parse(match[1]) as string;
  } catch {
    return undefined;
  }
}

function tomlStringArray(text: string, key: string): string[] {
  const match = new RegExp(`^\\s*${key}\\s*=\\s*(\\[[^\\n]*\\])\\s*(?:#.*)?$`, "m").exec(text);
  if (!match) return [];
  try {
    const value = JSON.parse(match[1]);
    return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : [];
  } catch {
    return [];
  }
}

function isSgwServerEntry(entry: Record<string, unknown>): boolean {
  if (Array.isArray(entry.command)) {
    const command = entry.command.filter((item): item is string => typeof item === "string");
    if (command.length !== entry.command.length || command.length === 0) return false;
    return isSgwCommand(command[0], command.slice(1));
  }
  if (typeof entry.command !== "string") return false;
  const args = Array.isArray(entry.args) && entry.args.every((item) => typeof item === "string") ? entry.args as string[] : [];
  return isSgwCommand(entry.command, args);
}

function agentEntryContractIssue(agentId: string, entry: Record<string, unknown>): string | undefined {
  if (agentId === "opencode") {
    if (entry.type !== "local" || !Array.isArray(entry.command)) {
      return "does not contain a valid OpenCode local MCP server entry.";
    }
    if (entry.enabled === false) return "has the s-gw MCP server disabled.";
  }
  if (agentId === "vscode" && entry.type !== "stdio") {
    return "does not contain a valid VS Code stdio MCP server entry.";
  }
  if (agentId === "copilot") {
    const tools = entry.tools;
    const localType = entry.type === undefined || entry.type === "local" || entry.type === "stdio";
    if (!localType || !Array.isArray(tools) || tools.length === 0 ||
      !tools.every((tool) => typeof tool === "string")) {
      return "does not contain a complete GitHub Copilot CLI local MCP server entry.";
    }
  }
  return undefined;
}

function sgwServerEntryAvailable(entry: Record<string, unknown>, ctx: WorkContext): boolean {
  if (Array.isArray(entry.command)) {
    const command = entry.command.filter((item): item is string => typeof item === "string");
    return command.length === entry.command.length && command.length > 0 &&
      sgwCommandAvailable(command[0], command.slice(1), ctx);
  }
  if (typeof entry.command !== "string") return false;
  const args = Array.isArray(entry.args) && entry.args.every((item) => typeof item === "string")
    ? entry.args as string[]
    : [];
  return sgwCommandAvailable(entry.command, args, ctx);
}

function isSgwCommand(command: string | undefined, args: string[]): boolean {
  if (!command) return false;
  const base = path.basename(command).toLowerCase().replace(/\.cmd$|\.exe$/, "");
  if (base === "s-gw-mcp" || base === "secret-gateway-mcp") return args.length === 0;
  if (base !== "node" && base !== "nodejs") return false;
  return args.length === 1 && /(?:^|[\\/])dist[\\/]mcp-server\.js$/i.test(args[0]);
}

function sgwCommandAvailable(command: string | undefined, args: string[], ctx: WorkContext): boolean {
  if (ctx.platform === "win32" && command && /\.(?:cmd|bat)$/i.test(command)) return false;
  if (!isSgwCommand(command, args) || !command) return false;
  if (!executableAvailable(command, ctx)) return false;
  const base = path.basename(command).toLowerCase().replace(/\.cmd$|\.exe$/, "");
  if (base === "node" || base === "nodejs") {
    return existsSync(args[0]) && statSync(args[0]).isFile();
  }
  return true;
}

function executableAvailable(command: string, ctx: WorkContext): boolean {
  if (!path.isAbsolute(command) && !command.includes("/") && !command.includes("\\")) {
    return commandPath(command, ctx.pathEnv, ctx.platform, ctx.env) !== undefined;
  }
  try {
    const info = statSync(command);
    return info.isFile() && (ctx.platform === "win32" || (info.mode & 0o111) !== 0);
  } catch {
    return false;
  }
}

function samePath(left: string, right: string, platform: NodeJS.Platform): boolean {
  const resolvedLeft = path.resolve(left);
  const resolvedRight = path.resolve(right);
  if (platform === "win32") return resolvedLeft.toLowerCase() === resolvedRight.toLowerCase();
  return resolvedLeft === resolvedRight;
}

function removeTomlSection(text: string, section: TomlSection): string {
  let start = section.start;
  let end = section.end;
  while (end < text.length && text[end] === "\n") end += 1;
  if (start > 0 && text[start - 1] === "\n") start -= 1;
  const next = `${text.slice(0, start)}${text.slice(end)}`;
  return next.replace(/\n{3,}/g, "\n\n");
}

function resourceReady(resource: AgentResourceStatus): boolean {
  return resource.state === "installed" || resource.state === "existing" || resource.state === "unsupported";
}

function asResult(
  status: AgentIntegrationStatus,
  action: "install" | "uninstall",
  changed: boolean,
  dryRun: boolean,
  backups: string[]
): AgentIntegrationResult {
  return { ...status, action, changed, dryRun, backups };
}

function readManifest(manifestPath: string): AgentManifest {
  if (!existsSync(manifestPath)) return { version: 1, agents: {} };
  const current = readTextIfPresent(manifestPath);
  if (current.error) throw new Error(current.error);
  try {
    const parsed = JSON.parse(current.value || "") as unknown;
    if (!validManifest(parsed)) throw new Error("unsupported manifest shape");
    return parsed;
  } catch (error) {
    throw new Error(`Cannot read ${manifestPath}: ${error instanceof Error ? error.message : String(error)}. s-gw will not overwrite it.`);
  }
}

function validManifest(value: unknown): value is AgentManifest {
  if (!isPlainObject(value) || value.version !== 1 || !isPlainObject(value.agents)) return false;
  for (const ownership of Object.values(value.agents)) {
    if (!isPlainObject(ownership) || typeof ownership.updatedAt !== "string") return false;
    if (ownership.mcp !== undefined && !validOwnedResource(ownership.mcp, ["json-entry", "toml-block"])) return false;
    if (ownership.skill !== undefined && !validOwnedResource(ownership.skill, ["skill"])) return false;
  }
  return true;
}

function validOwnedResource(value: unknown, kinds: OwnedResource["kind"][]): value is OwnedResource {
  if (!isPlainObject(value)) return false;
  return typeof value.path === "string" && value.path.length > 0 &&
    typeof value.fingerprint === "string" && /^[a-f0-9]{64}$/i.test(value.fingerprint) &&
    typeof value.kind === "string" && kinds.includes(value.kind as OwnedResource["kind"]) &&
    (value.parentCreated === undefined || typeof value.parentCreated === "boolean");
}

function writeManifest(manifestPath: string, manifest: AgentManifest): void {
  atomicWrite(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, currentMode(manifestPath, 0o600));
}

function readTextIfPresent(filePath: string): { value?: string; error?: string } {
  try {
    return { value: readRegularFileSnapshot(filePath).content.toString("utf8") };
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return {};
    return { error: `Cannot read ${filePath}: ${error instanceof Error ? error.message : String(error)}` };
  }
}

function backupFile(filePath: string, homeDir: string, agentId: string, label: string): string {
  const backupDir = path.join(homeDir, ".s-gw", "backups", "agents");
  mkdirSync(backupDir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = path.join(backupDir, `${stamp}-${agentId}-${label}-${path.basename(filePath)}-${randomUUID().slice(0, 8)}.bak`);
  const tmp = `${backupPath}.tmp`;
  copyFileSync(filePath, tmp);
  chmodSync(tmp, 0o600);
  renameSync(tmp, backupPath);
  return backupPath;
}

function atomicWrite(filePath: string, content: string | Buffer, mode: number): void {
  mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmp = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(tmp, "wx", mode);
    writeFileSync(fd, content);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, filePath);
    chmodSync(filePath, mode);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(tmp)) unlinkSync(tmp);
    throw error;
  }
}

function currentMode(filePath: string, fallback: number): number {
  try {
    return readRegularFileSnapshot(filePath).mode;
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return fallback;
    throw error;
  }
}

function rememberFile(
  filePath: string,
  rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }>
): void {
  try {
    const snapshot = readRegularFileSnapshot(filePath);
    rollbacks.push({ path: filePath, existed: true, content: snapshot.content, mode: snapshot.mode });
  } catch (error) {
    if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    rollbacks.push({ path: filePath, existed: false });
  }
}

function readRegularFileSnapshot(filePath: string): { content: Buffer; mode: number; modifiedAt: number } {
  let fd: number | undefined;
  try {
    fd = openSync(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const before = fstatSync(fd);
    const current = lstatSync(filePath);
    if (!before.isFile() || current.isSymbolicLink() || !current.isFile() ||
        before.dev !== current.dev || before.ino !== current.ino) {
      throw new Error(`${filePath} is not a stable regular file. s-gw left it unchanged.`);
    }

    const content = readFileSync(fd);
    return { content, mode: before.mode & 0o777, modifiedAt: before.mtimeMs };
  } catch (error) {
    if (isNodeError(error) && error.code === "ELOOP") {
      throw new Error(`${filePath} is a symbolic link. s-gw left it unchanged.`);
    }
    throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function rollbackFiles(rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }>): void {
  for (const rollback of [...rollbacks].reverse()) {
    try {
      if (!rollback.existed) {
        if (existsSync(rollback.path)) unlinkSync(rollback.path);
        removeEmptyDir(path.dirname(rollback.path));
        continue;
      }
      atomicWrite(rollback.path, rollback.content || Buffer.alloc(0), rollback.mode || 0o600);
    } catch {
      // The original error is more useful; backups remain available for recovery.
    }
  }
}

function removeEmptyDir(dir: string): void {
  try {
    if (readdirSync(dir).length === 0) rmdirSync(dir);
  } catch {
    // Parent directories belong to the agent and may contain new files.
  }
}

function resolveHomePath(input: string, homeDir: string): string | undefined {
  if (input === "~") return homeDir;
  if (input.startsWith("~/")) return path.join(homeDir, input.slice(2));
  return undefined;
}

function requiredAdapter(agentId: string): AgentAdapter {
  const adapter = adapters.find((candidate) => candidate.id === agentId);
  if (!adapter) throw new Error(`No safe automatic installer is available for ${agentId}.`);
  return adapter;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function fingerprintObject(value: Record<string, unknown>): string {
  return fingerprintText(JSON.stringify(sortObject(value)));
}

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObject);
  if (!isPlainObject(value)) return value;
  const next: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) next[key] = sortObject(value[key]);
  return next;
}

function fingerprintText(value: string): string {
  return createHash("sha256").update(value.replace(/\r\n/g, "\n").trim()).digest("hex");
}
