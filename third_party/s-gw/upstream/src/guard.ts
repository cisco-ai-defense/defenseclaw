import { spawn } from "node:child_process";
import { readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { resolveAgentProfile, type AgentProfile } from "./agents.js";
import { addLocalSecret, preferredLocalSecretBackend } from "./gateway.js";
import { previewHandle, scanText } from "./scanner.js";
import { SecretStore } from "./store.js";
import type { ScanCandidate } from "./types.js";

export interface GuardRunOptions {
  agent: string;
  command?: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  extraEnv?: Record<string, string>;
  scrubEnv?: boolean;
  persist?: boolean;
  allowedCommands?: string[];
}

export interface GuardEnvFinding {
  name: string;
  handle: string;
  token: string;
  type: string;
  provider?: string;
  ruleId?: string;
  severity?: string;
}

export interface GuardRunPlan {
  agent: {
    id: string;
    displayName: string;
  };
  command: string;
  args: string[];
  cwd: string;
  mode: "guarded";
  scrubbedEnv: GuardEnvFinding[];
  keptEnvCount: number;
  scrubbedEnvCount: number;
  mcp: {
    serverName: string;
    command: string;
  };
  instructions: string;
  dryRun: boolean;
  warnings: string[];
}

export interface GuardRunPreparation {
  plan: GuardRunPlan;
  env: Record<string, string>;
}

export interface GuardLauncher {
  command: string;
  args: string[];
}

const defaultAgentCommands: Record<string, string> = {
  codex: "codex",
  claudecode: "claude",
  opencode: "opencode",
  geminicli: "gemini",
  openclaw: "openclaw",
  zeptoclaw: "zeptoclaw",
  openhands: "openhands",
  antigravity: "agy"
};

export function guardStatus() {
  const agents = [
    "codex",
    "claudecode",
    "cursor",
    "opencode",
    "vscode",
    "openclaw",
    "zeptoclaw",
    "hermes",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "omnigent"
  ].map((id) => {
    const profile = resolveAgentProfile(id);
    return {
      id: profile.id,
      displayName: profile.displayName,
      mcpStatus: profile.mcp.status,
      configPaths: profile.mcp.configPaths,
      defaultRunCommand: defaultAgentCommands[profile.id],
      directRunSupported: Boolean(defaultAgentCommands[profile.id])
    };
  });

  return {
    mode: "guarded-agent-launcher",
    envScrubbing: true,
    rawSecretPolicy: "credential-like environment values are replaced with stable SGW tokens before launch",
    configInstall: "planned",
    agents
  };
}

export async function prepareGuardedRun(store: SecretStore, options: GuardRunOptions): Promise<GuardRunPreparation> {
  const profile = resolveAgentProfile(options.agent);
  const command = options.command || defaultAgentCommands[profile.id];
  if (!command) {
    throw new Error(`Guard run for ${profile.displayName} needs --command because it has no safe default CLI launcher yet.`);
  }

  const cwd = options.cwd || process.cwd();
  const baseEnv = normalizeEnv(options.env || process.env);
  for (const [key, value] of Object.entries(options.extraEnv || {})) {
    baseEnv[key] = value;
  }

  const scrubbedEnv: GuardEnvFinding[] = [];
  let guardedEnv = { ...baseEnv };
  if (options.scrubEnv !== false) {
    const scrubbed = await scrubEnvironment(store, profile, guardedEnv, {
      persist: options.persist === true,
      allowedCommands: options.allowedCommands || []
    });
    guardedEnv = scrubbed.env;
    scrubbedEnv.push(...scrubbed.findings);
  }

  const instructions = guardInstructions(profile, scrubbedEnv);
  guardedEnv.SGW_GUARD_MODE = "1";
  guardedEnv.SGW_GUARD_AGENT = profile.id;
  guardedEnv.SGW_GUARD_INSTRUCTIONS = instructions;
  guardedEnv.SGW_GUARD_TOKENIZED_ENV = JSON.stringify(
    scrubbedEnv.map((item) => ({
      name: item.name,
      handle: item.handle,
      token: item.token,
      type: item.type,
      provider: item.provider,
      ruleId: item.ruleId,
      severity: item.severity
    }))
  );

  const args = options.args || [];
  const warnings: string[] = [];
  if (scrubbedEnv.length === 0) {
    warnings.push("No credential-like environment variables were detected.");
  }
  if (profile.mcp.status !== "supported") {
    warnings.push(`${profile.displayName} MCP setup is marked ${profile.mcp.status}; install/config may need manual review.`);
  }

  return {
    env: guardedEnv,
    plan: {
      agent: {
        id: profile.id,
        displayName: profile.displayName
      },
      command,
      args,
      cwd,
      mode: "guarded",
      scrubbedEnv,
      keptEnvCount: Object.keys(guardedEnv).length - scrubbedEnv.length,
      scrubbedEnvCount: scrubbedEnv.length,
      mcp: {
        serverName: "s-gw",
        command: "s-gw-mcp"
      },
      instructions,
      dryRun: options.persist !== true,
      warnings
    }
  };
}

export async function runGuardedAgent(store: SecretStore, options: GuardRunOptions): Promise<number> {
  const prepared = await prepareGuardedRun(store, {
    ...options,
    persist: true
  });

  process.stderr.write(
    `s-gw guard mode: launching ${prepared.plan.agent.displayName}; tokenized ${prepared.plan.scrubbedEnvCount} environment credential(s).\n`
  );

  const launcher = resolveGuardLauncher(prepared.plan.command, prepared.plan.args, {
    cwd: prepared.plan.cwd,
    env: prepared.env
  });
  const child = spawn(launcher.command, launcher.args, {
    cwd: prepared.plan.cwd,
    env: prepared.env,
    stdio: "inherit",
    shell: false
  });

  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) {
        resolve(128 + signalToExitCode(signal));
        return;
      }
      resolve(code ?? 1);
    });
  });
}

export function resolveGuardLauncher(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; platform?: NodeJS.Platform } = {}
): GuardLauncher {
  const platform = options.platform || process.platform;
  if (platform !== "win32") {
    return { command, args: [...args] };
  }

  const resolved = findWindowsCommand(command, options.cwd || process.cwd(), options.env || process.env);
  if (!resolved) {
    const extension = path.win32.extname(command).toLowerCase();
    if ([".bat", ".cmd", ".ps1"].includes(extension)) {
      throw new Error(`Windows guard mode will not launch unresolved script ${command}.`);
    }
    throw new Error(`Windows guard mode could not resolve executable ${command}.`);
  }

  const extension = path.extname(resolved).toLowerCase();
  if (extension === ".cmd") {
    const script = canonicalNpmNodeTarget(resolved);
    return { command: process.execPath, args: [script, ...args] };
  }
  if (extension === ".bat" || extension === ".ps1") {
    throw new Error(
      `Windows guard mode will not launch script ${resolved}. Use a native executable or a canonical npm .cmd shim.`
    );
  }
  if (extension !== ".exe" && extension !== ".com") {
    throw new Error(`Windows guard mode will not launch non-native executable ${resolved}.`);
  }

  return { command: resolved, args: [...args] };
}

function findWindowsCommand(command: string, cwd: string, env: NodeJS.ProcessEnv): string | undefined {
  if (!command || command.includes("\0")) return undefined;

  const extension = path.extname(command);
  const suffixes = extension
    ? [""]
    : windowsPathExtensions(env).filter((suffix) => suffix !== ".PS1");
  const hasDirectory = command.includes("/") || command.includes("\\");
  const directories = hasDirectory
    ? [""]
    : windowsPath(env).split(";").map((item) => trimPathEntry(item)).filter(Boolean);

  for (const directory of directories) {
    const base = hasDirectory
      ? path.resolve(cwd, command)
      : path.resolve(directory, command);
    for (const suffix of suffixes) {
      const candidate = `${base}${suffix.toLowerCase()}`;
      const exact = regularFile(candidate) ? candidate : windowsCaseVariant(base, suffix);
      if (exact && regularFile(exact)) return exact;
    }
  }

  return undefined;
}

function windowsPathExtensions(env: NodeJS.ProcessEnv): string[] {
  const raw = envValue(env, "PATHEXT") || ".COM;.EXE;.BAT;.CMD";
  const allowed = new Set([".COM", ".EXE", ".BAT", ".CMD"]);
  const out: string[] = [];
  for (const item of raw.split(";")) {
    const value = item.trim().toUpperCase();
    if (!allowed.has(value) || out.includes(value)) continue;
    out.push(value);
  }
  return out.length > 0 ? out : [".COM", ".EXE", ".BAT", ".CMD"];
}

function windowsPath(env: NodeJS.ProcessEnv): string {
  return envValue(env, "PATH") || "";
}

function envValue(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const entry = Object.entries(env).find(([key]) => key.toUpperCase() === name);
  return typeof entry?.[1] === "string" ? entry[1] : undefined;
}

function trimPathEntry(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function windowsCaseVariant(base: string, suffix: string): string | undefined {
  if (!suffix) return undefined;
  const upper = `${base}${suffix}`;
  if (regularFile(upper)) return upper;
  return undefined;
}

function regularFile(filePath: string): boolean {
  try {
    return statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function canonicalNpmNodeTarget(shimPath: string): string {
  let source: string;
  try {
    source = readFileSync(shimPath, "utf8");
  } catch (error) {
    throw new Error(`Could not read Windows launcher ${shimPath}: ${errorMessage(error)}`);
  }

  if (source.length > 64 * 1024 || source.includes("\0")) {
    throw unsupportedWindowsShim(shimPath);
  }
  const normalized = source.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  if (normalized.includes("\r")) {
    throw unsupportedWindowsShim(shimPath);
  }
  const lines = normalized.split("\n");
  const header = [
    "@ECHO off",
    "GOTO start",
    ":find_dp0",
    "SET dp0=%~dp0",
    "EXIT /b",
    ":start",
    "SETLOCAL",
    "CALL :find_dp0"
  ];
  if (!header.every((line, index) => lines[index] === line)) {
    throw unsupportedWindowsShim(shimPath);
  }
  if (!lines.includes('IF EXIST "%dp0%\\node.exe" (')
    || !lines.includes('  SET "_prog=%dp0%\\node.exe"')
    || !lines.includes('  SET "_prog=node"')) {
    throw unsupportedWindowsShim(shimPath);
  }

  const nonEmpty = lines.filter((line) => line.length > 0);
  const launchLine = nonEmpty.at(-1) || "";
  const match = launchLine.match(
    /^endLocal & goto #_undefined_# 2>NUL \|\| title %COMSPEC% & "%_prog%"\s+"%dp0%\\([^"]+)"\s+%\*$/
  );
  if (!match || (normalized.match(/%\*/g) || []).length !== 1) {
    throw unsupportedWindowsShim(shimPath);
  }

  const segments = match[1].split(/[\\/]+/);
  const shimDirectory = path.dirname(shimPath);
  const localBinShim = path.basename(shimDirectory).toLowerCase() === ".bin"
    && path.basename(path.dirname(shimDirectory)).toLowerCase() === "node_modules";
  const localParent = localBinShim && segments[0] === "..";
  const targetSegments = localParent ? segments.slice(1) : segments;
  if (targetSegments.length === 0
    || targetSegments.some((segment) => !safeShimSegment(segment))
    || segments.slice(localParent ? 1 : 0).includes("..")) {
    throw unsupportedWindowsShim(shimPath);
  }
  const target = path.resolve(shimDirectory, ...segments);
  if (!/\.(?:cjs|js|mjs)$/i.test(target) || !regularFile(target)) {
    throw unsupportedWindowsShim(shimPath);
  }

  const shimRoot = realpathSync(localParent ? path.dirname(shimDirectory) : shimDirectory);
  const realTarget = realpathSync(target);
  const relative = path.relative(shimRoot, realTarget);
  if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw unsupportedWindowsShim(shimPath);
  }
  return realTarget;
}

function safeShimSegment(segment: string): boolean {
  return Boolean(segment)
    && segment !== "."
    && segment !== ".."
    && !/[\x00-\x1f%!:*?"<>|&^]/.test(segment);
}

function unsupportedWindowsShim(shimPath: string): Error {
  return new Error(
    `Windows guard mode refused ${shimPath} because it is not a canonical npm Node.js .cmd shim. Use a native executable or reinstall the npm command.`
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function scrubEnvironment(
  store: SecretStore,
  profile: AgentProfile,
  env: Record<string, string>,
  options: { persist: boolean; allowedCommands: string[] }
): Promise<{ env: Record<string, string>; findings: GuardEnvFinding[] }> {
  const out = { ...env };
  const findings: GuardEnvFinding[] = [];

  for (const [name, value] of Object.entries(env)) {
    if (shouldDropEnv(name)) {
      delete out[name];
      continue;
    }

    if (!value || shouldSkipEnv(name)) {
      continue;
    }

    const line = `${name}=${value}`;
    const result = await scanText(line, async (candidate: ScanCandidate) => {
      if (!options.persist) {
        return previewHandle(candidate);
      }

      const record = await addLocalSecret(store, {
        name: `${profile.id} env ${name}`,
        type: candidate.type,
        provider: candidate.provider,
        ruleId: candidate.ruleId,
        severity: candidate.severity,
        confidence: candidate.confidence,
        value: candidate.value,
        source: `guard-env:${profile.id}:${name}`,
        policy: {
          injectEnv: name,
          allowedCommands: options.allowedCommands,
          maxOutputBytes: 16_384
        }
      }, preferredLocalSecretBackend());
      return record.handle;
    });

    if (result.findings.length === 0) {
      continue;
    }

    const prefix = `${name}=`;
    out[name] = result.tokenizedText.startsWith(prefix)
      ? result.tokenizedText.slice(prefix.length)
      : result.findings.map((finding) => finding.token).join("\n");

    for (const finding of result.findings) {
      findings.push({
        name,
        handle: finding.handle,
        token: finding.token,
        type: finding.type,
        provider: finding.provider,
        ruleId: finding.ruleId,
        severity: finding.severity
      });
    }
  }

  return { env: out, findings };
}

function normalizeEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (typeof value === "string") {
      out[key] = value;
    }
  }
  return out;
}

function shouldDropEnv(name: string): boolean {
  return (
    name === "SGW_MASTER_PASSPHRASE" ||
    name === "SGW_GUARD_AGENT" ||
    name === "SGW_GUARD_INSTRUCTIONS" ||
    name === "SGW_GUARD_MODE" ||
    name === "SGW_GUARD_TOKENIZED_ENV"
  );
}

function shouldSkipEnv(name: string): boolean {
  const commonNonSecret = new Set([
    "HOME",
    "LANG",
    "LOGNAME",
    "OLDPWD",
    "PATH",
    "PWD",
    "SHELL",
    "SHLVL",
    "TERM",
    "TMPDIR",
    "USER",
    "_"
  ]);

  return (
    commonNonSecret.has(name) ||
    name.startsWith("npm_")
  );
}

function guardInstructions(profile: AgentProfile, scrubbedEnv: GuardEnvFinding[]): string {
  const names = scrubbedEnv.map((item) => `${item.name}=${item.token}`).join(", ") || "none";
  return [
    `s-gw guard mode is active for ${profile.displayName}.`,
    `Credential-like environment values were replaced with SGW handles: ${names}.`,
    "Treat SGW handles as unique secret representations, not redactions.",
    "Do not ask the user to paste raw credentials.",
    "Use s-gw MCP tools to scan files/text and request local approved execution when a credential-backed action is needed.",
    "Raw secret values must remain in the local s-gw store and local approved child processes."
  ].join(" ");
}

function signalToExitCode(signal: NodeJS.Signals): number {
  const known: Partial<Record<NodeJS.Signals, number>> = {
    SIGHUP: 1,
    SIGINT: 2,
    SIGQUIT: 3,
    SIGTERM: 15
  };

  return known[signal] ?? 1;
}
