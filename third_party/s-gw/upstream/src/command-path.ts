import { accessSync, constants, realpathSync, statSync } from "node:fs";
import path from "node:path";

export interface CommandPathOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
}

const windowsNativeExtensions = [".EXE", ".COM"];
const windowsScriptExtensions = new Set([".CMD", ".BAT", ".PS1"]);

export function resolveCommandExecutable(command: string, options: CommandPathOptions = {}): string {
  const platform = options.platform || process.platform;
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  const requested = command.trim();
  if (!requested || requested.includes("\0")) {
    throw new Error("Command must be a non-empty executable name without null bytes.");
  }

  rejectWindowsScript(requested, platform, pathApi);
  const names = executableNames(requested, platform, options.env || process.env, pathApi);
  if (pathApi.isAbsolute(requested)) {
    for (const name of names) {
      const found = canonicalExecutable(name, platform);
      if (found) return found;
    }
    throw new Error(`Command executable is unavailable or not executable: ${requested}`);
  }

  if (requested.includes("/") || requested.includes("\\")) {
    throw new Error(`Relative command paths are not allowed: ${requested}`);
  }

  const env = options.env || process.env;
  const cwd = options.cwd || process.cwd();
  for (const entry of commandPath(env, platform).split(pathApi.delimiter)) {
    const directory = trimPathEntry(entry, platform);
    if (!directory) continue;
    const absoluteDir = pathApi.resolve(cwd, directory);
    for (const name of names) {
      const found = canonicalExecutable(pathApi.join(absoluteDir, name), platform);
      if (found) return found;
    }
  }

  throw new Error(`Command executable could not be resolved on PATH: ${requested}`);
}

export function verifyPinnedCommand(
  command: string,
  resolvedCommand: string | undefined,
  options: CommandPathOptions = {}
): string {
  if (!resolvedCommand) {
    throw new Error(
      "This legacy request has no pinned executable. Create a new request so s-gw can approve the exact command path."
    );
  }

  const platform = options.platform || process.platform;
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  if (!pathApi.isAbsolute(resolvedCommand) || resolvedCommand.includes("\0")) {
    throw new Error("The request's pinned executable path is invalid. Create a new request.");
  }
  rejectWindowsScript(resolvedCommand, platform, pathApi);

  const pinned = canonicalExecutable(resolvedCommand, platform);
  if (!pinned || !sameExecutablePath(pinned, resolvedCommand, platform)) {
    throw new Error("The request's pinned executable is unavailable or no longer canonical. Create a new request.");
  }

  const current = resolveCommandExecutable(command, options);
  if (!sameExecutablePath(current, pinned, platform)) {
    throw new Error(
      `Command '${command}' resolves to a different executable than the approved request. Create a new request.`
    );
  }
  return pinned;
}

export function isAbsoluteCommand(command: string, platform: NodeJS.Platform = process.platform): boolean {
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  return pathApi.isAbsolute(command.trim());
}

function executableNames(
  requested: string,
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  pathApi: typeof path.posix | typeof path.win32
): string[] {
  if (platform !== "win32") return [requested];

  const ext = pathApi.extname(requested).toUpperCase();
  if (ext) {
    if (!windowsNativeExtensions.includes(ext)) {
      throw new Error(`Windows command execution requires a native .exe or .com executable: ${requested}`);
    }
    return [requested];
  }

  const configured = envValue(env, "PATHEXT", platform) || windowsNativeExtensions.join(";");
  const extensions: string[] = [];
  for (const item of configured.split(";")) {
    const value = item.trim().toUpperCase();
    if (!windowsNativeExtensions.includes(value) || extensions.includes(value)) continue;
    extensions.push(value);
  }
  for (const fallback of windowsNativeExtensions) {
    if (!extensions.includes(fallback)) extensions.push(fallback);
  }
  return extensions.map((extension) => `${requested}${extension.toLowerCase()}`);
}

function canonicalExecutable(candidate: string, platform: NodeJS.Platform): string | undefined {
  try {
    const canonical = realpathSync.native(candidate);
    if (!statSync(canonical).isFile()) return undefined;
    accessSync(canonical, platform === "win32" ? constants.F_OK : constants.X_OK);
    return canonical;
  } catch {
    return undefined;
  }
}

function commandPath(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): string {
  return envValue(env, "PATH", platform) || "";
}

function envValue(env: NodeJS.ProcessEnv, name: string, platform: NodeJS.Platform): string | undefined {
  if (platform !== "win32") return env[name];
  const entry = Object.entries(env).find(([key]) => key.toUpperCase() === name);
  return typeof entry?.[1] === "string" ? entry[1] : undefined;
}

function trimPathEntry(value: string, platform: NodeJS.Platform): string {
  const trimmed = value.trim();
  if (platform === "win32" && trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function rejectWindowsScript(
  command: string,
  platform: NodeJS.Platform,
  pathApi: typeof path.posix | typeof path.win32
): void {
  if (platform !== "win32") return;
  const ext = pathApi.extname(command).toUpperCase();
  if (windowsScriptExtensions.has(ext)) {
    throw new Error(`Windows script launchers are not accepted for credential execution: ${command}`);
  }
}

function sameExecutablePath(left: string, right: string, platform: NodeJS.Platform): boolean {
  if (platform === "win32") return left.toLowerCase() === right.toLowerCase();
  return left === right;
}
