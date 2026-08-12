import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, chmod, lstat, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { getSgwHome } from "./paths.js";
import { sanitizeKnownSecrets } from "./scanner.js";
import type { CommandAction, ExecutionSummary, RequestRecord, SecretRecord } from "./types.js";
import {
  createPrivateWindowsSshDirectory,
  trustedWindowsSystemExecutable,
  trustedWindowsSystemRoot,
  verifyPrivateWindowsKeyFile
} from "./windows-acl.js";

export const SGW_SSH_SESSION_COMMAND = "s-gw:ssh-session";
export const WINDOWS_SSH_KEY_ONLY_ERROR = "Windows owned SSH supports ssh-key and private-key handles only; password and keyboard-interactive authentication are disabled.";
export const WINDOWS_SSH_CLOSE_MESSAGE = "Windows uses one-shot SSH commands; there is no persistent s-gw SSH session to close.";

export interface SshSessionInput {
  target: string;
  port?: number;
  args?: string[];
  injectEnv?: string;
  workingDir?: string;
  timeoutMs?: number;
}

interface ProcessResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export function buildSshSessionAction(input: SshSessionInput): CommandAction {
  const target = normalizeSshTarget(input.target);
  const port = normalizeSshPort(input.port);
  return {
    kind: "ssh_session",
    command: SGW_SSH_SESSION_COMMAND,
    args: input.args || [],
    injectEnv: input.injectEnv || "SGW_SSH_CREDENTIAL",
    workingDir: input.workingDir,
    timeoutMs: input.timeoutMs ?? 30_000,
    ssh: { target, port }
  };
}

export function defaultSshInjectEnv(secret: SecretRecord): string {
  if (secret.policy.injectEnv) {
    return secret.policy.injectEnv;
  }
  if (secret.type === "ssh-key" || secret.type === "private-key") {
    return "SGW_SSH_PRIVATE_KEY";
  }
  return "SGW_SSH_PASSWORD";
}

export function normalizeSshTarget(target: string): string {
  const trimmed = String(target || "").trim();
  if (!trimmed || trimmed.includes("\0") || /[\r\n]/.test(trimmed)) {
    throw new Error("SSH target is required and cannot contain control characters.");
  }
  if (trimmed.startsWith("-") || /\s/.test(trimmed)) {
    throw new Error(`Invalid SSH target: ${trimmed}`);
  }
  return trimmed;
}

export function normalizeSshPort(port?: number): number {
  const value = port ?? 22;
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error("SSH port must be an integer from 1 to 65535.");
  }
  return value;
}

export function sshSessionIdentity(action: CommandAction): string {
  const target = action.ssh?.target ? normalizeSshTarget(action.ssh.target) : "";
  const port = normalizeSshPort(action.ssh?.port);
  return `${target}:${port}`;
}

export async function runOwnedSshSession(
  request: RequestRecord,
  secretRecord: SecretRecord,
  secretValue: string,
  home = getSgwHome()
): Promise<ExecutionSummary> {
  if (request.action.kind !== "ssh_session") {
    throw new Error("runOwnedSshSession requires an ssh_session action.");
  }

  const target = normalizeSshTarget(request.action.ssh?.target || "");
  const port = normalizeSshPort(request.action.ssh?.port);
  const sshPath = await resolveSshClient();
  const maxOutput = secretRecord.policy.maxOutputBytes || 16_384;
  const captureCap = maxOutput + Math.max(secretValue.length, 0);
  let auth: PreparedSshAuth | undefined;

  try {
    assertSshCredentialSupported(secretRecord);
    if (process.platform === "win32") {
      auth = await prepareSshAuth(secretRecord, secretValue);
      return await runWindowsSshCommand(request, sshPath, target, port, auth, secretValue, maxOutput, captureCap);
    }

    auth = await prepareSshAuth(secretRecord, secretValue);
    const socketPath = await controlSocketPath(home, request.handle, target, port);
    if (!(await controlMasterIsActive(sshPath, socketPath, target, port, request.action.timeoutMs, captureCap))) {
      await openControlMaster(
        sshPath,
        socketPath,
        target,
        port,
        request.action.timeoutMs,
        auth,
        captureCap,
        maxOutput,
        request.handle,
        secretValue
      );
    }

    const remoteArgs = request.action.args.length > 0 ? request.action.args : ["true"];
    const result = await runProcess(
      sshPath,
      [
        "-S", socketPath,
        "-o", "ControlMaster=no",
        "-o", "BatchMode=yes",
        "-p", String(port),
        target,
        ...remoteArgs
      ],
      {
        timeoutMs: request.action.timeoutMs,
        env: await baseSshEnv(),
        maxOutputBytes: captureCap,
        rejectOnNonZero: false
      }
    );

    return sshSummary(request, result, secretValue, maxOutput);
  } catch (error) {
    throw sanitizedSshError(error, request.handle, secretValue, maxOutput);
  } finally {
    await auth?.cleanup();
  }
}

export async function closeOwnedSshSession(input: { handle: string; target: string; port?: number; home?: string }): Promise<ProcessResult> {
  const target = normalizeSshTarget(input.target);
  const port = normalizeSshPort(input.port);
  if (process.platform === "win32") {
    return {
      exitCode: 0,
      signal: null,
      stdout: `${WINDOWS_SSH_CLOSE_MESSAGE}\n`,
      stderr: "",
      durationMs: 0,
      timedOut: false
    };
  }
  const socketPath = await controlSocketPath(input.home || getSgwHome(), input.handle, target, port);
  const sshPath = await resolveSshClient();
  return runProcess(sshPath, ["-S", socketPath, "-O", "exit", "-p", String(port), target], {
    timeoutMs: 10_000,
    env: await baseSshEnv(),
    maxOutputBytes: 16_384,
    rejectOnNonZero: false
  });
}

export function assertSshCredentialSupported(secret: SecretRecord): void {
  if (process.platform !== "win32") {
    return;
  }
  if (secret.type !== "ssh-key" && secret.type !== "private-key") {
    throw new Error(WINDOWS_SSH_KEY_ONLY_ERROR);
  }
}

async function runWindowsSshCommand(
  request: RequestRecord,
  sshPath: string,
  target: string,
  port: number,
  auth: PreparedSshAuth,
  secretValue: string,
  maxOutput: number,
  captureCap: number
): Promise<ExecutionSummary> {
  const remoteArgs = request.action.args.length > 0 ? request.action.args : ["true"];
  const sshArgs = [
    "-T",
    "-F", "none",
    "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "PermitLocalCommand=no",
    "-o", "IdentityAgent=none",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "GSSAPIAuthentication=no",
    "-o", "HostbasedAuthentication=no",
    "-o", "PubkeyAuthentication=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "BatchMode=yes",
    ...auth.args,
    "-p", String(port),
    target,
    ...remoteArgs
  ];
  if (!auth.validateBeforeSpawn) {
    throw new Error("The Windows SSH private key has no pre-spawn validation.");
  }
  await auth.validateBeforeSpawn();
  const result = await runProcess(
    sshPath,
    sshArgs,
    {
      timeoutMs: request.action.timeoutMs,
      env: auth.env,
      maxOutputBytes: captureCap,
      rejectOnNonZero: false
    }
  );
  return sshSummary(request, result, secretValue, maxOutput);
}

async function resolveSshClient(): Promise<string> {
  const configured = process.env.SGW_SSH_CLI?.trim();
  if (configured) {
    return resolveIsolatedTestSshClient(configured);
  }

  if (process.platform === "win32") {
    return trustedWindowsSystemExecutable("OpenSSH", "ssh.exe");
  }

  const candidate = "/usr/bin/ssh";
  const info = await lstat(candidate).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
    throw new Error("The trusted system SSH client is unavailable at /usr/bin/ssh.");
  }
  const actual = await realpath(candidate).catch(() => "");
  if (!actual || actual !== candidate) {
    throw new Error("The trusted system SSH client path could not be validated.");
  }
  return actual;
}

async function resolveIsolatedTestSshClient(configured: string): Promise<string> {
  if (process.env.SGW_TEST_MODE !== "1") {
    throw new Error("SGW_SSH_CLI is available only in isolated test mode.");
  }
  if (!path.isAbsolute(configured)) {
    throw new Error("SGW_SSH_CLI must be an absolute path in isolated test mode.");
  }

  const info = await lstat(configured).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink()) {
    throw new Error("The configured Windows SSH client is not a regular local file.");
  }
  const actual = await realpath(configured).catch(() => "");
  if (!actual || !sameWindowsPath(actual, configured)) {
    throw new Error("The configured test SSH client path could not be validated.");
  }
  const configuredRoot = process.env.SGW_TEST_HOME_ROOT?.trim();
  if (!configuredRoot) {
    throw new Error("SGW_TEST_HOME_ROOT is required for a test SSH client override.");
  }
  const testRoot = await realpath(path.resolve(configuredRoot)).catch(() => "");
  if (!testRoot || !isPathInside(actual, testRoot)) {
    throw new Error("The configured test SSH client must stay inside SGW_TEST_HOME_ROOT.");
  }
  return actual;
}

async function controlMasterIsActive(
  sshPath: string,
  socketPath: string,
  target: string,
  port: number,
  timeoutMs: number,
  maxOutputBytes: number
): Promise<boolean> {
  const exists = await fileExists(socketPath);
  if (!exists) {
    return false;
  }

  const result = await runProcess(sshPath, ["-S", socketPath, "-O", "check", "-p", String(port), target], {
    timeoutMs: timeoutMs > 0 ? Math.min(timeoutMs, 10_000) : 10_000,
    env: await baseSshEnv(),
    maxOutputBytes,
    rejectOnNonZero: false
  });
  return result.exitCode === 0;
}

async function openControlMaster(
  sshPath: string,
  socketPath: string,
  target: string,
  port: number,
  timeoutMs: number,
  auth: PreparedSshAuth,
  captureBytes: number,
  maxOutputBytes: number,
  handle: string,
  secretValue: string
): Promise<void> {
  const result = await runProcess(
    sshPath,
    [
      "-M",
      "-N",
      "-f",
      "-o", "ControlMaster=yes",
      "-o", `ControlPath=${socketPath}`,
      "-o", "ControlPersist=10m",
      "-o", "ServerAliveInterval=30",
      "-o", "ServerAliveCountMax=2",
      "-o", "StrictHostKeyChecking=accept-new",
      "-o", "BatchMode=no",
      "-p", String(port),
      ...auth.args,
      target
    ],
    { timeoutMs, env: auth.env, maxOutputBytes: captureBytes, rejectOnNonZero: false }
  );

  if (result.exitCode !== 0) {
    const detail = result.stderr || result.stdout || `ssh exited ${result.exitCode}`;
    const cleanDetail = sanitizeKnownSecrets(detail, [{ handle, value: secretValue }]);
    throw new Error(`Could not open s-gw-owned SSH session to ${target}: ${capBytes(cleanDetail.trim(), maxOutputBytes)}`);
  }
}

interface PreparedSshAuth {
  args: string[];
  env: NodeJS.ProcessEnv;
  cleanup: () => Promise<void>;
  validateBeforeSpawn?: () => Promise<void>;
}

async function prepareSshAuth(secret: SecretRecord, value: string): Promise<PreparedSshAuth> {
  const env = await baseSshEnv();
  const windowsDir = process.platform === "win32" ? await createPrivateWindowsSshDirectory() : undefined;
  const tmpDir = windowsDir?.dirPath || await mkdtemp(path.join(os.tmpdir(), "sgw-ssh-"));
  let cleaned = false;
  const cleanup = async () => {
    if (cleaned) {
      return;
    }
    await rm(tmpDir, { recursive: true, force: true });
    if (await fileExists(tmpDir)) {
      throw new Error("Could not remove the temporary SSH credential directory.");
    }
    cleaned = true;
  };

  try {
    if (secret.type === "ssh-key" || secret.type === "private-key" || looksLikePrivateKey(value)) {
      const keyPath = path.join(tmpDir, "identity");
      let validateBeforeSpawn: (() => Promise<void>) | undefined;
      if (process.platform === "win32") {
        await writeFile(keyPath, value.endsWith("\n") ? value : `${value}\n`, { flag: "wx" });
        validateBeforeSpawn = await verifyPrivateWindowsKeyFile(keyPath, windowsDir!.sid);
      } else {
        await writeFile(keyPath, value.endsWith("\n") ? value : `${value}\n`, { mode: 0o600 });
        await chmod(keyPath, 0o600);
      }
      return {
        args: ["-i", keyPath, "-o", "IdentitiesOnly=yes"],
        env,
        cleanup,
        validateBeforeSpawn
      };
    }

    const passPath = path.join(tmpDir, "password");
    const askpassPath = path.join(tmpDir, "askpass.sh");
    await writeFile(passPath, value, { mode: 0o600 });
    await chmod(passPath, 0o600);
    await writeFile(askpassPath, '#!/bin/sh\ncat "$SGW_ASKPASS_FILE"\n', { mode: 0o700 });
    await chmod(askpassPath, 0o700);
    return {
      args: ["-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no"],
      env: {
        ...env,
        DISPLAY: env.DISPLAY || "sgw-local",
        SSH_ASKPASS_REQUIRE: "force",
        SSH_ASKPASS: askpassPath,
        SGW_ASKPASS_FILE: passPath
      },
      cleanup
    };
  } catch (error) {
    try {
      await cleanup();
    } catch (cleanupError) {
      throw new Error(`SSH credential preparation failed, and its temporary directory could not be removed: ${errorMessage(cleanupError)}`);
    }
    throw error;
  }
}

function looksLikePrivateKey(value: string): boolean {
  return /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(value);
}

async function controlSocketPath(home: string, handle: string, target: string, port: number): Promise<string> {
  const dir = process.env.SGW_SSH_CONTROL_DIR || path.join(home, "ssh-sessions");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const digest = createHash("sha256")
    .update(handle)
    .update("\0")
    .update(target)
    .update("\0")
    .update(String(port))
    .digest("base64url")
    .slice(0, 32);
  return path.join(dir, `ctl-${digest}`);
}

async function baseSshEnv(): Promise<NodeJS.ProcessEnv> {
  if (process.platform === "win32") {
    const systemRoot = await trustedWindowsSystemRoot();
    const env: NodeJS.ProcessEnv = {
      SystemRoot: systemRoot,
      WINDIR: systemRoot,
      PATH: `${path.join(systemRoot, "System32")};${systemRoot}`
    };
    for (const key of ["USERPROFILE", "TEMP", "TMP"]) {
      const value = process.env[key];
      if (value) {
        env[key] = value;
      }
    }
    return env;
  }

  const env: NodeJS.ProcessEnv = {};
  for (const key of ["HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME", "SHELL", "TERM", "TMPDIR", "USER"]) {
    const value = process.env[key];
    if (value) {
      env[key] = value;
    }
  }
  env.PATH = "/usr/bin:/bin";
  return env;
}

async function runProcess(
  command: string,
  args: string[],
  options: {
    timeoutMs: number;
    env: NodeJS.ProcessEnv;
    maxOutputBytes: number;
    rejectOnNonZero?: boolean;
  }
): Promise<ProcessResult> {
  const started = Date.now();
  const child = spawn(command, args, {
    env: options.env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  const timeout = options.timeoutMs > 0
    ? setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => child.kill("SIGKILL"), 1_500);
    }, options.timeoutMs)
    : undefined;

  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendBounded(stdout, chunk.toString("utf8"), options.maxOutputBytes);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendBounded(stderr, chunk.toString("utf8"), options.maxOutputBytes);
  });

  let status: { code: number | null; signal: NodeJS.Signals | null };
  try {
    status = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.on("error", reject);
      child.on("close", (code, signal) => resolve({ code, signal }));
    });
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
    if (killTimer) {
      clearTimeout(killTimer);
    }
  }

  const result = {
    exitCode: timedOut ? 124 : status.code,
    signal: status.signal,
    stdout,
    stderr,
    durationMs: Date.now() - started,
    timedOut
  };

  if (options.rejectOnNonZero !== false && result.exitCode !== 0) {
    throw new Error(stderr || stdout || `Command exited ${result.exitCode}`);
  }

  return result;
}

function appendBounded(current: string, extra: string, maxBytes: number): string {
  const combined = current + extra;
  if (Buffer.byteLength(combined, "utf8") <= maxBytes) {
    return combined;
  }
  return capBytes(combined, maxBytes);
}

function capBytes(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text, "utf8") <= maxBytes) {
    return text;
  }
  return text.slice(0, maxBytes) + "\n<<SGW_OUTPUT_TRUNCATED>>";
}

function sshSummary(
  request: RequestRecord,
  result: ProcessResult,
  secretValue: string,
  maxOutput: number
): ExecutionSummary {
  const known = [{ handle: request.handle, value: secretValue }];
  const sanitizedStdout = sanitizeKnownSecrets(result.stdout, known);
  const sanitizedStderr = sanitizeKnownSecrets(result.stderr, known);
  const cleanStdout = capBytes(sanitizedStdout, maxOutput);
  const cleanStderr = capBytes(sanitizedStderr, maxOutput);
  return {
    exitCode: result.timedOut ? 124 : result.exitCode,
    signal: result.signal,
    stdout: cleanStdout,
    stderr: cleanStderr,
    proof: proofFor(request, cleanStdout, cleanStderr),
    durationMs: result.durationMs,
    timeoutMs: request.action.timeoutMs,
    timedOut: result.timedOut,
    sanitized: cleanStdout !== result.stdout || cleanStderr !== result.stderr
  };
}

function sanitizedSshError(error: unknown, handle: string, secretValue: string, maxOutput: number): Error {
  const message = sanitizeKnownSecrets(errorMessage(error), [{ handle, value: secretValue }]);
  return new Error(capBytes(message, maxOutput));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sameWindowsPath(left: string, right: string): boolean {
  return path.normalize(left).replace(/[\\/]+$/, "").toLowerCase()
    === path.normalize(right).replace(/[\\/]+$/, "").toLowerCase();
}

function isPathInside(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function proofFor(request: RequestRecord, stdout: string, stderr: string): string {
  const digest = createHash("sha256")
    .update(request.id)
    .update(request.handle)
    .update(stdout)
    .update(stderr)
    .digest("base64url")
    .slice(0, 24);
  return `s-gw-proof:${request.id}:${digest}`;
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}
