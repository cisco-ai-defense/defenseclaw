import { createHash } from "node:crypto";
import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { verifyPinnedCommand } from "./command-path.js";
import {
  assertActionAllowed,
  type ExecutionLaunch,
  type ReusableExecutionPermit,
  type SecretStore
} from "./store.js";
import { sanitizeKnownSecrets } from "./scanner.js";
import { assertSshCredentialSupported, runOwnedSshSession } from "./ssh.js";
import type { ExecutionSummary, RequestRecord, SecretRecord } from "./types.js";

export interface ExecutionOptions {
  engine?: "auto" | "rust" | "typescript";
  coreBinary?: string;
}

export async function executeApprovedRequest(
  store: SecretStore,
  requestId: string,
  options: ExecutionOptions = {}
): Promise<ExecutionSummary> {
  const request = await store.claimApprovedRequest(requestId);
  try {
    const summary = await executeRequest(store, request, options);
    await store.markExecuted(requestId, summary);
    return summary;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await store.markFailed(requestId, message);
    throw error;
  }
}

export async function executeReusablePermit(
  store: SecretStore,
  permit: ReusableExecutionPermit,
  options: ExecutionOptions = {}
): Promise<ExecutionSummary> {
  const initialRequest = await store.validateReusableExecutionPermit(permit);
  if (initialRequest.action.kind !== "env_command") {
    throw new Error("Reusable execution permits only support environment-command actions.");
  }

  const prepared = await prepareEnvExecution(store, initialRequest);
  let nativeLaunch = false;
  try {
    return await store.launchReusableExecution(permit, (request) => {
      const launch = launchReusableEnvCommand(
        request,
        prepared.command,
        prepared.secretRecord,
        prepared.secretValue,
        prepared.extraSecrets,
        options
      );
      nativeLaunch = launch.nativeLaunch;
      return launch;
    });
  } catch (error) {
    if (!nativeLaunch || executionEngine(options.engine) !== "auto" || !isNativeLaunchError(error)) {
      throw error;
    }

    return store.launchReusableExecution(permit, (request) => {
      return startTypeScriptEnvCommand(
        request,
        prepared.command,
        prepared.secretRecord,
        prepared.secretValue,
        prepared.extraSecrets
      );
    });
  }
}

function commandForExecution(request: RequestRecord): string {
  if (request.action.kind !== "env_command") {
    throw new Error("Pinned command validation only supports environment-command actions.");
  }
  return verifyPinnedCommand(request.action.command, request.action.resolvedCommand);
}

async function executeRequest(
  store: SecretStore,
  request: RequestRecord,
  options: ExecutionOptions,
  executionOptions: { cacheOnePassword?: boolean } = {}
): Promise<ExecutionSummary> {
  const command = request.action.kind === "env_command"
    ? commandForExecution(request)
    : undefined;
  const secretRecord = await store.getSecretRecord(request.handle);
  assertActionAllowed(secretRecord, request.action);
  if (request.action.kind === "ssh_session") {
    assertSshCredentialSupported(secretRecord);
  }
  const secretValue = await store.revealSecretForLocalUse(request.handle, request, {
    cache: executionOptions.cacheOnePassword !== false
  });
  if (request.action.kind === "ssh_session") {
    return runOwnedSshSession(request, secretRecord, secretValue, store.home);
  }
  const extraSecrets = await resolveExtraSecrets(store, request, executionOptions);
  return runEnvCommand(request, command!, secretRecord, secretValue, extraSecrets, options);
}

interface PreparedEnvExecution {
  command: string;
  secretRecord: SecretRecord;
  secretValue: string;
  extraSecrets: ResolvedEnvSecret[];
}

async function prepareEnvExecution(store: SecretStore, request: RequestRecord): Promise<PreparedEnvExecution> {
  const command = commandForExecution(request);
  const secretRecord = await store.getSecretRecord(request.handle);
  assertActionAllowed(secretRecord, request.action);
  const secretValue = await store.revealSecretForLocalUse(request.handle, request);
  const extraSecrets = await resolveExtraSecrets(store, request);
  return { command, secretRecord, secretValue, extraSecrets };
}

async function runEnvCommand(
  request: RequestRecord,
  command: string,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[],
  options: ExecutionOptions
): Promise<ExecutionSummary> {
  const engine = executionEngine(options.engine);
  const coreBinary = options.coreBinary || rustCoreBinary();
  if (engine !== "typescript" && existsSync(coreBinary)) {
    if (!nativeCoreIsCompatible(coreBinary)) {
      if (engine === "rust") {
        throw new Error(`Rust execution core is not compatible with ${process.platform}-${process.arch}: ${coreBinary}`);
      }
      return startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets).completion;
    }

    try {
      return await startRustEnvCommand(coreBinary, request, command, secretRecord, secretValue, extraSecrets).completion;
    } catch (error) {
      if (engine === "auto" && isNativeLaunchError(error)) {
        return startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets).completion;
      }
      if (engine === "rust" && isNativeLaunchError(error)) {
        throw new Error(`Rust execution core could not be launched: ${coreBinary}. ${errorMessage(error)}`);
      }
      throw error;
    }
  }
  if (engine === "rust") {
    throw new Error(`Rust execution core is unavailable: ${coreBinary}`);
  }

  return startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets).completion;
}

interface ReusableEnvLaunch extends ExecutionLaunch<ExecutionSummary> {
  nativeLaunch: boolean;
}

function launchReusableEnvCommand(
  request: RequestRecord,
  command: string,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[],
  options: ExecutionOptions
): ReusableEnvLaunch {
  const engine = executionEngine(options.engine);
  const coreBinary = options.coreBinary || rustCoreBinary();
  if (engine !== "typescript" && existsSync(coreBinary)) {
    if (!nativeCoreIsCompatible(coreBinary)) {
      if (engine === "rust") {
        throw new Error(`Rust execution core is not compatible with ${process.platform}-${process.arch}: ${coreBinary}`);
      }
      return { ...startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets), nativeLaunch: false };
    }

    const launch = startRustEnvCommand(coreBinary, request, command, secretRecord, secretValue, extraSecrets);
    if (engine !== "rust") {
      return { ...launch, nativeLaunch: true };
    }
    return {
      nativeLaunch: true,
      completion: launch.completion.catch((error) => {
        if (isNativeLaunchError(error)) {
          throw new Error(`Rust execution core could not be launched: ${coreBinary}. ${errorMessage(error)}`);
        }
        throw error;
      })
    };
  }
  if (engine === "rust") {
    throw new Error(`Rust execution core is unavailable: ${coreBinary}`);
  }

  return { ...startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets), nativeLaunch: false };
}

function startRustEnvCommand(
  coreBinary: string,
  request: RequestRecord,
  command: string,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[]
): ExecutionLaunch<ExecutionSummary> {
  const maxOutput = secretRecord.policy.maxOutputBytes || 16_384;
  const child = spawn(coreBinary, ["execute"], {
    env: buildCoreEnv(),
    shell: false,
    stdio: ["pipe", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  const responseLimit = Math.max(1_048_576, maxOutput * 4);

  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendBounded(stdout, chunk.toString("utf8"), responseLimit);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendBounded(stderr, chunk.toString("utf8"), responseLimit);
  });

  const childCompletion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  const input = new Promise<void>((resolve, reject) => {
    child.stdin.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "EPIPE") {
        resolve();
        return;
      }
      reject(error);
    });
    child.stdin.end(JSON.stringify({
      version: 1,
      requestId: request.id,
      handle: request.handle,
      command,
      args: request.action.args,
      injectEnv: request.action.injectEnv,
      secretValue,
      env: extraSecrets.map((item) => ({
        handle: item.handle,
        injectEnv: item.injectEnv,
        value: item.value
      })),
      workingDir: request.action.workingDir,
      timeoutMs: request.action.timeoutMs,
      maxOutputBytes: maxOutput
    }), resolve);
  });

  const completion = Promise.all([childCompletion, input]).then(([status]) => {
    if (status.code !== 0) {
      throw new Error(stderr.trim() || `Rust execution core exited ${status.code ?? status.signal ?? "unexpectedly"}.`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      throw new Error("Rust execution core returned an invalid response.");
    }
    const summary = parseCoreSummary(parsed, request);
    const secretValues = [secretValue, ...extraSecrets.map((item) => item.value)];
    if (secretValues.some((value) => summary.stdout.includes(value) || summary.stderr.includes(value))) {
      throw new Error("Rust execution core returned unsanitized output.");
    }

    const expectedProof = proofFor(request, summary.stdout, summary.stderr);
    if (summary.proof !== expectedProof) {
      throw new Error("Rust execution core returned an invalid execution proof.");
    }
    return summary;
  });
  void completion.catch(() => undefined);
  return { completion };
}

function parseCoreSummary(value: unknown, request: RequestRecord): ExecutionSummary {
  if (!value || typeof value !== "object") {
    throw new Error("Rust execution core returned an invalid summary.");
  }
  const summary = value as Record<string, unknown>;
  const validExit = summary.exitCode === null || Number.isInteger(summary.exitCode);
  const validSignal = summary.signal === null || typeof summary.signal === "string";
  if (
    !validExit
    || !validSignal
    || typeof summary.stdout !== "string"
    || typeof summary.stderr !== "string"
    || typeof summary.proof !== "string"
    || typeof summary.durationMs !== "number"
    || !Number.isFinite(summary.durationMs)
    || summary.durationMs < 0
    || summary.timeoutMs !== request.action.timeoutMs
    || typeof summary.timedOut !== "boolean"
    || typeof summary.sanitized !== "boolean"
  ) {
    throw new Error("Rust execution core returned an invalid summary.");
  }

  return summary as unknown as ExecutionSummary;
}

function executionEngine(override?: ExecutionOptions["engine"]): "auto" | "rust" | "typescript" {
  const configured = override || process.env.SGW_EXECUTION_ENGINE?.trim().toLowerCase() || "auto";
  if (configured === "auto" || configured === "rust" || configured === "typescript") {
    return configured;
  }
  throw new Error(`Unsupported SGW_EXECUTION_ENGINE value: ${configured}`);
}

function rustCoreBinary(): string {
  const extension = process.platform === "win32" ? ".exe" : "";
  return fileURLToPath(new URL(
    `../dist/native/${process.platform}-${process.arch}/s-gw-core${extension}`,
    import.meta.url
  ));
}

function nativeCoreIsCompatible(coreBinary: string): boolean {
  try {
    if (process.platform !== "win32") accessSync(coreBinary, constants.X_OK);
    const header = readFileSync(coreBinary).subarray(0, 4096);
    if (header[0] === 0x23 && header[1] === 0x21) return true;
    if (process.platform === "darwin") return compatibleMachO(header);
    if (process.platform === "win32") return compatiblePe(header);
    return compatibleElf(header);
  } catch {
    return false;
  }
}

function compatibleElf(header: Buffer): boolean {
  if (header.length < 20 || !header.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    return false;
  }
  const littleEndian = header[5] === 1;
  if (!littleEndian && header[5] !== 2) return false;
  const machine = littleEndian ? header.readUInt16LE(18) : header.readUInt16BE(18);
  const expected: Partial<Record<NodeJS.Architecture, number>> = {
    arm: 40,
    arm64: 183,
    ia32: 3,
    x64: 62
  };
  return expected[process.arch] === machine;
}

function compatibleMachO(header: Buffer): boolean {
  if (header.length < 8) return false;
  const magic = header.subarray(0, 4).toString("hex");
  const thinLittle = magic === "cefaedfe" || magic === "cffaedfe";
  const thinBig = magic === "feedface" || magic === "feedfacf";
  if (thinLittle || thinBig) {
    const cpu = thinLittle ? header.readUInt32LE(4) : header.readUInt32BE(4);
    return cpu === machCpuType();
  }

  const fatBig = magic === "cafebabe" || magic === "cafebabf";
  const fatLittle = magic === "bebafeca" || magic === "bfbafeca";
  if (!fatBig && !fatLittle) return false;
  const read32 = fatLittle
    ? (offset: number) => header.readUInt32LE(offset)
    : (offset: number) => header.readUInt32BE(offset);
  const count = read32(4);
  const entrySize = magic === "cafebabf" || magic === "bfbafeca" ? 32 : 20;
  if (count > 64 || header.length < 8 + count * entrySize) return false;
  for (let index = 0; index < count; index += 1) {
    if (read32(8 + index * entrySize) === machCpuType()) return true;
  }
  return false;
}

function machCpuType(): number {
  if (process.arch === "arm64") return 0x0100000c;
  if (process.arch === "x64") return 0x01000007;
  if (process.arch === "arm") return 12;
  if (process.arch === "ia32") return 7;
  return -1;
}

function compatiblePe(header: Buffer): boolean {
  if (header.length < 64 || header[0] !== 0x4d || header[1] !== 0x5a) return false;
  const offset = header.readUInt32LE(0x3c);
  if (offset + 6 > header.length || header.subarray(offset, offset + 4).toString("hex") !== "50450000") {
    return false;
  }
  const expected: Partial<Record<NodeJS.Architecture, number>> = {
    arm64: 0xaa64,
    ia32: 0x014c,
    x64: 0x8664
  };
  return header.readUInt16LE(offset + 4) === expected[process.arch];
}

function isNativeLaunchError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === "EACCES" || code === "ENOENT" || code === "ENOEXEC";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function buildCoreEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const copyKeys = [
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LOGNAME",
    "NO_COLOR",
    "PATH",
    "SHELL",
    "SYSTEMROOT",
    "TERM",
    "TMPDIR",
    "USER",
    "USERPROFILE",
    "WINDIR"
  ];
  for (const key of copyKeys) {
    const value = process.env[key];
    if (value) {
      env[key] = value;
    }
  }
  env.PATH ||= process.platform === "win32"
    ? "C:\\Windows\\System32;C:\\Windows"
    : "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";
  return env;
}

function startTypeScriptEnvCommand(
  request: RequestRecord,
  command: string,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[]
): ExecutionLaunch<ExecutionSummary> {
  const started = Date.now();
  const maxOutput = secretRecord.policy.maxOutputBytes || 16_384;
  const secretPairs = [
    { handle: request.handle, value: secretValue },
    ...extraSecrets.map((item) => ({ handle: item.handle, value: item.value }))
  ];
  const longestSecretBytes = secretPairs.reduce((max, item) => Math.max(max, Buffer.byteLength(item.value, "utf8")), 0);
  // Capture slightly more than the display cap so a secret that straddles the
  // boundary is still present in full when we sanitize. Without this headroom,
  // truncating raw output first could cut a secret in half and leak the prefix.
  const captureCap = maxOutput + longestSecretBytes;
  const env = buildExecutionEnv(request.action.injectEnv, secretValue, extraSecrets);
  const child = spawn(command, request.action.args, {
    cwd: request.action.workingDir,
    env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  const timeout = request.action.timeoutMs > 0
    ? setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => {
        child.kill("SIGKILL");
      }, 1_500);
    }, request.action.timeoutMs)
    : undefined;

  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendBounded(stdout, chunk.toString("utf8"), captureCap);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendBounded(stderr, chunk.toString("utf8"), captureCap);
  });

  const completion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal }));
  }).then((status) => {
    if (timeout) {
      clearTimeout(timeout);
    }
    if (killTimer) {
      clearTimeout(killTimer);
    }

    const sanitizedStdout = sanitizeKnownSecrets(stdout, secretPairs);
    const sanitizedStderr = sanitizeKnownSecrets(stderr, secretPairs);
    const cleanStdout = capBytes(sanitizedStdout, maxOutput);
    const cleanStderr = capBytes(sanitizedStderr, maxOutput);
    return {
      exitCode: timedOut ? 124 : status.code,
      signal: status.signal,
      stdout: cleanStdout,
      stderr: cleanStderr,
      proof: proofFor(request, cleanStdout, cleanStderr),
      durationMs: Date.now() - started,
      timeoutMs: request.action.timeoutMs,
      timedOut,
      sanitized: sanitizedStdout !== stdout || sanitizedStderr !== stderr
    } satisfies ExecutionSummary;
  });
  void completion.catch(() => undefined);
  return { completion };
}

interface ResolvedEnvSecret {
  handle: string;
  injectEnv: string;
  value: string;
}

async function resolveExtraSecrets(
  store: SecretStore,
  request: RequestRecord,
  executionOptions: { cacheOnePassword?: boolean } = {}
): Promise<ResolvedEnvSecret[]> {
  const out: ResolvedEnvSecret[] = [];
  for (const binding of request.action.env || []) {
    const secret = await store.getSecretRecord(binding.handle);
    assertActionAllowed(secret, {
      ...request.action,
      injectEnv: binding.injectEnv,
      env: []
    });
    out.push({
      handle: binding.handle,
      injectEnv: binding.injectEnv,
      value: await store.revealSecretForLocalUse(binding.handle, request, {
        cache: executionOptions.cacheOnePassword !== false
      })
    });
  }

  return out;
}

function buildExecutionEnv(
  injectEnv: string,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[]
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const copyKeys = [
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LOGNAME",
    "NO_COLOR",
    "PATH",
    "SHELL",
    "TERM",
    "TMPDIR",
    "USER"
  ];

  for (const key of copyKeys) {
    const value = process.env[key];
    if (value) {
      env[key] = value;
    }
  }

  env.PATH ||= "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";
  env[injectEnv] = secretValue;
  for (const item of extraSecrets) {
    env[item.injectEnv] = item.value;
  }
  return env;
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
