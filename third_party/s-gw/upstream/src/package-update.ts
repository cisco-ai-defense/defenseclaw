import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { getSgwHome } from "./paths.js";
import {
  installPersistentKeychainHelper,
  pinPackagedKeychainHelper,
  type PackagedKeychainHelperPin,
  type PersistentKeychainHelperInstall
} from "./unlock.js";

export const LEGACY_PACKAGE_NAME = "s-gw";
export const SCOPED_PACKAGE_NAME = "@s-gw/s-gw";
export const DEFAULT_UPDATE_TARGET = `${SCOPED_PACKAGE_NAME}@latest`;

export interface NpmCommandResult {
  status: number;
  stdout: string;
  stderr: string;
}

export type NpmCommandRunner = (
  args: string[],
  env: NodeJS.ProcessEnv
) => Promise<NpmCommandResult>;

export interface PackageUpdateOptions {
  target?: string;
  npmCommand?: string;
  npmPrefix?: string;
  sgwHome?: string;
  env?: NodeJS.ProcessEnv;
  runNpm?: NpmCommandRunner;
}

export interface PackageInstallOptions extends PackageUpdateOptions {
  dryRun?: boolean;
  servicesAlreadyStopped?: boolean;
  stopServices?: () => Promise<void>;
  restartServices?: () => Promise<void>;
}

export interface InstalledNpmPackage {
  name: typeof LEGACY_PACKAGE_NAME | typeof SCOPED_PACKAGE_NAME;
  version: string;
  packageRoot: string;
  resolved?: string;
}

export interface GlobalSgwInstall {
  npmPrefix: string;
  npmRoot: string;
  binDir: string;
  legacy: InstalledNpmPackage | null;
  scoped: InstalledNpmPackage | null;
}

export interface UpdateTarget {
  spec: string;
  installSpec: string;
  name: typeof SCOPED_PACKAGE_NAME;
  version: string;
}

export type PackageUpdateStepId = "stop-services" | "remove-legacy" | "install-scoped";

export interface PackageUpdateStep {
  id: PackageUpdateStepId;
  description: string;
  npmArgs?: string[];
}

export interface PackageUpdatePlan {
  target: UpdateTarget;
  installed: GlobalSgwInstall;
  migrationRequired: boolean;
  dataHome: string;
  steps: PackageUpdateStep[];
  rollback: PackageRollbackPlan | null;
  nextCommands: string[];
}

export interface PackageRollbackPlan {
  packageName: typeof LEGACY_PACKAGE_NAME;
  version: string;
  strategy: "temporary-backup";
}

export interface PackageUpdateResult {
  changed: boolean;
  dryRun: boolean;
  plan: PackageUpdatePlan;
  installed: GlobalSgwInstall;
  dataHomePreserved: boolean;
  keychainHelper?: PersistentKeychainHelperInstall;
  keychainCompatibility?: PackagedKeychainHelperPin;
  nextCommands: string[];
}

interface PreparedRollback {
  target: string;
  tempDir?: string;
}

export class PackageUpdateError extends Error {
  readonly phase: string;
  readonly recoveryCommands: string[];
  readonly summary: string;

  constructor(message: string, phase: string, recoveryCommands: string[] = []) {
    const recovery = recoveryCommands.length > 0
      ? `${message}\nRecovery:\n${recoveryCommands.map((command) => `  ${command}`).join("\n")}`
      : message;
    super(recovery);
    this.name = "PackageUpdateError";
    this.phase = phase;
    this.recoveryCommands = recoveryCommands;
    this.summary = message;
  }
}

export interface ReleaseAsset {
  name: string;
  downloadUrl?: string;
}

export interface ReleasePackageAssets {
  packageAsset: ReleaseAsset;
  checksumAsset: ReleaseAsset;
  checksumKind: "per-file" | "sha256sums";
}

export async function inspectGlobalSgwInstall(options: PackageUpdateOptions = {}): Promise<GlobalSgwInstall> {
  const npm = npmContext(options);
  const prefix = options.npmPrefix
    ? path.resolve(options.npmPrefix)
    : await readNpmPath(npm, ["prefix", "--global"], "global prefix");
  const npmRoot = await readNpmPath(
    npm,
    ["root", "--global", "--prefix", prefix],
    "global package directory"
  );
  const listed = await npm.run(["list", "--global", "--prefix", prefix, "--depth=0", "--json"]);
  if (listed.status !== 0) {
    throw npmFailure(`Could not read global npm packages under ${prefix}.`, "inspect", listed, []);
  }
  const parsed = parseNpmList(listed, prefix);

  return {
    npmPrefix: prefix,
    npmRoot,
    binDir: process.platform === "win32" ? prefix : path.join(prefix, "bin"),
    legacy: packageFromList(parsed, LEGACY_PACKAGE_NAME, npmRoot),
    scoped: packageFromList(parsed, SCOPED_PACKAGE_NAME, npmRoot)
  };
}

export async function planPackageUpdate(options: PackageUpdateOptions = {}): Promise<PackageUpdatePlan> {
  const targetSpec = cleanTarget(options.target);
  const npm = npmContext(options);
  const installed = await inspectGlobalSgwInstall(options);
  const target = await inspectTarget(npm, targetSpec);
  const migrationRequired = installed.legacy !== null;
  const steps: PackageUpdateStep[] = [
    {
      id: "stop-services",
      description: "Stop the s-gw background surfaces and close the native app unless it is performing this update itself."
    }
  ];

  if (migrationRequired) {
    steps.push({
      id: "remove-legacy",
      description: `Remove only the legacy ${LEGACY_PACKAGE_NAME}@${installed.legacy?.version} package to free the shared s-gw commands.`,
      npmArgs: uninstallArgs(installed.npmPrefix, LEGACY_PACKAGE_NAME)
    });
  }

  steps.push({
    id: "install-scoped",
    description: `Install ${target.name}@${target.version} from ${target.spec}.`,
    npmArgs: installArgs(installed.npmPrefix, target.installSpec)
  });

  const rollback: PackageRollbackPlan | null = installed.legacy ? {
    packageName: LEGACY_PACKAGE_NAME,
    version: installed.legacy.version,
    strategy: "temporary-backup"
  } : null;

  return {
    target,
    installed,
    migrationRequired,
    dataHome: path.resolve(options.sgwHome || getSgwHome()),
    steps,
    rollback,
    nextCommands: ["s-gw setup", "s-gw doctor", "s-gw app open"]
  };
}

export async function installPackageUpdate(options: PackageInstallOptions = {}): Promise<PackageUpdateResult> {
  const plan = await planPackageUpdate(options);
  if (options.dryRun) {
    return {
      changed: false,
      dryRun: true,
      plan,
      installed: plan.installed,
      dataHomePreserved: true,
      nextCommands: plan.nextCommands
    };
  }

  if (!options.servicesAlreadyStopped && !options.stopServices) {
    throw new PackageUpdateError(
      "Stop the s-gw service, menu-bar helper, and native app before installing. The caller must provide stopServices or confirm servicesAlreadyStopped.",
      "stop-services",
      ["s-gw stop"]
    );
  }

  const npm = npmContext(options);
  const dataExisted = await pathExists(plan.dataHome);
  let removedLegacy = false;
  let rollback: PreparedRollback | null = null;
  let stopAttempted = false;
  let restartAttempted = false;
  let keychainHelper: PersistentKeychainHelperInstall | undefined;
  let keychainCompatibility: PackagedKeychainHelperPin | undefined;

  try {
    if (options.stopServices) {
      stopAttempted = true;
      try {
        await options.stopServices();
      } catch (error) {
        throw new PackageUpdateError(
          `Could not stop s-gw cleanly: ${errorMessage(error)}`,
          "stop-services"
        );
      }
    }

    keychainHelper = preserveInstalledKeychainHelper(plan);

    if (plan.installed.legacy) {
      rollback = await prepareLegacyRollback(plan, npm);
      const removed = await npm.run(uninstallArgs(plan.installed.npmPrefix, LEGACY_PACKAGE_NAME));
      if (removed.status !== 0) {
        await discardRollback(rollback);
        rollback = null;
        throw npmFailure(
          `Could not remove legacy ${LEGACY_PACKAGE_NAME}@${plan.installed.legacy.version}. The scoped package was not installed.`,
          "remove-legacy",
          removed,
          []
        );
      }
      removedLegacy = true;

      const afterRemove = await inspectGlobalSgwInstall(options);
      if (afterRemove.legacy) {
        throw new PackageUpdateError(
          `npm still reports ${LEGACY_PACKAGE_NAME}@${afterRemove.legacy.version} under ${afterRemove.npmPrefix}. The scoped package was not installed.`,
          "remove-legacy",
          recoveryFor(plan, rollback)
        );
      }
    }

    const installed = await npm.run(installArgs(plan.installed.npmPrefix, plan.target.installSpec));
    if (installed.status !== 0) {
      const message = removedLegacy
        ? `Could not install ${plan.target.name}@${plan.target.version} after removing the legacy package. Your s-gw data at ${plan.dataHome} was not intentionally changed.`
        : `Could not install ${plan.target.name}@${plan.target.version}.`;
      throw npmFailure(message, "install-scoped", installed, recoveryFor(plan, rollback));
    }

    const finalInstall = await inspectGlobalSgwInstall(options);
    if (!finalInstall.scoped || finalInstall.legacy || finalInstall.scoped.version !== plan.target.version) {
      throw new PackageUpdateError(
        `npm completed, but the global package state is invalid: expected scoped=${plan.target.version}, found scoped=${finalInstall.scoped?.version || "missing"}, legacy=${finalInstall.legacy?.version || "absent"}.`,
        "verify-install",
        recoveryFor(plan, rollback)
      );
    }

    const dataHomePreserved = !dataExisted || await pathExists(plan.dataHome);
    if (!dataHomePreserved) {
      throw new PackageUpdateError(
        `The package installed, but the existing s-gw data directory is no longer present at ${plan.dataHome}. Do not run setup until the data is restored from backup. Services remain stopped to avoid initializing an empty store.`,
        "verify-data",
        recoveryFor(plan, rollback, false)
      );
    }

    if (process.platform === "darwin" && keychainHelper && finalInstall.scoped) {
      keychainCompatibility = pinPackagedKeychainHelper(
        finalInstall.scoped.packageRoot,
        keychainHelper.helperPath,
        plan.dataHome
      );
    }

    await discardRollback(rollback);
    rollback = null;
    removedLegacy = false;

    if (stopAttempted && options.restartServices) {
      restartAttempted = true;
      try {
        await options.restartServices();
      } catch (error) {
        throw new PackageUpdateError(
          `${plan.target.name}@${plan.target.version} installed, but s-gw could not restart: ${errorMessage(error)}`,
          "restart-services",
          plan.nextCommands
        );
      }
    }

    return {
      changed: true,
      dryRun: false,
      plan,
      installed: finalInstall,
      dataHomePreserved,
      keychainHelper,
      keychainCompatibility,
      nextCommands: plan.nextCommands
    };
  } catch (error) {
    let failure = packageUpdateFailure(error, plan, rollback, removedLegacy);
    if (removedLegacy && rollback) {
      try {
        await restoreLegacyPackage(plan, rollback, npm);
        await discardRollback(rollback);
        rollback = null;
        removedLegacy = false;
        failure = new PackageUpdateError(
          `${failure.summary}\nThe previous ${LEGACY_PACKAGE_NAME}@${plan.installed.legacy?.version} package was restored before services restarted.`,
          failure.phase
        );
      } catch (rollbackError) {
        failure = new PackageUpdateError(
          `${failure.summary}\nAutomatic rollback failed: ${errorMessage(rollbackError)}`,
          failure.phase,
          recoveryFor(plan, rollback, failure.phase !== "verify-data")
        );
      }
    }
    if (stopAttempted && !restartAttempted && options.restartServices && failure.phase !== "verify-data") {
      restartAttempted = true;
      try {
        await options.restartServices();
      } catch (restartError) {
        failure = new PackageUpdateError(
          `${failure.summary}\nCould not restart the stopped s-gw services: ${errorMessage(restartError)}`,
          failure.phase,
          uniqueCommands([...failure.recoveryCommands, "s-gw start --no-open-app"])
        );
      }
    }
    throw failure;
  }
}

function preserveInstalledKeychainHelper(
  plan: PackageUpdatePlan
): PersistentKeychainHelperInstall | undefined {
  if (process.platform !== "darwin") {
    return undefined;
  }

  const current = plan.installed.scoped || plan.installed.legacy;
  if (!current) {
    return undefined;
  }

  const target = `${process.platform}-${process.arch}`;
  const candidates = [
    path.join(current.packageRoot, "dist", "native", target, "s-gw-keychain-helper"),
    path.join(current.packageRoot, "dist", "native", "s-gw-keychain-helper"),
    path.join(current.packageRoot, "dist", "native", "sgw-keychain-helper")
  ];
  const sourcePath = candidates.find((candidate) => existsSync(candidate));
  if (!sourcePath) {
    return undefined;
  }

  return installPersistentKeychainHelper({
    sourcePath,
    sgwHome: plan.dataHome
  });
}

export function selectReleasePackageAssets(
  assets: ReleaseAsset[],
  expectedVersion?: string
): ReleasePackageAssets {
  const packageCandidates = assets.filter((asset) => isSgwTarball(asset.name));
  const expectedName = expectedVersion ? `s-gw-${expectedVersion.replace(/^v/i, "")}.tgz`.toLowerCase() : null;
  const packageAsset = expectedName
    ? packageCandidates.find((asset) => asset.name.toLowerCase() === expectedName)
    : packageCandidates.length === 1 ? packageCandidates[0] : undefined;

  if (!packageAsset) {
    const expected = expectedName || "one versioned s-gw-*.tgz asset";
    throw new Error(`Release must include ${expected}.`);
  }

  const perFileNames = new Set([
    `${packageAsset.name}.sha256`.toLowerCase(),
    `${packageAsset.name.slice(0, -path.extname(packageAsset.name).length)}.sha256`.toLowerCase()
  ]);
  const perFile = assets.find((asset) => perFileNames.has(asset.name.toLowerCase()));
  if (perFile) {
    return { packageAsset, checksumAsset: perFile, checksumKind: "per-file" };
  }

  const sums = assets.find((asset) => /^sha256sums(?:\.txt)?$/i.test(asset.name));
  if (sums) {
    return { packageAsset, checksumAsset: sums, checksumKind: "sha256sums" };
  }

  throw new Error(
    `Release asset ${packageAsset.name} requires ${packageAsset.name}.sha256 or SHA256SUMS.txt.`
  );
}

export async function verifyReleasePackageChecksum(
  packagePath: string,
  checksumText: string,
  checksumKind: ReleasePackageAssets["checksumKind"] = "sha256sums"
): Promise<string> {
  const packageName = path.basename(packagePath);
  const expected = expectedSha256(checksumText, packageName, checksumKind);
  if (!expected) {
    throw new Error(`Checksum file does not contain a SHA-256 digest for ${packageName}.`);
  }

  const actual = createHash("sha256").update(await readFile(packagePath)).digest("hex");
  if (actual !== expected.toLowerCase()) {
    throw new Error(`SHA-256 mismatch for ${packageName}.`);
  }
  return actual;
}

export async function validateReleaseDirectory(
  directory: string,
  expectedVersion?: string
): Promise<ReleasePackageAssets> {
  const entries = await readdir(directory, { withFileTypes: true });
  const assets = entries.filter((entry) => entry.isFile()).map((entry) => ({ name: entry.name }));
  const selected = selectReleasePackageAssets(assets, expectedVersion);
  const checksum = await readFile(path.join(directory, selected.checksumAsset.name), "utf8");
  await verifyReleasePackageChecksum(
    path.join(directory, selected.packageAsset.name),
    checksum,
    selected.checksumKind
  );

  const sums = assets.find((asset) => /^sha256sums(?:\.txt)?$/i.test(asset.name));
  if (sums && sums.name !== selected.checksumAsset.name) {
    await verifyReleasePackageChecksum(
      path.join(directory, selected.packageAsset.name),
      await readFile(path.join(directory, sums.name), "utf8"),
      "sha256sums"
    );
  }
  return selected;
}

function cleanTarget(target: string | undefined): string {
  const value = target?.trim() || DEFAULT_UPDATE_TARGET;
  if (value.startsWith("-")) {
    throw new PackageUpdateError("The update package target cannot start with '-'.", "preflight");
  }
  return value;
}

function npmContext(options: PackageUpdateOptions): {
  run: (args: string[]) => Promise<NpmCommandResult>;
  commandLabel: string;
} {
  const inheritedEnv = { ...process.env, ...options.env };
  if (options.runNpm) {
    const runner = options.runNpm;
    return {
      run: (args) => runner(args, inheritedEnv),
      commandLabel: options.npmCommand || "npm"
    };
  }

  const runtime = npmRuntime(options.npmCommand, inheritedEnv);
  const env = npmEnvironment(inheritedEnv);
  return {
    run: (args) => runCommand(runtime.command, [...runtime.leadingArgs, ...args], env),
    commandLabel: options.npmCommand || "npm"
  };
}

async function inspectTarget(
  npm: { run: (args: string[]) => Promise<NpmCommandResult>; commandLabel: string },
  spec: string
): Promise<UpdateTarget> {
  const result = await npm.run(["pack", "--dry-run", "--ignore-scripts", "--json", "--", spec]);
  if (result.status !== 0) {
    throw npmFailure(`Could not inspect update package ${spec}. No packages were changed.`, "preflight", result, []);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new PackageUpdateError(
      `${npm.commandLabel} returned invalid metadata for ${spec}. No packages were changed.`,
      "preflight"
    );
  }
  const metadata = Array.isArray(parsed) ? parsed[0] as { name?: unknown; version?: unknown } : null;
  if (!metadata || metadata.name !== SCOPED_PACKAGE_NAME || typeof metadata.version !== "string" || !metadata.version) {
    throw new PackageUpdateError(
      `Refusing to install ${spec}: expected ${SCOPED_PACKAGE_NAME}, got ${String(metadata?.name || "unknown package")}.`,
      "preflight"
    );
  }

  return {
    spec,
    installSpec: registryTarget(spec) ? `${SCOPED_PACKAGE_NAME}@${metadata.version}` : spec,
    name: SCOPED_PACKAGE_NAME,
    version: metadata.version
  };
}

function registryTarget(spec: string): boolean {
  return /^@s-gw\/s-gw(?:@[^/]+)?$/.test(spec);
}

function npmRuntime(command: string | undefined, env: NodeJS.ProcessEnv): {
  command: string;
  leadingArgs: string[];
} {
  const requested = command?.trim();
  if (requested) return runtimeForPath(requested);

  const npmExecPath = env.npm_execpath;
  if (npmExecPath && existsSync(npmExecPath)) {
    return runtimeForPath(npmExecPath);
  }

  const nodeDir = path.dirname(process.execPath);
  const jsCandidates = process.platform === "win32"
    ? [path.join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js")]
    : [path.resolve(nodeDir, "../lib/node_modules/npm/bin/npm-cli.js")];
  for (const candidate of jsCandidates) {
    if (existsSync(candidate)) return runtimeForPath(candidate);
  }

  const sibling = path.join(nodeDir, process.platform === "win32" ? "npm.cmd" : "npm");
  if (existsSync(sibling)) return runtimeForPath(sibling);
  return runtimeForPath(process.platform === "win32" ? "npm.cmd" : "npm");
}

function runtimeForPath(command: string): { command: string; leadingArgs: string[] } {
  if (/\.(?:c?m?js)$/i.test(command)) {
    return { command: process.execPath, leadingArgs: [command] };
  }
  if (process.platform === "win32" && /\.(?:cmd|bat)$/i.test(command)) {
    throw new PackageUpdateError(
      "Windows package updates require npm-cli.js and will not execute npm through a command shell. Reinstall Node.js with npm included, then retry.",
      "preflight"
    );
  }
  return { command, leadingArgs: [] };
}

async function runCommand(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv
): Promise<NpmCommandResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr?.on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", (error) => {
      resolve({ status: 1, stdout, stderr: `${stderr}\n${error.message}`.trim() });
    });
    child.on("close", (code) => resolve({ status: code ?? 1, stdout, stderr }));
  });
}

function npmEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of [
    "APPDATA",
    "ComSpec",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "NO_COLOR",
    "NO_PROXY",
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USER",
    "USERNAME",
    "USERPROFILE",
    "WINDIR",
    "http_proxy",
    "https_proxy",
    "no_proxy"
  ]) {
    const value = source[key];
    if (typeof value === "string" && value) env[key] = value;
  }
  return env;
}

async function readNpmPath(
  npm: { run: (args: string[]) => Promise<NpmCommandResult>; commandLabel: string },
  args: string[],
  label: string
): Promise<string> {
  const result = await npm.run(args);
  if (result.status !== 0) {
    throw npmFailure(`Could not determine npm ${label}.`, "inspect", result, []);
  }
  const lines = result.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const value = lines.at(-1);
  if (!value) {
    throw new PackageUpdateError(`${npm.commandLabel} returned an empty ${label}.`, "inspect");
  }
  return path.resolve(value);
}

function parseNpmList(result: NpmCommandResult, prefix: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(result.stdout) as { dependencies?: Record<string, unknown> };
    return parsed.dependencies || {};
  } catch {
    const details = npmOutput(result);
    throw new PackageUpdateError(
      `Could not read global npm packages under ${prefix}.${details ? ` npm: ${details}` : ""}`,
      "inspect"
    );
  }
}

function packageFromList(
  dependencies: Record<string, unknown>,
  name: typeof LEGACY_PACKAGE_NAME | typeof SCOPED_PACKAGE_NAME,
  npmRoot: string
): InstalledNpmPackage | null {
  const entry = dependencies[name];
  if (!entry || typeof entry !== "object") return null;
  const details = entry as { version?: unknown; resolved?: unknown };
  if (typeof details.version !== "string" || !details.version) return null;
  return {
    name,
    version: details.version,
    packageRoot: path.join(npmRoot, ...name.split("/")),
    resolved: typeof details.resolved === "string" ? details.resolved : undefined
  };
}

function installArgs(prefix: string, target: string): string[] {
  return ["install", "--global", "--prefix", prefix, "--ignore-scripts", "--", target];
}

function uninstallArgs(
  prefix: string,
  packageName: typeof LEGACY_PACKAGE_NAME | typeof SCOPED_PACKAGE_NAME
): string[] {
  return ["uninstall", "--global", "--prefix", prefix, "--ignore-scripts", "--", packageName];
}

function npmFailure(
  message: string,
  phase: string,
  result: NpmCommandResult,
  recoveryCommands: string[]
): PackageUpdateError {
  const detail = npmOutput(result);
  return new PackageUpdateError(`${message}${detail ? ` npm: ${detail}` : ""}`, phase, recoveryCommands);
}

function npmOutput(result: NpmCommandResult): string {
  return (result.stderr.trim() || result.stdout.trim()).split(/\r?\n/).slice(-8).join("\n");
}

function recoveryFor(
  plan: PackageUpdatePlan,
  rollback: PreparedRollback | null,
  includeSetup = true
): string[] {
  if (!rollback || !plan.installed.legacy) return [];
  const commands = [
    commandText("npm", uninstallArgs(plan.installed.npmPrefix, SCOPED_PACKAGE_NAME)),
    commandText("npm", installArgs(plan.installed.npmPrefix, rollback.target))
  ];
  if (includeSetup) commands.push("s-gw setup");
  return commands;
}

function packageUpdateFailure(
  error: unknown,
  plan: PackageUpdatePlan,
  rollback: PreparedRollback | null,
  removedLegacy: boolean
): PackageUpdateError {
  const failure = error instanceof PackageUpdateError
    ? error
    : new PackageUpdateError(errorMessage(error), "install");
  if (!removedLegacy) return failure;

  const recoveryCommands = uniqueCommands([
    ...failure.recoveryCommands,
    ...recoveryFor(plan, rollback, failure.phase !== "verify-data")
  ]);
  if (recoveryCommands.length === failure.recoveryCommands.length) return failure;
  return new PackageUpdateError(failure.summary, failure.phase, recoveryCommands);
}

async function restoreLegacyPackage(
  plan: PackageUpdatePlan,
  rollback: PreparedRollback,
  npm: { run: (args: string[]) => Promise<NpmCommandResult> }
): Promise<void> {
  const removedScoped = await npm.run(uninstallArgs(plan.installed.npmPrefix, SCOPED_PACKAGE_NAME));
  if (removedScoped.status !== 0) {
    throw new Error(npmOutput(removedScoped) || `Could not remove ${SCOPED_PACKAGE_NAME}.`);
  }

  const restored = await npm.run(installArgs(plan.installed.npmPrefix, rollback.target));
  if (restored.status !== 0) {
    throw new Error(npmOutput(restored) || `Could not restore ${LEGACY_PACKAGE_NAME}.`);
  }

  const expected = plan.installed.legacy;
  if (!expected) throw new Error("Legacy package metadata is unavailable after rollback.");
  try {
    const manifest = JSON.parse(await readFile(path.join(expected.packageRoot, "package.json"), "utf8")) as {
      name?: unknown;
      version?: unknown;
    };
    if (manifest.name !== LEGACY_PACKAGE_NAME || manifest.version !== expected.version) {
      throw new Error("restored package identity does not match the previous installation");
    }
    if (!await pathExists(path.join(expected.packageRoot, "dist", "cli.js"))) {
      throw new Error("restored package is missing dist/cli.js");
    }
    const scopedRoot = path.join(plan.installed.npmRoot, ...SCOPED_PACKAGE_NAME.split("/"));
    if (await pathExists(path.join(scopedRoot, "package.json"))) {
      throw new Error(`restored package still conflicts with ${SCOPED_PACKAGE_NAME}`);
    }
  } catch (error) {
    throw new Error(`Could not verify the restored ${LEGACY_PACKAGE_NAME}@${expected.version}: ${errorMessage(error)}`);
  }
}

function uniqueCommands(commands: string[]): string[] {
  return [...new Set(commands)];
}

async function prepareLegacyRollback(
  plan: PackageUpdatePlan,
  npm: { run: (args: string[]) => Promise<NpmCommandResult>; commandLabel: string }
): Promise<PreparedRollback> {
  if (!plan.installed.legacy || !plan.rollback) {
    throw new PackageUpdateError("Legacy rollback preparation was requested without a legacy package.", "backup-legacy");
  }
  const backupDir = await mkdtemp(path.join(os.tmpdir(), "sgw-legacy-rollback-"));
  const result = await npm.run([
    "pack",
    "--ignore-scripts",
    "--json",
    "--pack-destination",
    backupDir,
    "--",
    plan.installed.legacy.packageRoot
  ]);
  if (result.status !== 0) {
    await rm(backupDir, { recursive: true, force: true });
    throw npmFailure(
      `Could not create a local rollback copy of ${LEGACY_PACKAGE_NAME}@${plan.installed.legacy.version}. The installed package was not removed.`,
      "backup-legacy",
      result,
      []
    );
  }

  try {
    const packed = JSON.parse(result.stdout) as Array<{ name?: string; version?: string; filename?: string }>;
    const artifact = packed[0];
    if (artifact?.name !== LEGACY_PACKAGE_NAME ||
      artifact.version !== plan.installed.legacy.version ||
      !artifact.filename) {
      throw new Error("npm returned unexpected rollback package metadata.");
    }
    const target = path.join(backupDir, path.basename(artifact.filename));
    if (!await pathExists(target)) throw new Error("npm did not create the rollback tarball.");
    return { target, tempDir: backupDir };
  } catch (error) {
    await rm(backupDir, { recursive: true, force: true });
    throw new PackageUpdateError(
      `Could not verify the local rollback copy. The installed package was not removed: ${errorMessage(error)}`,
      "backup-legacy"
    );
  }
}

async function discardRollback(rollback: PreparedRollback | null): Promise<void> {
  if (!rollback?.tempDir) return;
  await rm(rollback.tempDir, { recursive: true, force: true }).catch(() => undefined);
}

function commandText(command: string, args: string[]): string {
  return [command, ...args].map(shellWord).join(" ");
}

function shellWord(value: string): string {
  if (/^[a-zA-Z0-9_@%+=:,./-]+$/.test(value)) return value;
  if (process.platform === "win32") return `"${value.replaceAll('"', '\\"')}"`;
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function isSgwTarball(name: string): boolean {
  return /^s-gw-(?:s-gw-)?[^/]+\.tgz$/i.test(name);
}

function expectedSha256(
  text: string,
  packageName: string,
  kind: ReleasePackageAssets["checksumKind"]
): string | null {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    const bsd = line.match(/^SHA256\s*\((.+)\)\s*=\s*([a-fA-F0-9]{64})$/i);
    if (bsd && checksumNameMatches(bsd[1], packageName)) return bsd[2];

    const gnu = line.match(/^([a-fA-F0-9]{64})\s+[* ]?(.+)$/);
    if (gnu && checksumNameMatches(gnu[2], packageName)) return gnu[1];
  }

  if (kind === "per-file" && lines.length === 1 && /^[a-fA-F0-9]{64}$/.test(lines[0])) {
    return lines[0];
  }
  return null;
}

function checksumNameMatches(value: string, packageName: string): boolean {
  return path.basename(value.trim().replace(/^\*+/, "")) === packageName;
}

async function pathExists(value: string): Promise<boolean> {
  try {
    await stat(value);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
