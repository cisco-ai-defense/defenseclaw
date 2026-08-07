import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  chmodSync,
  constants,
  copyFileSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getSgwHome, MASTER_KEYCHAIN_SERVICE, SECRET_KEYCHAIN_SERVICE } from "./paths.js";
import { resolveSelfContainedMacRuntime } from "./self-contained-runtime.js";
import { trustedWindowsPowerShellSync, windowsSystemEnvironment } from "./windows-system.js";

const nativeHelperName = "s-gw-keychain-helper";
const nativeInspectorName = "s-gw-keychain-inspector";
const keychainRepairService = "com.s-gw.sgw.keychain-repair";
const windowsCredentialHelperName = "s-gw-credential.ps1";
const keychainRepairTimeoutMs = 10_000;
const staleKeychainRepairMs = 30_000;
const defaultSecretToolTimeoutMs = 10_000;
const defaultWindowsCredentialHelperTimeoutMs = 30_000;
const maxWindowsCredentialHelperTestTimeoutMs = 120_000;
const maxSecretToolInputBytes = 8_191;

export interface KeychainInfo {
  supported: boolean;
  service: string;
  account: string;
  provider: "native-helper" | "security-cli" | "secret-service-cli" | "windows-helper" | "none";
  helperPath?: string;
}

export interface UnlockStatus {
  envConfigured: boolean;
  activeSource: "env" | "linux-secret-service" | "macos-keychain" | "windows-credential-manager" | "none";
  keychain: KeychainInfo & {
    configured: boolean;
    state: "configured" | "missing" | "unavailable";
    error?: string;
  };
}

export interface MacKeychainItemRef {
  service: string;
  account: string;
  label?: string;
}

export interface PersistentKeychainHelperInstall {
  helperPath: string;
  sourcePath: string;
  changed: boolean;
}

export interface PersistentKeychainHelperOptions {
  sourcePath?: string;
  sgwHome?: string;
}

export interface PackagedKeychainHelperPin {
  sourcePath: string;
  packagePath: string;
  changed: boolean;
}

export interface PreservedKeychainHelperIdentity {
  sourcePath: string;
  helperPath: string;
  changed: boolean;
}

export interface MacKeychainAccessRepair {
  state: "already-bound" | "migrated" | "recovered" | "missing" | "unsupported";
  helperPath?: string;
}

export function requireUnlockPassphrase(): string {
  const fromEnv = process.env.SGW_MASTER_PASSPHRASE;
  if (validPassphrase(fromEnv)) {
    return fromEnv;
  }

  const fromKeychain = readKeychainPassphrase();
  if (validPassphrase(fromKeychain)) {
    return fromKeychain;
  }

  throw new Error(
    "s-gw needs a local unlock passphrase. Run `s-gw unlock keychain set --value-stdin` or set SGW_MASTER_PASSPHRASE."
  );
}

export function unlockStatus(): UnlockStatus {
  const envConfigured = validPassphrase(process.env.SGW_MASTER_PASSPHRASE);
  const keychain = keychainInfo();
  const passphrase = inspectKeychainPassphrase(keychain);
  const configured = passphrase.state === "configured";

  let activeSource: UnlockStatus["activeSource"] = "none";
  if (envConfigured) {
    activeSource = "env";
  } else if (configured) {
    activeSource = process.platform === "win32"
      ? "windows-credential-manager"
      : process.platform === "linux" ? "linux-secret-service" : "macos-keychain";
  }

  return {
    envConfigured,
    activeSource,
    keychain: {
      ...keychain,
      configured,
      ...passphrase
    }
  };
}

export function setKeychainPassphrase(passphrase: string): void {
  if (!validPassphrase(passphrase)) {
    throw new Error("Unlock passphrase must be at least 8 characters.");
  }

  ensureLocalCredentialStore();
  preparePersistentMacHelper();
  if (managedMacKeychainAccessEnabled()) {
    setManagedMacKeychainItem(masterPassphraseRef(), passphrase);
    return;
  }
  runKeychainSet(keychainInfo(), passphrase);
}

export function deleteKeychainPassphrase(): boolean {
  ensureLocalCredentialStore();
  preparePersistentMacHelper();
  if (managedMacKeychainAccessEnabled()) {
    return deleteManagedMacKeychainItem(masterPassphraseRef());
  }

  const info = keychainInfo();
  if (!keychainItemExists(info)) {
    return false;
  }
  if (info.provider === "windows-helper" && info.helperPath) {
    const output = runWindowsCredentialHelper(
      info.helperPath,
      ["delete", "-Service", info.service, "-Account", info.account]
    );
    const result = JSON.parse(output) as { deleted?: unknown };
    if (typeof result.deleted !== "boolean") {
      throw new Error("Windows Credential Manager delete returned an invalid response.");
    }
    if (keychainItemExists(info)) {
      throw new Error(`The OS credential store did not delete the unlock value for account ${info.account}.`);
    }
    return result.deleted;
  }
  runKeychainDelete(info);
  if (keychainItemExists(info)) {
    throw new Error(`The OS credential store did not delete the unlock value for account ${info.account}.`);
  }
  return true;
}

export function hasKeychainPassphrase(): boolean {
  const info = keychainInfo();
  return inspectKeychainPassphrase(info).state === "configured";
}

function inspectKeychainPassphrase(
  info: KeychainInfo
): { state: "configured" | "missing" | "unavailable"; error?: string } {
  if (!info.supported || info.provider === "none") {
    return { state: "unavailable", error: missingCredentialStoreError().message };
  }
  if (process.env.SGW_DISABLE_KEYCHAIN === "1") {
    return { state: "unavailable", error: "OS credential-store access is disabled by SGW_DISABLE_KEYCHAIN." };
  }
  try {
    return { state: keychainItemExists(info) ? "configured" : "missing" };
  } catch (error) {
    return {
      state: "unavailable",
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

export function keychainInfo(): KeychainInfo {
  return {
    supported: supportsLocalCredentialStore(),
    service: process.env.SGW_KEYCHAIN_SERVICE || MASTER_KEYCHAIN_SERVICE,
    account: process.env.SGW_KEYCHAIN_ACCOUNT || os.userInfo().username || "local-user",
    ...keychainProvider()
  };
}

export function defaultSecretKeychainService(): string {
  return process.env.SGW_SECRET_KEYCHAIN_SERVICE || SECRET_KEYCHAIN_SERVICE;
}

export function setMacKeychainItem(ref: MacKeychainItemRef, value: string): void {
  if (!value) {
    throw new Error("Cannot store an empty Keychain item.");
  }

  preparePersistentMacHelper();
  if (managedMacKeychainAccessEnabled()) {
    setManagedMacKeychainItem(ref, value);
    return;
  }
  const info = keychainInfoForItem(ref);
  ensureNativeCredentialStore(info);
  runKeychainSet(info, value, ref.label || "s-gw local secret");
}

export function getMacKeychainItem(ref: MacKeychainItemRef): string {
  preparePersistentMacHelper();
  if (managedMacKeychainAccessEnabled()) {
    return readManagedMacKeychainItem(ref).value;
  }
  const info = keychainInfoForItem(ref);
  ensureNativeCredentialStore(info);
  return runKeychainGet(info).replace(/\r?\n$/, "");
}

export function deleteMacKeychainItem(ref: MacKeychainItemRef): boolean {
  preparePersistentMacHelper();
  if (managedMacKeychainAccessEnabled()) {
    return deleteManagedMacKeychainItem(ref);
  }
  const info = keychainInfoForItem(ref);
  ensureNativeCredentialStore(info);
  if (info.provider === "secret-service-cli") {
    if (!keychainItemExists(info)) return false;
    runKeychainDelete(info);
    if (keychainItemExists(info)) {
      throw new Error(`Linux Secret Service did not delete the item for account ${ref.account}.`);
    }
    return true;
  }
  runKeychainDelete(info);
  return true;
}

export function repairKeychainPassphraseAccess(): MacKeychainAccessRepair {
  if (!managedMacKeychainAccessEnabled()) {
    return { state: "unsupported" };
  }
  preparePersistentMacHelper();
  return repairManagedMacKeychainItem(masterPassphraseRef());
}

export function repairMacKeychainItemAccess(ref: MacKeychainItemRef): MacKeychainAccessRepair {
  if (!managedMacKeychainAccessEnabled()) {
    return { state: "unsupported" };
  }
  preparePersistentMacHelper();
  return repairManagedMacKeychainItem(ref);
}

function readKeychainPassphrase(): string | undefined {
  if (!supportsLocalCredentialStore() || process.env.SGW_DISABLE_KEYCHAIN === "1") {
    return undefined;
  }

  preparePersistentMacHelper();
  if (managedMacKeychainAccessEnabled()) {
    const ref = masterPassphraseRef();
    const itemExists = keychainItemExists(keychainInfoForItem(ref));
    if (!itemExists && !keychainItemExists(keychainInfoForItem(keychainRepairBackupRef(ref)))) {
      return undefined;
    }
    return readManagedMacKeychainItem(ref).value;
  }

  try {
    const info = keychainInfo();
    const output = runKeychainGet(info);

    return output.replace(/\r?\n$/, "");
  } catch {
    return undefined;
  }
}

function ensureLocalCredentialStore(): void {
  if (!keychainInfo().supported) {
    throw new Error("OS credential-store unlock is only available on macOS, Windows, or Linux with Secret Service.");
  }
}

function ensureNativeCredentialStore(info: KeychainInfo): void {
  if (!info.supported) {
    throw new Error("OS credential-store secret storage is only available on macOS or Windows.");
  }

  if (
    (info.provider !== "native-helper"
      && info.provider !== "windows-helper"
      && info.provider !== "secret-service-cli")
    || !info.helperPath
  ) {
    throw missingCredentialStoreError();
  }
}

function keychainInfoForItem(ref: MacKeychainItemRef): KeychainInfo {
  const service = ref.service.trim();
  const account = ref.account.trim();
  if (!service || !account) {
    throw new Error("Keychain service and account are required.");
  }

  return {
    supported: supportsLocalCredentialStore(),
    service,
    account,
    ...keychainProvider()
  };
}

function validPassphrase(value: string | undefined): value is string {
  return typeof value === "string" && value.trim().length >= 8;
}

function keychainProvider(): Pick<KeychainInfo, "provider" | "helperPath"> {
  if (process.platform === "win32") {
    const helperPath = findWindowsCredentialHelper();
    return helperPath ? { provider: "windows-helper", helperPath } : { provider: "none" };
  }

  if (process.platform === "linux") {
    const helperPath = findLinuxSecretTool();
    return helperPath ? { provider: "secret-service-cli", helperPath } : { provider: "none" };
  }

  if (process.platform !== "darwin") {
    return { provider: "none" };
  }

  const helperPath = findNativeHelper();
  if (helperPath) {
    return { provider: "native-helper", helperPath };
  }

  if (process.env.SGW_ALLOW_SECURITY_CLI === "1") {
    return { provider: "security-cli" };
  }

  return { provider: "none" };
}

function supportsLocalCredentialStore(): boolean {
  return process.platform === "darwin" || process.platform === "linux" || process.platform === "win32";
}

function findNativeHelper(): string | undefined {
  const fromEnv = testOnlyHelperOverride("SGW_KEYCHAIN_HELPER");
  if (fromEnv && existsSync(fromEnv)) {
    assertUsableHelper(fromEnv);
    return fromEnv;
  }

  const persistent = persistentKeychainHelperPath();
  if (existsSync(persistent)) {
    return persistent;
  }

  return findPackagedNativeHelper();
}

function findPackagedNativeHelper(): string | undefined {
  return packagedNativeHelperCandidates().find((candidate) => existsSync(candidate));
}

function packagedNativeHelperCandidates(): string[] {
  if (process.platform !== "darwin") return [];

  const here = path.dirname(fileURLToPath(import.meta.url));
  const nativeTarget = `${process.platform}-${process.arch}`;
  return uniquePaths([
    path.resolve(here, "native", nativeTarget, nativeHelperName),
    path.resolve(here, "native", nativeHelperName),
    ...(process.env.SGW_TEST_MODE === "1"
      ? [
          path.resolve(here, "..", "dist", "native", nativeTarget, nativeHelperName),
          path.resolve(here, "..", "dist", "native", nativeHelperName)
        ]
      : [])
  ]);
}

function findPackagedKeychainInspector(): string | undefined {
  if (process.platform !== "darwin") return undefined;

  const fromEnv = testOnlyHelperOverride("SGW_KEYCHAIN_INSPECTOR");
  if (fromEnv) return existsSync(fromEnv) ? path.resolve(fromEnv) : undefined;

  const here = path.dirname(fileURLToPath(import.meta.url));
  const nativeTarget = `${process.platform}-${process.arch}`;
  const candidates = [
    path.resolve(here, "native", nativeTarget, nativeInspectorName),
    ...(process.env.SGW_TEST_MODE === "1"
      ? [path.resolve(here, "..", "dist", "native", nativeTarget, nativeInspectorName)]
      : [])
  ];
  return candidates.find((candidate) => existsSync(candidate));
}

export function persistentKeychainHelperPath(sgwHome = getSgwHome()): string {
  const nativeTarget = `${process.platform}-${process.arch}`;
  return path.join(path.resolve(sgwHome), "native", nativeTarget, nativeHelperName);
}

export function installPersistentKeychainHelper(
  options: PersistentKeychainHelperOptions = {}
): PersistentKeychainHelperInstall {
  if (process.platform !== "darwin") {
    throw new Error("The persistent Keychain helper is only available on macOS.");
  }

  const source = options.sourcePath || findPackagedNativeHelper();
  if (!source) {
    throw missingCredentialStoreError();
  }
  const sourcePath = path.resolve(source);
  if (!existsSync(sourcePath)) throw missingCredentialStoreError();
  assertUsableHelper(sourcePath);

  const helperPath = persistentKeychainHelperPath(options.sgwHome);
  if (existsSync(helperPath)) {
    assertUsableHelper(helperPath);
    if (helperHash(sourcePath) !== helperHash(helperPath)) {
      preserveLegacyKeychainHelper(sourcePath, options.sgwHome);
    }
    chmodSync(helperPath, 0o700);
    return { helperPath, sourcePath, changed: false };
  }

  const helperDir = path.dirname(helperPath);
  mkdirSync(helperDir, { recursive: true, mode: 0o700 });
  chmodSync(helperDir, 0o700);
  const staging = `${helperPath}.install-${process.pid}-${Date.now()}`;

  try {
    copyFileSync(sourcePath, staging);
    chmodSync(staging, 0o700);
    try {
      linkSync(staging, helperPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  } finally {
    rmSync(staging, { force: true });
  }

  assertUsableHelper(helperPath);
  return { helperPath, sourcePath, changed: true };
}

export function pinPackagedKeychainHelper(
  packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
  sourcePath = persistentKeychainHelperPath(),
  sgwHome = getSgwHome()
): PackagedKeychainHelperPin | undefined {
  if (process.platform !== "darwin") return undefined;
  if (resolveSelfContainedMacRuntime(packageRoot)) return undefined;

  assertUsableHelper(sourcePath);
  const nativeTarget = `${process.platform}-${process.arch}`;
  const packagePath = path.join(path.resolve(packageRoot), "dist", "native", nativeTarget, nativeHelperName);
  const sourceHash = helperHash(sourcePath);

  if (existsSync(packagePath)) {
    const info = lstatSync(packagePath);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error(`Refusing to replace an unsafe packaged Keychain helper: ${packagePath}`);
    }
    if (helperHash(packagePath) === sourceHash) {
      return { sourcePath, packagePath, changed: false };
    }
    preserveLegacyKeychainHelper(packagePath, sgwHome);
  }

  mkdirSync(path.dirname(packagePath), { recursive: true });
  const staging = `${packagePath}.pin-${process.pid}-${Date.now()}`;
  try {
    copyFileSync(sourcePath, staging);
    chmodSync(staging, 0o755);
    renameSync(staging, packagePath);
  } finally {
    rmSync(staging, { force: true });
  }

  assertUsableHelper(packagePath);
  if (helperHash(packagePath) !== sourceHash) {
    throw new Error(`Packaged Keychain helper verification failed: ${packagePath}`);
  }
  return { sourcePath, packagePath, changed: true };
}

export function preserveLegacyKeychainHelper(
  sourcePath: string,
  sgwHome = getSgwHome()
): PreservedKeychainHelperIdentity {
  const resolvedSource = path.resolve(sourcePath);
  assertUsableHelper(resolvedSource);
  const hash = helperHash(resolvedSource);
  const legacyRoot = path.join(path.resolve(sgwHome), "native", "legacy");
  const helperPath = path.join(legacyRoot, hash, nativeHelperName);

  if (existsSync(helperPath)) {
    assertUsableHelper(helperPath);
    if (helperHash(helperPath) !== hash) {
      throw new Error(`Preserved Keychain helper verification failed: ${helperPath}`);
    }
    chmodSync(helperPath, 0o700);
    return { sourcePath: resolvedSource, helperPath, changed: false };
  }

  mkdirSync(path.dirname(helperPath), { recursive: true, mode: 0o700 });
  chmodSync(legacyRoot, 0o700);
  chmodSync(path.dirname(helperPath), 0o700);
  const staging = `${helperPath}.preserve-${process.pid}-${Date.now()}`;
  try {
    copyFileSync(resolvedSource, staging);
    chmodSync(staging, 0o700);
    linkSync(staging, helperPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  } finally {
    rmSync(staging, { force: true });
  }

  assertUsableHelper(helperPath);
  if (helperHash(helperPath) !== hash) {
    throw new Error(`Preserved Keychain helper verification failed: ${helperPath}`);
  }
  return { sourcePath: resolvedSource, helperPath, changed: true };
}

function helperHash(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function preparePersistentMacHelper(): void {
  if (process.platform !== "darwin" || testOnlyHelperOverride("SGW_KEYCHAIN_HELPER")) {
    return;
  }
  if (!existsSync(persistentKeychainHelperPath())) {
    installPersistentKeychainHelper();
  }
}

function assertUsableHelper(helperPath: string): void {
  const info = statSync(helperPath);
  if (!info.isFile() || info.size === 0) {
    throw new Error(`Keychain helper is not a usable file: ${helperPath}`);
  }
  accessSync(helperPath, constants.X_OK);
}

interface ManagedMacKeychainRead {
  value: string;
  repair: MacKeychainAccessRepair;
}

interface TrustedHelperResolution {
  helpers: string[];
  cleanup: () => void;
}

let keychainAclDumpCache: string | undefined;
const keychainRepairWait = new Int32Array(new SharedArrayBuffer(4));

function managedMacKeychainAccessEnabled(): boolean {
  return process.platform === "darwin" && !testOnlyHelperOverride("SGW_KEYCHAIN_HELPER");
}

function masterPassphraseRef(): MacKeychainItemRef {
  const info = keychainInfo();
  return {
    service: info.service,
    account: info.account,
    label: "s-gw local unlock passphrase"
  };
}

function repairManagedMacKeychainItem(ref: MacKeychainItemRef): MacKeychainAccessRepair {
  return withKeychainRepairLock(() => {
    const info = keychainInfoForItem(ref);
    if (!keychainItemExists(info)) {
      const recovered = recoverInterruptedKeychainRepair(ref);
      return recovered?.repair || { state: "missing" };
    }
    return readManagedMacKeychainItemLocked(ref).repair;
  });
}

function readManagedMacKeychainItem(ref: MacKeychainItemRef): ManagedMacKeychainRead {
  return withKeychainRepairLock(() => readManagedMacKeychainItemLocked(ref));
}

function readManagedMacKeychainItemLocked(ref: MacKeychainItemRef): ManagedMacKeychainRead {
  const persistent = persistentKeychainHelperPath();
  assertUsableHelper(persistent);
  const info = keychainInfoForItem(ref);

  if (!keychainItemExists(info)) {
    const recovered = recoverInterruptedKeychainRepair(ref);
    if (recovered) return recovered;
    throw new Error(`Keychain item was not found for account ${ref.account}.`);
  }

  const resolution = resolveTrustedHelper(ref, persistent);
  try {
    if (resolution.helpers.includes(persistent)) {
      removeRepairBackup(ref, persistent);
      return {
        value: runNativeHelper(persistent, keychainGetArgs(ref)).replace(/\r?\n$/, ""),
        repair: { state: "already-bound", helperPath: persistent }
      };
    }

    const source = resolution.helpers[0];
    if (!source) throw untrustedKeychainItemError(ref);

    const value = runNativeHelper(source, keychainGetArgs(ref)).replace(/\r?\n$/, "");
    const backup = keychainRepairBackupRef(ref);
    const backupInfo = keychainInfoForItem(backup);
    if (keychainItemExists(backupInfo)) {
      const backupResolution = resolveTrustedHelper(backup, persistent);
      try {
        if (!backupResolution.helpers.includes(persistent)) throw untrustedKeychainItemError(backup);
      } finally {
        backupResolution.cleanup();
      }
    }
    runKeychainSet({ ...backupInfo, provider: "native-helper", helperPath: persistent }, value, backup.label);
    verifyKeychainValue(backup, persistent, value);

    runNativeHelper(source, keychainDeleteArgs(ref));
    try {
      runKeychainSet({ ...info, provider: "native-helper", helperPath: persistent }, value, ref.label);
      verifyKeychainValue(ref, persistent, value);
    } catch (migrationError) {
      try {
        runKeychainSet({ ...info, provider: "native-helper", helperPath: source }, value, ref.label);
        verifyKeychainValue(ref, source, value);
        runKeychainDelete({ ...backupInfo, provider: "native-helper", helperPath: persistent });
      } catch {
        throw new Error(
          `Keychain access repair failed for ${ref.account}; a verified recovery copy remains in macOS Keychain. ` +
          "Run `s-gw unlock keychain repair` before using this handle again."
        );
      }
      throw migrationError;
    }

    runKeychainDelete({ ...backupInfo, provider: "native-helper", helperPath: persistent });
    return {
      value,
      repair: { state: "migrated", helperPath: persistent }
    };
  } finally {
    resolution.cleanup();
  }
}

function setManagedMacKeychainItem(ref: MacKeychainItemRef, value: string): void {
  withKeychainRepairLock(() => {
    const persistent = persistentKeychainHelperPath();
    assertUsableHelper(persistent);
    const info = keychainInfoForItem(ref);

    if (keychainItemExists(info)) {
      readManagedMacKeychainItemLocked(ref);
    } else {
      recoverInterruptedKeychainRepair(ref);
    }

    runKeychainSet({ ...info, provider: "native-helper", helperPath: persistent }, value, ref.label);
    verifyKeychainValue(ref, persistent, value);
  });
}

function deleteManagedMacKeychainItem(ref: MacKeychainItemRef): boolean {
  return withKeychainRepairLock(() => {
    const persistent = persistentKeychainHelperPath();
    assertUsableHelper(persistent);
    const info = keychainInfoForItem(ref);
    let deleted = false;

    if (keychainItemExists(info)) {
      const resolution = resolveTrustedHelper(ref, persistent);
      try {
        const helper = resolution.helpers[0];
        if (!helper) throw untrustedKeychainItemError(ref);
        runNativeHelper(helper, keychainDeleteArgs(ref));
        deleted = true;
      } finally {
        resolution.cleanup();
      }
    }

    const backup = keychainRepairBackupRef(ref);
    const backupInfo = keychainInfoForItem(backup);
    if (keychainItemExists(backupInfo)) {
      const resolution = resolveTrustedHelper(backup, persistent);
      try {
        if (!resolution.helpers.includes(persistent)) throw untrustedKeychainItemError(backup);
        runKeychainDelete({ ...backupInfo, provider: "native-helper", helperPath: persistent });
      } finally {
        resolution.cleanup();
      }
    }

    return deleted;
  });
}

function recoverInterruptedKeychainRepair(ref: MacKeychainItemRef): ManagedMacKeychainRead | undefined {
  const persistent = persistentKeychainHelperPath();
  const backup = keychainRepairBackupRef(ref);
  const backupInfo = keychainInfoForItem(backup);
  if (!keychainItemExists(backupInfo)) return undefined;

  const resolution = resolveTrustedHelper(backup, persistent);
  try {
    if (!resolution.helpers.includes(persistent)) throw untrustedKeychainItemError(backup);
    const value = runNativeHelper(persistent, keychainGetArgs(backup)).replace(/\r?\n$/, "");
    const info = keychainInfoForItem(ref);
    runKeychainSet({ ...info, provider: "native-helper", helperPath: persistent }, value, ref.label);
    verifyKeychainValue(ref, persistent, value);
    runKeychainDelete({ ...backupInfo, provider: "native-helper", helperPath: persistent });
    return {
      value,
      repair: { state: "recovered", helperPath: persistent }
    };
  } finally {
    resolution.cleanup();
  }
}

function removeRepairBackup(ref: MacKeychainItemRef, persistent: string): void {
  const backup = keychainRepairBackupRef(ref);
  const info = keychainInfoForItem(backup);
  if (!keychainItemExists(info)) return;

  const resolution = resolveTrustedHelper(backup, persistent);
  try {
    if (!resolution.helpers.includes(persistent)) throw untrustedKeychainItemError(backup);
    runKeychainDelete({ ...info, provider: "native-helper", helperPath: persistent });
  } finally {
    resolution.cleanup();
  }
}

function verifyKeychainValue(ref: MacKeychainItemRef, helperPath: string, expected: string): void {
  const actual = runNativeHelper(helperPath, keychainGetArgs(ref)).replace(/\r?\n$/, "");
  if (actual !== expected) {
    throw new Error(`Keychain verification failed for account ${ref.account}.`);
  }
}

function resolveTrustedHelper(ref: MacKeychainItemRef, persistent: string): TrustedHelperResolution {
  const known = safeHelperCandidates([
    persistent,
    ...packagedNativeHelperCandidates(),
    ...preservedLegacyHelperCandidates(),
    ...(process.env.SGW_KEYCHAIN_LEGACY_HELPERS || "").split(path.delimiter)
  ]);
  const firstMatch = inspectTrustedHelpers(ref, known);
  if (firstMatch.length > 0) {
    return { helpers: preferPersistent(firstMatch, persistent), cleanup: () => undefined };
  }

  const candidates = safeHelperCandidates([...known, ...trustedApplicationPaths(ref)]);
  const matches = inspectTrustedHelpers(ref, candidates);
  return {
    helpers: preferPersistent(matches, persistent),
    cleanup: () => undefined
  };
}

function preservedLegacyHelperCandidates(): string[] {
  const legacyRoot = path.join(path.resolve(getSgwHome()), "native", "legacy");
  try {
    return readdirSync(legacyRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && /^[a-f0-9]{64}$/.test(entry.name))
      .map((entry) => path.join(legacyRoot, entry.name, nativeHelperName));
  } catch {
    return [];
  }
}

function inspectTrustedHelpers(ref: MacKeychainItemRef, candidates: string[]): string[] {
  if (candidates.length === 0) return [];
  const inspector = findPackagedKeychainInspector();
  if (!inspector) {
    throw new Error("The macOS Keychain inspector is missing. Reinstall s-gw before accessing credentials.");
  }

  const args = ["trusted-helper", "--service", ref.service, "--account", ref.account];
  for (const candidate of candidates) args.push("--candidate", candidate);
  const result = spawnSync(inspector, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status === 44) return [];
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `Keychain inspector failed with status ${result.status}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error("Keychain inspector returned invalid JSON.");
  }
  const values = (parsed as { trustedHelpers?: unknown }).trustedHelpers;
  if (!Array.isArray(values)) throw new Error("Keychain inspector returned an invalid helper list.");
  const allowed = new Set(candidates);
  return values.filter((value): value is string => typeof value === "string" && allowed.has(value));
}

function trustedApplicationPaths(ref: MacKeychainItemRef): string[] {
  if (keychainAclDumpCache === undefined) {
    const result = spawnSync(keychainStatusCliPath(), ["dump-keychain", "-a"], {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"]
    });
    if (result.status !== 0) {
      throw new Error(result.stderr.trim() || `Keychain ACL inspection failed with status ${result.status}`);
    }
    keychainAclDumpCache = `${result.stdout}\n${result.stderr}`;
  }
  return parseKeychainTrustedApplicationPaths(keychainAclDumpCache, ref.service, ref.account);
}

export function parseKeychainTrustedApplicationPaths(
  dump: string,
  service: string,
  account: string
): string[] {
  const blocks = dump.split(/(?=keychain: )/g);
  for (const block of blocks) {
    const foundService = block.match(/"svce"<blob>="([^"]*)"/)?.[1];
    const foundAccount = block.match(/"acct"<blob>="([^"]*)"/)?.[1];
    if (foundService !== service || foundAccount !== account) continue;

    const paths: string[] = [];
    const matcher = /^\s+\d+:\s+(\/.*?)\s+\((?:OK|status\s+-?\d+)\)\s*$/gm;
    for (const match of block.matchAll(matcher)) paths.push(match[1]);
    return uniquePaths(paths);
  }
  return [];
}

function safeHelperCandidates(candidates: string[]): string[] {
  return uniquePaths(candidates.filter(Boolean).map((candidate) => path.resolve(candidate))).filter((candidate) => {
    if (!existsSync(candidate)) return false;
    if (![nativeHelperName, "sgw-keychain-helper"].includes(path.basename(candidate))) return false;
    try {
      const info = lstatSync(candidate);
      const uid = typeof process.getuid === "function" ? process.getuid() : info.uid;
      if (!info.isFile() || info.isSymbolicLink()) return false;
      if (info.uid !== 0 && info.uid !== uid) return false;
      if ((info.mode & 0o022) !== 0) return false;
      accessSync(candidate, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

function preferPersistent(matches: string[], persistent: string): string[] {
  return matches.includes(persistent)
    ? [persistent, ...matches.filter((candidate) => candidate !== persistent)]
    : matches;
}

function keychainRepairBackupRef(ref: MacKeychainItemRef): MacKeychainItemRef {
  const account = createHash("sha256").update(ref.service).update("\0").update(ref.account).digest("hex");
  return {
    service: keychainRepairService,
    account,
    label: "s-gw Keychain repair backup"
  };
}

function keychainGetArgs(ref: MacKeychainItemRef): string[] {
  return ["get", "--service", ref.service, "--account", ref.account];
}

function keychainDeleteArgs(ref: MacKeychainItemRef): string[] {
  return ["delete", "--service", ref.service, "--account", ref.account];
}

function untrustedKeychainItemError(ref: MacKeychainItemRef): Error {
  return new Error(
    `No trusted s-gw helper is available for Keychain account ${ref.account}. ` +
    "s-gw stopped before requesting your login password. Run `s-gw unlock keychain repair`."
  );
}

function withKeychainRepairLock<T>(body: () => T): T {
  const lockPath = path.join(path.resolve(getSgwHome()), ".keychain-repair.lock");
  mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  const started = Date.now();

  while (true) {
    try {
      mkdirSync(lockPath, { mode: 0o700 });
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > staleKeychainRepairMs) {
          rmSync(lockPath, { recursive: true, force: true });
          continue;
        }
      } catch (statError) {
        if ((statError as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw statError;
      }
      if (Date.now() - started > keychainRepairTimeoutMs) {
        throw new Error(`Timed out waiting for Keychain repair lock at ${lockPath}.`);
      }
      Atomics.wait(keychainRepairWait, 0, 0, 25);
    }
  }

  try {
    return body();
  } finally {
    rmSync(lockPath, { recursive: true, force: true });
  }
}

function uniquePaths(values: string[]): string[] {
  return [...new Set(values.filter(Boolean).map((value) => path.resolve(value)))];
}

function findWindowsCredentialHelper(): string | undefined {
  const fromEnv = testOnlyHelperOverride("SGW_WINDOWS_CREDENTIAL_HELPER")
    || testOnlyHelperOverride("SGW_KEYCHAIN_HELPER");
  if (fromEnv && existsSync(fromEnv)) {
    return path.resolve(fromEnv);
  }

  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, "windows", windowsCredentialHelperName),
    ...(process.env.SGW_TEST_MODE === "1"
      ? [path.resolve(here, "..", "dist", "windows", windowsCredentialHelperName)]
      : [])
  ];

  return candidates.find((candidate) => existsSync(candidate));
}

function findLinuxSecretTool(): string | undefined {
  const candidates: string[] = [];
  if (process.env.SGW_TEST_MODE === "1" && process.env.SGW_SECRET_TOOL !== undefined) {
    candidates.push(path.resolve(process.env.SGW_SECRET_TOOL));
  } else {
    candidates.push("/usr/bin/secret-tool", "/bin/secret-tool");
  }

  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    try {
      const info = lstatSync(candidate);
      const currentUid = typeof process.getuid === "function" ? process.getuid() : info.uid;
      const trustedOwner = info.uid === 0 || (process.env.SGW_TEST_MODE === "1" && info.uid === currentUid);
      if (!info.isFile() || info.isSymbolicLink() || !trustedOwner || (info.mode & 0o022) !== 0) {
        continue;
      }
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Try the next fixed system path.
    }
  }

  return undefined;
}

function runKeychainGet(info: KeychainInfo): string {
  if (info.provider === "native-helper" && info.helperPath) {
    return runNativeHelper(info.helperPath, ["get", "--service", info.service, "--account", info.account]);
  }

  if (info.provider === "security-cli") {
    return runSecurity([
      "find-generic-password",
      "-a",
      info.account,
      "-s",
      info.service,
      "-w"
    ]);
  }

  if (info.provider === "windows-helper" && info.helperPath) {
    return runWindowsCredentialHelper(info.helperPath, ["get", "-Service", info.service, "-Account", info.account]);
  }

  if (info.provider === "secret-service-cli" && info.helperPath) {
    return runSecretTool(info.helperPath, ["lookup", ...secretServiceAttributes(info)]);
  }

  throw missingCredentialStoreError();
}

function keychainItemExists(info: KeychainInfo): boolean {
  if (process.platform === "darwin") {
    const result = spawnSync(
      keychainStatusCliPath(),
      ["find-generic-password", "-a", info.account, "-s", info.service],
      { encoding: "utf8", stdio: ["ignore", "ignore", "pipe"] }
    );

    if (result.error) {
      throw result.error;
    }
    if (result.status === 0) {
      return true;
    }
    if (result.status === 44) {
      return false;
    }
    throw new Error(result.stderr.trim() || `Keychain status check failed with status ${result.status}`);
  }

  if (info.provider === "windows-helper" && info.helperPath) {
    const output = runWindowsCredentialHelper(
      info.helperPath,
      ["status", "-Service", info.service, "-Account", info.account]
    );
    const status = JSON.parse(output) as { configured?: unknown };
    if (typeof status.configured !== "boolean") {
      throw new Error("Windows Credential Manager status returned an invalid response.");
    }
    return status.configured;
  }

  if (info.provider === "secret-service-cli" && info.helperPath) {
    const result = spawnSync(info.helperPath, ["lookup", ...secretServiceAttributes(info)], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: secretToolTimeoutMs(),
      killSignal: "SIGKILL"
    });
    assertSecretToolCompleted(result);
    if (result.status === 0) return result.stdout.replace(/\r?\n$/, "").length > 0;
    if (result.status === 1 && !result.stderr.trim()) return false;
    throw new Error(result.stderr.trim() || `Secret Service status check failed with status ${result.status}`);
  }

  return false;
}

function runKeychainSet(info: KeychainInfo, passphrase: string, label = "s-gw local unlock passphrase"): void {
  if (info.provider === "native-helper" && info.helperPath) {
    runNativeHelper(info.helperPath, ["set", "--service", info.service, "--account", info.account, "--label", label], passphrase);
    return;
  }

  if (info.provider === "security-cli") {
    runSecurity([
      "add-generic-password",
      "-U",
      "-a",
      info.account,
      "-s",
      info.service,
      "-l",
      label,
      "-w",
      passphrase
    ]);
    return;
  }

  if (info.provider === "windows-helper" && info.helperPath) {
    runWindowsCredentialHelper(
      info.helperPath,
      ["set", "-Service", info.service, "-Account", info.account, "-Label", label],
      passphrase
    );
    return;
  }

  if (info.provider === "secret-service-cli" && info.helperPath) {
    const byteLength = Buffer.byteLength(passphrase, "utf8");
    if (byteLength > maxSecretToolInputBytes) {
      throw new Error(
        `Linux Secret Service values are limited to ${maxSecretToolInputBytes} UTF-8 bytes by secret-tool; received ${byteLength}.`
      );
    }
    runSecretTool(
      info.helperPath,
      [`store`, `--label=${label}`, ...secretServiceAttributes(info)],
      passphrase
    );
    return;
  }

  throw missingCredentialStoreError();
}

function runKeychainDelete(info: KeychainInfo): void {
  if (info.provider === "native-helper" && info.helperPath) {
    runNativeHelper(info.helperPath, ["delete", "--service", info.service, "--account", info.account]);
    return;
  }

  if (info.provider === "security-cli") {
    runSecurity(["delete-generic-password", "-a", info.account, "-s", info.service]);
    return;
  }

  if (info.provider === "windows-helper" && info.helperPath) {
    runWindowsCredentialHelper(info.helperPath, ["delete", "-Service", info.service, "-Account", info.account]);
    return;
  }

  if (info.provider === "secret-service-cli" && info.helperPath) {
    runSecretTool(info.helperPath, ["clear", ...secretServiceAttributes(info)]);
    return;
  }

  throw missingCredentialStoreError();
}

function missingCredentialStoreError(): Error {
  if (process.platform === "darwin") {
    return new Error(
      `No compatible macOS Keychain helper is available for darwin-${process.arch}. ` +
      "Public npm and DMG releases currently include Apple Silicon native surfaces; Intel Macs must build them from source."
    );
  }
  if (process.platform === "linux") {
    return new Error(
      "Linux Secret Service is unavailable. Install libsecret-tools and start an unlocked user keyring, " +
      "or use SGW_MASTER_PASSPHRASE for an explicit foreground/headless session."
    );
  }
  return new Error("No local OS credential-store provider is available. Run `npm run build:native`.");
}

function secretServiceAttributes(info: Pick<KeychainInfo, "service" | "account">): string[] {
  return ["application", "s-gw", "service", info.service, "account", info.account];
}

function runSecretTool(helperPath: string, args: string[], input?: string): string {
  const result = spawnSync(helperPath, args, {
    input,
    encoding: "utf8",
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    timeout: secretToolTimeoutMs(),
    killSignal: "SIGKILL"
  });
  assertSecretToolCompleted(result);
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `Linux Secret Service helper failed with status ${result.status}`);
  }
  return result.stdout;
}

function secretToolTimeoutMs(): number {
  if (process.env.SGW_TEST_MODE !== "1") return defaultSecretToolTimeoutMs;
  const configured = Number(process.env.SGW_SECRET_TOOL_TIMEOUT_MS);
  return Number.isInteger(configured) && configured > 0 && configured <= defaultSecretToolTimeoutMs
    ? configured
    : defaultSecretToolTimeoutMs;
}

function assertSecretToolCompleted(result: ReturnType<typeof spawnSync>): void {
  if (!result.error) return;
  if ((result.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
    throw new Error(`Linux Secret Service helper timed out after ${secretToolTimeoutMs()} ms.`);
  }
  throw result.error;
}

function runNativeHelper(helperPath: string, args: string[], input?: string): string {
  const result = spawnSync(helperPath, args, {
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"]
  });

  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `Native Keychain helper failed with status ${result.status}`);
  }

  return result.stdout;
}

function runSecurity(args: string[]): string {
  return execFileSync("/usr/bin/security", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function keychainStatusCliPath(): string {
  return testOnlyHelperOverride("SGW_KEYCHAIN_STATUS_CLI") || "/usr/bin/security";
}

function testOnlyHelperOverride(name: string): string | undefined {
  const configured = process.env[name];
  if (!configured) return undefined;
  if (process.env.SGW_TEST_MODE !== "1") {
    throw new Error(`${name} is restricted to isolated s-gw tests; reinstall s-gw to restore its packaged helper.`);
  }
  if (configured.includes("\0") || /[\r\n]/.test(configured)) {
    throw new Error(`Invalid ${name} test helper path.`);
  }
  return path.resolve(configured);
}

function runWindowsCredentialHelper(helperPath: string, args: string[], input?: string): string {
  const powershell = trustedWindowsPowerShellSync();
  const timeoutMs = windowsCredentialHelperTimeoutMs();
  const result = spawnSync(powershell, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    helperPath,
    ...args
  ], {
    cwd: path.dirname(powershell),
    input,
    encoding: "utf8",
    env: windowsSystemEnvironment(),
    stdio: ["pipe", "pipe", "pipe"],
    timeout: timeoutMs,
    killSignal: "SIGKILL"
  });

  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      throw new Error(`Windows Credential Manager helper timed out after ${timeoutMs} ms.`);
    }
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `Windows Credential Manager helper failed with status ${result.status}`);
  }

  return result.stdout;
}

export function windowsCredentialHelperTimeoutMs(): number {
  if (process.env.SGW_TEST_MODE !== "1") return defaultWindowsCredentialHelperTimeoutMs;
  const configured = Number(process.env.SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS);
  return Number.isInteger(configured) && configured > 0 && configured <= maxWindowsCredentialHelperTestTimeoutMs
    ? configured
    : defaultWindowsCredentialHelperTimeoutMs;
}
