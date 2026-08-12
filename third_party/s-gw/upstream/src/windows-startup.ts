import { Buffer } from "node:buffer";
import { mkdirSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { getSgwHome, getSgwRecoveryHome } from "./paths.js";
import { trustedWindowsPowerShellSync, windowsSystemEnvironment } from "./windows-system.js";

const STARTUP_DESCRIPTION = "s-gw per-user login startup (managed)";
const STARTUP_FILE_NAME = "s-gw Credential Gateway.lnk";
const PAYLOAD_VERSION = 1;
const defaultStartupOperationTimeoutMs = 30_000;
const maxStartupOperationTestTimeoutMs = 120_000;
const AUTHORITY_ENV_KEYS = [
  "SGW_EXECUTION_ENGINE",
  "SGW_HOME",
  "SGW_KEYCHAIN_ACCOUNT",
  "SGW_KEYCHAIN_SERVICE",
  "SGW_RECOVERY_HOME",
  "SGW_SECRET_BACKEND",
  "SGW_SECRET_KEYCHAIN_SERVICE"
] as const;

export interface WindowsStartupConfig {
  version: 1;
  userSid: string;
  port: number;
  tray: boolean;
  env: Record<string, string>;
}

export interface WindowsStartupShortcutStatus {
  shortcutPath: string;
  installed: boolean;
  managed: boolean;
  current: boolean;
  enabled: boolean;
  collision: boolean;
  targetPath?: string;
  cliPath?: string;
  config?: WindowsStartupConfig;
  error?: string;
}

interface ShortcutRecord {
  shortcutPath: string;
  currentSid: string;
  exists: boolean;
  targetPath?: string;
  arguments?: string;
  description?: string;
  workingDirectory?: string;
}

const WINDOWS_STARTUP_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$marker = 's-gw per-user login startup (managed)'
$fileName = 's-gw Credential Gateway.lnk'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $identity.User.Value
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
$creatorOwnerSid = 'S-1-3-0'
$trustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$accessAndOwner = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner

function Test-SamePath([string]$left, [string]$right) {
  return [string]::Equals(
    $left.TrimEnd([System.IO.Path]::DirectorySeparatorChar),
    $right.TrimEnd([System.IO.Path]::DirectorySeparatorChar),
    [System.StringComparison]::OrdinalIgnoreCase
  )
}

function Assert-LocalFixedPath([string]$inputPath) {
  if (-not $inputPath) { throw 'The per-user Startup folder is unavailable.' }
  $fullPath = [System.IO.Path]::GetFullPath($inputPath)
  if ((New-Object System.Uri($fullPath)).IsUnc) {
    throw 'The per-user Startup folder must not use a UNC location.'
  }
  $volume = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($fullPath))
  if ($volume.DriveType -ne [System.IO.DriveType]::Fixed) {
    throw 'The per-user Startup folder must use a fixed local volume.'
  }
  return $fullPath
}

function Test-TrustedOwner([string]$sid) {
  return $sid -eq $currentSid -or $sid -eq $systemSid -or $sid -eq $administratorsSid -or $sid -eq $trustedInstallerSid
}

function Assert-TrustedDirectory([string]$dirPath, [bool]$writeSensitive = $true) {
  $dirPath = Assert-LocalFixedPath $dirPath
  $info = [System.IO.DirectoryInfo]::new($dirPath)
  $info.Refresh()
  if (-not $info.Exists -or ($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not (Test-SamePath $info.FullName $dirPath)) {
    throw ('The per-user Startup path is not a stable local directory: ' + $dirPath)
  }
  $acl = $info.GetAccessControl($accessAndOwner)
  $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if (-not (Test-TrustedOwner $ownerSid)) {
    throw ('The per-user Startup path has an unexpected owner: ' + $ownerSid)
  }
  $unsafe = (
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  )
  if ($writeSensitive) {
    $unsafe = $unsafe -bor [System.Security.AccessControl.FileSystemRights]::Write
  }
  foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    if ($rule.AccessControlType -ne $allow) { continue }
    $sid = $rule.IdentityReference.Value
    if ($sid -eq $currentSid -or $sid -eq $systemSid -or $sid -eq $administratorsSid -or $sid -eq $creatorOwnerSid -or $sid -eq $trustedInstallerSid) { continue }
    if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if (($rule.FileSystemRights -band $unsafe) -ne 0) {
      throw ('The per-user Startup path grants unsafe access to ' + $sid)
    }
  }
}

function Assert-TrustedDirectoryChain([string]$leafPath) {
  $cursor = Assert-LocalFixedPath $leafPath
  $volumeRoot = [System.IO.Path]::GetPathRoot($cursor)
  $writeSensitive = $true
  while ($true) {
    Assert-TrustedDirectory $cursor $writeSensitive
    if (Test-SamePath $cursor $volumeRoot) { break }
    $parent = [System.IO.Directory]::GetParent($cursor)
    if (-not $parent) { throw 'A trusted Windows path could not be anchored to its fixed volume.' }
    $cursor = $parent.FullName
    $writeSensitive = $false
  }
}

function Assert-TrustedFile([string]$filePath, [string]$label) {
  $fullPath = Assert-LocalFixedPath $filePath
  $info = [System.IO.FileInfo]::new($fullPath)
  $info.Refresh()
  if (-not $info.Exists -or ($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not (Test-SamePath $info.FullName $fullPath)) {
    throw ($label + ' is not a stable local file.')
  }
  $acl = $info.GetAccessControl($accessAndOwner)
  $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if (-not (Test-TrustedOwner $ownerSid)) {
    throw ($label + ' has an unexpected owner: ' + $ownerSid)
  }
  $unsafe = (
    [System.Security.AccessControl.FileSystemRights]::Write -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  )
  foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    if ($rule.AccessControlType -ne $allow) { continue }
    $sid = $rule.IdentityReference.Value
    if ($sid -eq $currentSid -or $sid -eq $systemSid -or $sid -eq $administratorsSid -or $sid -eq $creatorOwnerSid -or $sid -eq $trustedInstallerSid) { continue }
    if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if (($rule.FileSystemRights -band $unsafe) -ne 0) {
      throw ($label + ' grants unsafe access to ' + $sid)
    }
  }
  return $fullPath
}

function Get-TrustedStartupFolder() {
  $profile = Assert-LocalFixedPath ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile))
  $startup = if ($env:SGW_WINDOWS_STARTUP_TEST_ROOT) {
    Assert-LocalFixedPath $env:SGW_WINDOWS_STARTUP_TEST_ROOT
  } else {
    Assert-LocalFixedPath ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Startup))
  }
  $profilePrefix = $profile.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
  if (-not (Test-SamePath $startup $profile) -and -not $startup.StartsWith($profilePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The per-user Startup folder must stay inside the current user profile.'
  }
  if (-not [System.IO.Directory]::Exists($startup)) {
    $null = [System.IO.Directory]::CreateDirectory($startup)
  }
  Assert-TrustedDirectoryChain $startup
  return $startup
}

function Read-Shortcut([string]$shortcutPath) {
  if (-not [System.IO.File]::Exists($shortcutPath)) {
    return [PSCustomObject]@{ shortcutPath = $shortcutPath; currentSid = $currentSid; exists = $false }
  }
  $info = [System.IO.FileInfo]::new($shortcutPath)
  $info.Refresh()
  if (($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not (Test-SamePath $info.FullName $shortcutPath)) {
    throw 'The s-gw Startup shortcut is not a stable local file.'
  }
  $null = Assert-TrustedFile $shortcutPath 'The s-gw Startup shortcut'
  $shell = New-Object -ComObject WScript.Shell
  $shortcut = $shell.CreateShortcut($shortcutPath)
  return [PSCustomObject]@{
    shortcutPath = $shortcutPath
    currentSid = $currentSid
    exists = $true
    targetPath = [string]$shortcut.TargetPath
    arguments = [string]$shortcut.Arguments
    description = [string]$shortcut.Description
    workingDirectory = [string]$shortcut.WorkingDirectory
  }
}

function Test-ManagedShortcut($record) {
  if (-not $record.exists -or $record.description -ne $marker) { return $false }
  if ([System.IO.Path]::GetFileName([string]$record.targetPath) -cnotmatch '^(?i:node\.exe)$') { return $false }
  return [string]$record.arguments -cmatch '^"[^"]+" "__windows-login-start" "--payload" "[A-Za-z0-9_-]+"$'
}

$startup = Get-TrustedStartupFolder
$shortcutPath = [System.IO.Path]::Combine($startup, $fileName)
$mode = $env:SGW_WINDOWS_STARTUP_MODE

if ($mode -eq 'inspect') {
  [Console]::Out.WriteLine(((Read-Shortcut $shortcutPath) | ConvertTo-Json -Compress))
  exit 0
}

if ($mode -eq 'install') {
  $existing = Read-Shortcut $shortcutPath
  if ($existing.exists -and -not (Test-ManagedShortcut $existing)) {
    throw 'An unmanaged item already uses the s-gw Startup shortcut name. Move it manually before installing s-gw startup.'
  }
  $target = [System.IO.Path]::GetFullPath($env:SGW_WINDOWS_STARTUP_TARGET)
  $cliPath = [System.IO.Path]::GetFullPath($env:SGW_WINDOWS_STARTUP_CLI)
  $working = [System.IO.Path]::GetFullPath($env:SGW_WINDOWS_STARTUP_WORKING)
  $arguments = $env:SGW_WINDOWS_STARTUP_ARGUMENTS
  $null = Assert-TrustedFile $target 'The Windows Node.js runtime'
  $null = Assert-TrustedFile $cliPath 'The s-gw CLI runtime'
  Assert-TrustedDirectoryChain ([System.IO.Path]::GetDirectoryName($target))
  Assert-TrustedDirectoryChain ([System.IO.Path]::GetDirectoryName($cliPath))
  Assert-TrustedDirectoryChain $working
  $stage = [System.IO.Path]::Combine($startup, '.s-gw-startup-' + [System.Guid]::NewGuid().ToString('N') + '.lnk')
  $backup = [System.IO.Path]::Combine($startup, '.s-gw-startup-backup-' + [System.Guid]::NewGuid().ToString('N') + '.lnk')
  try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($stage)
    $shortcut.TargetPath = $target
    $shortcut.Arguments = $arguments
    $shortcut.WorkingDirectory = $working
    $shortcut.WindowStyle = 7
    $shortcut.Description = $marker
    $shortcut.Save()
    $staged = Read-Shortcut $stage
    if (-not $staged.exists -or -not (Test-SamePath $staged.targetPath $target) -or $staged.arguments -cne $arguments -or $staged.description -cne $marker -or -not (Test-SamePath $staged.workingDirectory $working)) {
      throw 'The staged s-gw Startup shortcut did not preserve its exact launch contract.'
    }
    $movedExisting = $false
    if ($existing.exists) {
      [System.IO.File]::Move($shortcutPath, $backup)
      $movedExisting = $true
    }
    try {
      [System.IO.File]::Move($stage, $shortcutPath)
      $installed = Read-Shortcut $shortcutPath
      if (-not $installed.exists -or -not (Test-SamePath $installed.targetPath $target) -or $installed.arguments -cne $arguments -or $installed.description -cne $marker -or -not (Test-SamePath $installed.workingDirectory $working)) {
        throw 'The installed s-gw Startup shortcut did not preserve its exact launch contract.'
      }
      if ([System.IO.File]::Exists($backup)) { [System.IO.File]::Delete($backup) }
      [Console]::Out.WriteLine(($installed | ConvertTo-Json -Compress))
    } catch {
      if ([System.IO.File]::Exists($shortcutPath)) { [System.IO.File]::Delete($shortcutPath) }
      if ($movedExisting -and [System.IO.File]::Exists($backup)) {
        [System.IO.File]::Move($backup, $shortcutPath)
      }
      throw
    }
  } finally {
    if ([System.IO.File]::Exists($stage)) { [System.IO.File]::Delete($stage) }
  }
  exit 0
}

if ($mode -eq 'uninstall') {
  $existing = Read-Shortcut $shortcutPath
  if (-not $existing.exists) {
    [Console]::Out.WriteLine(($existing | ConvertTo-Json -Compress))
    exit 0
  }
  if (-not (Test-ManagedShortcut $existing) -or
      -not (Test-SamePath $existing.targetPath $env:SGW_WINDOWS_STARTUP_TARGET) -or
      $existing.arguments -cne $env:SGW_WINDOWS_STARTUP_ARGUMENTS -or
      $existing.description -cne $marker -or
      -not (Test-SamePath $existing.workingDirectory $env:SGW_WINDOWS_STARTUP_WORKING)) {
    throw 'The s-gw Startup shortcut changed before uninstall; it was not removed.'
  }
  [System.IO.File]::Delete($shortcutPath)
  if ([System.IO.File]::Exists($shortcutPath)) { throw 'The s-gw Startup shortcut could not be removed.' }
  [Console]::Out.WriteLine(((Read-Shortcut $shortcutPath) | ConvertTo-Json -Compress))
  exit 0
}

throw 'Unsupported s-gw Windows Startup operation.'
`;

export function buildWindowsStartupConfig(userSid: string, port: number, tray: boolean): WindowsStartupConfig {
  if (!/^S-\d+(?:-\d+)+$/.test(userSid)) {
    throw new Error("The Windows startup identity is invalid.");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`Invalid Windows startup port: ${port}`);
  }

  const env: Record<string, string> = {
    SGW_EXECUTION_ENGINE: process.env.SGW_EXECUTION_ENGINE?.trim().toLowerCase() || "",
    SGW_HOME: getSgwHome(),
    SGW_RECOVERY_HOME: getSgwRecoveryHome(),
    SGW_KEYCHAIN_SERVICE: process.env.SGW_KEYCHAIN_SERVICE || "com.s-gw.sgw.master-passphrase",
    SGW_KEYCHAIN_ACCOUNT: process.env.SGW_KEYCHAIN_ACCOUNT || os.userInfo().username || "local-user",
    SGW_SECRET_KEYCHAIN_SERVICE: process.env.SGW_SECRET_KEYCHAIN_SERVICE || "com.s-gw.sgw.secret",
    SGW_SECRET_BACKEND: process.env.SGW_SECRET_BACKEND?.trim().toLowerCase() || ""
  };
  return validateWindowsStartupConfig({ version: PAYLOAD_VERSION, userSid, port, tray, env });
}

export function encodeWindowsStartupConfig(config: WindowsStartupConfig): string {
  const valid = validateWindowsStartupConfig(config);
  return Buffer.from(JSON.stringify(valid), "utf8").toString("base64url");
}

export function decodeWindowsStartupConfig(payload: string): WindowsStartupConfig {
  if (!/^[A-Za-z0-9_-]{16,8192}$/.test(payload)) {
    throw new Error("The Windows startup payload is malformed.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    throw new Error("The Windows startup payload is malformed.");
  }
  return validateWindowsStartupConfig(parsed);
}

export function applyWindowsStartupConfig(config: WindowsStartupConfig): () => void {
  const valid = validateWindowsStartupConfig(config);
  const previous = new Map<string, string | undefined>();
  for (const key of AUTHORITY_ENV_KEYS) {
    previous.set(key, process.env[key]);
    const value = valid.env[key];
    if (value) process.env[key] = value;
    else delete process.env[key];
  }
  for (const key of [
    "SGW_DISABLE_KEYCHAIN",
    "SGW_KEYCHAIN_HELPER",
    "SGW_MASTER_PASSPHRASE",
    "SGW_SECRET_TOOL",
    "SGW_WINDOWS_CREDENTIAL_HELPER"
  ]) {
    previous.set(key, process.env[key]);
    delete process.env[key];
  }
  return () => {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
}

export async function installWindowsStartupShortcut(options: {
  nodePath: string;
  cliPath: string;
  port: number;
  tray: boolean;
}): Promise<WindowsStartupShortcutStatus> {
  const identity = runShortcutOperation("inspect");
  const config = buildWindowsStartupConfig(identity.currentSid, options.port, options.tray);
  const payload = encodeWindowsStartupConfig(config);
  const argumentsValue = startupArguments(options.cliPath, payload);
  runShortcutOperation("install", {
    targetPath: options.nodePath,
    cliPath: options.cliPath,
    argumentsValue,
    workingDirectory: path.dirname(options.cliPath)
  });
  return windowsStartupShortcutStatus(options.nodePath, options.cliPath);
}

export async function windowsStartupShortcutStatus(
  nodePath: string,
  cliPath: string
): Promise<WindowsStartupShortcutStatus> {
  const record = runShortcutOperation("inspect");
  if (!record.exists) {
    return emptyStatus(record.shortcutPath);
  }

  const parsed = parseManagedArguments(record.arguments || "");
  const managed = record.description === STARTUP_DESCRIPTION
    && path.basename(record.targetPath || "").toLowerCase() === "node.exe"
    && parsed !== undefined;
  if (!managed || !parsed) {
    return {
      ...emptyStatus(record.shortcutPath),
      installed: true,
      collision: true,
      targetPath: record.targetPath,
      error: "An unmanaged item uses the s-gw Startup shortcut name."
    };
  }

  try {
    const config = decodeWindowsStartupConfig(parsed.payload);
    if (config.userSid.toLowerCase() !== record.currentSid.toLowerCase()) {
      throw new Error("The Windows startup payload belongs to another user.");
    }
    const current = sameWindowsPath(record.targetPath || "", nodePath)
      && sameWindowsPath(parsed.cliPath, cliPath)
      && sameWindowsPath(record.workingDirectory || "", path.dirname(cliPath));
    return {
      shortcutPath: record.shortcutPath,
      installed: true,
      managed: true,
      current,
      enabled: true,
      collision: false,
      targetPath: record.targetPath,
      cliPath: parsed.cliPath,
      config,
      ...(!current ? { error: "The managed Startup shortcut points to a different s-gw runtime; run setup to refresh it." } : {})
    };
  } catch (error) {
    return {
      shortcutPath: record.shortcutPath,
      installed: true,
      managed: false,
      current: false,
      enabled: false,
      collision: true,
      targetPath: record.targetPath,
      cliPath: parsed.cliPath,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

export async function uninstallWindowsStartupShortcut(
  nodePath: string,
  cliPath: string,
  verifiedStatus?: WindowsStartupShortcutStatus
): Promise<WindowsStartupShortcutStatus> {
  const status = verifiedStatus || await windowsStartupShortcutStatus(nodePath, cliPath);
  if (!status.installed) return status;
  if (!status.managed || !status.targetPath || !status.cliPath || !status.config) {
    throw new Error(status.error || "The existing Windows Startup item is not managed by s-gw.");
  }
  const payload = encodeWindowsStartupConfig(status.config);
  runShortcutOperation("uninstall", {
    targetPath: status.targetPath,
    cliPath: status.cliPath,
    argumentsValue: startupArguments(status.cliPath, payload),
    workingDirectory: path.dirname(status.cliPath)
  });
  return windowsStartupShortcutStatus(nodePath, cliPath);
}

export async function installedWindowsStartupConfig(
  nodePath: string,
  cliPath: string,
  expectedPayload?: string,
  verifiedStatus?: WindowsStartupShortcutStatus
): Promise<WindowsStartupConfig> {
  const status = verifiedStatus || await windowsStartupShortcutStatus(nodePath, cliPath);
  if (!status.installed || !status.managed || !status.current || !status.config) {
    throw new Error(status.error || "The s-gw Windows login startup is not installed.");
  }
  if (expectedPayload && encodeWindowsStartupConfig(status.config) !== expectedPayload) {
    throw new Error("The Windows startup invocation does not match the installed managed shortcut.");
  }
  return status.config;
}

function validateWindowsStartupConfig(value: unknown): WindowsStartupConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The Windows startup payload must be an object.");
  }
  const item = value as Record<string, unknown>;
  if (!exactKeys(item, ["env", "port", "tray", "userSid", "version"])
    || item.version !== PAYLOAD_VERSION
    || typeof item.userSid !== "string"
    || !/^S-\d+(?:-\d+)+$/.test(item.userSid)
    || !Number.isInteger(item.port)
    || Number(item.port) < 1
    || Number(item.port) > 65_535
    || typeof item.tray !== "boolean"
    || !item.env
    || typeof item.env !== "object"
    || Array.isArray(item.env)) {
    throw new Error("The Windows startup payload has an invalid schema.");
  }
  const rawEnv = item.env as Record<string, unknown>;
  if (!exactKeys(rawEnv, [...AUTHORITY_ENV_KEYS])) {
    throw new Error("The Windows startup payload contains an unsupported environment setting.");
  }
  const env: Record<string, string> = {};
  for (const key of AUTHORITY_ENV_KEYS) {
    const raw = rawEnv[key];
    if (typeof raw !== "string" || raw.length > 4_096 || /[\0\r\n]/.test(raw)) {
      throw new Error(`The Windows startup payload has an invalid ${key} value.`);
    }
    env[key] = raw;
  }
  for (const key of ["SGW_HOME", "SGW_RECOVERY_HOME"]) {
    const inputPath = env[key];
    if (!inputPath || !path.isAbsolute(inputPath) || isUncPath(inputPath)) {
      throw new Error(`The Windows startup payload requires an absolute local ${key} path.`);
    }
  }
  if (sameWindowsPath(env.SGW_HOME, env.SGW_RECOVERY_HOME)
    || isInside(env.SGW_HOME, env.SGW_RECOVERY_HOME)
    || isInside(env.SGW_RECOVERY_HOME, env.SGW_HOME)) {
    throw new Error("The Windows startup primary and recovery homes must not overlap.");
  }
  for (const key of ["SGW_KEYCHAIN_ACCOUNT", "SGW_KEYCHAIN_SERVICE", "SGW_SECRET_KEYCHAIN_SERVICE"]) {
    if (!env[key] || env[key].trim() !== env[key]) {
      throw new Error(`The Windows startup payload requires a bounded ${key} value.`);
    }
  }
  if (!/^(?:|keychain|local)$/.test(env.SGW_SECRET_BACKEND)) {
    throw new Error("The Windows startup payload has an unsupported secret backend.");
  }
  if (!/^(?:|auto|rust|typescript)$/.test(env.SGW_EXECUTION_ENGINE)) {
    throw new Error("The Windows startup payload has an unsupported execution engine.");
  }
  return {
    version: 1,
    userSid: item.userSid,
    port: Number(item.port),
    tray: item.tray,
    env
  };
}

function runShortcutOperation(
  mode: "inspect" | "install" | "uninstall",
  expected: { targetPath: string; cliPath: string; argumentsValue: string; workingDirectory: string } | undefined = undefined
): ShortcutRecord {
  const extra: NodeJS.ProcessEnv = { SGW_WINDOWS_STARTUP_MODE: mode };
  const testRoot = windowsStartupTestRoot();
  if (testRoot) extra.SGW_WINDOWS_STARTUP_TEST_ROOT = testRoot;
  if (expected) {
    for (const value of [expected.targetPath, expected.cliPath, expected.argumentsValue, expected.workingDirectory]) {
      if (!value || value.length > 8_192 || /[\0\r\n]/.test(value)) {
        throw new Error("The Windows Startup shortcut contract contains an invalid value.");
      }
    }
    extra.SGW_WINDOWS_STARTUP_TARGET = expected.targetPath;
    extra.SGW_WINDOWS_STARTUP_CLI = expected.cliPath;
    extra.SGW_WINDOWS_STARTUP_ARGUMENTS = expected.argumentsValue;
    extra.SGW_WINDOWS_STARTUP_WORKING = expected.workingDirectory;
  }
  const encoded = Buffer.from(WINDOWS_STARTUP_SCRIPT, "utf16le").toString("base64");
  const powershell = trustedWindowsPowerShellSync();
  const result = spawnSync(powershell, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-EncodedCommand",
    encoded
  ], {
    cwd: path.dirname(powershell),
    encoding: "utf8",
    env: windowsSystemEnvironment(extra),
    maxBuffer: 64 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: windowsStartupOperationTimeoutMs(),
    windowsHide: true
  });
  if (result.error) {
    throw new Error(`Could not manage the Windows login startup: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || "").trim() || "Could not manage the Windows login startup.");
  }
  const line = result.stdout.trim().split(/\r?\n/).filter(Boolean).at(-1) || "";
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new Error("Windows login startup management returned an invalid response.");
  }
  return validateShortcutRecord(parsed);
}

export function windowsStartupOperationTimeoutMs(): number {
  if (process.env.SGW_TEST_MODE !== "1") return defaultStartupOperationTimeoutMs;
  const configured = Number(process.env.SGW_WINDOWS_STARTUP_OPERATION_TIMEOUT_MS);
  return Number.isInteger(configured) && configured > 0 && configured <= maxStartupOperationTestTimeoutMs
    ? configured
    : defaultStartupOperationTimeoutMs;
}

function windowsStartupTestRoot(): string | undefined {
  if (process.env.SGW_TEST_MODE !== "1") return undefined;
  const root = process.env.SGW_TEST_HOME_ROOT?.trim();
  if (!root || !path.isAbsolute(root)) {
    throw new Error("SGW_TEST_HOME_ROOT is required for Windows Startup tests.");
  }
  const realRoot = realpathSync(root);
  const startup = path.join(realRoot, "windows-startup");
  mkdirSync(startup, { recursive: true });
  const realStartup = realpathSync(startup);
  if (!isInside(realStartup, realRoot)) {
    throw new Error("The Windows Startup test path escaped SGW_TEST_HOME_ROOT.");
  }
  return realStartup;
}

function validateShortcutRecord(value: unknown): ShortcutRecord {
  if (!value || typeof value !== "object") {
    throw new Error("Windows login startup management returned an invalid response.");
  }
  const item = value as Record<string, unknown>;
  if (typeof item.shortcutPath !== "string"
    || !path.isAbsolute(item.shortcutPath)
    || typeof item.currentSid !== "string"
    || !/^S-\d+(?:-\d+)+$/.test(item.currentSid)
    || typeof item.exists !== "boolean") {
    throw new Error("Windows login startup management returned an invalid response.");
  }
  if (!item.exists) {
    return { shortcutPath: item.shortcutPath, currentSid: item.currentSid, exists: false };
  }
  for (const key of ["targetPath", "arguments", "description", "workingDirectory"]) {
    if (typeof item[key] !== "string" || String(item[key]).length > 8_192 || /[\0\r\n]/.test(String(item[key]))) {
      throw new Error("Windows login startup management returned an invalid shortcut record.");
    }
  }
  return {
    shortcutPath: item.shortcutPath,
    currentSid: item.currentSid,
    exists: true,
    targetPath: item.targetPath as string,
    arguments: item.arguments as string,
    description: item.description as string,
    workingDirectory: item.workingDirectory as string
  };
}

function startupArguments(cliPath: string, payload: string): string {
  if (!path.isAbsolute(cliPath) || /["\0\r\n]/.test(cliPath)) {
    throw new Error("The Windows startup CLI path is invalid.");
  }
  return [cliPath, "__windows-login-start", "--payload", payload].map(quoteWindowsArgument).join(" ");
}

function quoteWindowsArgument(value: string): string {
  if (/["\0\r\n]/.test(value)) {
    throw new Error("The Windows startup argument is invalid.");
  }
  return `"${value.replace(/(\\*)"/g, "$1$1\\\"").replace(/(\\+)$/, "$1$1")}"`;
}

function parseManagedArguments(value: string): { cliPath: string; payload: string } | undefined {
  const match = /^"([^"]+)" "__windows-login-start" "--payload" "([A-Za-z0-9_-]+)"$/.exec(value);
  if (!match || !path.isAbsolute(match[1])) return undefined;
  return { cliPath: match[1], payload: match[2] };
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === [...expected].sort()[index]);
}

function emptyStatus(shortcutPath: string): WindowsStartupShortcutStatus {
  return {
    shortcutPath,
    installed: false,
    managed: false,
    current: false,
    enabled: false,
    collision: false
  };
}

function isUncPath(value: string): boolean {
  return value.startsWith("\\\\") || value.startsWith("//");
}

function isInside(candidate: string, root: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return Boolean(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function sameWindowsPath(left: string, right: string): boolean {
  return path.normalize(left).replace(/[\\/]+$/, "").toLowerCase()
    === path.normalize(right).replace(/[\\/]+$/, "").toLowerCase();
}
