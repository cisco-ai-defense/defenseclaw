import { spawn } from "node:child_process";
import type { BigIntStats } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import {
  trustedWindowsSystemExecutableSync,
  trustedWindowsSystemRootSync,
  windowsSystemEnvironment
} from "./windows-system.js";

const defaultAclOperationTimeoutMs = 30_000;
const maxAclOperationTestTimeoutMs = 120_000;

const WINDOWS_ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$mode = $env:SGW_WINDOWS_ACL_MODE
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $identity.User.Value
$systemSid = 'S-1-5-18'
$administratorsSid = 'S-1-5-32-544'
$creatorOwnerSid = 'S-1-3-0'
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$accessAndOwner = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner
$target = $null

trap {
  if ($mode -eq 'create-directory' -and $target -and [System.IO.Directory]::Exists($target)) {
    try { [System.IO.Directory]::Delete($target, $false) } catch {}
  }
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}

function Test-SamePath([string]$left, [string]$right) {
  return [string]::Equals(
    $left.TrimEnd([System.IO.Path]::DirectorySeparatorChar),
    $right.TrimEnd([System.IO.Path]::DirectorySeparatorChar),
    [System.StringComparison]::OrdinalIgnoreCase
  )
}

function Assert-LocalFixedPath([string]$inputPath) {
  if (-not $inputPath) {
    throw 'The SSH credential root is unavailable.'
  }
  $fullPath = [System.IO.Path]::GetFullPath($inputPath)
  if ((New-Object System.Uri($fullPath)).IsUnc) {
    throw 'The SSH temporary path must not use a UNC location.'
  }
  $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
  $volume = New-Object System.IO.DriveInfo($volumeRoot)
  if ($volume.DriveType -ne [System.IO.DriveType]::Fixed) {
    throw 'The SSH temporary path must use a fixed local volume.'
  }
  return $fullPath
}

function Get-StableDirectory([string]$dirPath) {
  $dirInfo = [System.IO.DirectoryInfo]::new($dirPath)
  $dirInfo.Refresh()
  if (-not $dirInfo.Exists) {
    throw 'The SSH credential directory does not exist.'
  }
  if (($dirInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not (Test-SamePath $dirInfo.FullName $dirPath)) {
    throw 'The SSH credential path is not a stable local directory.'
  }
  return $dirInfo
}

function Assert-TrustedAncestor([string]$dirPath, [bool]$isAuthRoot) {
  $dirInfo = Get-StableDirectory $dirPath
  $acl = $dirInfo.GetAccessControl($accessAndOwner)
  $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($ownerSid -ne $currentSid -and $ownerSid -ne $systemSid -and $ownerSid -ne $administratorsSid) {
    throw ('The SSH credential ancestor has an unexpected owner: ' + $ownerSid)
  }

  $unsafeRights = (
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  )
  if ($isAuthRoot) {
    $unsafeRights = $unsafeRights -bor [System.Security.AccessControl.FileSystemRights]::Write
  }

  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  foreach ($rule in $rules) {
    if ($rule.AccessControlType -ne $allow) {
      continue
    }
    $sid = $rule.IdentityReference.Value
    if ($sid -eq $currentSid -or $sid -eq $systemSid -or $sid -eq $administratorsSid -or $sid -eq $creatorOwnerSid) {
      continue
    }
    if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
      continue
    }
    if (($rule.FileSystemRights -band $unsafeRights) -ne 0) {
      throw ('The SSH credential ancestor grants unsafe access to ' + $sid)
    }
  }
}

function Get-AuthRoot() {
  if ($env:SGW_WINDOWS_ACL_TEST_ROOT) {
    return (Assert-LocalFixedPath $env:SGW_WINDOWS_ACL_TEST_ROOT)
  }
  return (Assert-LocalFixedPath ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)))
}

function Assert-TrustedRootChain([string]$rootPath) {
  $profilePath = Assert-LocalFixedPath ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile))
  $profilePrefix = $profilePath.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
  if (-not (Test-SamePath $rootPath $profilePath) -and -not $rootPath.StartsWith($profilePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The SSH credential root must stay inside the current local user profile.'
  }

  $paths = New-Object 'System.Collections.Generic.List[string]'
  $cursor = $rootPath
  while ($true) {
    $paths.Add($cursor)
    if (Test-SamePath $cursor $profilePath) {
      break
    }
    $parent = [System.IO.Directory]::GetParent($cursor)
    if (-not $parent) {
      throw 'The SSH credential root could not be anchored to the current profile.'
    }
    $cursor = $parent.FullName
  }
  $profileParent = [System.IO.Directory]::GetParent($profilePath)
  if ($profileParent) {
    $paths.Add($profileParent.FullName)
  }
  foreach ($pathEntry in $paths) {
    Assert-TrustedAncestor $pathEntry (Test-SamePath $pathEntry $rootPath)
  }
}

function New-PrivateDirectorySecurity() {
  $acl = [System.Security.AccessControl.DirectorySecurity]::new()
  $acl.SetOwner($identity.User)
  $acl.SetAccessRuleProtection($true, $false)
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identity.User, $full, $inherit, $propagation, $allow))
  if ($currentSid -ne $systemSid) {
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($systemSid), $full, $inherit, $propagation, $allow))
  }
  return $acl
}

function New-PrivateFileSecurity() {
  $acl = [System.Security.AccessControl.FileSecurity]::new()
  $acl.SetOwner($identity.User)
  $acl.SetAccessRuleProtection($true, $false)
  $none = [System.Security.AccessControl.InheritanceFlags]::None
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identity.User, $full, $none, $propagation, $allow))
  if ($currentSid -ne $systemSid) {
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($systemSid), $full, $none, $propagation, $allow))
  }
  return $acl
}

if ($env:SGW_WINDOWS_ACL_EXPECTED_SID -and $env:SGW_WINDOWS_ACL_EXPECTED_SID -ne $currentSid) {
  throw 'The Windows identity changed while preparing the SSH key.'
}

if ($mode -eq 'create-directory') {
  $root = Get-AuthRoot
  Assert-TrustedRootChain $root
  for ($attempt = 0; $attempt -lt 8; $attempt += 1) {
    $candidate = [System.IO.Path]::Combine($root, 's-gw-ssh-' + [System.Guid]::NewGuid().ToString('N'))
    if (-not [System.IO.Directory]::Exists($candidate)) {
      $target = $candidate
      break
    }
  }
  if (-not $target) {
    throw 'Could not reserve a private Windows SSH directory name.'
  }
  $null = [System.IO.Directory]::CreateDirectory($target, (New-PrivateDirectorySecurity))
} else {
  $target = Assert-LocalFixedPath $env:SGW_WINDOWS_ACL_PATH
  $root = Get-AuthRoot
  $authDir = $target
  if ($mode -eq 'verify-file') {
    $authDir = [System.IO.Directory]::GetParent($target).FullName
  } elseif ($mode -ne 'verify-directory') {
    throw 'Unsupported Windows ACL operation.'
  }
  $authParent = [System.IO.Directory]::GetParent($authDir)
  $authName = [System.IO.Path]::GetFileName($authDir)
  if (-not $authParent -or -not (Test-SamePath $authParent.FullName $root) -or $authName -cnotmatch '^s-gw-ssh-[0-9a-f]{32}$') {
    throw 'The SSH credential path escaped its trusted per-user root.'
  }
}

Assert-TrustedRootChain $root

if ($mode -eq 'verify-file') {
  if (-not [System.IO.File]::Exists($target)) {
    throw 'The SSH private-key file does not exist.'
  }
  $fileInfo = [System.IO.FileInfo]::new($target)
  $fileInfo.Refresh()
  if (($fileInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or -not (Test-SamePath $fileInfo.FullName $target)) {
    throw 'The SSH private-key path is not a stable local file.'
  }
  $fileInfo.SetAccessControl((New-PrivateFileSecurity))
  $fileInfo.Refresh()
  if (-not $fileInfo.Exists -or
      ($fileInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      -not (Test-SamePath $fileInfo.FullName $target)) {
    throw 'The SSH private-key path changed while its access was secured.'
  }
  $acl = $fileInfo.GetAccessControl($accessAndOwner)
} elseif ($mode -eq 'create-directory' -or $mode -eq 'verify-directory') {
  $dirInfo = Get-StableDirectory $target
  $acl = $dirInfo.GetAccessControl($accessAndOwner)
  if (-not $acl.AreAccessRulesProtected) {
    throw 'The SSH temporary directory still inherits access rules.'
  }
} else {
  throw 'Unsupported Windows ACL operation.'
}

if (-not $acl.AreAccessRulesProtected) {
  throw 'The SSH temporary path still inherits access rules.'
}

$ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($ownerSid -ne $currentSid) {
  throw ('The SSH temporary path owner is not the current Windows identity: ' + $ownerSid)
}

$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
$currentSeen = $false
$systemSeen = $false
foreach ($rule in $rules) {
  $sid = $rule.IdentityReference.Value
  if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
    throw 'The SSH temporary path contains a non-allow access rule.'
  }
  if ($sid -ne $currentSid -and $sid -ne $systemSid) {
    throw ('The SSH temporary path grants access to an unexpected identity: ' + $sid)
  }
  if (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl) {
    throw ('The SSH temporary path has an incomplete access rule for ' + $sid)
  }
  if ($sid -eq $currentSid) {
    $currentSeen = $true
  }
  if ($sid -eq $systemSid) {
    $systemSeen = $true
  }
  if ($mode -eq 'verify-file') {
    if ($rule.IsInherited -or
        $rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or
        $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
      throw ('The SSH private-key file has an inheritable access rule for ' + $sid)
    }
  } else {
    if ($rule.IsInherited -or $rule.InheritanceFlags -ne $inherit -or $rule.PropagationFlags -ne $propagation) {
      throw ('The SSH temporary directory has incomplete child protection for ' + $sid)
    }
  }
}

if (-not $currentSeen) {
  throw 'The current Windows identity does not control the SSH temporary path.'
}
if (-not $systemSeen) {
  throw 'The Windows SYSTEM identity does not control the SSH temporary path.'
}
$expectedRuleCount = 2
if ($currentSid -eq $systemSid) {
  $expectedRuleCount = 1
}
if ($rules.Count -ne $expectedRuleCount) {
  throw 'The SSH temporary path does not have the expected access-rule count.'
}

Assert-TrustedRootChain $root
$result = @{ verified = $true; sid = $currentSid; rules = $rules.Count }
if ($mode -eq 'create-directory') {
  $result.path = $target
}
[Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
`;

export async function createPrivateWindowsSshDirectory(): Promise<{ dirPath: string; sid: string }> {
  const result = await runAclOperation("create-directory", "");
  if (!result.path) {
    throw new Error("Windows ACL verification did not return the private SSH directory.");
  }
  return { dirPath: result.path, sid: result.sid };
}

export async function verifyPrivateWindowsKeyFile(
  filePath: string,
  expectedSid: string
): Promise<() => Promise<void>> {
  const original = await stablePrivateKeyIdentity(filePath);
  await securePrivateWindowsKeyFile(filePath, expectedSid, original);
  return () => securePrivateWindowsKeyFile(filePath, expectedSid, original);
}

interface FileIdentity {
  dev: bigint;
  ino: bigint;
}

async function securePrivateWindowsKeyFile(
  filePath: string,
  expectedSid: string,
  original: FileIdentity
): Promise<void> {
  assertSameFileIdentity(original, await stablePrivateKeyIdentity(filePath));
  await runAclOperation("verify-directory", path.dirname(filePath), expectedSid);
  assertSameFileIdentity(original, await stablePrivateKeyIdentity(filePath));
  await runAclOperation("verify-file", filePath, expectedSid);
  assertSameFileIdentity(original, await stablePrivateKeyIdentity(filePath));
}

interface AclResult {
  verified: true;
  sid: string;
  rules: number;
  path?: string;
}

async function runAclOperation(mode: string, target: string, expectedSid?: string): Promise<AclResult> {
  const systemRoot = await trustedWindowsSystemRoot();
  const powershell = await trustedWindowsSystemExecutableAtRoot(
    systemRoot,
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe"
  );
  const encoded = Buffer.from(WINDOWS_ACL_SCRIPT, "utf16le").toString("base64");
  const env = windowsSystemEnv(systemRoot);
  env.SGW_WINDOWS_ACL_MODE = mode;
  env.SGW_WINDOWS_ACL_PATH = target;
  if (process.env.SGW_TEST_MODE === "1") {
    const configuredRoot = process.env.SGW_TEST_HOME_ROOT?.trim();
    if (!configuredRoot) {
      throw new Error("SGW_TEST_HOME_ROOT is required for Windows SSH ACL tests.");
    }
    const testRoot = await realpath(configuredRoot).catch(() => "");
    if (!testRoot || !path.isAbsolute(testRoot)) {
      throw new Error("The Windows SSH ACL test root could not be validated.");
    }
    env.SGW_WINDOWS_ACL_TEST_ROOT = testRoot;
  }
  if (expectedSid) {
    env.SGW_WINDOWS_ACL_EXPECTED_SID = expectedSid;
  }

  const child = spawn(powershell, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-EncodedCommand", encoded
  ], {
    cwd: path.dirname(powershell),
    env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendSmall(stdout, chunk.toString("utf8"));
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendSmall(stderr, chunk.toString("utf8"));
  });

  let timedOut = false;
  const timeoutMs = windowsAclOperationTimeoutMs();
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, timeoutMs);
  const status = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  }).finally(() => clearTimeout(timeout));

  if (timedOut) {
    throw new Error("Timed out while securing the Windows SSH private-key path.");
  }
  if (status.code !== 0) {
    const detail = (stderr || stdout).trim();
    throw new Error(`Could not secure the Windows SSH private-key path${detail ? `: ${detail}` : "."}`);
  }

  const line = stdout.trim().split(/\r?\n/).filter(Boolean).at(-1) || "";
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new Error("Windows ACL verification returned an invalid response.");
  }
  if (!isAclResult(parsed, mode === "create-directory") || (expectedSid && parsed.sid !== expectedSid)) {
    throw new Error("Windows ACL verification did not confirm the current user boundary.");
  }
  return parsed;
}

export function windowsAclOperationTimeoutMs(): number {
  if (process.env.SGW_TEST_MODE !== "1") return defaultAclOperationTimeoutMs;
  const configured = Number(process.env.SGW_WINDOWS_ACL_OPERATION_TIMEOUT_MS);
  return Number.isInteger(configured) && configured > 0 && configured <= maxAclOperationTestTimeoutMs
    ? configured
    : defaultAclOperationTimeoutMs;
}

export async function trustedWindowsSystemExecutable(...parts: string[]): Promise<string> {
  return trustedWindowsSystemExecutableSync(...parts);
}

export async function trustedWindowsSystemRoot(): Promise<string> {
  return trustedWindowsSystemRootSync();
}

async function trustedWindowsSystemExecutableAtRoot(systemRoot: string, ...parts: string[]): Promise<string> {
  if (!sameWindowsPath(trustedWindowsSystemRootSync(), systemRoot)) {
    throw new Error("Trusted Windows system executable path validation failed.");
  }
  return trustedWindowsSystemExecutableSync(...parts);
}

function windowsSystemEnv(systemRoot: string): NodeJS.ProcessEnv {
  const env = windowsSystemEnvironment();
  env.SystemRoot = systemRoot;
  env.WINDIR = systemRoot;
  return env;
}

function isAclResult(value: unknown, requirePath: boolean): value is AclResult {
  if (!value || typeof value !== "object") {
    return false;
  }
  const result = value as Partial<AclResult>;
  return result.verified === true
    && typeof result.sid === "string"
    && /^S-\d+(?:-\d+)+$/.test(result.sid)
    && Number.isInteger(result.rules)
    && Number(result.rules) === (result.sid === "S-1-5-18" ? 1 : 2)
    && (!requirePath || (typeof result.path === "string" && path.isAbsolute(result.path)));
}

function sameWindowsPath(left: string, right: string): boolean {
  return path.normalize(left).replace(/[\\/]+$/, "").toLowerCase()
    === path.normalize(right).replace(/[\\/]+$/, "").toLowerCase();
}

async function stablePrivateKeyIdentity(filePath: string): Promise<FileIdentity> {
  const before = await privateKeyInfo(filePath);
  const after = await privateKeyInfo(filePath);
  if (before.dev !== after.dev || before.ino !== after.ino) {
    throw new Error("The Windows SSH private-key file changed while its identity was checked.");
  }
  return { dev: before.dev, ino: before.ino };
}

async function privateKeyInfo(filePath: string): Promise<BigIntStats> {
  const info = await lstat(filePath, { bigint: true }).catch(() => undefined);
  if (!info || !info.isFile() || info.isSymbolicLink() || info.dev === 0n || info.ino === 0n) {
    throw new Error("The Windows SSH private-key file does not have a stable identity.");
  }
  return info;
}

function assertSameFileIdentity(before: FileIdentity, after: FileIdentity): void {
  if (before.dev !== after.dev || before.ino !== after.ino) {
    throw new Error("The Windows SSH private-key file changed while its access was secured.");
  }
}

function appendSmall(current: string, chunk: string): string {
  const combined = current + chunk;
  return Buffer.byteLength(combined, "utf8") <= 8_192 ? combined : combined.slice(0, 8_192);
}
