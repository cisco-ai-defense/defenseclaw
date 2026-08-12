import { realpathSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export interface SelfContainedMacRuntime {
  appPath: string;
  runtimePath: string;
  packageRoot: string;
  nodePath: string;
  cliPath: string;
  mcpPath: string;
  menuBarAppPath: string;
}

const runtimeMarker = "runtime.json";

export function resolveSelfContainedMacRuntime(packageRoot: string): SelfContainedMacRuntime | undefined {
  if (process.platform !== "darwin") return undefined;

  const resolvedPackageRoot = path.resolve(packageRoot);
  const runtimePath = path.dirname(resolvedPackageRoot);
  const resourcesPath = path.dirname(runtimePath);
  const contentsPath = path.dirname(resourcesPath);
  const appPath = path.dirname(contentsPath);
  const expectedPackageRoot = path.join(appPath, "Contents", "Resources", "s-gw-runtime", "package");

  if (resolvedPackageRoot !== expectedPackageRoot || !isSelfContainedMacApp(appPath)) {
    return undefined;
  }

  const nodePath = path.join(runtimePath, "node", "bin", "node");
  const cliPath = path.join(resolvedPackageRoot, "dist", "cli.js");
  const mcpPath = path.join(resolvedPackageRoot, "dist", "mcp-server.js");
  const menuBarAppPath = path.join(appPath, "Contents", "Library", "LoginItems", "s-gw Menu Bar.app");

  if (!isExecutableFile(nodePath) || !isRegularFile(cliPath) || !isRegularFile(mcpPath)) {
    return undefined;
  }

  return {
    appPath,
    runtimePath,
    packageRoot: resolvedPackageRoot,
    nodePath,
    cliPath,
    mcpPath,
    menuBarAppPath
  };
}

export function isSelfContainedMacApp(appPath: string): boolean {
  if (process.platform !== "darwin") return false;

  const resolvedAppPath = path.resolve(appPath);
  const runtimePath = path.join(resolvedAppPath, "Contents", "Resources", "s-gw-runtime");
  const markerPath = path.join(runtimePath, runtimeMarker);
  const appBinary = path.join(resolvedAppPath, "Contents", "MacOS", "s-gw");
  const nodePath = path.join(runtimePath, "node", "bin", "node");
  const packageRoot = path.join(runtimePath, "package");
  const cliPath = path.join(packageRoot, "dist", "cli.js");
  const mcpPath = path.join(packageRoot, "dist", "mcp-server.js");
  return isRegularFile(markerPath)
    && isExecutableFile(appBinary)
    && isExecutableFile(nodePath)
    && isRegularFile(cliPath)
    && isRegularFile(mcpPath);
}

export function isTransientMacAppLocation(appPath: string): boolean {
  const resolved = path.resolve(appPath);
  const relativeToVolumes = path.relative("/Volumes", resolved);
  return relativeToVolumes === "" || (!relativeToVolumes.startsWith("..") && !path.isAbsolute(relativeToVolumes))
    || resolved.includes("/AppTranslocation/");
}

export function isInstalledMacAppLocation(
  appPath: string,
  applicationsDirectories = ["/Applications", path.join(os.homedir(), "Applications")]
): boolean {
  const resolvedAppPath = canonicalPath(appPath);
  return applicationsDirectories.some((directory) => isWithin(resolvedAppPath, canonicalPath(directory)));
}

function isRegularFile(filePath: string): boolean {
  try {
    return statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function isExecutableFile(filePath: string): boolean {
  try {
    const info = statSync(filePath);
    return info.isFile() && (info.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

function canonicalPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  try {
    return realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function isWithin(candidate: string, directory: string): boolean {
  const relative = path.relative(directory, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
