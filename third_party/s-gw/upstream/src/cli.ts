#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { stdin } from "node:process";
import {
  agentIntegrationStatus,
  installAgentIntegrations,
  mcpAuthorityEnvironment,
  refreshManagedAgentIntegrations,
  resolvePackagedMcpCommand,
  uninstallAgentIntegrations
} from "./agent-install.js";
import { getAgentCodeGuardPlan, listAgentProfiles, renderAgentMcpSnippet, resolveAgentProfile } from "./agents.js";
import { unknownCommandMessage } from "./command-suggest.js";
import { startConsoleServer } from "./console-server.js";
import { executeApprovedRequest, executeReusablePermit } from "./executor.js";
import {
  buildEnvCommandAction,
  buildSshSessionAction,
  preferredLocalSecretBackend,
  scanLocalFile,
  scanTextToOnePassword,
  type LocalSecretBackend
} from "./gateway.js";
import { guardStatus, prepareGuardedRun, runGuardedAgent } from "./guard.js";
import {
  assertMacRuntimeForManagedSurfaces,
  ensureWindowsConsole,
  getPackageLayout,
  installMacAppBundle,
  installConsoleLaunchAgent,
  installMenuBarLaunchAgent,
  installSystemdUserService,
  installWindowsLoginService,
  launchAgentStatus,
  normalizeMenuBarCountMode,
  openMacApp,
  openMenuBarHelper,
  openWindowsClient,
  openWindowsHelper,
  packageHealth,
  refreshMacRuntimeServices,
  restartWindowsSurfaces,
  startInstalledWindowsLoginService,
  startInstalledLaunchAgent,
  startInstalledSystemdUserService,
  stopInstalledLaunchAgent,
  stopInstalledSystemdUserService,
  stopInstalledWindowsLoginService,
  stopMacApp,
  stopWindowsSurfaces,
  type WindowsStoppedSurfaces,
  uninstallConsoleLaunchAgent,
  uninstallMenuBarLaunchAgent,
  uninstallSystemdUserService,
  uninstallWindowsLoginService,
  windowsLoginServiceStatus,
  systemdUserServiceStatus
} from "./install.js";
import { listOnePasswordSecretReferences, onePasswordStatus, readOnePasswordReference } from "./onepassword.js";
import { installPackageUpdate, planPackageUpdate } from "./package-update.js";
import { SGW_SSH_SESSION_COMMAND, closeOwnedSshSession, defaultSshInjectEnv } from "./ssh.js";
import { normalizeCommandGrant, SecretStore } from "./store.js";
import {
  deleteKeychainPassphrase,
  installPersistentKeychainHelper,
  pinPackagedKeychainHelper,
  repairKeychainPassphraseAccess,
  setKeychainPassphrase,
  unlockStatus
} from "./unlock.js";
import { releaseChecker } from "./update-check.js";
import { trustedWindowsSystemExecutableSync, windowsSystemEnvironment } from "./windows-system.js";
import type {
  ApprovalAgentScope,
  ApprovalMode,
  ApprovalPolicyDecision,
  ApprovalPolicyActionKind,
  ApprovalPolicyConditions,
  CommandEnvBinding,
  HandleSummary,
  RequestRecord,
  RequestState,
  SecretSeverity,
  SecretType
} from "./types.js";

interface ParsedArgs {
  command: string[];
  flags: Record<string, string | boolean | string[]>;
}

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  const [first, second, third] = parsed.command;

  if (!first || first === "help" || first === "--help") {
    printHelp();
    return;
  }

  if (first === "setup" && (second === "-h" || hasFlag(parsed.flags, "help"))) {
    printSetupHelp();
    return;
  }

  if (first === "mcp") {
    await import("./mcp-server.js");
    return;
  }

  if (first === "__windows-login-start") {
    if (process.platform !== "win32") {
      throw new Error("Windows login startup is only available on Windows.");
    }
    const payload = getFlag(parsed.flags, "payload");
    if (!payload) throw new Error("Windows login startup requires its managed payload.");
    await startInstalledWindowsLoginService(payload);
    return;
  }

  const store = new SecretStore();

  if (first === "init") {
    await store.init();
    printJson({ ok: true, storePath: store.storePath });
    return;
  }

  if (first === "update") {
    if (second === "check") {
      printJson(await releaseChecker.check(hasFlag(parsed.flags, "force")));
      return;
    }

    if (process.platform === "darwin") {
      const layout = getPackageLayout();
      if (layout.isSelfContainedMacApp) {
        throw new Error("This self-contained s-gw.app updates through the macOS installer. Download the current DMG from the release page, quit s-gw, replace the app in Applications, then reopen it.");
      }
      if (layout.standaloneMacAppInstalled) {
        throw new Error("A self-contained s-gw.app is already installed. Open that app to update it instead of using the npm package updater.");
      }
    }

    const updateOptions = {
      target: getFlag(parsed.flags, "package"),
      npmPrefix: getFlag(parsed.flags, "npm-prefix")
    };
    if (second === "plan") {
      printJson(await planPackageUpdate(updateOptions));
      return;
    }
    if (second === "install") {
      const services = updateServiceLifecycle(hasFlag(parsed.flags, "keep-app-running"));
      printJson(await installPackageUpdate({
        ...updateOptions,
        dryRun: hasFlag(parsed.flags, "dry-run"),
        stopServices: services.stop,
        restartServices: services.restart
      }));
      return;
    }

    throw new Error("Usage: s-gw update check [--force] | plan [--package PATH_OR_SPEC] | install [--package PATH_OR_SPEC] [--dry-run]");
  }

  if (first === "setup") {
    await handleSetupCommand(store, parsed.flags);
    return;
  }

  if (first === "console") {
    const host = getFlag(parsed.flags, "host") || "127.0.0.1";
    const port = numericFlag(parsed.flags, "port", 8718);

    let running;
    try {
      running = await startConsoleServer({ host, port, store });
    } catch (error) {
      if (isAddressInUse(error)) {
        // Very common first-run snag: `s-gw setup`/`s-gw start` already left a
        // console daemon on this port, so the foreground `s-gw console` can't
        // bind it. Don't dump a raw Node listen error — say what's going on.
        throw new Error(
          `Port ${port} on ${host} is already in use — the s-gw console is probably already running at http://${host}:${port}/. ` +
            `Open that URL, or run \`s-gw console --port <other>\` for a separate instance, or \`s-gw stop\` to stop the background console.`
        );
      }
      throw error;
    }

    if (!hasFlag(parsed.flags, "no-open")) {
      openBrowser(running.url);
    }

    process.stdout.write(`s-gw console running at ${running.url}\n`);
    process.stdout.write("Press Ctrl+C to stop.\n");
    await waitForever();
    await running.close();
    return;
  }

  if (first === "doctor" || first === "status") {
    printJson(packageHealth(numericFlag(parsed.flags, "port", 8718)));
    return;
  }

  if (first === "start") {
    await handleStartCommand(parsed.flags);
    return;
  }

  if (first === "stop") {
    await handleStopCommand();
    return;
  }

  if (first === "service") {
    await handleServiceCommand(second, parsed.flags);
    return;
  }

  if (first === "menubar") {
    await handleMenuBarCommand(second, parsed.flags);
    return;
  }

  if (first === "helper") {
    await handleMenuBarCommand(second, parsed.flags);
    return;
  }

  if (first === "onepassword") {
    await handleOnePasswordCommand(store, second, parsed.flags);
    return;
  }

  if (first === "approval") {
    await handleApprovalCommand(store, second, third, parsed.flags);
    return;
  }

  if (first === "ssh") {
    await handleSshCommand(store, second, third, parsed.flags);
    return;
  }

  if (first === "aws") {
    await handleAwsCommand(store, second, parsed.flags, parsed.command.slice(2));
    return;
  }

  if (first === "app") {
    await handleAppCommand(second, parsed.flags);
    return;
  }

  if (first === "guard") {
    await handleGuardCommand(store, second, third, parsed.flags);
    return;
  }

  if (first === "run" && second === "env-command") {
    await handleOneShotEnvCommand(store, third, parsed.flags);
    return;
  }

  if (first === "run") {
    await handleGuardRun(store, second, parsed.flags);
    return;
  }

  if (first === "unlock" && second === "status") {
    printJson(unlockStatus());
    return;
  }

  if (first === "unlock" && second === "keychain" && third === "set") {
    const passphrase = await readStdinValue(parsed.flags, "value-stdin", "unlock passphrase");
    setKeychainPassphrase(passphrase);
    printJson({
      ok: true,
      keychain: unlockStatus().keychain
    });
    return;
  }

  if (first === "unlock" && second === "keychain" && third === "delete") {
    printJson({
      deleted: deleteKeychainPassphrase(),
      keychain: unlockStatus().keychain
    });
    return;
  }

  if (first === "unlock" && second === "keychain" && third === "repair") {
    const keychainHelper = process.platform === "darwin" ? installPersistentKeychainHelper() : undefined;
    const keychainCompatibility = process.platform === "darwin" ? pinPackagedKeychainHelper() : undefined;
    const master = repairKeychainPassphraseAccess();
    await store.init();
    const secrets = await store.repairKeychainAccess();
    printJson({
      ok: secrets.failed.length === 0,
      keychainHelper,
      keychainCompatibility,
      master,
      secrets
    });
    return;
  }

  if (first === "secret" && second === "add") {
    const value = await readStdinValue(parsed.flags, "value-stdin", "secret");
    const record = await store.addSecret({
      name: requireFlag(parsed.flags, "name"),
      type: secretType(getFlag(parsed.flags, "type") || "unknown"),
      value,
      policy: {
        injectEnv: getFlag(parsed.flags, "inject-env"),
        allowedCommands: getFlagList(parsed.flags, "allow-command"),
        maxOutputBytes: numericFlag(parsed.flags, "max-output-bytes", 16_384)
      }
    });

    printJson({
      handle: record.handle,
      name: record.name,
      type: record.type,
      policy: record.policy
    });
    return;
  }

  if (first === "secret" && (second === "add-keychain" || second === "add-kc")) {
    const value = await readStdinValue(parsed.flags, "value-stdin", "secret");
    const record = await store.addKeychainSecret({
      name: requireFlag(parsed.flags, "name"),
      type: secretType(getFlag(parsed.flags, "type") || "unknown"),
      value,
      service: getFlag(parsed.flags, "service"),
      source: getFlag(parsed.flags, "source"),
      policy: {
        injectEnv: getFlag(parsed.flags, "inject-env"),
        allowedCommands: getFlagList(parsed.flags, "allow-command"),
        maxOutputBytes: numericFlag(parsed.flags, "max-output-bytes", 16_384)
      }
    });

    printJson({
      handle: record.handle,
      name: record.name,
      type: record.type,
      provider: record.provider,
      backend: record.backend,
      policy: record.policy
    });
    return;
  }

  if (first === "secret" && (second === "add-1password" || second === "add-op")) {
    const reference = requireFlag(parsed.flags, "ref");
    if (hasFlag(parsed.flags, "verify")) {
      await readOnePasswordReference(reference);
    }

    const record = await store.addOnePasswordReference({
      name: requireFlag(parsed.flags, "name"),
      type: secretType(getFlag(parsed.flags, "type") || "unknown"),
      reference,
      policy: {
        injectEnv: getFlag(parsed.flags, "inject-env"),
        allowedCommands: getFlagList(parsed.flags, "allow-command"),
        maxOutputBytes: numericFlag(parsed.flags, "max-output-bytes", 16_384)
      }
    });

    printJson({
      handle: record.handle,
      name: record.name,
      type: record.type,
      provider: record.provider,
      backend: record.backend,
      verified: hasFlag(parsed.flags, "verify"),
      policy: record.policy
    });
    return;
  }

  if (first === "secret" && second === "list") {
    const handles = await store.listHandles();
    // An empty list with no unlock source is ambiguous: it reads like "no secrets yet"
    // when really the ledger can't be unlocked at all. Nudge to stderr so the stdout JSON
    // stays clean for scripts.
    if (handles.length === 0 && unlockStatus().activeSource === "none") {
      process.stderr.write(
        "s-gw: no secrets, and no unlock material is configured. Run `s-gw setup` before enrolling secrets.\n"
      );
    }
    printJson(handles);
    return;
  }

  if (first === "secret" && (second === "delete" || second === "remove")) {
    const handle = third || requireFlag(parsed.flags, "handle");
    printJson(await store.deleteSecret(handle));
    return;
  }

  if (first === "secret" && second === "allow-command") {
    const handle = third || requireFlag(parsed.flags, "handle");
    const command = getFlag(parsed.flags, "command") || SGW_SSH_SESSION_COMMAND;
    printJson(await store.allowCommand(handle, command));
    return;
  }

  if (first === "secret" && second === "set-inject-env") {
    const handle = third || requireFlag(parsed.flags, "handle");
    printJson(await store.setInjectEnv(handle, requireFlag(parsed.flags, "inject-env")));
    return;
  }

  if (first === "scan-file") {
    const target = second;
    if (!target) {
      throw new Error("scan-file requires a path.");
    }

    const persist = !hasFlag(parsed.flags, "preview");
    printJson(await scanLocalFile(store, target, { persist, backend: secretBackendFlag(parsed.flags) }));
    return;
  }

  if (first === "agent" && second === "list") {
    const integrationById = new Map(agentIntegrationStatus().map((item) => [item.agentId, item]));
    printJson(listAgentProfiles().map((profile) => ({
      ...profile,
      integration: integrationById.get(profile.id)
    })));
    return;
  }

  if (first === "agent" && second === "status") {
    printJson({ ok: true, results: agentIntegrationStatus({ agentIds: third ? [third] : undefined }) });
    return;
  }

  if (first === "agent" && second === "install") {
    assertMacRuntimeForAgentConfiguration();
    const results = installAgentIntegrations({
      agentIds: third ? [third] : undefined,
      dryRun: hasFlag(parsed.flags, "dry-run")
    });
    const ok = results.every((result) => result.state !== "conflict");
    printJson({ ok, results });
    if (!ok) process.exitCode = 1;
    return;
  }

  if (first === "agent" && second === "uninstall") {
    assertMacRuntimeForAgentConfiguration();
    const results = uninstallAgentIntegrations({
      agentIds: third ? [third] : undefined,
      dryRun: hasFlag(parsed.flags, "dry-run")
    });
    const ok = results.every((result) => result.state !== "conflict");
    printJson({ ok, results });
    if (!ok) process.exitCode = 1;
    return;
  }

  if (first === "agent" && second === "show") {
    if (!third) {
      throw new Error("agent show requires an agent name.");
    }

    assertMacRuntimeForAgentConfiguration();
    const profile = resolveAgentProfile(third);
    printJson({
      ...profile,
      mcpSnippet: profile.mcp.supported ? renderAgentMcpSnippet(profile.id, mcpSnippetOptions(parsed.flags)) : null,
      codeGuardPlan: getAgentCodeGuardPlan(profile.id)
    });
    return;
  }

  if (first === "agent" && second === "codeguard-plan") {
    if (!third) {
      throw new Error("agent codeguard-plan requires an agent name.");
    }

    printJson(getAgentCodeGuardPlan(third));
    return;
  }

  if (first === "agent" && second === "mcp-snippet") {
    if (!third) {
      throw new Error("agent mcp-snippet requires an agent name.");
    }

    assertMacRuntimeForAgentConfiguration();
    process.stdout.write(`${renderAgentMcpSnippet(third, mcpSnippetOptions(parsed.flags))}\n`);
    return;
  }

  if (first === "requests") {
    if (hasFlag(parsed.flags, "recover")) {
      // --recover (clear all stranded) or --recover REQ / `requests recover REQ` (one).
      const target = second || getFlag(parsed.flags, "recover");
      const recovered = await store.forceRecoverExecutions(typeof target === "string" ? target : undefined);
      printJson({ recoveredCount: recovered.length, recovered });
      return;
    }

    if (second === "cleanup" || hasFlag(parsed.flags, "cleanup")) {
      printJson(
        await store.cleanupRequests({
          pendingOlderThanMs: numericFlag(parsed.flags, "pending-ttl-ms", 24 * 60 * 60 * 1000),
          approvedOlderThanMs: numericFlag(parsed.flags, "approved-ttl-ms", 60 * 60 * 1000),
          duplicatePending: !hasFlag(parsed.flags, "no-dedupe")
        })
      );
      return;
    }

    const state = getFlag(parsed.flags, "state") as RequestState | undefined;
    printJson(
      await store.listRequests({
        state,
        active: hasFlag(parsed.flags, "active"),
        limit: hasFlag(parsed.flags, "all") ? undefined : numericFlag(parsed.flags, "limit", 100)
      })
    );
    return;
  }

  if (first === "approve") {
    if (!second) {
      throw new Error("approve requires a request id.");
    }

    const mode = getFlag(parsed.flags, "mode");
    const duration = getFlag(parsed.flags, "duration") || getFlag(parsed.flags, "duration-ms");
    const agentScope = getFlag(parsed.flags, "agent-scope");
    printJson(
      await store.approveRequest(second, {
        mode: mode ? approvalMode(mode) : undefined,
        durationMs: duration ? parseDurationMs(duration) : undefined,
        agentScope: agentScope ? approvalAgentScope(agentScope) : undefined
      })
    );
    return;
  }

  if (first === "deny") {
    if (!second) {
      throw new Error("deny requires a request id.");
    }

    printJson(await store.denyRequest(second));
    return;
  }

  if (first === "execute") {
    if (!second) {
      throw new Error("execute requires a request id.");
    }

    printJson(await executeApprovedRequest(store, second));
    return;
  }

  if (first === "execute-next") {
    const request = await findNextApprovedRequest(store, parsed.flags);
    printJson({
      requestId: request.id,
      summary: await executeApprovedRequest(store, request.id)
    });
    return;
  }

  if (first === "request" && second === "env-command") {
    const handle = third || requireFlag(parsed.flags, "handle");
    const action = buildEnvCommandAction({
      command: requireFlag(parsed.flags, "command"),
      args: commandArgsFromFlags(parsed.flags),
      injectEnv: requireFlag(parsed.flags, "inject-env"),
      env: envBindingsFromFlags(parsed.flags),
      workingDir: getFlag(parsed.flags, "cwd"),
      timeoutMs: numericFlag(parsed.flags, "timeout-ms", 30_000)
    });
    printJson(await store.createRequest(handle, action, getFlag(parsed.flags, "reason") || "Local CLI request"));
    return;
  }

  if (first === "store" && (second === "backups" || second === "backup")) {
    printJson(await store.listStoreBackups());
    return;
  }

  throw new Error(unknownCommandMessage(parsed.command));
}

function parseArgs(args: string[]): ParsedArgs {
  const command: string[] = [];
  const flags: Record<string, string | boolean | string[]> = {};
  for (let i = 0; i < args.length; i += 1) {
    const item = args[i];
    if (item === "--") {
      flags["--"] = args.slice(i + 1);
      break;
    }

    if (!item.startsWith("--")) {
      command.push(item);
      continue;
    }

    const equals = item.indexOf("=");
    if (equals > 2) {
      addFlag(flags, item.slice(2, equals), item.slice(equals + 1));
      continue;
    }

    const key = item.slice(2);
    const next = args[i + 1];
    if (next !== undefined && flagTakesValue(key) && (!next.startsWith("--") || key === "arg")) {
      addFlag(flags, key, next);
      i += 1;
      continue;
    }

    if (!next || next.startsWith("--")) {
      addFlag(flags, key, true);
      continue;
    }

    addFlag(flags, key, next);
    i += 1;
  }

  return { command, flags };
}

const valueFlags = new Set([
  "access-handle",
  "agent",
  "allow-command",
  "action-kind",
  "approved-ttl-ms",
  "arg",
  "args-json",
  "backend",
  "command",
  "console-url",
  "count",
  "cwd",
  "decision",
  "duration",
  "duration-ms",
  "env",
  "expires-at",
  "handle",
  "id",
  "inject-env",
  "kind",
  "limit",
  "max-output-bytes",
  "menubar-count",
  "min-severity",
  "mode",
  "name",
  "npm-prefix",
  "package",
  "payload",
  "pending-ttl-ms",
  "port",
  "priority",
  "provider",
  "reason",
  "recover",
  "ref",
  "resolved-command",
  "secret-handle",
  "service",
  "server-name",
  "source",
  "ssh-port",
  "ssh-target",
  "state",
  "target",
  "timeout-ms",
  "type",
  "vault",
  "with-env",
  "working-dir",
  "wrapper"
]);

function flagTakesValue(key: string): boolean {
  return valueFlags.has(key);
}

function addFlag(flags: Record<string, string | boolean | string[]>, key: string, value: string | boolean): void {
  const existing = flags[key];
  if (existing === undefined) {
    flags[key] = value;
    return;
  }

  if (Array.isArray(existing)) {
    existing.push(String(value));
    return;
  }

  flags[key] = [String(existing), String(value)];
}

async function readStdinValue(
  flags: Record<string, string | boolean | string[]>,
  flagName: string,
  label: string
): Promise<string> {
  if (!hasFlag(flags, flagName)) {
    throw new Error(`Use --${flagName} so the ${label} never appears in shell history or chat.`);
  }

  const chunks: Buffer[] = [];
  for await (const chunk of stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

function getFlag(flags: Record<string, string | boolean | string[]>, key: string): string | undefined {
  const value = flags[key];
  if (Array.isArray(value)) {
    return value.at(-1);
  }

  if (typeof value === "string") {
    return value;
  }

  return undefined;
}

function getFlagList(flags: Record<string, string | boolean | string[]>, key: string): string[] {
  const value = flags[key];
  if (Array.isArray(value)) {
    return value;
  }

  if (typeof value === "string") {
    return [value];
  }

  return [];
}

function commandArgsFromFlags(flags: Record<string, string | boolean | string[]>): string[] {
  const passthrough = getFlagList(flags, "--");
  if (passthrough.length > 0) {
    return passthrough;
  }

  const jsonArgs = getFlag(flags, "args-json");
  if (jsonArgs) {
    const parsed = JSON.parse(jsonArgs) as unknown;
    if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string")) {
      throw new Error("--args-json must be a JSON array of strings.");
    }
    return parsed;
  }

  return getFlagList(flags, "arg");
}

function envBindingsFromFlags(flags: Record<string, string | boolean | string[]>): CommandEnvBinding[] {
  const values = getFlagList(flags, "with-env");
  const out: CommandEnvBinding[] = [];
  for (const value of values) {
    const index = value.indexOf("=");
    if (index <= 0 || index === value.length - 1) {
      throw new Error("--with-env must look like ENV=HANDLE.");
    }

    out.push({
      injectEnv: value.slice(0, index),
      handle: value.slice(index + 1)
    });
  }

  return out;
}

async function findNextApprovedRequest(
  store: SecretStore,
  flags: Record<string, string | boolean | string[]>
) {
  const handle = getFlag(flags, "handle");
  const kind = getFlag(flags, "kind");
  const command = getFlag(flags, "command");
  let requests = await store.listRequests({ state: "approved", limit: 1000 });
  if (handle) {
    requests = requests.filter((request) => request.handle === handle);
  }
  if (kind) {
    requests = requests.filter((request) => request.action.kind === kind);
  }
  if (command) {
    requests = requests.filter((request) => request.action.command === command);
  }

  if (requests.length === 0) {
    throw new Error("No approved request matches execute-next filters.");
  }
  if (requests.length > 1 && !handle && !command) {
    throw new Error("Multiple approved requests match. Add --handle or --command before using execute-next.");
  }

  return requests[0];
}

function requireFlag(flags: Record<string, string | boolean | string[]>, key: string): string {
  const value = getFlag(flags, key);
  if (!value) {
    throw new Error(`Missing --${key}.`);
  }

  return value;
}

function hasFlag(flags: Record<string, string | boolean | string[]>, key: string): boolean {
  return flags[key] !== undefined;
}

function numericFlag(flags: Record<string, string | boolean | string[]>, key: string, fallback: number): number {
  const raw = getFlag(flags, key);
  if (!raw) {
    return fallback;
  }

  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    throw new Error(`--${key} must be a number.`);
  }

  return parsed;
}

function optionalNumericFlag(flags: Record<string, string | boolean | string[]>, key: string): number | undefined {
  const raw = getFlag(flags, key);
  if (!raw) {
    return undefined;
  }

  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    throw new Error(`--${key} must be a number.`);
  }
  return parsed;
}

function secretBackendFlag(flags: Record<string, string | boolean | string[]>): LocalSecretBackend {
  const raw = getFlag(flags, "backend");
  if (!raw) {
    return preferredLocalSecretBackend();
  }

  const normalized = raw.trim().toLowerCase();
  if (normalized === "local" || normalized === "keychain") {
    return normalized;
  }

  throw new Error("--backend must be either local or keychain.");
}

function secretType(input: string): SecretType {
  const allowed: SecretType[] = [
    "api-token",
    "ssh-key",
    "private-key",
    "password",
    "credential",
    "access-key",
    "unknown"
  ];

  return allowed.includes(input as SecretType) ? (input as SecretType) : "unknown";
}

function approvalPolicySecretType(input: string): SecretType {
  const type = secretType(input);
  if (type === "unknown" && input.trim().toLowerCase() !== "unknown") {
    throw new Error(`--type is not a supported credential type: ${input}`);
  }
  return type;
}

function approvalMode(input: string): ApprovalMode {
  const normalized = input.trim().toLowerCase();
  switch (normalized) {
  case "per-transaction":
  case "transaction":
  case "per":
    return "per-transaction";
  case "timed-session":
  case "timed":
  case "time":
    return "timed-session";
  case "login-session":
  case "login":
  case "session":
    return "login-session";
  case "always":
  case "unlimited":
  case "forever":
    return "always";
  default:
    throw new Error("--mode must be per-transaction, timed-session, login-session, or always.");
  }
}

function approvalAgentScope(input: string): ApprovalAgentScope {
  const normalized = input.trim().toLowerCase();
  switch (normalized) {
  case "same-agent":
  case "agent":
  case "this-agent":
  case "same":
    return "same-agent";
  case "any-agent":
  case "all-agents":
  case "all":
  case "any":
    return "any-agent";
  default:
    throw new Error("--agent-scope must be same-agent or any-agent.");
  }
}

function approvalPolicyDecision(input: string): ApprovalPolicyDecision {
  const normalized = input.trim().toLowerCase();
  if (normalized === "allow" || normalized === "ask" || normalized === "deny") {
    return normalized;
  }

  throw new Error("--decision must be allow, ask, or deny.");
}

function approvalPolicyActionKind(input: string): ApprovalPolicyActionKind {
  const normalized = input.trim().toLowerCase();
  if (normalized === "env-command" || normalized === "env_command" || normalized === "command") {
    return "env_command";
  }
  if (normalized === "ssh-session" || normalized === "ssh_session" || normalized === "ssh") {
    return "ssh_session";
  }

  throw new Error("--action-kind must be env_command or ssh_session.");
}

function optionalSecretSeverity(input: string | undefined): SecretSeverity | undefined {
  if (!input) {
    return undefined;
  }

  const normalized = input.trim().toLowerCase();
  if (normalized === "low" || normalized === "medium" || normalized === "high" || normalized === "critical") {
    return normalized;
  }

  throw new Error("--min-severity must be low, medium, high, or critical.");
}

function parseDurationMs(input: string): number {
  const trimmed = input.trim().toLowerCase();
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(ms|msec|millisecond|milliseconds|s|sec|second|seconds|m|min|minute|minutes|h|hr|hour|hours|d|day|days)?$/);
  if (!match) {
    throw new Error("--duration must look like 15m, 2h, 1d, or a millisecond number.");
  }

  const value = Number(match[1]);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("--duration must be a positive number.");
  }

  const unit = match[2] || "ms";
  if (unit === "ms" || unit === "msec" || unit.startsWith("millisecond")) {
    return Math.floor(value);
  }
  if (unit === "s" || unit === "sec" || unit.startsWith("second")) {
    return Math.floor(value * 1000);
  }
  if (unit === "m" || unit === "min" || unit.startsWith("minute")) {
    return Math.floor(value * 60 * 1000);
  }
  if (unit === "h" || unit === "hr" || unit.startsWith("hour")) {
    return Math.floor(value * 60 * 60 * 1000);
  }
  if (unit === "d" || unit.startsWith("day")) {
    return Math.floor(value * 24 * 60 * 60 * 1000);
  }

  throw new Error(`Unsupported duration unit: ${unit}`);
}

function mcpSnippetOptions(flags: Record<string, string | boolean | string[]>) {
  const command = getFlag(flags, "command");
  const args = getFlagList(flags, "arg");
  const explicitEnv = parseEnvFlags(getFlagList(flags, "env"));
  const authorityEnv = mcpAuthorityEnvironment({
    env: { ...process.env, ...explicitEnv }
  });
  const env = {
    ...explicitEnv,
    ...authorityEnv
  };
  if (process.platform === "darwin") {
    const layout = getPackageLayout();
    if (layout.isSelfContainedMacApp && !command) {
      const bundled = resolvePackagedMcpCommand(layout, {
        platform: process.platform,
        pathEnv: process.env.PATH || "",
        env: process.env,
        mcpServerPath: layout.mcpPath
      });
      return {
        serverName: getFlag(flags, "server-name"),
        command: bundled.command,
        args: args.length > 0 ? args : bundled.args,
        env
      };
    }
  }

  return {
    serverName: getFlag(flags, "server-name"),
    command,
    args,
    env
  };
}

function assertMacRuntimeForAgentConfiguration(): void {
  if (process.platform === "darwin") {
    assertMacRuntimeForManagedSurfaces(getPackageLayout());
  }
}

function parseEnvFlags(values: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  for (const value of values) {
    const idx = value.indexOf("=");
    if (idx <= 0) {
      throw new Error(`--env values must be KEY=VALUE. Got: ${value}`);
    }

    const key = value.slice(0, idx).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw new Error(`Invalid env key for --env: ${key}`);
    }

    env[key] = value.slice(idx + 1);
  }

  return env;
}

async function handleSetupCommand(
  store: SecretStore,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (process.platform === "win32" && hasFlag(flags, "no-service") && !hasFlag(flags, "no-menubar")) {
    throw new Error("--no-service requires --no-menubar on Windows because the tray helper requires its matching console.");
  }

  if (process.platform === "darwin") {
    const layout = getPackageLayout();
    assertMacRuntimeForManagedSurfaces(layout);
  }

  const port = numericFlag(flags, "port", 8718);
  const keychainHelper = process.platform === "darwin" ? installPersistentKeychainHelper() : undefined;
  const keychainCompatibility = process.platform === "darwin" ? pinPackagedKeychainHelper() : undefined;
  const beforeUnlock = unlockStatus();
  const backgroundRequested = !hasFlag(flags, "no-service")
    || (process.platform === "darwin" && !hasFlag(flags, "no-menubar"));
  if (backgroundRequested && beforeUnlock.envConfigured && process.platform === "win32") {
    throw new Error(
      "Windows background startup will not persist or inherit SGW_MASTER_PASSPHRASE. " +
      "Unset it before setup, or use `s-gw setup --no-service --no-menubar` for a foreground-only installation."
    );
  }
  if (backgroundRequested && beforeUnlock.envConfigured && process.platform === "darwin") {
    throw new Error(
      "macOS background startup will not persist or inherit SGW_MASTER_PASSPHRASE. " +
      "Unset it before setup, or use `s-gw setup --no-service --no-menubar` for a foreground-only installation."
    );
  }
  if (backgroundRequested && beforeUnlock.envConfigured && process.platform === "linux") {
    throw new Error(
      "Linux background startup will not persist or inherit SGW_MASTER_PASSPHRASE. " +
      "Unset it before setup, or use `s-gw setup --no-service --no-menubar` for a foreground-only installation."
    );
  }
  const masterKeychainRepair = process.platform === "darwin" && beforeUnlock.keychain.configured
    ? repairKeychainPassphraseAccess()
    : undefined;
  let unlockAction = beforeUnlock.activeSource === "none" ? "not-configured" : `existing-${beforeUnlock.activeSource}`;

  if (beforeUnlock.activeSource === "none") {
    if (process.platform !== "darwin" && process.platform !== "linux" && process.platform !== "win32") {
      throw new Error("s-gw setup needs a supported local OS credential store or SGW_MASTER_PASSPHRASE.");
    }
    if (beforeUnlock.keychain.state === "unavailable") {
      throw new Error(
        "s-gw setup cannot verify existing OS credential-store unlock material and will not generate or replace it. " +
        (beforeUnlock.keychain.error || "Make the local credential store available, then retry.")
      );
    }

    const passphrase = hasFlag(flags, "passphrase-stdin")
      ? await readStdinValue(flags, "passphrase-stdin", "unlock passphrase")
      : randomBytes(32).toString("base64url");
    setKeychainPassphrase(passphrase);
    unlockAction = hasFlag(flags, "passphrase-stdin") ? "stored-keychain-passphrase" : "generated-keychain-passphrase";
  }

  await store.init();
  const secretKeychainRepair = process.platform === "darwin"
    ? await store.repairKeychainAccess()
    : undefined;
  const consoleUrl = `http://127.0.0.1:${port}/`;
  let service: unknown = process.platform === "linux"
    ? systemdUserServiceStatus()
    : launchAgentStatus("console");
  let menuBar = launchAgentStatus("menubar");
  let windowsConsole: unknown;
  let windowsHelper: unknown;
  const appInstall = process.platform === "darwin" ? installMacAppBundle() : undefined;

  if (process.platform === "darwin" && !hasFlag(flags, "no-service")) {
    service = await installConsoleLaunchAgent({ port, start: true });
  } else if (process.platform === "linux" && !hasFlag(flags, "no-service")) {
    service = await installSystemdUserService({ port, start: true });
  } else if (process.platform === "win32" && !hasFlag(flags, "no-service")) {
    const windowsService = await installWindowsLoginService({
      port,
      start: true,
      tray: !hasFlag(flags, "no-menubar")
    });
    service = windowsService;
    windowsConsole = windowsService.active
      ? { consoleUrl: windowsService.consoleUrl, pid: windowsService.consolePid }
      : undefined;
    windowsHelper = windowsService.helperActive
      ? { consoleUrl: windowsService.consoleUrl }
      : undefined;
  }

  if (process.platform === "darwin" && !hasFlag(flags, "no-menubar")) {
    menuBar = await installMenuBarLaunchAgent({
      port,
      start: true,
      notify: !hasFlag(flags, "no-notify"),
      countMode: normalizeMenuBarCountMode(getFlag(flags, "menubar-count"))
    });
  }

  const opened = shouldOpenUi(flags) && !(process.platform === "win32" && hasFlag(flags, "no-service"))
    ? await openPreferredUi(port, consoleUrl)
    : undefined;
  const agents = hasFlag(flags, "no-agents")
    ? { skipped: true, results: [] }
    : { skipped: false, results: installAgentIntegrations() };

  printJson({
    ok: !secretKeychainRepair || secretKeychainRepair.failed.length === 0,
    unlock: unlockAction,
    storePath: store.storePath,
    consoleUrl,
    opened,
    service,
    menuBar,
    windowsConsole,
    windowsHelper,
    keychainHelper,
    keychainCompatibility,
    keychainRepair: {
      master: masterKeychainRepair,
      secrets: secretKeychainRepair
    },
    appInstall,
    agents,
    nextSteps: [
      "Open the native app with `s-gw app open`.",
      "Run `s-gw agent status` to review detected agent connections or resolve any reported conflicts.",
      "Enroll secrets locally with `s-gw secret add-keychain --value-stdin` or scan files with `s-gw scan-file PATH`."
    ]
  });
}

async function handleStartCommand(flags: Record<string, string | boolean | string[]>): Promise<void> {
  const port = numericFlag(flags, "port", 8718);
  const consoleUrl = `http://127.0.0.1:${port}/`;
  if (process.platform === "win32") {
    if (hasFlag(flags, "no-service") && !hasFlag(flags, "no-menubar")) {
      throw new Error("--no-service requires --no-menubar on Windows because the tray helper requires its matching console.");
    }
    if (hasFlag(flags, "no-service")) {
      printJson({ ok: true, consoleUrl, opened: undefined, service: undefined });
      return;
    }
    const service = await installWindowsLoginService({
      port,
      start: true,
      tray: !hasFlag(flags, "no-menubar")
    });
    const opened = shouldOpenUi(flags) ? await openPreferredUi(port, consoleUrl) : undefined;
    printJson({ ok: true, consoleUrl, opened, service });
    return;
  }

  if (process.platform === "linux") {
    const service = await installSystemdUserService({ port, start: true });
    const opened = shouldOpenUi(flags) ? await openPreferredUi(port, consoleUrl) : undefined;
    printJson({ ok: true, consoleUrl, opened, service });
    return;
  }

  const service = launchAgentStatus("console").installed
    ? startInstalledLaunchAgent("console")
    : await installConsoleLaunchAgent({ port, start: true });
  const menuBar = launchAgentStatus("menubar").installed
    ? startInstalledLaunchAgent("menubar")
    : await installMenuBarLaunchAgent({ port, start: true });

  const opened = shouldOpenUi(flags) ? await openPreferredUi(port, consoleUrl) : undefined;

  printJson({ ok: true, consoleUrl, opened, service, menuBar });
}

async function handleStopCommand(): Promise<void> {
  if (process.platform === "win32") {
    const service = await windowsLoginServiceStatus();
    if (service.installed && !service.managed) {
      throw new Error(service.error || "The Windows login startup is not managed by s-gw.");
    }
    if (service.managed) {
      const stoppedService = await stopInstalledWindowsLoginService();
      printJson({ ok: true, windows: stoppedService.stopped, service: stoppedService });
      return;
    }
    printJson({ ok: true, windows: stopWindowsSurfaces() });
    return;
  }
  const { service, menuBar } = stopBackgroundSurfaces();
  printJson({ ok: true, service, menuBar });
}

function updateServiceLifecycle(keepAppRunning: boolean): {
  stop: () => Promise<void>;
  restart: () => Promise<void>;
} {
  const serviceBefore = launchAgentStatus("console");
  const menuBarBefore = launchAgentStatus("menubar");
  const systemdBefore = process.platform === "linux" ? systemdUserServiceStatus() : undefined;
  const serviceWasLoaded = process.platform === "darwin" && serviceBefore.installed && serviceBefore.loaded;
  const menuBarWasLoaded = process.platform === "darwin" && menuBarBefore.installed && menuBarBefore.loaded;
  const systemdWasActive = Boolean(systemdBefore?.installed && systemdBefore.active);
  let macAppWasRunning = false;
  let windowsStopped: WindowsStoppedSurfaces | undefined;
  let windowsServiceBefore: Awaited<ReturnType<typeof windowsLoginServiceStatus>> | undefined;

  return {
    stop: async () => {
      stopBackgroundSurfaces();
      if (process.platform === "darwin" && !keepAppRunning) {
        macAppWasRunning = Boolean(stopMacApp());
      } else if (process.platform === "win32") {
        windowsServiceBefore = await windowsLoginServiceStatus();
        if (windowsServiceBefore.installed && !windowsServiceBefore.managed) {
          throw new Error(windowsServiceBefore.error || "The Windows login startup is not managed by s-gw.");
        }
        windowsStopped = windowsServiceBefore.managed
          ? (await stopInstalledWindowsLoginService()).stopped
          : stopWindowsSurfaces();
      }
    },
    restart: async () => {
      const failures: string[] = [];
      if (process.platform === "darwin") {
        restartLaunchAgent("console", serviceWasLoaded, failures);
        restartLaunchAgent("menubar", menuBarWasLoaded, failures);
        await verifyRestoredLaunchAgents(serviceWasLoaded, menuBarWasLoaded, failures);
        if (macAppWasRunning) {
          try {
            openMacApp();
          } catch (error) {
            failures.push(`app: ${error instanceof Error ? error.message : String(error)}`);
          }
        }
      } else if (process.platform === "win32" && windowsStopped) {
        try {
          if (windowsServiceBefore?.managed && windowsServiceBefore.config) {
            await installWindowsLoginService({
              port: windowsServiceBefore.config.port,
              start: windowsServiceBefore.active,
              tray: windowsServiceBefore.config.tray
            });
          } else {
            await restartWindowsSurfaces(windowsStopped);
          }
        } catch (error) {
          failures.push(`Windows surfaces: ${error instanceof Error ? error.message : String(error)}`);
        }
      } else if (process.platform === "linux" && systemdWasActive) {
        try {
          startInstalledSystemdUserService();
        } catch (error) {
          failures.push(`systemd service: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      if (failures.length > 0) {
        throw new Error(failures.join("; "));
      }
    }
  };
}

async function verifyRestoredLaunchAgents(
  serviceWasLoaded: boolean,
  menuBarWasLoaded: boolean,
  failures: string[]
): Promise<void> {
  if (!serviceWasLoaded && !menuBarWasLoaded) return;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const serviceReady = !serviceWasLoaded || launchAgentStatus("console").loaded;
    const menuReady = !menuBarWasLoaded || launchAgentStatus("menubar").loaded;
    if (serviceReady && menuReady) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (serviceWasLoaded && !launchAgentStatus("console").loaded) failures.push("console: did not remain loaded");
  if (menuBarWasLoaded && !launchAgentStatus("menubar").loaded) failures.push("menubar: did not remain loaded");
}

function restartLaunchAgent(
  kind: "console" | "menubar",
  wasLoaded: boolean,
  failures: string[]
): void {
  if (!wasLoaded) return;
  try {
    startInstalledLaunchAgent(kind);
  } catch (error) {
    failures.push(`${kind}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function stopBackgroundSurfaces() {
  const serviceBefore = launchAgentStatus("console");
  const menuBarBefore = launchAgentStatus("menubar");
  let service: unknown = serviceBefore;
  if (process.platform === "darwin" && serviceBefore.installed) {
    service = stopInstalledLaunchAgent("console");
  } else if (process.platform === "linux") {
    const systemdBefore = systemdUserServiceStatus();
    service = systemdBefore.installed ? stopInstalledSystemdUserService() : systemdBefore;
  }
  const menuBar = process.platform === "darwin" && menuBarBefore.installed
    ? stopInstalledLaunchAgent("menubar")
    : menuBarBefore;
  return { service, menuBar };
}

async function handleServiceCommand(
  action: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (process.platform === "win32") {
    if (action === "install") {
      printJson(await installWindowsLoginService({
        port: numericFlag(flags, "port", 8718),
        start: hasFlag(flags, "start"),
        tray: hasFlag(flags, "menubar")
      }));
      return;
    }
    if (action === "start") {
      printJson(await startInstalledWindowsLoginService());
      return;
    }
    if (action === "stop") {
      printJson(await stopInstalledWindowsLoginService());
      return;
    }
    if (action === "status") {
      printJson(await windowsLoginServiceStatus());
      return;
    }
    if (action === "uninstall") {
      printJson(await uninstallWindowsLoginService());
      return;
    }
    throw new Error("service requires install, start, stop, status, or uninstall.");
  }

  if (process.platform === "linux") {
    if (action === "install") {
      printJson(await installSystemdUserService({
        port: numericFlag(flags, "port", 8718),
        start: hasFlag(flags, "start")
      }));
      return;
    }
    if (action === "start") {
      printJson(startInstalledSystemdUserService());
      return;
    }
    if (action === "stop") {
      printJson(stopInstalledSystemdUserService());
      return;
    }
    if (action === "status") {
      printJson(systemdUserServiceStatus());
      return;
    }
    if (action === "uninstall") {
      printJson(await uninstallSystemdUserService());
      return;
    }
    throw new Error("service requires install, start, stop, status, or uninstall.");
  }

  if (action === "install") {
    printJson(
      await installConsoleLaunchAgent({
        port: numericFlag(flags, "port", 8718),
        start: hasFlag(flags, "start")
      })
    );
    return;
  }

  if (action === "start") {
    printJson(startInstalledLaunchAgent("console"));
    return;
  }

  if (action === "stop") {
    printJson(stopInstalledLaunchAgent("console"));
    return;
  }

  if (action === "status") {
    printJson(launchAgentStatus("console"));
    return;
  }

  if (action === "uninstall") {
    printJson(await uninstallConsoleLaunchAgent());
    return;
  }

  throw new Error("service requires install, start, stop, status, or uninstall.");
}

async function handleMenuBarCommand(
  action: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (action === "app-path") {
    const layout = getPackageLayout();
    process.stdout.write(`${process.platform === "win32" ? layout.windowsHelperLauncherPath : layout.menuBarAppPath}\n`);
    return;
  }

  if (action === "open") {
    if (process.platform === "win32") {
      printJson(
        await openWindowsHelper({
          consoleUrl: getFlag(flags, "console-url"),
          port: numericFlag(flags, "port", 8718)
        })
      );
      return;
    }

    printJson(
      openMenuBarHelper({
        consoleUrl: getFlag(flags, "console-url"),
        port: numericFlag(flags, "port", 8718),
        show: hasFlag(flags, "show"),
        notify: !hasFlag(flags, "no-notify"),
        countMode: normalizeMenuBarCountMode(getFlag(flags, "count"))
      })
    );
    return;
  }

  if (action === "install") {
    printJson(
      await installMenuBarLaunchAgent({
        consoleUrl: getFlag(flags, "console-url"),
        port: numericFlag(flags, "port", 8718),
        start: hasFlag(flags, "start"),
        notify: !hasFlag(flags, "no-notify"),
        countMode: normalizeMenuBarCountMode(getFlag(flags, "count"))
      })
    );
    return;
  }

  if (action === "start") {
    printJson(startInstalledLaunchAgent("menubar"));
    return;
  }

  if (action === "stop") {
    printJson(stopInstalledLaunchAgent("menubar"));
    return;
  }

  if (action === "status") {
    printJson(launchAgentStatus("menubar"));
    return;
  }

  if (action === "uninstall") {
    printJson(await uninstallMenuBarLaunchAgent());
    return;
  }

  throw new Error("menubar requires app-path, open, install, start, stop, status, or uninstall.");
}

async function handleOnePasswordCommand(
  store: SecretStore,
  action: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (!action || action === "status") {
    printJson(onePasswordStatus());
    return;
  }

  if (action === "import") {
    const vault = getFlag(flags, "vault") || "Dev";
    const candidates = await listOnePasswordSecretReferences(vault);
    if (hasFlag(flags, "dry-run")) {
      printJson({
        vault,
        candidates: candidates.map((candidate) => ({
          name: onePasswordHandleName(candidate.itemTitle, candidate.fieldLabel),
          type: candidate.secretType,
          itemTitle: candidate.itemTitle,
          itemId: candidate.itemId,
          itemCategory: candidate.itemCategory,
          fieldLabel: candidate.fieldLabel,
          fieldId: candidate.fieldId,
          fieldType: candidate.fieldType,
          fieldPurpose: candidate.fieldPurpose,
          suggestedEnv: candidate.suggestedEnv,
          companionFields: (candidate.companionFields || []).map((field) => ({
            name: onePasswordHandleName(field.itemTitle, field.fieldLabel),
            type: field.secretType,
            itemTitle: field.itemTitle,
            itemId: field.itemId,
            itemCategory: field.itemCategory,
            fieldLabel: field.fieldLabel,
            fieldId: field.fieldId,
            fieldType: field.fieldType,
            fieldPurpose: field.fieldPurpose,
            suggestedEnv: field.suggestedEnv
          }))
        }))
      });
      return;
    }

    const imported = [];
    const includeCompanions = hasFlag(flags, "include-companions");
    const toImport = [];
    const seenRefs = new Set<string>();
    for (const candidate of candidates) {
      toImport.push(candidate);
      seenRefs.add(candidate.reference);
      if (!includeCompanions) {
        continue;
      }
      for (const companion of candidate.companionFields || []) {
        if (seenRefs.has(companion.reference)) {
          continue;
        }
        seenRefs.add(companion.reference);
        toImport.push(companion);
      }
    }

    for (const candidate of toImport) {
      const record = await store.addOnePasswordReference({
        name: onePasswordHandleName(candidate.itemTitle, candidate.fieldLabel),
        type: candidate.secretType,
        reference: candidate.reference,
        source: `onepassword:${vault}`,
        policy: {
          injectEnv: getFlag(flags, "inject-env") || candidate.suggestedEnv,
          allowedCommands: getFlagList(flags, "allow-command"),
          maxOutputBytes: numericFlag(flags, "max-output-bytes", 16_384)
        }
      });

      imported.push({
        handle: record.handle,
        name: record.name,
        type: record.type,
        backend: record.backend,
        provider: record.provider,
        itemTitle: candidate.itemTitle,
        fieldLabel: candidate.fieldLabel,
        suggestedEnv: candidate.suggestedEnv,
        policy: record.policy
      });
    }

    printJson({ vault, includeCompanions, importedCount: imported.length, imported });
    return;
  }

  if (action === "capture") {
    const vault = getFlag(flags, "vault") || "Dev";
    const text = await readStdinValue(flags, "text-stdin", "text to scan");
    const result = await scanTextToOnePassword(store, text, {
      vault,
      source: getFlag(flags, "source") || "onepassword-capture",
      defaultName: getFlag(flags, "name"),
      policy: {
        injectEnv: getFlag(flags, "inject-env"),
        allowedCommands: getFlagList(flags, "allow-command"),
        maxOutputBytes: numericFlag(flags, "max-output-bytes", 16_384)
      }
    });

    printJson({
      vault,
      backend: "onepassword",
      capturedCount: result.findings.length,
      tokenizedText: result.tokenizedText,
      findings: result.findings
    });
    return;
  }

  throw new Error("onepassword requires status, import, or capture.");
}

async function handleOneShotEnvCommand(
  store: SecretStore,
  handleArg: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  const handle = handleArg || requireFlag(flags, "handle");
  const action = buildEnvCommandAction({
    command: requireFlag(flags, "command"),
    args: commandArgsFromFlags(flags),
    injectEnv: requireFlag(flags, "inject-env"),
    env: envBindingsFromFlags(flags),
    workingDir: getFlag(flags, "cwd"),
    timeoutMs: numericFlag(flags, "timeout-ms", 30_000)
  });
  const admission = await store.prepareOneShotExecution(
    handle,
    action,
    getFlag(flags, "reason") || "Local CLI one-shot execution"
  );

  if (admission.kind === "request") {
    printJson({
      approvalRequired: admission.request.state !== "approved",
      localApprovalCommand: admission.request.state === "approved" ? undefined : `s-gw approve ${admission.request.id}`,
      localRunCommand: `s-gw execute ${admission.request.id}`,
      request: admission.request
    });
    return;
  }

  const summary = await executeReusablePermit(store, admission.permit);
  if (hasFlag(flags, "raw")) {
    printRawSummary(summary);
    return;
  }

  printJson({
    approvalRequired: false,
    reusableAuthorization: admission.permit.authorization,
    summary
  });
}

async function handleSshCommand(
  store: SecretStore,
  action: string | undefined,
  handleArg: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (action === "close") {
    const handle = handleArg || requireFlag(flags, "handle");
    printJson(await closeOwnedSshSession({
      handle,
      target: requireFlag(flags, "target"),
      port: numericFlag(flags, "port", 22),
      home: store.home
    }));
    return;
  }

  if (action === "run" && getFlag(flags, "request-id")) {
    printJson(await executeApprovedRequest(store, requireFlag(flags, "request-id")));
    return;
  }

  if (action === "request" || action === "run") {
    const handle = handleArg || requireFlag(flags, "handle");
    const secret = await store.getSecretRecord(handle);
    const remoteArgs = commandArgsFromFlags(flags);
    const sshAction = buildSshSessionAction({
      target: requireFlag(flags, "target"),
      port: numericFlag(flags, "port", 22),
      args: remoteArgs,
      injectEnv: getFlag(flags, "inject-env") || defaultSshInjectEnv(secret),
      workingDir: getFlag(flags, "cwd"),
      timeoutMs: numericFlag(flags, "timeout-ms", 30_000)
    });
    const reason = getFlag(flags, "reason") || "s-gw-owned SSH session request";
    const request = await store.createRequest(handle, sshAction, reason);
    if (action === "request" || request.state !== "approved") {
      printJson({
        approvalRequired: request.state !== "approved",
        localApprovalCommand: request.state === "approved" ? undefined : `s-gw approve ${request.id}`,
        localRunCommand: `s-gw ssh run --request-id ${request.id}`,
        request
      });
      return;
    }

    printJson(await executeApprovedRequest(store, request.id));
    return;
  }

  throw new Error("ssh requires request, run, or close.");
}

async function handleAwsCommand(
  store: SecretStore,
  action: string | undefined,
  flags: Record<string, string | boolean | string[]>,
  positionalArgs: string[] = []
): Promise<void> {
  if (!action && hasFlag(flags, "version")) {
    throw new Error("`s-gw aws --version` does not run the AWS CLI. Use `aws --version`, or choose a configured wrapper with `s-gw aws plan --wrapper PATH` and run `s-gw aws run --raw --wrapper PATH -- --version`.");
  }

  const handles = await resolveAwsHandles(store, flags);
  const wrapper = chooseAwsWrapper(handles.secret, handles.access, getFlag(flags, "wrapper"));
  const awsArgs = positionalArgs.length > 0 ? positionalArgs : commandArgsFromFlags(flags);

  if (!action || action === "plan" || action === "path") {
    const sampleArgs = awsArgs.length > 0 ? awsArgs : ["sts", "get-caller-identity"];
    printJson({
      ok: true,
      wrapper,
      secretHandle: handles.secret.handle,
      secretEnv: handles.secret.policy.injectEnv || "AWS_SECRET_ACCESS_KEY",
      accessKeyHandle: handles.access.handle,
      accessKeyEnv: handles.access.policy.injectEnv || "AWS_ACCESS_KEY_ID",
      sampleRequestCommand: awsCommandLine("request", sampleArgs, { wrapper, handles }),
      sampleRunCommand: awsCommandLine("run", sampleArgs, { wrapper, handles })
    });
    return;
  }

  if (action !== "request" && action !== "run") {
    throw new Error("aws requires request, run, or plan.");
  }
  if (awsArgs.length === 0) {
    throw new Error("aws request/run needs AWS CLI arguments after `--`, for example `s-gw aws run -- sts get-caller-identity`.");
  }

  if (action === "request") {
    const request = await createAwsRequest(store, handles, wrapper, awsArgs, flags);
    printJson(awsRequestResponse(request, wrapper, awsArgs, handles));
    return;
  }

  const awsAction = buildAwsAction(handles, wrapper, awsArgs, flags);
  const admission = await store.prepareOneShotExecution(
    handles.secret.handle,
    awsAction,
    getFlag(flags, "reason") || "s-gw AWS command request"
  );
  if (admission.kind === "request") {
    printJson(awsRequestResponse(admission.request, wrapper, awsArgs, handles));
    return;
  }

  const summary = await executeReusablePermit(store, admission.permit);
  if (hasFlag(flags, "raw")) {
    printRawSummary(summary);
    return;
  }

  printJson({
    approvalRequired: false,
    repeatCommand: awsCommandLine("run", awsArgs, { wrapper, handles }),
    wrapper,
    secretHandle: handles.secret.handle,
    accessKeyHandle: handles.access.handle,
    reusableAuthorization: admission.permit.authorization,
    summary
  });
}

interface AwsHandles {
  secret: HandleSummary;
  access: HandleSummary;
}

async function resolveAwsHandles(
  store: SecretStore,
  flags: Record<string, string | boolean | string[]>
): Promise<AwsHandles> {
  const handles = await store.listHandles();
  const secretHandle = getFlag(flags, "secret-handle");
  const accessHandle = getFlag(flags, "access-handle");
  const secret = secretHandle
    ? findHandle(handles, secretHandle, "--secret-handle")
    : findAwsSecretHandle(handles);
  const access = accessHandle
    ? findHandle(handles, accessHandle, "--access-handle")
    : findAwsAccessHandle(handles, secret.handle);

  if (secret.handle === access.handle) {
    throw new Error("AWS secret and access-key handles must be different.");
  }

  return { secret, access };
}

function findHandle(handles: HandleSummary[], handle: string, label: string): HandleSummary {
  const found = handles.find((item) => item.handle === handle);
  if (!found) {
    throw new Error(`Unknown ${label}: ${handle}`);
  }
  return found;
}

function findAwsSecretHandle(handles: HandleSummary[]): HandleSummary {
  const exact = handles.find((item) => item.policy.injectEnv === "SGW_AWS_DEV_CREDENTIAL")
    || handles.find((item) => item.policy.injectEnv === "AWS_SECRET_ACCESS_KEY");
  if (exact) {
    return exact;
  }

  const named = handles.find((item) => {
    const name = item.name.toLowerCase();
    return name.includes("aws") && !name.includes("access key id") && !name.includes("username");
  });
  if (named) {
    return named;
  }

  throw new Error("No AWS secret handle found. Enroll or import AWS-dev through s-gw, then retry.");
}

function findAwsAccessHandle(handles: HandleSummary[], secretHandle: string): HandleSummary {
  const exact = handles.find((item) => item.handle !== secretHandle && item.policy.injectEnv === "SGW_AWS_DEV_ACCESS_KEY_ID")
    || handles.find((item) => item.handle !== secretHandle && item.policy.injectEnv === "AWS_ACCESS_KEY_ID");
  if (exact) {
    return exact;
  }

  const named = handles.find((item) => {
    const name = item.name.toLowerCase();
    return item.handle !== secretHandle && name.includes("aws") && (name.includes("access key id") || name.includes("username"));
  });
  if (named) {
    return named;
  }

  throw new Error("No AWS access-key-id handle found. Import companion fields with `s-gw onepassword import --include-companions`, then retry.");
}

function chooseAwsWrapper(secret: HandleSummary, access: HandleSummary, requested?: string): string {
  const secretAllowed = new Set((secret.policy.allowedCommands || []).map(normalizeCommandGrant));
  const accessAllowed = new Set((access.policy.allowedCommands || []).map(normalizeCommandGrant));
  const common = [...secretAllowed].filter((command) => accessAllowed.has(command));

  if (common.length === 0) {
    throw new Error("No shared AWS wrapper command is allowed for the AWS secret/access handles. Update both handle policies to allow the same wrapper.");
  }

  if (requested) {
    const normalizedRequested = normalizeCommandGrant(requested);
    if (!common.includes(normalizedRequested)) {
      throw new Error(`AWS wrapper is not allowed by both credential handles: ${requested}`);
    }
    return normalizedRequested;
  }

  if (common.length > 1) {
    const choices = common.map((command) => `  ${command}`).join("\n");
    throw new Error(`Multiple AWS wrappers are allowed by both credential handles. Select one explicitly with --wrapper:\n${choices}`);
  }

  return common[0];
}

async function createAwsRequest(
  store: SecretStore,
  handles: AwsHandles,
  wrapper: string,
  awsArgs: string[],
  flags: Record<string, string | boolean | string[]>
): Promise<RequestRecord> {
  const action = buildAwsAction(handles, wrapper, awsArgs, flags);
  return store.createRequest(handles.secret.handle, action, getFlag(flags, "reason") || "s-gw AWS command request");
}

function buildAwsAction(
  handles: AwsHandles,
  wrapper: string,
  awsArgs: string[],
  flags: Record<string, string | boolean | string[]>
) {
  return buildEnvCommandAction({
    command: wrapper,
    args: awsArgs,
    injectEnv: handles.secret.policy.injectEnv || "AWS_SECRET_ACCESS_KEY",
    env: [{
      handle: handles.access.handle,
      injectEnv: handles.access.policy.injectEnv || "AWS_ACCESS_KEY_ID"
    }],
    workingDir: getFlag(flags, "cwd"),
    timeoutMs: numericFlag(flags, "timeout-ms", 30_000)
  });
}

function awsRequestResponse(
  request: RequestRecord,
  wrapper: string,
  awsArgs: string[],
  handles: AwsHandles
) {
  return {
    approvalRequired: request.state !== "approved",
    localApprovalCommand: request.state === "approved"
      ? undefined
      : `s-gw approve ${request.id} --mode timed-session --duration 8h --agent-scope any-agent`,
    localRunCommand: `s-gw execute ${request.id}`,
    repeatCommand: awsCommandLine("run", awsArgs, { wrapper, handles }),
    wrapper,
    secretHandle: handles.secret.handle,
    accessKeyHandle: handles.access.handle,
    request
  };
}

function awsCommandLine(
  action: "request" | "run",
  args: string[],
  options: { wrapper?: string; handles?: AwsHandles } = {}
): string {
  const parts = ["s-gw", "aws", action];
  if (options.handles) {
    parts.push("--secret-handle", options.handles.secret.handle);
    parts.push("--access-handle", options.handles.access.handle);
  }
  if (options.wrapper) {
    parts.push("--wrapper", options.wrapper);
  }
  return [...parts.map(shellArg), "--", ...args.map(shellArg)].join(" ");
}

function shellArg(value: string): string {
  const safe = process.platform === "win32"
    ? /^[A-Za-z0-9_./\\:=@+~-]+$/
    : /^[A-Za-z0-9_./:=@%+-]+$/;
  const specialPowerShellPrefix = process.platform === "win32"
    && (value.startsWith("@") || value.startsWith("~"));
  if (safe.test(value) && !specialPowerShellPrefix) {
    return value;
  }
  if (process.platform === "win32") {
    return `'${value.replaceAll("'", "''")}'`;
  }
  return `'${value.replace(/'/g, "'\\''")}'`;
}

async function handleApprovalCommand(
  store: SecretStore,
  action: string | undefined,
  target: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (action === "policy" || action === "policies") {
    await handleApprovalPolicyCommand(store, target, flags);
    return;
  }

  if (!action || action === "settings" || action === "get") {
    printJson(await store.getApprovalSettings());
    return;
  }

  if (action === "grants" || action === "list") {
    printJson(await store.listApprovalGrants());
    return;
  }

  if (action === "revoke") {
    const id = target || requireFlag(flags, "id");
    printJson(await store.revokeApprovalGrant(id));
    return;
  }

  if (action === "clear") {
    printJson(await store.clearApprovalGrants());
    return;
  }

  if (action === "set") {
    const mode = approvalMode(requireFlag(flags, "mode"));
    const duration = getFlag(flags, "duration") || getFlag(flags, "duration-ms");
    printJson(
      await store.setApprovalSettings({
        mode,
        durationMs: duration ? parseDurationMs(duration) : undefined
      })
    );
    return;
  }

  throw new Error("approval requires settings/get, grants/list, policy, revoke, clear, or set.");
}

async function handleApprovalPolicyCommand(
  store: SecretStore,
  action: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (!action || action === "list") {
    printJson(await store.listApprovalPolicyRules());
    return;
  }

  if (action === "add") {
    const duration = getFlag(flags, "duration") || getFlag(flags, "duration-ms");
    printJson(
      await store.addApprovalPolicyRule({
        name: getFlag(flags, "name"),
        enabled: !hasFlag(flags, "disabled"),
        priority: optionalNumericFlag(flags, "priority"),
        decision: approvalPolicyDecision(getFlag(flags, "decision") || "ask"),
        durationMs: duration ? parseDurationMs(duration) : undefined,
        expiresAt: getFlag(flags, "expires-at"),
        conditions: approvalPolicyConditionsFromFlags(flags)
      })
    );
    return;
  }

  if (action === "update" || action === "edit") {
    if (!approvalPolicyUpdateFlags.some((flag) => hasFlag(flags, flag))) {
      throw new Error("approval policy update needs at least one change.");
    }

    const duration = getFlag(flags, "duration") || getFlag(flags, "duration-ms");
    const conditions = approvalPolicyConditionPatchFromFlags(flags);
    printJson(
      await store.updateApprovalPolicyRule(requireFlag(flags, "id"), {
        name: hasFlag(flags, "name") ? getFlag(flags, "name") : undefined,
        enabled: hasFlag(flags, "enabled") ? true : hasFlag(flags, "disabled") ? false : undefined,
        priority: hasFlag(flags, "priority") ? optionalNumericFlag(flags, "priority") : undefined,
        decision: hasFlag(flags, "decision") ? approvalPolicyDecision(getFlag(flags, "decision") || "ask") : undefined,
        durationMs: duration ? parseDurationMs(duration) : undefined,
        expiresAt: hasFlag(flags, "clear-expiry") ? null : hasFlag(flags, "expires-at") ? getFlag(flags, "expires-at") : undefined,
        conditions
      })
    );
    return;
  }

  if (action === "arrange" || action === "organize") {
    printJson(await store.arrangeApprovalPolicyRules());
    return;
  }

  if (action === "delete" || action === "remove") {
    printJson(await store.deleteApprovalPolicyRule(requireFlag(flags, "id")));
    return;
  }

  if (action === "enable" || action === "disable") {
    const id = requireFlag(flags, "id");
    printJson(await store.setApprovalPolicyRuleEnabled(id, action === "enable"));
    return;
  }

  throw new Error("approval policy requires list, add, update, arrange, delete, enable, or disable.");
}

const approvalPolicyUpdateFlags = [
  "name",
  "enabled",
  "disabled",
  "priority",
  "decision",
  "duration",
  "duration-ms",
  "expires-at",
  "clear-expiry",
  "handle",
  "binding",
  "type",
  "provider",
  "min-severity",
  "agent",
  "action-kind",
  "command",
  "resolved-command",
  "inject-env",
  "working-dir",
  "cwd",
  "ssh-target",
  "target",
  "ssh-port",
  "port"
];

function approvalPolicyConditionsFromFlags(
  flags: Record<string, string | boolean | string[]>
): ApprovalPolicyConditions {
  return {
    handles: getFlagList(flags, "handle"),
    envBindings: approvalPolicyEnvBindingsFromFlags(flags),
    secretTypes: getFlagList(flags, "type").map(approvalPolicySecretType),
    providers: getFlagList(flags, "provider"),
    minSeverity: optionalSecretSeverity(getFlag(flags, "min-severity")),
    agents: getFlagList(flags, "agent"),
    actionKinds: getFlagList(flags, "action-kind").map(approvalPolicyActionKind),
    commands: getFlagList(flags, "command"),
    resolvedCommands: getFlagList(flags, "resolved-command"),
    injectEnvs: getFlagList(flags, "inject-env"),
    workingDirs: getFlagList(flags, "working-dir").concat(getFlagList(flags, "cwd")),
    sshTargets: getFlagList(flags, "ssh-target").concat(getFlagList(flags, "target")),
    sshPorts: getFlagList(flags, "ssh-port").concat(getFlagList(flags, "port")).map((item) => Number(item))
  };
}

function approvalPolicyConditionPatchFromFlags(
  flags: Record<string, string | boolean | string[]>
): Partial<ApprovalPolicyConditions> | undefined {
  const fields = [
    "handle",
    "binding",
    "type",
    "provider",
    "min-severity",
    "agent",
    "action-kind",
    "command",
    "resolved-command",
    "inject-env",
    "working-dir",
    "cwd",
    "ssh-target",
    "target",
    "ssh-port",
    "port"
  ];
  if (!fields.some((field) => hasFlag(flags, field))) {
    return undefined;
  }

  const patch: Partial<ApprovalPolicyConditions> = {};
  if (hasFlag(flags, "handle")) patch.handles = getFlagList(flags, "handle");
  if (hasFlag(flags, "binding")) patch.envBindings = approvalPolicyEnvBindingsFromFlags(flags);
  if (hasFlag(flags, "type")) patch.secretTypes = getFlagList(flags, "type").map(approvalPolicySecretType);
  if (hasFlag(flags, "provider")) patch.providers = getFlagList(flags, "provider");
  if (hasFlag(flags, "min-severity")) patch.minSeverity = optionalSecretSeverity(getFlag(flags, "min-severity"));
  if (hasFlag(flags, "agent")) patch.agents = getFlagList(flags, "agent");
  if (hasFlag(flags, "action-kind")) patch.actionKinds = getFlagList(flags, "action-kind").map(approvalPolicyActionKind);
  if (hasFlag(flags, "command")) patch.commands = getFlagList(flags, "command");
  if (hasFlag(flags, "resolved-command")) patch.resolvedCommands = getFlagList(flags, "resolved-command");
  if (hasFlag(flags, "inject-env")) patch.injectEnvs = getFlagList(flags, "inject-env");
  if (hasFlag(flags, "working-dir") || hasFlag(flags, "cwd")) {
    patch.workingDirs = getFlagList(flags, "working-dir").concat(getFlagList(flags, "cwd"));
  }
  if (hasFlag(flags, "ssh-target") || hasFlag(flags, "target")) {
    patch.sshTargets = getFlagList(flags, "ssh-target").concat(getFlagList(flags, "target"));
  }
  if (hasFlag(flags, "ssh-port") || hasFlag(flags, "port")) {
    patch.sshPorts = getFlagList(flags, "ssh-port").concat(getFlagList(flags, "port")).map((item) => Number(item));
  }
  return patch;
}

function approvalPolicyEnvBindingsFromFlags(
  flags: Record<string, string | boolean | string[]>
): CommandEnvBinding[] {
  const values = getFlagList(flags, "binding");
  const out: CommandEnvBinding[] = [];
  for (const value of values) {
    const index = value.indexOf("=");
    if (index <= 0 || index === value.length - 1) {
      throw new Error("--binding must look like ENV=HANDLE.");
    }
    out.push({
      injectEnv: value.slice(0, index),
      handle: value.slice(index + 1)
    });
  }
  return out;
}

function onePasswordHandleName(itemTitle: string, fieldLabel: string): string {
  return `${itemTitle} ${fieldLabel}`.trim();
}

async function handleAppCommand(
  action: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (action === "app-path") {
    const layout = getPackageLayout();
    process.stdout.write(`${process.platform === "win32" ? layout.windowsClientLauncherPath : layout.macAppPath}\n`);
    return;
  }

  if (action === "install") {
    if (process.platform !== "darwin") {
      throw new Error("app install is only available on macOS.");
    }
    printJson(installMacAppBundle());
    return;
  }

  if (action === "refresh-services") {
    if (process.platform !== "darwin") {
      throw new Error("app refresh-services is only available on macOS.");
    }
    const services = await refreshMacRuntimeServices();
    const agents = hasFlag(flags, "no-agents") ? [] : refreshManagedAgentIntegrations();
    const ok = agents.every((agent) => agent.state !== "conflict");
    printJson({ ok, services, agents });
    if (!ok) process.exitCode = 1;
    return;
  }

  if (action === "refresh-agents") {
    if (process.platform !== "darwin") {
      throw new Error("app refresh-agents is only available on macOS.");
    }
    const lockTimeoutMs = numericFlag(flags, "lock-timeout-ms", 35_000);
    const agents = refreshManagedAgentIntegrations({ lockTimeoutMs });
    const ok = agents.every((agent) => agent.state !== "conflict");
    printJson({ ok, agents });
    if (!ok) process.exitCode = 1;
    return;
  }

  if (action === "open") {
    if (process.platform === "win32") {
      printJson(
        await openWindowsClient({
          consoleUrl: getFlag(flags, "console-url"),
          port: numericFlag(flags, "port", 8718)
        })
      );
      return;
    }

    printJson(
      openMacApp({
        consoleUrl: getFlag(flags, "console-url"),
        port: numericFlag(flags, "port", 8718)
      })
    );
    return;
  }

  throw new Error("app requires app-path, install, open, refresh-services, or refresh-agents.");
}

async function handleGuardCommand(
  store: SecretStore,
  action: string | undefined,
  agent: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (!action || action === "status") {
    printJson(guardStatus());
    return;
  }

  if (action === "run") {
    await handleGuardRun(store, agent || getFlag(flags, "agent"), flags);
    return;
  }

  throw new Error("guard requires status or run.");
}

async function handleGuardRun(
  store: SecretStore,
  agent: string | undefined,
  flags: Record<string, string | boolean | string[]>
): Promise<void> {
  if (!agent) {
    throw new Error("guard run requires an agent name.");
  }

  const options = {
    agent,
    command: getFlag(flags, "command"),
    args: getFlagList(flags, "--"),
    cwd: getFlag(flags, "cwd") || process.cwd(),
    extraEnv: parseEnvFlags(getFlagList(flags, "env")),
    scrubEnv: !hasFlag(flags, "no-scrub-env"),
    allowedCommands: getFlagList(flags, "allow-command")
  };

  if (hasFlag(flags, "dry-run")) {
    const prepared = await prepareGuardedRun(store, {
      ...options,
      persist: false
    });
    printJson(prepared.plan);
    return;
  }

  const code = await runGuardedAgent(store, options);
  process.exitCode = code;
}

async function openPreferredUi(port: number, consoleUrl: string) {
  if (process.platform === "win32") {
    const opened = await openWindowsClient({ port, consoleUrl });
    return { kind: "windows-client", ...opened };
  }

  try {
    const opened = openMacApp({ port, consoleUrl });
    return { kind: "mac-app", ...opened };
  } catch {
    openBrowser(consoleUrl);
    return { kind: "web-console", consoleUrl };
  }
}

function shouldOpenUi(flags: Record<string, string | boolean | string[]>): boolean {
  if (hasFlag(flags, "no-open-console") || hasFlag(flags, "no-open-app")) return false;
  if (process.platform === "linux" && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) return false;
  return true;
}

function openBrowser(url: string): void {
  const command = process.platform === "darwin"
    ? "/usr/bin/open"
    : process.platform === "win32"
      ? trustedWindowsSystemExecutableSync("rundll32.exe")
      : "/usr/bin/xdg-open";
  const args = process.platform === "win32"
    ? [`${trustedWindowsSystemExecutableSync("url.dll")},FileProtocolHandler`, url]
    : [url];
  const child = spawn(command, args, {
    detached: true,
    env: process.platform === "win32" ? windowsSystemEnvironment() : process.env,
    stdio: "ignore",
    shell: false
  });
  child.on("error", () => undefined);
  child.unref();
}

async function waitForever(): Promise<void> {
  await new Promise<void>((resolve) => {
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
}

function isAddressInUse(error: unknown): boolean {
  return (error as { code?: string } | null)?.code === "EADDRINUSE";
}

function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function printRawSummary(summary: { stdout: string; stderr: string; exitCode: number | null; signal: NodeJS.Signals | null }): void {
  process.stdout.write(summary.stdout);
  if (summary.stderr) {
    process.stderr.write(summary.stderr);
  }
  process.exitCode = summary.exitCode ?? (summary.signal ? 1 : 0);
}

function printHelp(): void {
  process.stdout.write(`s-gw local credential gateway

Commands:
  s-gw init
  s-gw setup [--port 8718] [--passphrase-stdin] [--menubar-count pending|credentials|none] [--no-open-app] [--no-service] [--no-menubar] [--no-agents]
  s-gw status
  s-gw start [--port 8718] [--no-open-app] [--no-service] [--no-menubar]
  s-gw stop
  s-gw doctor
  s-gw update check [--force]
  s-gw update plan [--package PATH_OR_SPEC]
  s-gw update install [--package PATH_OR_SPEC] [--dry-run]
  s-gw mcp
  s-gw console [--host 127.0.0.1] [--port 8718] [--no-open]
  s-gw app app-path
  s-gw app install
  s-gw app open [--port 8718] [--console-url URL]
  s-gw app refresh-services [--no-agents]
  s-gw app refresh-agents [--lock-timeout-ms 35000]
  s-gw guard status
  s-gw guard run AGENT [--dry-run] [--command CMD] [--env KEY=VALUE] [--allow-command CMD] [--] [agent args...]
  s-gw run AGENT [--dry-run] [--command CMD] [--env KEY=VALUE] [--allow-command CMD] [--] [agent args...]
  s-gw run env-command HANDLE --command CMD --inject-env ENV [--with-env ENV=HANDLE] [--arg VALUE] [--raw]
  s-gw service install [--port 8718] [--start] [--menubar]
  s-gw service start|stop|status|uninstall
  s-gw menubar app-path
  s-gw menubar open [--port 8718] [--console-url URL] [--count pending|credentials|none] [--show] [--no-notify]
  s-gw menubar install [--port 8718] [--console-url URL] [--count pending|credentials|none] [--start] [--no-notify]
  s-gw menubar start|stop|status|uninstall
  s-gw helper open
  s-gw unlock status
  s-gw unlock keychain set --value-stdin
  s-gw unlock keychain delete
  s-gw unlock keychain repair
  s-gw secret add --name NAME --type api-token --value-stdin --inject-env ENV --allow-command CMD
  s-gw secret add-keychain --name NAME --type api-token --value-stdin --inject-env ENV --allow-command CMD [--service SERVICE]
  s-gw secret add-1password --name NAME --type api-token --ref op://vault/item/field --inject-env ENV --allow-command CMD [--verify]
  s-gw secret list
  s-gw secret delete HANDLE
  s-gw secret allow-command HANDLE [--command s-gw:ssh-session]
  s-gw secret set-inject-env HANDLE --inject-env ENV
  s-gw onepassword status
  s-gw onepassword import [--vault Dev] [--dry-run] [--include-companions] [--allow-command CMD]
  s-gw onepassword capture --text-stdin [--vault Dev] [--name NAME] [--inject-env ENV] [--allow-command CMD]
  s-gw aws plan|request|run [--wrapper CMD] [--timeout-ms 0] [--raw] -- AWS_ARGS...
  s-gw ssh request HANDLE --target user@host [--port 22] [--arg VALUE]
  s-gw ssh run HANDLE --target user@host [--port 22] [--] [remote command...]
  s-gw ssh run --request-id REQUEST_ID
  s-gw ssh close HANDLE --target user@host [--port 22]
  s-gw approval settings
  s-gw approval set --mode per-transaction|timed-session|login-session|always [--duration 15m]
  s-gw approval grants
  s-gw approval policy list
  s-gw approval policy add --name NAME --decision allow|ask|deny [--handle HANDLE] [--binding ENV=HANDLE] [--agent Codex] [--command NAME] [--resolved-command /path/to/tool] [--action-kind env_command|ssh_session] [--duration 8h]
  s-gw approval policy update --id POLICY_ID [--name NAME] [--decision allow|ask|deny] [--handle HANDLE] [--agent Codex] [--command NAME] [--resolved-command /path/to/tool] [--clear-expiry]
  s-gw approval policy arrange
  s-gw approval policy delete --id POLICY_ID
  s-gw approval policy enable|disable --id POLICY_ID
  s-gw approval revoke GRANT_ID
  s-gw approval clear
  s-gw scan-file PATH [--preview] [--backend keychain|local]
  s-gw agent list
  s-gw agent status [AGENT]
  s-gw agent install [AGENT] [--dry-run]
  s-gw agent uninstall [AGENT] [--dry-run]
  s-gw agent show AGENT [--command CMD] [--arg VALUE] [--env KEY=VALUE]
  s-gw agent codeguard-plan AGENT
  s-gw agent mcp-snippet AGENT [--command CMD] [--arg VALUE] [--env KEY=VALUE]
  s-gw request env-command HANDLE --command CMD --inject-env ENV [--with-env ENV=HANDLE] [--arg VALUE] [--args-json JSON] [--timeout-ms 0]
  s-gw requests [--state pending] [--active] [--limit 100] [--all]
  s-gw requests --recover [REQUEST_ID]
  s-gw requests cleanup [--pending-ttl-ms 86400000] [--approved-ttl-ms 3600000] [--no-dedupe]
  s-gw execute-next [--handle HANDLE] [--kind env_command|ssh_session] [--command CMD]
  s-gw store backups
  s-gw approve REQUEST_ID [--mode per-transaction|timed-session|login-session|always] [--duration 8h] [--agent-scope same-agent|any-agent]
  s-gw deny REQUEST_ID
  s-gw execute REQUEST_ID
`);
}

function printSetupHelp(): void {
  process.stdout.write(`Usage: s-gw setup [options]

Initialize the local credential store and install the requested desktop integrations.

Options:
  --port PORT                         Console port (default: 8718)
  --passphrase-stdin                  Read the unlock passphrase from stdin
  --menubar-count MODE               pending, credentials, or none
  --no-open-app                      Do not open the native app
  --no-service                       Do not install or start the console service
  --no-menubar                       Do not install or start the menu-bar helper
  --no-agents                        Do not configure detected coding agents
  -h, --help                         Show this help and exit
`);
}

async function run(): Promise<void> {
  await main();
  await printUpdateNotice();
}

async function printUpdateNotice(): Promise<void> {
  if (!process.stderr.isTTY || process.env.SGW_DISABLE_UPDATE_CHECK === "1") return;
  const command = process.argv[2];
  if (command !== "status" && command !== "doctor") return;

  const update = await releaseChecker.check();
  if (!update.available || !update.installerReady || !update.latestVersion || !update.releaseUrl) return;
  process.stderr.write(
    `\ns-gw ${update.latestVersion} is available. Run \`s-gw update check\` or visit ${update.releaseUrl}\n`
  );
}

run().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`s-gw error: ${message}\n`);
  process.exitCode = 1;
});
