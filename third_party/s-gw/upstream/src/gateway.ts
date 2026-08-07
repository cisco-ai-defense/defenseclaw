import { readFile } from "node:fs/promises";
import path from "node:path";
import { createOnePasswordSecretReference } from "./onepassword.js";
import { SecretStore } from "./store.js";
import { previewHandle, scanText } from "./scanner.js";
import { buildSshSessionAction } from "./ssh.js";
import type { CommandAction, CommandEnvBinding, ScanCandidate, ScanResult, SecretPolicy, SecretType } from "./types.js";
import type { AddKeychainSecretInput, AddSecretInput } from "./store.js";
import { keychainInfo } from "./unlock.js";

export type LocalSecretBackend = "local" | "keychain";

export interface ScanOptions {
  persist?: boolean;
  source?: string;
  defaultName?: string;
  backend?: LocalSecretBackend;
}

export interface OnePasswordScanOptions {
  vault?: string;
  source?: string;
  defaultName?: string;
  policy?: Partial<SecretPolicy>;
}

export async function scanLocalText(
  store: SecretStore,
  text: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const persist = options.persist === true;
  const backend = options.backend || "local";

  return scanText(text, async (candidate: ScanCandidate) => {
    if (!persist) {
      return previewHandle(candidate);
    }

    const record = await addLocalSecret(store, {
      name: nameForCandidate(candidate, options.defaultName),
      type: candidate.type,
      provider: candidate.provider,
      ruleId: candidate.ruleId,
      severity: candidate.severity,
      confidence: candidate.confidence,
      value: candidate.value,
      source: options.source,
      policy: {
        allowedCommands: [],
        maxOutputBytes: 16_384
      }
    }, backend);

    return record.handle;
  });
}

export async function addLocalSecret(
  store: SecretStore,
  input: AddSecretInput & Pick<AddKeychainSecretInput, "service">,
  backend: LocalSecretBackend = "local"
) {
  if (backend === "keychain") {
    return store.addKeychainSecret(input);
  }

  return store.addSecret(input);
}

export function preferredLocalSecretBackend(): LocalSecretBackend {
  const configured = process.env.SGW_SECRET_BACKEND?.trim().toLowerCase();
  if (configured === "local" || configured === "keychain") {
    return configured;
  }

  if (
    process.platform === "linux"
    && typeof process.env.SGW_MASTER_PASSPHRASE === "string"
    && process.env.SGW_MASTER_PASSPHRASE.trim().length >= 8
  ) {
    return "local";
  }

  if (
    (process.platform === "darwin" || process.platform === "linux" || process.platform === "win32")
    && process.env.SGW_DISABLE_KEYCHAIN !== "1"
    && keychainInfo().provider !== "none"
  ) {
    return "keychain";
  }

  return "local";
}

export async function scanTextToOnePassword(
  store: SecretStore,
  text: string,
  options: OnePasswordScanOptions = {}
): Promise<ScanResult> {
  const vault = options.vault || "Dev";

  return scanText(text, async (candidate: ScanCandidate) => {
    const title = onePasswordTitleForCandidate(candidate, options.defaultName);
    const created = await createOnePasswordSecretReference({
      vault,
      title,
      type: candidate.type,
      value: candidate.value,
      notes: onePasswordNotes(options.source)
    });
    const record = await store.addOnePasswordReference({
      name: title,
      type: candidate.type,
      reference: created.reference,
      source: `onepassword:${vault}`,
      policy: options.policy || {
        allowedCommands: [],
        maxOutputBytes: 16_384
      }
    });

    return record.handle;
  });
}

export async function scanLocalFile(
  store: SecretStore,
  filePath: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const resolved = path.resolve(filePath);
  const text = await readFile(resolved, "utf8");
  return scanLocalText(store, text, {
    persist: options.persist ?? true,
    source: resolved,
    defaultName: options.defaultName || path.basename(resolved),
    backend: options.backend
  });
}

function onePasswordTitleForCandidate(candidate: ScanCandidate, defaultName?: string): string {
  const base = defaultName?.trim() || `s-gw captured ${candidate.label || friendlyType(candidate.type)}`;
  const stamp = new Date().toISOString().replace(/[-:.]/g, "").slice(0, 15);
  return `${base} ${stamp}-${candidate.start}`;
}

function onePasswordNotes(source?: string): string {
  const suffix = source ? ` Source: ${source}` : "";
  return `Created by s-gw from a credential capture.${suffix}`;
}

export function buildEnvCommandAction(input: {
  command: string;
  args?: string[];
  injectEnv: string;
  env?: CommandEnvBinding[];
  workingDir?: string;
  timeoutMs?: number;
}): CommandAction {
  return {
    kind: "env_command",
    command: input.command,
    args: input.args || [],
    injectEnv: input.injectEnv,
    env: input.env,
    workingDir: input.workingDir,
    timeoutMs: input.timeoutMs ?? 30_000
  };
}

function nameForCandidate(candidate: ScanCandidate, defaultName?: string): string {
  const prefix = defaultName ? `${defaultName} ` : "";
  return `${prefix}${candidate.label || friendlyType(candidate.type)} ${candidate.start}`;
}

function friendlyType(type: SecretType): string {
  if (type === "api-token") {
    return "API token";
  }

  if (type === "private-key") {
    return "private key";
  }

  return type;
}

export { buildSshSessionAction };
