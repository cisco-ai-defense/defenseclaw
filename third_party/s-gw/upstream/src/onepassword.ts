import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { resolveCommandExecutable } from "./command-path.js";
import type { SecretType } from "./types.js";

export interface OnePasswordStatus {
  available: boolean;
  command: string;
  version?: string;
  serviceAccountConfigured: boolean;
  connectConfigured: boolean;
  error?: string;
}

export interface OnePasswordSecretReference {
  vault: string;
  itemId: string;
  itemTitle: string;
  itemCategory?: string;
  fieldId: string;
  fieldLabel: string;
  fieldType?: string;
  fieldPurpose?: string;
  reference: string;
  secretType: SecretType;
  suggestedEnv?: string;
  companionFields?: OnePasswordCompanionField[];
}

export interface OnePasswordCompanionField {
  vault: string;
  itemId: string;
  itemTitle: string;
  itemCategory?: string;
  fieldId: string;
  fieldLabel: string;
  fieldType?: string;
  fieldPurpose?: string;
  reference: string;
  secretType: SecretType;
  suggestedEnv?: string;
}

export interface CreateOnePasswordSecretInput {
  vault?: string;
  title: string;
  type: SecretType;
  value: string;
  notes?: string;
}

interface OnePasswordItemSummary {
  id: string;
  title: string;
  category?: string;
}

interface OnePasswordField {
  id?: string;
  label?: string;
  type?: string;
  purpose?: string;
  reference?: string;
}

interface OnePasswordItemDetail {
  id: string;
  title: string;
  category?: string;
  fields?: OnePasswordField[];
}

export function normalizeOnePasswordReference(reference: string): string {
  const trimmed = reference.trim();
  if (!trimmed) {
    throw new Error("1Password reference is required.");
  }

  if (trimmed.includes("\0") || /[\r\n]/.test(trimmed)) {
    throw new Error("1Password reference cannot contain control characters.");
  }

  if (!/^op:\/\/[^/]+\/[^/]+\/.+/.test(trimmed)) {
    throw new Error("1Password reference must look like op://vault/item/field.");
  }

  return trimmed;
}

export function onePasswordStatus(): OnePasswordStatus {
  let requested = process.env.SGW_OP_CLI?.trim() || process.env.SGW_REAL_OP_PATH?.trim() || "op";
  let command: string;
  try {
    requested = requestedOpCommand();
    command = resolveCommandExecutable(requested);
  } catch (error) {
    return {
      available: false,
      command: requested,
      serviceAccountConfigured: Boolean(process.env.OP_SERVICE_ACCOUNT_TOKEN),
      connectConfigured: Boolean(process.env.OP_CONNECT_HOST && process.env.OP_CONNECT_TOKEN),
      error: error instanceof Error ? error.message : String(error)
    };
  }
  const result = spawnSync(command, ["--version"], {
    encoding: "utf8",
    env: onePasswordEnvironment(),
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });

  return {
    available: result.status === 0,
    command,
    version: result.status === 0 ? result.stdout.trim() : undefined,
    serviceAccountConfigured: Boolean(process.env.OP_SERVICE_ACCOUNT_TOKEN),
    connectConfigured: Boolean(process.env.OP_CONNECT_HOST && process.env.OP_CONNECT_TOKEN),
    error: result.status === 0 ? undefined : (result.stderr.trim() || result.stdout.trim() || "op CLI is not available")
  };
}

export async function listOnePasswordSecretReferences(vault = "Dev"): Promise<OnePasswordSecretReference[]> {
  const normalizedVault = normalizeVaultName(vault);
  const items = await runOpJson<OnePasswordItemSummary[]>(["item", "list", "--vault", normalizedVault, "--format", "json"]);
  const refs: OnePasswordSecretReference[] = [];

  for (const item of items) {
    if (!item.id) {
      continue;
    }

    const detail = await runOpJson<OnePasswordItemDetail>(["item", "get", item.id, "--vault", normalizedVault, "--format", "json"]);
    const fields = detail.fields || [];
    const companionFields = fields
      .map((field) => companionForField(normalizedVault, detail, field))
      .filter((field): field is OnePasswordCompanionField => Boolean(field));
    for (const field of fields) {
      const candidate = referenceForField(normalizedVault, detail, field, companionFields);
      if (candidate) {
        refs.push(candidate);
      }
    }
  }

  refs.sort((a, b) => {
    const title = a.itemTitle.localeCompare(b.itemTitle);
    if (title !== 0) {
      return title;
    }

    return a.fieldLabel.localeCompare(b.fieldLabel);
  });

  return refs;
}

export async function createOnePasswordSecretReference(
  input: CreateOnePasswordSecretInput
): Promise<OnePasswordSecretReference> {
  const vault = normalizeVaultName(input.vault || "Dev");
  const title = normalizeItemTitle(input.title);
  if (!input.value) {
    throw new Error("Cannot create an empty 1Password secret.");
  }

  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-op-create-"));
  const templatePath = path.join(tmpDir, "item.json");

  try {
    await writeFile(templatePath, JSON.stringify(onePasswordTemplate(title, input.value, input.notes), null, 2), {
      mode: 0o600
    });

    const created = await runOpJson<OnePasswordItemDetail>([
      "item",
      "create",
      "--vault",
      vault,
      "--template",
      templatePath,
      "--format",
      "json"
    ]);
    const field = (created.fields || []).find((item) => item.id === "credential" || item.label === "credential");
    if (!field) {
      throw new Error("1Password did not return the created credential field.");
    }

    const fieldId = field.id?.trim() || "credential";
    return {
      vault,
      itemId: created.id,
      itemTitle: created.title || title,
      itemCategory: created.category,
      fieldId,
      fieldLabel: field.label?.trim() || fieldId,
      fieldType: field.type,
      fieldPurpose: field.purpose,
      reference: normalizeOnePasswordReference(field.reference || buildReference(vault, created.id, fieldId)),
      secretType: input.type
    };
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

export async function readOnePasswordReference(reference: string): Promise<string> {
  const normalized = normalizeOnePasswordReference(reference);
  const command = resolveOpCommand();
  const timeoutMs = timeoutFromEnv();

  const child = spawn(command, ["read", normalized], {
    env: onePasswordEnvironment(),
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
    killTimer = setTimeout(() => child.kill("SIGKILL"), 1_500);
  }, timeoutMs);

  child.stdout?.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });

  const status = await new Promise<{ code: number | null; error?: Error }>((resolve) => {
    child.on("error", (error) => resolve({ code: null, error }));
    child.on("close", (code) => resolve({ code }));
  });
  clearTimeout(timeout);
  if (killTimer) {
    clearTimeout(killTimer);
  }

  if (timedOut) {
    throw new Error(`Timed out reading 1Password reference after ${timeoutMs}ms.`);
  }

  if (status.error) {
    throw new Error(`Failed to run ${command}: ${status.error.message}`);
  }

  if (status.code !== 0) {
    const message = stderr.trim() || stdout.trim() || `${command} read failed.`;
    throw new Error(`1Password read failed: ${message}`);
  }

  if (!stdout) {
    throw new Error("1Password returned an empty secret.");
  }

  return stdout.replace(/\r?\n$/, "");
}

async function runOpJson<T>(args: string[], input?: string): Promise<T> {
  const output = await runOp(args, input);
  try {
    return JSON.parse(output) as T;
  } catch (error) {
    throw new Error(`1Password returned invalid JSON for op ${args.join(" ")}.`);
  }
}

async function runOp(args: string[], input?: string): Promise<string> {
  const command = resolveOpCommand();
  const timeoutMs = timeoutFromEnv();
  const child = spawn(command, args, {
    env: onePasswordEnvironment(),
    shell: false,
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
    killTimer = setTimeout(() => child.kill("SIGKILL"), 1_500);
  }, timeoutMs);

  if (input !== undefined && child.stdin) {
    child.stdin.end(input);
  }

  child.stdout?.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });

  const status = await new Promise<{ code: number | null; error?: Error }>((resolve) => {
    child.on("error", (error) => resolve({ code: null, error }));
    child.on("close", (code) => resolve({ code }));
  });
  clearTimeout(timeout);
  if (killTimer) {
    clearTimeout(killTimer);
  }

  if (timedOut) {
    throw new Error(`Timed out running 1Password CLI after ${timeoutMs}ms.`);
  }

  if (status.error) {
    throw new Error(`Failed to run ${command}: ${status.error.message}`);
  }

  if (status.code !== 0) {
    const message = stderr.trim() || stdout.trim() || `${command} ${args.join(" ")} failed.`;
    throw new Error(`1Password command failed: ${message}`);
  }

  return stdout;
}

function resolveOpCommand(): string {
  return resolveCommandExecutable(requestedOpCommand());
}

function requestedOpCommand(): string {
  const configured = process.env.SGW_OP_CLI?.trim();
  if (configured) return configured;

  const testCommand = process.env.SGW_REAL_OP_PATH?.trim();
  if (testCommand) {
    if (process.env.SGW_TEST_MODE !== "1") {
      throw new Error("SGW_REAL_OP_PATH is restricted to isolated s-gw tests; use SGW_OP_CLI for a custom 1Password CLI path.");
    }
    return testCommand;
  }
  return "op";
}

function onePasswordEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of [
    "APPDATA",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "NO_COLOR",
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "USER",
    "USERNAME",
    "USERPROFILE",
    "WINDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR"
  ]) {
    const value = process.env[key];
    if (value) env[key] = value;
  }
  for (const [key, value] of Object.entries(process.env)) {
    if (key.startsWith("OP_") && value) env[key] = value;
  }
  if (process.env.SGW_TEST_MODE === "1" && process.env.NODE_OPTIONS) {
    env.NODE_OPTIONS = process.env.NODE_OPTIONS;
  }
  return env;
}

function onePasswordTemplate(title: string, value: string, notes?: string) {
  return {
    title,
    category: "API_CREDENTIAL",
    fields: [
      {
        id: "notesPlain",
        type: "STRING",
        purpose: "NOTES",
        label: "notesPlain",
        value: notes || "Created by s-gw."
      },
      {
        id: "username",
        type: "STRING",
        label: "username",
        value: ""
      },
      {
        id: "credential",
        type: "CONCEALED",
        label: "credential",
        value
      },
      {
        id: "type",
        type: "MENU",
        label: "type",
        value: "API Key"
      },
      {
        id: "filename",
        type: "STRING",
        label: "filename",
        value: ""
      },
      {
        id: "validFrom",
        type: "DATE",
        label: "valid from",
        value: ""
      },
      {
        id: "expires",
        type: "DATE",
        label: "expires",
        value: ""
      },
      {
        id: "hostname",
        type: "STRING",
        label: "hostname",
        value: ""
      }
    ]
  };
}

function referenceForField(
  vault: string,
  item: OnePasswordItemDetail,
  field: OnePasswordField,
  companionFields: OnePasswordCompanionField[] = []
): OnePasswordSecretReference | undefined {
  const label = field.label?.trim() || field.id?.trim() || "";
  const id = field.id?.trim() || label;
  if (!id || !isSecretLikeField(field, label)) {
    return undefined;
  }

  const reference = normalizeOnePasswordReference(field.reference || buildReference(vault, item.id, id));
  return {
    vault,
    itemId: item.id,
    itemTitle: item.title,
    itemCategory: item.category,
    fieldId: id,
    fieldLabel: label || id,
    fieldType: field.type,
    fieldPurpose: field.purpose,
    reference,
    secretType: secretTypeFor(item, field, label),
    suggestedEnv: suggestedEnvForField(item, field, label, true),
    companionFields: companionFields.filter((companion) => companion.fieldId !== id)
  };
}

function companionForField(
  vault: string,
  item: OnePasswordItemDetail,
  field: OnePasswordField
): OnePasswordCompanionField | undefined {
  const label = field.label?.trim() || field.id?.trim() || "";
  const id = field.id?.trim() || label;
  if (!id || !isCompanionField(item, field, label)) {
    return undefined;
  }

  const reference = normalizeOnePasswordReference(field.reference || buildReference(vault, item.id, id));
  return {
    vault,
    itemId: item.id,
    itemTitle: item.title,
    itemCategory: item.category,
    fieldId: id,
    fieldLabel: label || id,
    fieldType: field.type,
    fieldPurpose: field.purpose,
    reference,
    secretType: companionSecretTypeFor(item, field, label),
    suggestedEnv: suggestedEnvForField(item, field, label, false)
  };
}

function normalizeItemTitle(title: string): string {
  const trimmed = title.trim();
  if (!trimmed || trimmed.includes("\0") || /[\r\n]/.test(trimmed)) {
    throw new Error("1Password item title is required.");
  }

  return trimmed.slice(0, 180);
}

function isSecretLikeField(field: OnePasswordField, label: string): boolean {
  const type = field.type?.toUpperCase() || "";
  const purpose = field.purpose?.toUpperCase() || "";
  const visibleLabel = label.toLowerCase();

  if (type === "OTP") {
    return false;
  }

  if (type === "CONCEALED" || purpose === "PASSWORD") {
    return true;
  }

  return /(password|passphrase|token|secret|credential|api.?key|access.?key|private.?key|client.?secret)/i.test(visibleLabel);
}

function isCompanionField(item: OnePasswordItemDetail, field: OnePasswordField, label: string): boolean {
  const type = field.type?.toUpperCase() || "";
  if (type === "OTP" || type === "CONCEALED" || isSecretLikeField(field, label)) {
    return false;
  }

  const visibleLabel = `${item.title} ${item.category || ""} ${label} ${field.id || ""}`.toLowerCase();
  return /(username|user name|access.?key.?id|key.?id|account.?id|client.?id|tenant.?id)/i.test(visibleLabel);
}

function secretTypeFor(item: OnePasswordItemDetail, field: OnePasswordField, label: string): SecretType {
  const text = `${item.title} ${item.category || ""} ${label} ${field.id || ""}`.toLowerCase();

  if (text.includes("private key") || text.includes("ssh")) {
    return "private-key";
  }

  if (text.includes("password") || text.includes("passphrase")) {
    return "password";
  }

  if (text.includes("access key")) {
    return "access-key";
  }

  if (text.includes("token") || text.includes("api key") || text.includes("apikey")) {
    return "api-token";
  }

  if (text.includes("credential") || text.includes("secret")) {
    return "credential";
  }

  return "unknown";
}

function companionSecretTypeFor(item: OnePasswordItemDetail, field: OnePasswordField, label: string): SecretType {
  const text = `${item.title} ${item.category || ""} ${label} ${field.id || ""}`.toLowerCase();
  if (text.includes("access key") || text.includes("aws")) {
    return "access-key";
  }
  if (text.includes("client id") || text.includes("username") || text.includes("user name")) {
    return "credential";
  }

  return "unknown";
}

function suggestedEnvForField(
  item: OnePasswordItemDetail,
  field: OnePasswordField,
  label: string,
  secretField: boolean
): string | undefined {
  const text = `${item.title} ${item.category || ""} ${label} ${field.id || ""}`.toLowerCase();
  if (text.includes("aws")) {
    return secretField ? "AWS_SECRET_ACCESS_KEY" : "AWS_ACCESS_KEY_ID";
  }
  if (secretField && /(token|api.?key)/i.test(text)) {
    return "API_TOKEN";
  }

  return undefined;
}

function buildReference(vault: string, itemId: string, fieldId: string): string {
  return `op://${encodeRefSegment(vault)}/${encodeRefSegment(itemId)}/${encodeRefSegment(fieldId)}`;
}

function encodeRefSegment(value: string): string {
  return value.replaceAll("/", "%2F");
}

function normalizeVaultName(vault: string): string {
  const trimmed = vault.trim();
  if (!trimmed || trimmed.includes("\0") || /[\r\n]/.test(trimmed)) {
    throw new Error("1Password vault name is required.");
  }

  return trimmed;
}

function timeoutFromEnv(): number {
  const raw = process.env.SGW_ONEPASSWORD_TIMEOUT_MS;
  if (!raw) {
    return 30_000;
  }

  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 30_000;
  }

  return Math.min(Math.floor(parsed), 300_000);
}
