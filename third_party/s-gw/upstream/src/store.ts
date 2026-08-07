import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, chmod, lstat, mkdir, open, readFile, readdir, rename, rm, rmdir, stat, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { decryptSecret, encryptSecret, fingerprintSecret, shortId } from "./crypto.js";
import { agentNameFromReason, requestAgentIdentity, requestAgentName, type AgentIdentity, type AgentIdentityContext } from "./agent-context.js";
import { isAbsoluteCommand, resolveCommandExecutable, verifyPinnedCommand } from "./command-path.js";
import { normalizeOnePasswordReference, readOnePasswordReference } from "./onepassword.js";
import { arrangeApprovalPolicyRules as arrangePolicyRules, compareApprovalPolicyRules } from "./policy-order.js";
import { SGW_SSH_SESSION_COMMAND, normalizeSshPort, normalizeSshTarget, sshSessionIdentity } from "./ssh.js";
import { ensureSgwHome, getSgwHome, getSgwLoginSessionId, getSgwRecoveryHome, getStorePath } from "./paths.js";
import {
  defaultSecretKeychainService,
  deleteMacKeychainItem,
  getMacKeychainItem,
  repairMacKeychainItemAccess,
  setMacKeychainItem,
  type MacKeychainItemRef
} from "./unlock.js";
import type {
  ApprovalGrant,
  ApprovalAgentScope,
  ApprovalMode,
  ApprovalPolicyActionKind,
  ApprovalPolicyConditions,
  ApprovalPolicyDecision,
  ApprovalPolicyRule,
  ApprovalSettings,
  AgentIdentitySource,
  AuditEvent,
  CommandAction,
  CommandEnvBinding,
  ExecutionSummary,
  HandleSummary,
  RequestRecord,
  RequestState,
  SecretPolicy,
  SecretRecord,
  SecretSeverity,
  SecretType,
  SecretValueCache,
  StoreFile
} from "./types.js";

const defaultApprovalSettings: ApprovalSettings = {
  mode: "per-transaction",
  durationMs: 15 * 60 * 1000
};

const maxApprovalDurationMs = 30 * 24 * 60 * 60 * 1000;
// Concurrent clients may need to serialize a durable control-plane write on a slow disk.
const lockTimeoutMs = 30_000;
const windowsLockRenameAttempts = 20;
const windowsLockRenameDelayMs = 10;
const emptyStoreLockStaleMs = 1_000;

// A request gets claimed into "executing" right before its secret is revealed. If the
// runner is killed, sleeps, or crashes before markExecuted/markFailed, that request is
// stranded. Anything still "executing" past this window almost certainly lost its runner,
// so we reap it back to a terminal failed state instead of bricking it forever.
const staleExecutionMs = 10 * 60 * 1000;
const maxStoreBackups = 20;
const requestBackupIntervalMs = 5 * 60 * 1000;
const storeMarkerName = ".store-initialized";
const controlStateName = ".store-control.json";
const pendingControlStateName = ".store-control.pending.json";
const reusableExecutionPermits = new WeakMap<object, string>();
const approvalPolicyConditionFields: Array<keyof ApprovalPolicyConditions> = [
  "handles",
  "envBindings",
  "secretTypes",
  "providers",
  "minSeverity",
  "agents",
  "actionKinds",
  "commands",
  "resolvedCommands",
  "injectEnvs",
  "workingDirs",
  "sshTargets",
  "sshPorts"
];

const emptyStore = (): StoreFile => ({
  version: 1,
  secrets: [],
  requests: [],
  audit: [],
  approvalSettings: { ...defaultApprovalSettings },
  approvalGrants: [],
  approvalPolicyRules: []
});

export interface AddSecretInput {
  name: string;
  type: SecretType;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  value: string;
  source?: string;
  policy?: Partial<SecretPolicy>;
}

export interface AddOnePasswordReferenceInput {
  name: string;
  type: SecretType;
  reference: string;
  source?: string;
  policy?: Partial<SecretPolicy>;
}

export interface AddKeychainSecretInput extends AddSecretInput {
  service?: string;
}

export interface SetApprovalSettingsInput {
  mode: ApprovalMode;
  durationMs?: number;
}

export interface AddApprovalPolicyRuleInput {
  name?: string;
  enabled?: boolean;
  priority?: number;
  decision: ApprovalPolicyDecision;
  conditions?: Partial<ApprovalPolicyConditions>;
  expiresAt?: string;
  durationMs?: number;
}

export interface UpdateApprovalPolicyRuleInput {
  name?: string;
  enabled?: boolean;
  priority?: number;
  decision?: ApprovalPolicyDecision;
  conditions?: Partial<ApprovalPolicyConditions>;
  expiresAt?: string | null;
  durationMs?: number;
}

export interface SetApprovalPolicyRuleEnabledResult {
  id: string;
  enabled: boolean;
}

export interface ArrangeApprovalPolicyRulesResult {
  rules: ApprovalPolicyRule[];
  reordered: number;
}

export interface ApproveRequestWithPolicyResult {
  request: RequestRecord;
  rule: ApprovalPolicyRule;
  created: boolean;
}

export interface ApproveRequestOptions {
  mode?: ApprovalMode;
  durationMs?: number;
  agentScope?: ApprovalAgentScope;
}

export interface DeleteSecretResult {
  handle: string;
  name: string;
  revokedApprovalGrants: number;
  revokedApprovalPolicies: number;
  failedRequests: RequestRecord[];
}

export interface ClearApprovalGrantsResult {
  revokedCount: number;
  revoked: ApprovalGrant[];
}

export interface RequestListOptions {
  state?: RequestState;
  active?: boolean;
  limit?: number;
}

export interface CleanupRequestsOptions {
  pendingOlderThanMs?: number;
  approvedOlderThanMs?: number;
  duplicatePending?: boolean;
}

export interface CleanupRequestsResult {
  cleanedCount: number;
  requests: RequestRecord[];
}

export interface StoreBackupSummary {
  path: string;
  bytes: number;
  modifiedAt: string;
}

export interface ReusableExecutionPermit {
  id: string;
  handle: string;
  reason: string;
  agentName: string;
  agentSource: AgentIdentitySource;
  action: CommandAction;
  createdAt: string;
  controlFingerprint: string;
  authorization: {
    kind: "grant" | "policy";
    id: string;
  };
}

export type OneShotExecutionAdmission =
  | { kind: "reusable"; permit: ReusableExecutionPermit }
  | { kind: "request"; request: RequestRecord };

export interface ExecutionLaunch<T> {
  completion: Promise<T>;
}

export interface KeychainAccessRepairSummary {
  checked: number;
  alreadyBound: number;
  migrated: number;
  recovered: number;
  missing: number;
  unsupported: number;
  failed: Array<{ handle: string; name: string; error: string }>;
}

interface StoreControlState {
  version: 1;
  fingerprint: string;
  updatedAt: string;
  secrets: number;
  approvalPolicyRules: number;
  recoverySealed?: true;
  recoveryCheckpoint?: string;
  recoveryVaultId?: string;
  recoveryNamespace?: string;
}

interface PendingStoreControlState {
  version: 1;
  previousFingerprint?: string;
  nextFingerprint: string;
  createdAt: string;
}

interface RecoveryCandidate {
  path: string;
  modifiedAtMs: number;
}

interface StoreRevision {
  storeText?: string;
  storeHash?: string;
  controlStateHash?: string;
  pendingStateHash?: string;
  manifestFingerprint?: string;
}

interface StoreLock {
  assertOwned(): Promise<void>;
}

interface StoreLockState {
  version: 1;
  pid: number;
  token: string;
  createdAt: string;
}

interface StoreLockInspection {
  state?: StoreLockState;
  markerPath?: string;
  empty?: boolean;
  modifiedAtMs?: number;
}

interface SealedControlPlaneCheckpoint extends RecoveryCandidate {
  fingerprint: string;
  sequence: number;
}

interface ControlPlaneHead {
  version: 1;
  checkpoint: string;
  fingerprint: string;
}

interface VerifiedRecoveryCandidate extends RecoveryCandidate {
  fingerprint: string;
}

export class SecretStore {
  readonly home: string;
  readonly storePath: string;

  constructor(home = getSgwHome()) {
    this.home = home;
    this.storePath = getStorePath(home);
  }

  async init(): Promise<void> {
    await ensureSgwHome(this.home);
    await this.withStoreLock(async (lock) => {
      await this.loadOrRecoverUnlocked(lock);
    });
  }

  async addSecret(input: AddSecretInput): Promise<SecretRecord> {
    if (!input.value) {
      throw new Error("Cannot add an empty secret.");
    }

    return this.mutate(async (store) => {
      const fingerprint = fingerprintSecret(input.value);
      const now = new Date().toISOString();
      const existing = store.secrets.find((secret) => secret.fingerprint === fingerprint);
      if (existing) {
        existing.updatedAt = now;
        existing.name = input.name || existing.name;
        existing.type = input.type || existing.type;
        existing.provider = input.provider || existing.provider;
        existing.backend = existing.backend || "local";
        existing.ruleId = input.ruleId || existing.ruleId;
        existing.severity = input.severity || existing.severity;
        existing.confidence = input.confidence ?? existing.confidence;
        existing.source = input.source || existing.source;
        existing.policy = normalizePolicy(input.policy, existing.policy);
        store.audit.push(audit("secret.matched", `Existing handle reused for ${existing.name}.`, existing.handle));
        return existing;
      }

      const record: SecretRecord = {
        handle: makeHandle(input.type),
        name: input.name,
        type: input.type,
        backend: "local",
        provider: input.provider,
        ruleId: input.ruleId,
        severity: input.severity,
        confidence: input.confidence,
        createdAt: now,
        updatedAt: now,
        source: input.source,
        fingerprint,
        encrypted: encryptSecret(input.value),
        policy: normalizePolicy(input.policy)
      };

      store.secrets.push(record);
      store.audit.push(audit("secret.added", `Added local handle for ${record.name}.`, record.handle));
      return record;
    });
  }

  async addKeychainSecret(input: AddKeychainSecretInput): Promise<SecretRecord> {
    if (!input.value) {
      throw new Error("Cannot add an empty secret.");
    }

    return this.mutate(async (store) => {
      const fingerprint = fingerprintSecret(input.value);
      const now = new Date().toISOString();
      const existing = store.secrets.find((secret) => secret.fingerprint === fingerprint);
      const handle = existing?.handle || makeHandle(input.type);
      const ref: MacKeychainItemRef = {
        service: input.service || defaultSecretKeychainService(),
        account: handle,
        label: keychainSecretLabel(input.name || existing?.name || handle)
      };

      setMacKeychainItem(ref, input.value);

      const encryptedRef = encryptSecret(JSON.stringify(keychainRefPayload(ref)));
      if (existing) {
        existing.updatedAt = now;
        existing.name = input.name || existing.name;
        existing.type = input.type || existing.type;
        existing.backend = "keychain";
        existing.provider = credentialStoreProvider();
        existing.ruleId = input.ruleId || existing.ruleId;
        existing.severity = input.severity || existing.severity;
        existing.confidence = input.confidence ?? existing.confidence;
        existing.source = input.source || existing.source || credentialStoreProvider();
        existing.encrypted = encryptedRef;
        existing.policy = normalizePolicy(input.policy, existing.policy);
        delete existing.cache;
        store.audit.push(audit("secret.matched", `Existing handle moved to OS credential store for ${existing.name}.`, existing.handle));
        return existing;
      }

      const record: SecretRecord = {
        handle,
        name: input.name,
        type: input.type,
        backend: "keychain",
        provider: credentialStoreProvider(),
        ruleId: input.ruleId,
        severity: input.severity,
        confidence: input.confidence,
        createdAt: now,
        updatedAt: now,
        source: input.source || credentialStoreProvider(),
        fingerprint,
        encrypted: encryptedRef,
        policy: normalizePolicy(input.policy)
      };

      store.secrets.push(record);
      store.audit.push(audit("secret.added", `Added OS credential-store-backed handle for ${record.name}.`, record.handle));
      return record;
    });
  }

  async addOnePasswordReference(input: AddOnePasswordReferenceInput): Promise<SecretRecord> {
    const reference = normalizeOnePasswordReference(input.reference);
    return this.mutate(async (store) => {
      const fingerprint = fingerprintSecret(`onepassword:${reference}`);
      const now = new Date().toISOString();
      const existing = store.secrets.find((secret) => secret.fingerprint === fingerprint);
      if (existing) {
        existing.updatedAt = now;
        existing.name = input.name || existing.name;
        existing.type = input.type || existing.type;
        existing.backend = "onepassword";
        existing.provider = "1password";
        existing.source = input.source || existing.source || "onepassword";
        existing.policy = normalizePolicy(input.policy, existing.policy);
        store.audit.push(audit("secret.matched", `Existing 1Password handle reused for ${existing.name}.`, existing.handle));
        return existing;
      }

      const record: SecretRecord = {
        handle: makeHandle(input.type),
        name: input.name,
        type: input.type,
        backend: "onepassword",
        provider: "1password",
        severity: "medium",
        confidence: 1,
        createdAt: now,
        updatedAt: now,
        source: input.source || "onepassword",
        fingerprint,
        encrypted: encryptSecret(reference),
        policy: normalizePolicy(input.policy)
      };

      store.secrets.push(record);
      store.audit.push(audit("secret.added", `Added 1Password-backed handle for ${record.name}.`, record.handle));
      return record;
    });
  }

  async listHandles(): Promise<HandleSummary[]> {
    const store = await this.read();
    return store.secrets.map((secret) => summarizeSecret(secret));
  }

  async getHandle(handle: string): Promise<HandleSummary | undefined> {
    const store = await this.read();
    const found = store.secrets.find((secret) => secret.handle === handle);
    return found ? summarizeSecret(found) : undefined;
  }

  async allowCommand(handle: string, command: string): Promise<HandleSummary> {
    const trimmed = command.trim();
    if (!trimmed) {
      throw new Error("Command is required.");
    }

    return this.mutate((store) => {
      const secret = store.secrets.find((item) => item.handle === handle);
      if (!secret) {
        throw new Error(`Unknown secret handle: ${handle}`);
      }

      const allowed = new Set(secret.policy.allowedCommands || []);
      allowed.add(trimmed);
      secret.policy = normalizePolicy({ allowedCommands: [...allowed] }, secret.policy);
      secret.updatedAt = new Date().toISOString();
      store.audit.push(audit("secret.policy.updated", `Allowed ${trimmed} for ${secret.name}.`, handle));
      return summarizeSecret(secret);
    });
  }

  async setInjectEnv(handle: string, injectEnv: string): Promise<HandleSummary> {
    const trimmed = injectEnv.trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed)) {
      throw new Error(`Invalid environment variable name: ${trimmed || "(empty)"}`);
    }

    return this.mutate((store) => {
      const secret = store.secrets.find((item) => item.handle === handle);
      if (!secret) {
        throw new Error(`Unknown secret handle: ${handle}`);
      }

      secret.policy = normalizePolicy({ injectEnv: trimmed }, secret.policy);
      secret.updatedAt = new Date().toISOString();
      store.audit.push(audit("secret.policy.updated", `Set inject environment to ${trimmed} for ${secret.name}.`, handle));
      return summarizeSecret(secret);
    });
  }

  async getSecretRecord(handle: string): Promise<SecretRecord> {
    const store = await this.read();
    const found = store.secrets.find((secret) => secret.handle === handle);
    if (!found) {
      throw new Error(`Unknown secret handle: ${handle}`);
    }

    return found;
  }

  async revealSecretForLocalUse(
    handle: string,
    request?: RequestRecord,
    options: { cache?: boolean } = {}
  ): Promise<string> {
    const record = await this.getSecretRecord(handle);
    if (record.backend === "onepassword") {
      const cached = cachedOnePasswordValue(record, request);
      if (cached) {
        return cached;
      }

      const reference = decryptSecret(record.encrypted);
      const value = await readOnePasswordReference(reference);
      if (options.cache !== false) {
        await this.storeOnePasswordCache(handle, value, request);
      }
      return value;
    }

    if (record.backend === "keychain") {
      return getMacKeychainItem(keychainRefFromRecord(record));
    }

    return decryptSecret(record.encrypted);
  }

  async repairKeychainAccess(): Promise<KeychainAccessRepairSummary> {
    const store = await this.read();
    const result: KeychainAccessRepairSummary = {
      checked: 0,
      alreadyBound: 0,
      migrated: 0,
      recovered: 0,
      missing: 0,
      unsupported: 0,
      failed: []
    };

    for (const record of store.secrets) {
      if (record.backend !== "keychain") continue;
      result.checked += 1;

      try {
        const repair = repairMacKeychainItemAccess(keychainRefFromRecord(record));
        if (repair.state === "already-bound") result.alreadyBound += 1;
        else if (repair.state === "migrated") result.migrated += 1;
        else if (repair.state === "recovered") result.recovered += 1;
        else if (repair.state === "missing") result.missing += 1;
        else result.unsupported += 1;
      } catch (error) {
        result.failed.push({
          handle: record.handle,
          name: record.name,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }

    return result;
  }

  private async storeOnePasswordCache(handle: string, value: string, request?: RequestRecord): Promise<void> {
    if (!request || !value) {
      return;
    }

    await this.mutate((store) => {
      const now = new Date().toISOString();
      pruneExpiredApprovalGrants(store, now);
      const secret = store.secrets.find((item) => item.handle === handle && item.backend === "onepassword");
      const primary = store.secrets.find((item) => item.handle === request.handle);
      const policyRule = request.approvalPolicyRuleId && primary
        ? matchingApprovalPolicyRuleForAction(store, primary, request.action, request.agentName || requestAgentName(request.reason), now)
        : undefined;
      const policyAuthorized = Boolean(
        policyRule?.decision === "allow" &&
        policyRule.id === request.approvalPolicyRuleId &&
        requestReferencesHandle(request, handle)
      );
      const grant = policyAuthorized ? undefined : store.approvalGrants.find((item) => {
        return item.id === request.approvalGrantId && requestReferencesHandle(request, handle);
      });
      if (!secret || (!policyAuthorized && (!grant || !grantAllowsCache(grant, now)))) {
        return;
      }

      const existing = secret.cache;
      const approvalGrantId = grant?.id;
      const approvalPolicyRuleId = policyAuthorized ? policyRule?.id : undefined;
      const sameAuthority = existing?.approvalGrantId === approvalGrantId &&
        existing?.approvalPolicyRuleId === approvalPolicyRuleId;
      secret.cache = {
        backend: "onepassword",
        encrypted: encryptSecret(value),
        fingerprint: fingerprintSecret(`onepassword-cache:${value}`),
        approvalGrantId,
        approvalPolicyRuleId,
        createdAt: sameAuthority && existing ? existing.createdAt : now,
        updatedAt: now,
        expiresAt: grant?.expiresAt || policyRule?.expiresAt,
        loginSessionId: grant?.mode === "always" ? undefined : grant?.loginSessionId
      };
      secret.updatedAt = now;
      store.audit.push(audit("secret.cache.updated", `Cached 1Password value for ${secret.name}.`, handle, request.id));
    });
  }

  async deleteSecret(handle: string): Promise<DeleteSecretResult> {
    return this.mutate((store) => {
      const index = store.secrets.findIndex((secret) => secret.handle === handle);
      if (index < 0) {
        throw new Error(`Unknown secret handle: ${handle}`);
      }

      const deleted = store.secrets[index];
      if (deleted.backend === "keychain") {
        deleteMacKeychainItem(keychainRefFromRecord(deleted));
      }
      store.secrets.splice(index, 1);

      const beforeGrants = store.approvalGrants.length;
      const beforePolicies = (store.approvalPolicyRules || []).length;
      const requestsById = new Map(store.requests.map((request) => [request.id, request]));
      store.approvalGrants = store.approvalGrants.filter((grant) => {
        if (grant.handle === handle) {
          return false;
        }

        const request = grant.lastRequestId ? requestsById.get(grant.lastRequestId) : undefined;
        return !request || !requestReferencesHandle(request, handle);
      });
      store.approvalPolicyRules = (store.approvalPolicyRules || []).filter((rule) => {
        return !(rule.conditions.handles || []).includes(handle) &&
          !(rule.conditions.envBindings || []).some((binding) => binding.handle === handle);
      });
      clearOnePasswordPolicyCaches(store);

      const now = new Date().toISOString();
      const failedRequests: RequestRecord[] = [];
      for (const request of store.requests) {
        if (!requestReferencesHandle(request, handle) || isTerminalRequestState(request.state)) {
          continue;
        }

        request.state = "failed";
        request.updatedAt = now;
        request.error = "Credential handle was deleted before the request completed.";
        failedRequests.push(request);
        store.audit.push(
          audit("request.failed", `Request ${request.id} failed because credential ${handle} was deleted.`, handle, request.id)
        );
      }

      store.audit.push(audit("secret.deleted", `Deleted credential handle for ${deleted.name}.`, handle));
      return {
        handle,
        name: deleted.name,
        revokedApprovalGrants: beforeGrants - store.approvalGrants.length,
        revokedApprovalPolicies: beforePolicies - store.approvalPolicyRules.length,
        failedRequests
      };
    });
  }

  async getApprovalSettings(): Promise<ApprovalSettings> {
    const store = await this.read();
    return normalizeApprovalSettings(store.approvalSettings);
  }

  async setApprovalSettings(input: SetApprovalSettingsInput): Promise<ApprovalSettings> {
    return this.mutate((store) => {
      const settings = normalizeApprovalSettings(input);
      store.approvalSettings = settings;
      store.approvalGrants = [];
      clearOnePasswordCaches(store);
      store.audit.push(audit("approval.settings.updated", `Approval mode changed to ${settings.mode}.`));
      return settings;
    });
  }

  async listApprovalGrants(): Promise<ApprovalGrant[]> {
    return this.mutate((store) => {
      pruneExpiredApprovalGrants(store, new Date().toISOString());
      return [...store.approvalGrants].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    });
  }

  async revokeApprovalGrant(id: string): Promise<ApprovalGrant> {
    return this.mutate((store) => {
      pruneExpiredApprovalGrants(store, new Date().toISOString());
      const index = store.approvalGrants.findIndex((grant) => grant.id === id);
      if (index < 0) {
        throw new Error(`Unknown approval grant: ${id}`);
      }

      const [revoked] = store.approvalGrants.splice(index, 1);
      clearOnePasswordCaches(store, new Set([revoked.id]));
      store.audit.push(audit("approval.grant.revoked", `Revoked approval grant ${id}.`, revoked.handle, revoked.lastRequestId));
      return revoked;
    });
  }

  async clearApprovalGrants(): Promise<ClearApprovalGrantsResult> {
    return this.mutate((store) => {
      pruneExpiredApprovalGrants(store, new Date().toISOString());
      const revoked = store.approvalGrants;
      store.approvalGrants = [];
      clearOnePasswordCaches(store);
      if (revoked.length > 0) {
        store.audit.push(audit("approval.grants.cleared", `Revoked ${revoked.length} approval grant(s).`));
      }

      return {
        revokedCount: revoked.length,
        revoked
      };
    });
  }

  async listApprovalPolicyRules(): Promise<ApprovalPolicyRule[]> {
    const store = await this.read();
    return sortApprovalPolicyRules(store.approvalPolicyRules || []);
  }

  async addApprovalPolicyRule(input: AddApprovalPolicyRuleInput): Promise<ApprovalPolicyRule> {
    return this.mutate((store) => {
      const now = new Date().toISOString();
      const rule = addApprovalPolicyRuleInStore(store, input, now);
      clearOnePasswordPolicyCaches(store);
      return rule;
    });
  }

  async updateApprovalPolicyRule(id: string, input: UpdateApprovalPolicyRuleInput): Promise<ApprovalPolicyRule> {
    return this.mutate((store) => {
      if (!hasApprovalPolicyUpdate(input)) {
        throw new Error("Approval policy update must include at least one change.");
      }

      const rules = store.approvalPolicyRules || [];
      const existing = rules.find((rule) => rule.id === id);
      if (!existing) {
        throw new Error(`Unknown approval policy: ${id}`);
      }

      const now = new Date().toISOString();
      const existingConditions = normalizeApprovalPolicyConditions(existing.conditions);
      if (exactBindingsWouldConflict(existingConditions, input.conditions)) {
        throw new Error("Approval policies with exact credential bindings keep their bindings, credentials, and environment variables fixed. Create a new rule to change them.");
      }
      const rule = normalizeApprovalPolicyRule(
        {
          ...existing,
          name: input.name === undefined ? existing.name : requirePolicyName(input.name),
          enabled: input.enabled === undefined ? existing.enabled : requirePolicyEnabled(input.enabled),
          priority: input.priority === undefined ? existing.priority : requirePolicyPriority(input.priority),
          decision: input.decision === undefined ? existing.decision : requireApprovalPolicyDecision(input.decision),
          conditions: input.conditions === undefined
            ? existingConditions
            : mergeApprovalPolicyConditions(existingConditions, input.conditions),
          expiresAt: resolveUpdatedPolicyExpiresAt(existing, input, now),
          updatedAt: existing.updatedAt
        },
        existing.updatedAt
      );
      if (sameApprovalPolicyRuleContent(existing, rule)) {
        return existing;
      }

      rule.updatedAt = now;

      store.approvalPolicyRules = sortApprovalPolicyRules(
        rules.map((candidate) => candidate.id === id ? rule : candidate)
      );
      clearOnePasswordPolicyCaches(store);
      store.audit.push(audit("approval.policy.updated", `Updated approval policy ${rule.name}.`));
      return rule;
    });
  }

  async arrangeApprovalPolicyRules(): Promise<ArrangeApprovalPolicyRulesResult> {
    const current = await this.read();
    const preview = arrangePolicyRules(current.approvalPolicyRules || []);
    if (preview.reordered === 0) {
      return preview;
    }

    return this.mutate((store) => {
      const now = new Date().toISOString();
      const arranged = arrangePolicyRules(store.approvalPolicyRules || [], now);
      if (arranged.reordered === 0) {
        return arranged;
      }

      store.approvalPolicyRules = arranged.rules;
      clearOnePasswordPolicyCaches(store);
      store.audit.push(
        audit("approval.policy.arranged", `Auto-arranged ${arranged.reordered} approval polic${arranged.reordered === 1 ? "y" : "ies"}.`)
      );
      return arranged;
    });
  }

  async deleteApprovalPolicyRule(id: string): Promise<ApprovalPolicyRule> {
    return this.mutate((store) => {
      const rules = store.approvalPolicyRules || [];
      const index = rules.findIndex((rule) => rule.id === id);
      if (index < 0) {
        throw new Error(`Unknown approval policy: ${id}`);
      }

      const [deleted] = rules.splice(index, 1);
      store.approvalPolicyRules = rules;
      clearOnePasswordPolicyCaches(store);
      store.audit.push(audit("approval.policy.deleted", `Deleted approval policy ${deleted.name}.`));
      return deleted;
    });
  }

  async setApprovalPolicyRuleEnabled(id: string, enabled: boolean): Promise<SetApprovalPolicyRuleEnabledResult> {
    return this.mutate((store) => {
      const rule = (store.approvalPolicyRules || []).find((item) => item.id === id);
      if (!rule) {
        throw new Error(`Unknown approval policy: ${id}`);
      }
      if (rule.enabled === enabled) {
        return { id, enabled };
      }

      rule.enabled = enabled;
      rule.updatedAt = new Date().toISOString();
      clearOnePasswordPolicyCaches(store);
      store.audit.push(
        audit("approval.policy.updated", `${enabled ? "Enabled" : "Disabled"} approval policy ${rule.name}.`)
      );
      return { id, enabled };
    });
  }

  async createRequest(
    handle: string,
    action: CommandAction,
    reason: string,
    agentContext: AgentIdentityContext = {}
  ): Promise<RequestRecord> {
    return this.mutate((store) => createRequestInStore(store, handle, action, reason, agentContext));
  }

  async prepareOneShotExecution(
    handle: string,
    action: CommandAction,
    reason: string,
    agentContext: AgentIdentityContext = {}
  ): Promise<OneShotExecutionAdmission> {
    return this.mutate((store) => oneShotExecutionAdmission(this.home, store, handle, action, reason, agentContext));
  }

  async validateReusableExecutionPermit(permit: ReusableExecutionPermit): Promise<RequestRecord> {
    assertReusableExecutionPermit(permit, this.home);
    const store = await this.read();
    return validatedReusableExecutionRequest(store, permit);
  }

  async launchReusableExecution<T>(
    permit: ReusableExecutionPermit,
    launch: (request: RequestRecord) => ExecutionLaunch<T>
  ): Promise<T> {
    assertReusableExecutionPermit(permit, this.home);
    await ensureSgwHome(this.home);
    const started = await this.withStoreLock(async (lock) => {
      const store = await this.loadOrRecoverUnlocked(lock);
      const request = validatedReusableExecutionRequest(store, permit);
      return launch(request);
    });
    return started.completion;
  }

  async listRequests(stateOrOptions?: RequestState | RequestListOptions): Promise<RequestRecord[]> {
    await this.recoverStaleExecutions();
    const store = await this.read();
    const options = typeof stateOrOptions === "string" ? { state: stateOrOptions } : stateOrOptions || {};
    let requests = sortRequestsForOperators(store.requests);
    if (options.state) {
      requests = requests.filter((request) => request.state === options.state);
    }
    if (options.active) {
      requests = requests.filter((request) => !isTerminalRequestState(request.state));
    }

    const limit = normalizeListLimit(options.limit);
    return limit ? requests.slice(0, limit) : requests;
  }

  async cleanupRequests(options: CleanupRequestsOptions = {}): Promise<CleanupRequestsResult> {
    return this.mutate((store) => {
      const now = new Date().toISOString();
      const cleaned: RequestRecord[] = [];
      if (options.duplicatePending !== false) {
        cleaned.push(...cleanupDuplicatePendingRequests(store, now));
      }

      const pendingMs = options.pendingOlderThanMs ?? 24 * 60 * 60 * 1000;
      const approvedMs = options.approvedOlderThanMs ?? 60 * 60 * 1000;
      cleaned.push(...cleanupOldRequests(store, now, pendingMs, approvedMs));

      return {
        cleanedCount: cleaned.length,
        requests: cleaned
      };
    });
  }

  async listStoreBackups(): Promise<StoreBackupSummary[]> {
    return listStoreBackups(this.home);
  }

  async getRequest(id: string): Promise<RequestRecord> {
    const store = await this.read();
    const found = store.requests.find((request) => request.id === id);
    if (!found) {
      throw new Error(`Unknown request: ${id}`);
    }

    return found;
  }

  async approveRequest(id: string, options: ApproveRequestOptions = {}): Promise<RequestRecord> {
    return this.updateRequest(id, (request, store) => {
      approvePendingRequest(store, request, id, options);
    });
  }

  async approveRequestWithScopedPolicy(id: string): Promise<ApproveRequestWithPolicyResult> {
    return this.mutate((store) => {
      const request = store.requests.find((item) => item.id === id);
      if (!request) {
        throw new Error(`Unknown request: ${id}`);
      }
      if (request.state !== "pending") {
        throw new Error(`Only pending requests can be approved. Current state: ${request.state}`);
      }

      const now = new Date().toISOString();
      const secret = store.secrets.find((item) => item.handle === request.handle);
      if (!secret) {
        throw new Error(`Unknown secret handle: ${request.handle}`);
      }
      const agentName = durablePolicyAgentName(request);
      let rule = matchingApprovalPolicyRuleForAction(store, secret, request.action, agentName, now);
      let created = false;

      if (rule?.decision !== "allow") {
        const deny = blockingDenyPolicyRuleForAction(store, secret, request.action, agentName, now);
        if (deny) {
          throw new Error(`Approval policy ${deny.name} denies this request. Edit or disable it before creating an allow rule.`);
        }

        addApprovalPolicyRuleInStore(store, scopedAllowPolicyInput(request, agentName), now, {
          handle: request.handle,
          requestId: request.id
        });
        created = true;
        const arranged = arrangePolicyRules(store.approvalPolicyRules || [], now);
        store.approvalPolicyRules = arranged.rules;
        rule = matchingApprovalPolicyRuleForAction(store, secret, request.action, agentName, now);
        if (rule?.decision !== "allow") {
          throw new Error("An existing policy takes precedence over this allow rule. Edit that policy before allowing this request.");
        }

        clearOnePasswordPolicyCaches(store);
        if (arranged.reordered > 0) {
          store.audit.push(
            audit("approval.policy.arranged", `Auto-arranged ${arranged.reordered} approval polic${arranged.reordered === 1 ? "y" : "ies"}.`)
          );
        }
      }

      approvePendingRequest(store, request, id, { mode: "per-transaction", agentScope: "same-agent" }, now, rule);
      return { request, rule, created };
    });
  }

  async denyRequest(id: string): Promise<RequestRecord> {
    return this.updateRequest(id, (request, store) => {
      if (request.state !== "pending") {
        throw new Error(`Only pending requests can be denied. Current state: ${request.state}`);
      }

      const now = new Date().toISOString();
      request.state = "denied";
      request.deniedAt = now;
      request.updatedAt = now;
      store.audit.push(audit("request.denied", `Denied execution request ${id}.`, request.handle, id));
    });
  }

  async claimApprovedRequest(id: string): Promise<RequestRecord> {
    const claimed = await this.mutate((store) => {
      // Reap any abandoned executions first so a previously-stranded request for the same
      // handle does not keep its approval grant alive or confuse the audit trail.
      const now = new Date().toISOString();
      reapStaleExecutions(store, now);
      pruneExpiredApprovalGrants(store, now);
      const request = store.requests.find((item) => item.id === id);
      if (!request) {
        throw new Error(`Unknown request: ${id}`);
      }
      if (request.state !== "approved") {
        throw new Error(`Request ${id} is ${request.state}; local approval is required before execution.`);
      }

      let upgradedLegacyAbsolute = false;
      try {
        upgradedLegacyAbsolute = request.action.kind === "env_command" &&
          !request.action.resolvedCommand && isAbsoluteCommand(request.action.command);
        request.action = actionReadyForExecution(request.action, true);
        const secret = store.secrets.find((item) => item.handle === request.handle);
        if (!secret) throw new Error(`Unknown secret handle: ${request.handle}`);
        assertActionAllowed(secret, request.action);
        assertBoundHandlesAllowed(store, request.handle, request.action);
        if (upgradedLegacyAbsolute) migrateRequestGrantToPinnedAction(store, request);
      } catch (error) {
        const executionError = errorMessage(error);
        request.state = "failed";
        request.updatedAt = now;
        request.error = executionError;
        store.audit.push(audit("request.failed", `Request ${id} failed: ${executionError}`, request.handle, id));
        return { request, error: executionError };
      }

      const authorizationError = automaticRequestAuthorizationError(store, request, now);
      if (authorizationError) {
        request.state = "denied";
        request.deniedAt = now;
        request.updatedAt = now;
        request.error = authorizationError;
        store.audit.push(audit("request.authorization_revoked", authorizationError, request.handle, id));
        return { request, error: authorizationError };
      }

      request.state = "executing";
      request.updatedAt = now;
      store.audit.push(audit("request.executing", `Executing approved request ${id}.`, request.handle, id));
      return { request };
    });

    if (claimed.error) {
      throw new Error(claimed.error);
    }
    return claimed.request;
  }

  /**
   * Mark requests stranded in "executing" (runner crashed/killed before reporting back) as
   * failed so the store self-heals. Returns the requests that were recovered.
   */
  async recoverStaleExecutions(): Promise<RequestRecord[]> {
    const store = await this.read();
    if (!store.requests.some((request) => request.state === "executing")) {
      return [];
    }

    let recovered: RequestRecord[] = [];
    await this.mutate((mutable) => {
      recovered = reapStaleExecutions(mutable, new Date().toISOString());
    });
    return recovered;
  }

  /**
   * Explicit user-driven recovery for requests stuck in "executing". Unlike the time-gated
   * automatic sweep, this fails them immediately — the operator has told us the runner is gone
   * (laptop slept, command was Ctrl-C'd, etc.). Pass a request id to recover just that one;
   * omit it to clear every stranded execution.
   */
  async forceRecoverExecutions(requestId?: string): Promise<RequestRecord[]> {
    return this.mutate((store) => {
      const now = new Date().toISOString();
      const targets = store.requests.filter((request) => {
        if (request.state !== "executing") {
          return false;
        }
        return !requestId || request.id === requestId;
      });

      if (requestId && targets.length === 0) {
        // Tell the user why nothing happened instead of silently returning an empty list.
        const found = store.requests.find((request) => request.id === requestId);
        if (!found) {
          throw new Error(`Unknown request: ${requestId}`);
        }
        throw new Error(`Request ${requestId} is ${found.state}, not executing; nothing to recover.`);
      }

      for (const request of targets) {
        request.state = "failed";
        request.updatedAt = now;
        request.error = "Execution was recovered manually before it finished. Create a new request to retry.";
        store.audit.push(
          audit("request.recovered", `Manually recovered stranded execution request ${request.id}.`, request.handle, request.id)
        );
      }

      return targets;
    });
  }

  async markExecuted(id: string, summary: ExecutionSummary): Promise<RequestRecord> {
    return this.updateRequest(id, (request, store) => {
      if (request.state !== "executing" && request.state !== "approved") {
        throw new Error(`Only approved or executing requests can be marked executed. Current state: ${request.state}`);
      }

      const now = new Date().toISOString();
      request.state = "executed";
      request.executedAt = now;
      request.updatedAt = now;
      request.resultSummary = summary;
      request.error = undefined;
      store.audit.push(audit("request.executed", `Executed request ${id}.`, request.handle, id));
    });
  }

  async markFailed(id: string, errorMessage: string): Promise<RequestRecord> {
    return this.updateRequest(id, (request, store) => {
      if (request.state !== "executing" && request.state !== "approved") {
        throw new Error(`Only approved or executing requests can be marked failed. Current state: ${request.state}`);
      }

      request.state = "failed";
      request.updatedAt = new Date().toISOString();
      request.error = errorMessage;
      store.audit.push(audit("request.failed", `Request ${id} failed: ${errorMessage}`, request.handle, id));
    });
  }

  async auditLog(): Promise<AuditEvent[]> {
    const store = await this.read();
    return store.audit;
  }

  private async updateRequest(
    id: string,
    updater: (request: RequestRecord, store: StoreFile) => void
  ): Promise<RequestRecord> {
    return this.mutate((store) => {
      const found = store.requests.find((request) => request.id === id);
      if (!found) {
        throw new Error(`Unknown request: ${id}`);
      }

      updater(found, store);
      return found;
    });
  }

  private async exists(): Promise<boolean> {
    try {
      await access(this.storePath, constants.F_OK);
      return true;
    } catch {
      return false;
    }
  }

  private async read(): Promise<StoreFile> {
    if (await this.exists()) {
      try {
        const store = await this.readUnlocked();
        if (await controlStateMatches(this.home, store)) {
          return store;
        }
      } catch {
        // Recovery runs under the store lock below.
      }
    }

    await ensureSgwHome(this.home);
    return this.withStoreLock((lock) => this.loadOrRecoverUnlocked(lock));
  }

  private async readUnlocked(): Promise<StoreFile> {
    const raw = await readFile(this.storePath, "utf8");
    return parseStoreFile(raw, this.storePath);
  }

  private async writeUnlocked(store: StoreFile, expectedRevision: StoreRevision, lock: StoreLock): Promise<void> {
    await ensureSgwHome(this.home);
    await lock.assertOwned();
    await assertStoreRevision(this.home, this.storePath, expectedRevision);

    await assertRecoveryVaultMatches(this.home, await readControlState(this.home));

    const previous = expectedRevision.storeText
      ? parseStoreFile(expectedRevision.storeText, this.storePath)
      : undefined;
    const previousFingerprint = previous ? controlPlaneFingerprint(previous) : undefined;
    const nextFingerprint = controlPlaneFingerprint(store);
    const controlChanged = previousFingerprint !== nextFingerprint;

    if (expectedRevision.manifestFingerprint && expectedRevision.manifestFingerprint !== previousFingerprint) {
      throw new Error("s-gw store control manifest changed while a write was in progress; retry the operation.");
    }

    if (controlChanged && previous && previousFingerprint) {
      await ensureSealedControlPlaneCheckpoint(this.home, previous, previousFingerprint, lock);
    }

    const nextCheckpoint = controlChanged
      ? await ensureSealedControlPlaneCheckpoint(this.home, store, nextFingerprint, lock)
      : undefined;

    if (controlChanged) {
      await lock.assertOwned();
      await assertStoreRevision(this.home, this.storePath, expectedRevision);
      await writePendingControlState(this.home, {
        version: 1,
        previousFingerprint: expectedRevision.manifestFingerprint,
        nextFingerprint,
        createdAt: new Date().toISOString()
      });
    }

    const revision = controlChanged
      ? await captureStoreRevision(this.home, this.storePath)
      : expectedRevision;
    await lock.assertOwned();
    await assertStoreRevision(this.home, this.storePath, revision);
    await backupCurrentStore(this.home, this.storePath, { force: controlChanged });
    await lock.assertOwned();
    await assertStoreRevision(this.home, this.storePath, revision);
    const serialized = serializeStore(store);
    await writeAtomicFile(this.storePath, serialized);

    const controlState = await readControlState(this.home);
    if (controlChanged || !controlState) {
      const checkpoint = nextCheckpoint || await ensureSealedControlPlaneCheckpoint(this.home, store, nextFingerprint, lock);
      await lock.assertOwned();
      await writeControlState(this.home, controlStateFor(this.home, store, nextFingerprint, checkpoint));
      await unlink(pendingControlStatePath(this.home)).catch(() => undefined);
    }
    await ensureStoreMarker(this.home);
  }

  private async mutate<T>(updater: (store: StoreFile) => T | Promise<T>): Promise<T> {
    await ensureSgwHome(this.home);
    return this.withStoreLock(async (lock) => {
      const store = await this.loadOrRecoverUnlocked(lock);
      const revision = await captureStoreRevision(this.home, this.storePath);
      const before = serializeStore(store);
      const result = await updater(store);
      if (serializeStore(store) !== before) {
        await this.writeUnlocked(store, revision, lock);
      }
      return result;
    });
  }

  private async loadOrRecoverUnlocked(lock: StoreLock): Promise<StoreFile> {
    const manifest = await readControlState(this.home);
    await assertRecoveryVaultMatches(this.home, manifest);
    if (!(await this.exists())) {
      if (manifest?.recoverySealed && !(await latestSealedExternalControlPlaneCheckpoint(this.home))) {
        const legacy = await latestSealedControlPlaneCheckpoint(legacyExternalControlPlaneBackupDir(this.home));
        if (!legacy) {
          throw new Error("s-gw sealed recovery checkpoint is unavailable; refusing to initialize from an unanchored ledger.");
        }
      }
      const recovered = await recoverStoreFromBackups(
        this.home,
        this.storePath,
        manifest?.fingerprint,
        lock,
        Boolean(manifest?.recoverySealed)
      );
      if (recovered) {
        return recovered;
      }

      if (manifest || await hasStoreMarker(this.home) || await hasRecoveryEvidence(this.home)) {
        throw new Error(
          `s-gw store is missing at ${this.storePath}; refusing to create an empty ledger because recovery evidence exists.`
        );
      }

      const fresh = emptyStore();
      const revision = await captureStoreRevision(this.home, this.storePath);
      await this.writeUnlocked(fresh, revision, lock);
      return fresh;
    }

    let store: StoreFile;
    try {
      store = await this.readUnlocked();
    } catch (error) {
      await preserveUnavailableStore(this.home, this.storePath, "invalid", lock);
      const recovered = await recoverStoreFromBackups(
        this.home,
        this.storePath,
        manifest?.fingerprint,
        lock,
        Boolean(manifest?.recoverySealed)
      );
      if (recovered) {
        return recovered;
      }
      throw new Error(`s-gw store is invalid and no verified recovery copy is available: ${errorMessage(error)}`);
    }

    const fingerprint = controlPlaneFingerprint(store);
    const pending = await readPendingControlState(this.home);
    if (!manifest) {
      const latest = await latestSealedExternalControlPlaneCheckpoint(this.home);
      if (latest) {
        if (latest.fingerprint !== fingerprint) {
          await preserveUnavailableStore(this.home, this.storePath, "missing-control-state", lock);
          const recovered = await recoverStoreFromBackups(this.home, this.storePath, latest.fingerprint, lock, true);
          if (recovered) {
            return recovered;
          }
          throw new Error("s-gw store control manifest is unavailable and no verified recovery copy exists.");
        }

        const checkpoint = await ensureSealedControlPlaneCheckpoint(this.home, store, fingerprint, lock);
        await lock.assertOwned();
        await writeControlState(this.home, controlStateFor(this.home, store, fingerprint, checkpoint));
        await unlink(pendingControlStatePath(this.home)).catch(() => undefined);
        await ensureStoreMarker(this.home);
        return store;
      }

      if (pending?.nextFingerprint === fingerprint && await hasRecoveryCandidateFingerprint(this.home, fingerprint)) {
        await initializeControlState(this.home, store, lock);
        return store;
      }

      const priorControlState = await fileExists(controlStatePath(this.home))
        || await hasStoreMarker(this.home)
        || await hasRecoveryEvidence(this.home);
      if (priorControlState) {
        if (await hasRecoveryCandidateFingerprint(this.home, fingerprint)) {
          const checkpoint = await ensureSealedControlPlaneCheckpoint(this.home, store, fingerprint, lock);
          await lock.assertOwned();
          await writeControlState(this.home, controlStateFor(this.home, store, fingerprint, checkpoint));
          await unlink(pendingControlStatePath(this.home)).catch(() => undefined);
          await ensureStoreMarker(this.home);
          return store;
        }

        await preserveUnavailableStore(this.home, this.storePath, "missing-control-state", lock);
        const recovered = await recoverStoreFromBackups(this.home, this.storePath, undefined, lock);
        if (recovered) {
          return recovered;
        }
        throw new Error("s-gw store control manifest is unavailable and no verified recovery copy exists.");
      }

      await initializeControlState(this.home, store, lock);
      return store;
    }

    if (fingerprint === manifest.fingerprint) {
      const manifestBelongsElsewhere = Boolean(
        manifest.recoveryNamespace && manifest.recoveryNamespace !== recoveryNamespace(this.home)
      );
      if (manifestBelongsElsewhere) {
        const latest = await latestSealedExternalControlPlaneCheckpoint(this.home);
        if (!latest) {
          throw new Error("s-gw control manifest belongs to another ledger and this ledger has no verified recovery checkpoint.");
        }
        await preserveUnavailableStore(this.home, this.storePath, "foreign-control-manifest", lock);
        const recovered = await recoverStoreFromBackups(this.home, this.storePath, latest.fingerprint, lock, true);
        if (recovered) {
          return recovered;
        }
        throw new Error("s-gw control manifest belongs to another ledger and recovery could not restore this ledger.");
      }

      if (manifest.recoverySealed) {
        if (!manifest.recoveryCheckpoint) {
          throw new Error("s-gw sealed recovery manifest has no checkpoint anchor; refusing to trust only the primary ledger.");
        }
        const anchor = await verifiedSealedControlPlaneCheckpoint(
          externalControlPlaneBackupDir(this.home),
          manifest.recoveryCheckpoint
        );
        if (!anchor || anchor.fingerprint !== fingerprint) {
          throw new Error(
            "s-gw sealed recovery anchor is unavailable or does not match the primary ledger; refusing to roll back credentials or policies."
          );
        }
        if (
          !manifest.recoveryVaultId ||
          manifest.recoveryVaultId !== recoveryVaultId(this.home) ||
          manifest.recoveryNamespace !== recoveryNamespace(this.home)
        ) {
          await lock.assertOwned();
          await writeControlState(this.home, controlStateFor(this.home, store, fingerprint, anchor));
        }
        await unlink(pendingControlStatePath(this.home)).catch(() => undefined);
        await ensureStoreMarker(this.home);
        return store;
      }

      const latest = await latestSealedExternalControlPlaneCheckpoint(this.home);
      if (latest && latest.fingerprint !== fingerprint) {
        await preserveUnavailableStore(this.home, this.storePath, "external-checkpoint-mismatch", lock);
        const recovered = await recoverStoreFromBackups(this.home, this.storePath, latest.fingerprint, lock);
        if (recovered) {
          return recovered;
        }
        throw new Error("s-gw external control-plane checkpoint does not match the current ledger.");
      }

      if (!latest) {
        const legacy = await latestLegacyExternalControlPlaneCheckpoint(this.home);
        if (legacy && legacy.fingerprint !== fingerprint) {
          await preserveUnavailableStore(this.home, this.storePath, "external-checkpoint-mismatch", lock);
          return restoreRecoveryCandidate(this.home, this.storePath, legacy, lock);
        }
      }

      const checkpoint = await ensureSealedControlPlaneCheckpoint(this.home, store, fingerprint, lock);
      await lock.assertOwned();
      await writeControlState(this.home, controlStateFor(this.home, store, fingerprint, checkpoint));
      await unlink(pendingControlStatePath(this.home)).catch(() => undefined);
      await ensureStoreMarker(this.home);
      return store;
    }

    if (
      !pending &&
      await migrateLegacyUnsealedControlState(this.home, store, manifest, fingerprint, lock)
    ) {
      return store;
    }

    if (pending?.nextFingerprint === fingerprint && pending.previousFingerprint === manifest.fingerprint) {
      const checkpoint = await ensureSealedControlPlaneCheckpoint(this.home, store, fingerprint, lock);
      await lock.assertOwned();
      await writeControlState(this.home, controlStateFor(this.home, store, fingerprint, checkpoint));
      await unlink(pendingControlStatePath(this.home)).catch(() => undefined);
      await ensureStoreMarker(this.home);
      return store;
    }

    await preserveUnavailableStore(this.home, this.storePath, "control-mismatch", lock);
    const recovered = await recoverStoreFromBackups(
      this.home,
      this.storePath,
      manifest.fingerprint,
      lock,
      Boolean(manifest.recoverySealed)
    );
    if (recovered) {
      return recovered;
    }

    throw new Error(
      `s-gw store control state changed outside a committed transaction; refusing to use or replace the ledger.`
    );
  }

  private async withStoreLock<T>(body: (lock: StoreLock) => Promise<T>): Promise<T> {
    const lockPath = `${this.storePath}.lock`;
    const started = Date.now();
    const state: StoreLockState = {
      version: 1,
      pid: process.pid,
      token: randomUUID(),
      createdAt: new Date().toISOString()
    };

    while (!(await publishStoreLock(lockPath, state))) {
      await removeAbandonedStoreLock(lockPath);
      if (Date.now() - started > storeLockTimeoutMs()) {
        throw new Error(`Timed out waiting for s-gw store lock at ${lockPath}.`);
      }
      await sleep(25);
    }

    const lock: StoreLock = {
      assertOwned: () => assertStoreLockOwnership(lockPath, state.token)
    };
    try {
      await lock.assertOwned();
      return await body(lock);
    } finally {
      await releaseStoreLock(lockPath, state.token);
    }
  }
}

function storeMarkerPath(home: string): string {
  return path.join(home, storeMarkerName);
}

function controlStatePath(home: string): string {
  return path.join(home, controlStateName);
}

function pendingControlStatePath(home: string): string {
  return path.join(home, pendingControlStateName);
}

function controlPlaneBackupDir(home: string): string {
  return path.join(home, "backups", "control-plane");
}

function externalControlPlaneBackupDir(home: string): string {
  return path.join(getSgwRecoveryHome(home), "control-plane", recoveryNamespace(home));
}

function legacyExternalControlPlaneBackupDir(home: string): string {
  return path.join(getSgwRecoveryHome(home), "control-plane");
}

function recoveryNamespace(home: string): string {
  return createHash("sha256").update(path.resolve(home)).digest("hex").slice(0, 24);
}

function recoveryVaultId(home: string): string {
  return createHash("sha256")
    .update(path.resolve(getSgwRecoveryHome(home)))
    .digest("hex");
}

async function assertRecoveryVaultMatches(home: string, manifest: StoreControlState | undefined): Promise<void> {
  if (!manifest?.recoverySealed || !manifest.recoveryVaultId) {
    return;
  }
  if (manifest.recoveryVaultId === recoveryVaultId(home)) {
    return;
  }
  const checkpoint = manifest.recoveryCheckpoint
    ? await verifiedSealedControlPlaneCheckpoint(externalControlPlaneBackupDir(home), manifest.recoveryCheckpoint)
    : undefined;
  if (
    checkpoint?.fingerprint === manifest.fingerprint &&
    path.basename(checkpoint.path) === manifest.recoveryCheckpoint
  ) {
    return;
  }
  throw new Error(
    "s-gw recovery home changed since this ledger was sealed; restore the original SGW_RECOVERY_HOME or copy its verified recovery namespace before continuing."
  );
}

function serializeStore(store: StoreFile): string {
  return `${JSON.stringify(store, null, 2)}\n`;
}

function parseStoreFile(raw: string, source: string): StoreFile {
  let parsed: Partial<StoreFile>;
  try {
    parsed = JSON.parse(raw) as Partial<StoreFile>;
  } catch {
    throw new Error(`Invalid JSON in s-gw store at ${source}`);
  }
  if (parsed.version !== 1 || !Array.isArray(parsed.secrets) || !Array.isArray(parsed.requests)) {
    throw new Error(`Invalid s-gw store at ${source}`);
  }
  return normalizeStoreFile(parsed);
}

async function captureStoreRevision(home: string, storePath: string): Promise<StoreRevision> {
  const [storeText, controlStateText, pendingStateText] = await Promise.all([
    readOptionalText(storePath),
    readOptionalText(controlStatePath(home)),
    readOptionalText(pendingControlStatePath(home))
  ]);
  return {
    storeText,
    storeHash: contentHash(storeText),
    controlStateHash: contentHash(controlStateText),
    pendingStateHash: contentHash(pendingStateText),
    manifestFingerprint: controlStateText ? parseControlState(controlStateText)?.fingerprint : undefined
  };
}

async function assertStoreRevision(home: string, storePath: string, expected: StoreRevision): Promise<void> {
  const current = await captureStoreRevision(home, storePath);
  if (
    current.storeHash !== expected.storeHash ||
    current.controlStateHash !== expected.controlStateHash ||
    current.pendingStateHash !== expected.pendingStateHash
  ) {
    throw new Error("s-gw ledger changed while a write was in progress; retry the operation.");
  }
}

async function readOptionalText(filePath: string): Promise<string | undefined> {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

function contentHash(content: string | undefined): string | undefined {
  return content === undefined
    ? undefined
    : createHash("sha256").update(content).digest("hex");
}

function controlPlaneFingerprint(store: StoreFile): string {
  const secrets = store.secrets.map(({ cache: _cache, updatedAt: _updatedAt, ...secret }) => secret)
    .sort((a, b) => a.handle.localeCompare(b.handle));
  const grants = store.approvalGrants.map(({ lastRequestId: _lastRequestId, updatedAt: _updatedAt, ...grant }) => grant)
    .sort((a, b) => a.id.localeCompare(b.id));
  const rules = [...store.approvalPolicyRules].sort((a, b) => a.id.localeCompare(b.id));
  const control = {
    version: store.version,
    secrets,
    approvalSettings: store.approvalSettings,
    approvalGrants: grants,
    approvalPolicyRules: rules
  };
  return createHash("sha256").update(JSON.stringify(canonicalValue(control))).digest("hex");
}

function legacyControlPlaneFingerprint(store: StoreFile): string {
  const secrets = store.secrets.map((secret) => {
    const copy = { ...secret };
    delete copy.cache;
    return copy;
  }).sort((a, b) => a.handle.localeCompare(b.handle));
  const grants = [...store.approvalGrants].sort((a, b) => a.id.localeCompare(b.id));
  const rules = [...store.approvalPolicyRules].sort((a, b) => a.id.localeCompare(b.id));
  const control = {
    version: store.version,
    secrets,
    approvalSettings: store.approvalSettings,
    approvalGrants: grants,
    approvalPolicyRules: rules
  };
  return createHash("sha256").update(JSON.stringify(canonicalValue(control))).digest("hex");
}

function controlPlaneSnapshot(store: StoreFile): StoreFile {
  const secrets = store.secrets.map((secret) => {
    const copy = { ...secret };
    delete copy.cache;
    return copy;
  });
  return {
    version: store.version,
    secrets,
    requests: [],
    audit: [],
    approvalSettings: store.approvalSettings,
    approvalGrants: store.approvalGrants,
    approvalPolicyRules: store.approvalPolicyRules
  };
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const input = value as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(input).sort()) {
    if (input[key] !== undefined) {
      output[key] = canonicalValue(input[key]);
    }
  }
  return output;
}

function controlStateFor(
  home: string,
  store: StoreFile,
  fingerprint = controlPlaneFingerprint(store),
  checkpoint?: SealedControlPlaneCheckpoint
): StoreControlState {
  return {
    version: 1,
    fingerprint,
    updatedAt: new Date().toISOString(),
    secrets: store.secrets.length,
    approvalPolicyRules: store.approvalPolicyRules.length,
    recoverySealed: true,
    recoveryCheckpoint: checkpoint ? path.basename(checkpoint.path) : undefined,
    recoveryVaultId: recoveryVaultId(home),
    recoveryNamespace: recoveryNamespace(home)
  };
}

async function controlStateMatches(home: string, store: StoreFile): Promise<boolean> {
  const manifest = await readControlState(home);
  if (
    !manifest?.recoverySealed ||
    !manifest.recoveryVaultId ||
    manifest.recoveryVaultId !== recoveryVaultId(home) ||
    manifest.recoveryNamespace !== recoveryNamespace(home) ||
    await fileExists(pendingControlStatePath(home))
  ) {
    return false;
  }
  const fingerprint = controlPlaneFingerprint(store);
  if (manifest.fingerprint !== fingerprint) {
    return false;
  }

  if (!manifest.recoveryCheckpoint) {
    return false;
  }
  const checkpoint = await verifiedSealedControlPlaneCheckpoint(
    externalControlPlaneBackupDir(home),
    manifest.recoveryCheckpoint
  );
  return checkpoint?.fingerprint === fingerprint;
}

async function readControlState(home: string): Promise<StoreControlState | undefined> {
  let raw: string;
  try {
    raw = await readFile(controlStatePath(home), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }

  const state = parseControlState(raw);
  if (!state) {
    throw new Error("s-gw store control manifest is invalid; refusing to trust or replace the ledger.");
  }
  return state;
}

function parseControlState(raw: string): StoreControlState | undefined {
  try {
    const value = JSON.parse(raw) as Partial<StoreControlState>;
    const sealedRecoveryIsComplete = value.recoverySealed !== true || (
      typeof value.recoveryCheckpoint === "string" &&
      isSealedCheckpointName(value.recoveryCheckpoint) &&
      typeof value.recoveryVaultId === "string" &&
      /^[a-f0-9]{64}$/.test(value.recoveryVaultId) &&
      typeof value.recoveryNamespace === "string" &&
      /^[a-f0-9]{24}$/.test(value.recoveryNamespace)
    );
    if (
      value.version !== 1 ||
      typeof value.fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(value.fingerprint) ||
      typeof value.updatedAt !== "string" ||
      typeof value.secrets !== "number" ||
      typeof value.approvalPolicyRules !== "number" ||
      (value.recoverySealed !== undefined && value.recoverySealed !== true) ||
      !sealedRecoveryIsComplete ||
      (value.recoveryCheckpoint !== undefined && !isSealedCheckpointName(value.recoveryCheckpoint)) ||
      (value.recoveryVaultId !== undefined && !/^[a-f0-9]{64}$/.test(value.recoveryVaultId)) ||
      (value.recoveryNamespace !== undefined && !/^[a-f0-9]{24}$/.test(value.recoveryNamespace))
    ) {
      return undefined;
    }
    return value as StoreControlState;
  } catch {
    return undefined;
  }
}

async function readPendingControlState(home: string): Promise<PendingStoreControlState | undefined> {
  try {
    const value = JSON.parse(await readFile(pendingControlStatePath(home), "utf8")) as Partial<PendingStoreControlState>;
    if (
      value.version !== 1 ||
      typeof value.nextFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(value.nextFingerprint) ||
      typeof value.createdAt !== "string" ||
      (value.previousFingerprint !== undefined && !/^[a-f0-9]{64}$/.test(value.previousFingerprint))
    ) {
      return undefined;
    }
    return value as PendingStoreControlState;
  } catch {
    return undefined;
  }
}

async function writeControlState(home: string, state: StoreControlState): Promise<void> {
  await writeAtomicFile(controlStatePath(home), `${JSON.stringify(state, null, 2)}\n`);
}

async function writePendingControlState(home: string, state: PendingStoreControlState): Promise<void> {
  await writeAtomicFile(pendingControlStatePath(home), `${JSON.stringify(state, null, 2)}\n`);
}

async function initializeControlState(home: string, store: StoreFile, lock: StoreLock): Promise<void> {
  const fingerprint = controlPlaneFingerprint(store);
  const checkpoint = await ensureSealedControlPlaneCheckpoint(home, store, fingerprint, lock);
  await lock.assertOwned();
  await writeControlState(home, controlStateFor(home, store, fingerprint, checkpoint));
  await unlink(pendingControlStatePath(home)).catch(() => undefined);
  await ensureStoreMarker(home);
}

async function migrateLegacyUnsealedControlState(
  home: string,
  store: StoreFile,
  manifest: StoreControlState,
  fingerprint: string,
  lock: StoreLock
): Promise<boolean> {
  if (manifest.recoverySealed ||
      manifest.secrets !== store.secrets.length ||
      manifest.approvalPolicyRules !== store.approvalPolicyRules.length ||
      legacyControlPlaneFingerprint(store) !== manifest.fingerprint) {
    return false;
  }

  const candidate = await findLegacyFingerprintCandidate(
    await listLegacyControlPlaneCandidates(home),
    manifest.fingerprint
  );
  if (!candidate) {
    return false;
  }

  const checkpointStore = parseStoreFile(await readFile(candidate.path, "utf8"), candidate.path);
  if (controlPlaneFingerprint(checkpointStore) !== fingerprint) {
    return false;
  }

  const checkpoint = await ensureSealedControlPlaneCheckpoint(home, store, fingerprint, lock);
  await lock.assertOwned();
  await writeControlState(home, controlStateFor(home, store, fingerprint, checkpoint));
  await unlink(pendingControlStatePath(home)).catch(() => undefined);
  await ensureStoreMarker(home);
  return true;
}

async function ensureSealedControlPlaneCheckpoint(
  home: string,
  store: StoreFile,
  fingerprint: string,
  lock: StoreLock
): Promise<SealedControlPlaneCheckpoint> {
  const serialized = serializeStore(controlPlaneSnapshot(store));
  const externalDir = externalControlPlaneBackupDir(home);
  const internalDir = controlPlaneBackupDir(home);
  let externalLatest = await latestSealedControlPlaneCheckpoint(externalDir);
  if (externalLatest?.fingerprint !== fingerprint) {
    await lock.assertOwned();
    externalLatest = await writeSealedControlPlaneCheckpoint(externalDir, serialized, fingerprint);
  }
  await writeExternalControlPlaneHead(externalDir, externalLatest);

  const internalLatest = await latestSealedControlPlaneCheckpoint(internalDir);
  if (internalLatest?.fingerprint !== fingerprint) {
    await lock.assertOwned();
    await writeSealedControlPlaneCheckpoint(internalDir, serialized, fingerprint);
  }

  return externalLatest;
}

async function writeSealedControlPlaneCheckpoint(
  backupDir: string,
  serialized: string,
  fingerprint: string
): Promise<SealedControlPlaneCheckpoint> {
  await mkdir(backupDir, { recursive: true, mode: 0o700 });
  const latestSequence = (await listSealedControlPlaneCheckpoints(backupDir))[0]?.sequence || 0;
  const firstSequence = Math.max(Date.now(), latestSequence + 1);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const sequence = String(firstSequence + attempt).padStart(13, "0");
    const checkpointPath = path.join(
      backupDir,
      `checkpoint-${sequence}-${shortId("cp")}-${fingerprint}.json`
    );
    let checkpoint: Awaited<ReturnType<typeof open>> | undefined;
    try {
      checkpoint = await open(checkpointPath, "wx", 0o400);
      await checkpoint.writeFile(serialized);
      await checkpoint.sync();
      await checkpoint.close();
      await syncDirectory(backupDir);
      const info = await stat(checkpointPath);
      return {
        path: checkpointPath,
        modifiedAtMs: info.mtimeMs,
        sequence: Number(sequence),
        fingerprint
      };
    } catch (error) {
      await checkpoint?.close().catch(() => undefined);
      if (isNodeError(error) && error.code === "EEXIST") {
        continue;
      }
      throw error;
    }
  }

  throw new Error(`Unable to create a unique s-gw control-plane checkpoint in ${backupDir}.`);
}

async function writeExternalControlPlaneHead(
  backupDir: string,
  checkpoint: SealedControlPlaneCheckpoint
): Promise<void> {
  const state: ControlPlaneHead = {
    version: 1,
    checkpoint: path.basename(checkpoint.path),
    fingerprint: checkpoint.fingerprint
  };
  const headPath = path.join(backupDir, "head.json");
  try {
    const existing = JSON.parse(await readFile(headPath, "utf8")) as Partial<ControlPlaneHead>;
    if (existing.version === state.version && existing.checkpoint === state.checkpoint && existing.fingerprint === state.fingerprint) {
      return;
    }
  } catch {
    // A missing or invalid index is rebuilt from the checkpoint that was just verified.
  }
  await writeAtomicFile(headPath, `${JSON.stringify(state, null, 2)}\n`);
}

async function latestSealedExternalControlPlaneCheckpoint(home: string): Promise<SealedControlPlaneCheckpoint | undefined> {
  return latestSealedControlPlaneCheckpoint(externalControlPlaneBackupDir(home));
}

async function latestSealedControlPlaneCheckpoint(dir: string): Promise<SealedControlPlaneCheckpoint | undefined> {
  const checkpoints = await listSealedControlPlaneCheckpoints(dir);
  for (const checkpoint of checkpoints) {
    const verified = await verifiedSealedControlPlaneCheckpoint(dir, path.basename(checkpoint.path));
    if (verified) return verified;
  }
  return undefined;
}

async function listSealedExternalControlPlaneCheckpoints(home: string): Promise<SealedControlPlaneCheckpoint[]> {
  return listSealedControlPlaneCheckpoints(externalControlPlaneBackupDir(home));
}

async function listLegacySealedExternalControlPlaneCheckpoints(home: string): Promise<SealedControlPlaneCheckpoint[]> {
  return listSealedControlPlaneCheckpoints(legacyExternalControlPlaneBackupDir(home));
}

async function latestLegacyExternalControlPlaneCheckpoint(home: string): Promise<VerifiedRecoveryCandidate | undefined> {
  const candidates = await listLegacyExternalControlPlaneCheckpoints(home);
  for (const candidate of candidates) {
    try {
      const store = parseStoreFile(await readFile(candidate.path, "utf8"), candidate.path);
      return { ...candidate, fingerprint: controlPlaneFingerprint(store) };
    } catch {
      continue;
    }
  }
  return undefined;
}

async function listLegacyExternalControlPlaneCheckpoints(home: string): Promise<RecoveryCandidate[]> {
  const dir = legacyExternalControlPlaneBackupDir(home);
  const entries = await readdir(dir).catch(() => []);
  const candidates: RecoveryCandidate[] = [];
  for (const entry of entries) {
    if (!/^store-.*\.json$/.test(entry)) {
      continue;
    }
    const candidatePath = path.join(dir, entry);
    const info = await regularFileInfo(candidatePath);
    if (info) {
      candidates.push({ path: candidatePath, modifiedAtMs: info.mtimeMs });
    }
  }
  return candidates.sort((left, right) => right.modifiedAtMs - left.modifiedAtMs);
}

async function listLegacyControlPlaneCandidates(home: string): Promise<RecoveryCandidate[]> {
  const candidates: RecoveryCandidate[] = [];
  for (const dir of [controlPlaneBackupDir(home), legacyExternalControlPlaneBackupDir(home)]) {
    const entries = await readdir(dir).catch(() => []);
    for (const entry of entries) {
      if (!/^store-.*\.json$/.test(entry)) {
        continue;
      }
      const candidatePath = path.join(dir, entry);
      const info = await regularFileInfo(candidatePath);
      if (info) {
        candidates.push({ path: candidatePath, modifiedAtMs: info.mtimeMs });
      }
    }
  }
  return candidates.sort((left, right) => right.modifiedAtMs - left.modifiedAtMs);
}

async function findLegacyFingerprintCandidate(
  candidates: RecoveryCandidate[],
  requiredFingerprint: string
): Promise<RecoveryCandidate | undefined> {
  for (const candidate of candidates) {
    try {
      const store = parseStoreFile(await readFile(candidate.path, "utf8"), candidate.path);
      if (legacyControlPlaneFingerprint(store) === requiredFingerprint) {
        return candidate;
      }
    } catch {
      continue;
    }
  }
  return undefined;
}

async function listSealedControlPlaneCheckpoints(dir: string): Promise<SealedControlPlaneCheckpoint[]> {
  const entries = await readdir(dir).catch(() => []);
  const checkpoints: SealedControlPlaneCheckpoint[] = [];
  for (const entry of entries) {
    const checkpoint = await sealedControlPlaneCheckpoint(dir, entry);
    if (checkpoint) checkpoints.push(checkpoint);
  }
  return checkpoints.sort((left, right) => {
    return right.sequence - left.sequence
      || right.modifiedAtMs - left.modifiedAtMs
      || right.path.localeCompare(left.path);
  });
}

async function verifiedSealedControlPlaneCheckpoint(
  dir: string,
  checkpointName: string
): Promise<SealedControlPlaneCheckpoint | undefined> {
  const checkpoint = await sealedControlPlaneCheckpoint(dir, checkpointName);
  if (!checkpoint) {
    return undefined;
  }
  try {
    const store = parseStoreFile(await readFile(checkpoint.path, "utf8"), checkpoint.path);
    return controlPlaneFingerprint(store) === checkpoint.fingerprint ? checkpoint : undefined;
  } catch {
    return undefined;
  }
}

async function sealedControlPlaneCheckpoint(
  dir: string,
  checkpointName: string
): Promise<SealedControlPlaneCheckpoint | undefined> {
  const match = /^checkpoint-(\d{13})-[A-Za-z0-9_-]+-([a-f0-9]{64})\.json$/.exec(checkpointName);
  if (!match) {
    return undefined;
  }
  const checkpointPath = path.join(dir, checkpointName);
  const info = await regularFileInfo(checkpointPath);
  if (!info) {
    return undefined;
  }
  return {
    path: checkpointPath,
    modifiedAtMs: info.mtimeMs,
    sequence: Number(match[1]),
    fingerprint: match[2]
  };
}

function isSealedCheckpointName(name: string): boolean {
  return /^checkpoint-\d{13}-[A-Za-z0-9_-]+-[a-f0-9]{64}\.json$/.test(name);
}

async function syncDirectory(dir: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(dir, "r");
    await handle.sync();
  } catch (error) {
    if (!isNodeError(error) || !["EINVAL", "EPERM", "EISDIR"].includes(error.code || "")) {
      throw error;
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function writeAtomicFile(targetPath: string, content: string): Promise<void> {
  const tmpPath = path.join(
    path.dirname(targetPath),
    `.${path.basename(targetPath)}.${process.pid}.${Date.now()}.tmp`
  );
  let tmpFile: Awaited<ReturnType<typeof open>> | undefined;
  try {
    tmpFile = await open(tmpPath, "wx", 0o600);
    await tmpFile.writeFile(content);
    await tmpFile.sync();
    await tmpFile.close();
    tmpFile = undefined;
    await rename(tmpPath, targetPath);
    await chmod(targetPath, 0o600);
    await syncDirectory(path.dirname(targetPath));
  } catch (error) {
    await tmpFile?.close().catch(() => undefined);
    await rm(tmpPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

async function ensureStoreMarker(home: string): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(storeMarkerPath(home), "wx", 0o600);
    await handle.writeFile("s-gw store initialized\n");
  } catch (error) {
    if (!isNodeError(error) || error.code !== "EEXIST") {
      throw error;
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function hasStoreMarker(home: string): Promise<boolean> {
  return fileExists(storeMarkerPath(home));
}

async function hasRecoveryEvidence(home: string): Promise<boolean> {
  return (await listRecoveryCandidates(home)).length > 0;
}

async function hasRecoveryCandidateFingerprint(home: string, requiredFingerprint: string): Promise<boolean> {
  const sealed = await listSealedExternalControlPlaneCheckpoints(home);
  if (sealed.length > 0) {
    return Boolean(await findRecoveryCandidate(sealed, requiredFingerprint));
  }
  const legacySealed = await listLegacySealedExternalControlPlaneCheckpoints(home);
  if (legacySealed.length > 0) {
    return Boolean(await findRecoveryCandidate(legacySealed, requiredFingerprint));
  }
  return Boolean(await findRecoveryCandidate(await listRecoveryCandidates(home), requiredFingerprint));
}

async function recoverStoreFromBackups(
  home: string,
  storePath: string,
  requiredFingerprint: string | undefined,
  lock: StoreLock,
  requireSealed = false
): Promise<StoreFile | undefined> {
  const sealed = await listSealedExternalControlPlaneCheckpoints(home);
  const sealedMatch = await findRecoveryCandidate(sealed, requiredFingerprint);
  if (sealedMatch) {
    return restoreRecoveryCandidate(home, storePath, sealedMatch, lock);
  }

  if (requiredFingerprint) {
    const legacySealed = await listLegacySealedExternalControlPlaneCheckpoints(home);
    const legacySealedMatch = await findRecoveryCandidate(legacySealed, requiredFingerprint);
    if (legacySealedMatch) {
      return restoreRecoveryCandidate(home, storePath, legacySealedMatch, lock);
    }

    if (sealed.length > 0 || legacySealed.length > 0 || requireSealed) {
      return undefined;
    }

    const legacy = await findRecoveryCandidate(
      await listLegacyExternalControlPlaneCheckpoints(home),
      requiredFingerprint
    );
    if (legacy) {
      return restoreRecoveryCandidate(home, storePath, legacy, lock);
    }
  } else if (sealed.length > 0 || requireSealed) {
    return undefined;
  }

  const fallback = await findRecoveryCandidate(
    await listRecoveryCandidates(home, { includeLegacyExternal: Boolean(requiredFingerprint) }),
    requiredFingerprint
  );
  if (!fallback) {
    return undefined;
  }
  return restoreRecoveryCandidate(home, storePath, fallback, lock);
}

async function findRecoveryCandidate(
  candidates: RecoveryCandidate[],
  requiredFingerprint?: string
): Promise<RecoveryCandidate | undefined> {
  for (const candidate of candidates) {
    try {
      if (!(await regularFileInfo(candidate.path))) {
        continue;
      }
      const store = parseStoreFile(await readFile(candidate.path, "utf8"), candidate.path);
      const fingerprint = controlPlaneFingerprint(store);
      if (!requiredFingerprint || fingerprint === requiredFingerprint) {
        return candidate;
      }
    } catch {
      continue;
    }
  }
  return undefined;
}

async function restoreRecoveryCandidate(
  home: string,
  storePath: string,
  candidate: RecoveryCandidate,
  lock: StoreLock
): Promise<StoreFile> {
  if (!(await regularFileInfo(candidate.path))) {
    throw new Error(`s-gw recovery candidate disappeared or is not a regular file: ${candidate.path}`);
  }
  const store = parseStoreFile(await readFile(candidate.path, "utf8"), candidate.path);
  const fingerprint = controlPlaneFingerprint(store);
  store.audit.push(audit(
    "store.recovered",
    `Recovered the s-gw ledger from ${path.basename(candidate.path)} after the primary store became unavailable.`
  ));
  await lock.assertOwned();
  await writeAtomicFile(storePath, serializeStore(store));
  const checkpoint = await ensureSealedControlPlaneCheckpoint(home, store, fingerprint, lock);
  await lock.assertOwned();
  await writeControlState(home, controlStateFor(home, store, fingerprint, checkpoint));
  await unlink(pendingControlStatePath(home)).catch(() => undefined);
  await ensureStoreMarker(home);
  return store;
}

async function preserveUnavailableStore(
  home: string,
  storePath: string,
  reason: string,
  lock: StoreLock
): Promise<void> {
  if (!(await fileExists(storePath))) {
    return;
  }
  await lock.assertOwned();
  const recoveryDir = path.join(home, "recovery", "automatic");
  await mkdir(recoveryDir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[-:.]/g, "");
  const recoveryPath = path.join(recoveryDir, `store-${reason}-${stamp}-${process.pid}.json`);
  await rename(storePath, recoveryPath);
  await chmod(recoveryPath, 0o600);
}

async function listRecoveryCandidates(
  home: string,
  options: { includeLegacyExternal?: boolean } = {}
): Promise<RecoveryCandidate[]> {
  const dirs = new Set([
    controlPlaneBackupDir(home),
    externalControlPlaneBackupDir(home),
    path.join(home, "backups", "manual"),
    path.join(home, "backups")
  ]);
  if (options.includeLegacyExternal !== false) {
    dirs.add(legacyExternalControlPlaneBackupDir(home));
  }
  const candidates: RecoveryCandidate[] = [];
  for (const dir of dirs) {
    const entries = await readdir(dir).catch(() => []);
    for (const entry of entries) {
      if (!entry.endsWith(".json")) {
        continue;
      }
      const candidatePath = path.join(dir, entry);
      const info = await regularFileInfo(candidatePath);
      if (info) {
        candidates.push({ path: candidatePath, modifiedAtMs: info.mtimeMs });
      }
    }
  }
  return candidates.sort((a, b) => b.modifiedAtMs - a.modifiedAtMs);
}

async function regularFileInfo(filePath: string): Promise<{ mtimeMs: number } | undefined> {
  const info = await lstat(filePath).catch(() => undefined);
  return info?.isFile() ? { mtimeMs: Number(info.mtimeMs) } : undefined;
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function backupCurrentStore(
  home: string,
  storePath: string,
  options: { force?: boolean } = {}
): Promise<void> {
  if (!options.force) {
    const latest = (await listStoreBackups(home))[0];
    if (latest && Date.now() - Date.parse(latest.modifiedAt) < requestBackupIntervalMs) {
      return;
    }
  }

  let current = "";
  try {
    current = await readFile(storePath, "utf8");
  } catch {
    return;
  }

  if (!current.trim()) {
    return;
  }

  const backupDir = path.join(home, "backups");
  await mkdir(backupDir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[-:.]/g, "").slice(0, 15);
  const backupPath = path.join(backupDir, `store-${stamp}-${process.pid}-${Date.now()}.json`);
  await writeFile(backupPath, current, { mode: 0o600 });
  await pruneStoreBackups(backupDir);
}

async function listStoreBackups(home: string): Promise<StoreBackupSummary[]> {
  const backupDir = path.join(home, "backups");
  const entries = await readdir(backupDir).catch(() => []);
  const backups: StoreBackupSummary[] = [];
  for (const entry of entries) {
    if (!/^store-\d{8}T\d{6}-\d+-\d+\.json$/.test(entry)) {
      continue;
    }

    const backupPath = path.join(backupDir, entry);
    const info = await stat(backupPath).catch(() => undefined);
    if (!info?.isFile()) {
      continue;
    }

    backups.push({
      path: backupPath,
      bytes: info.size,
      modifiedAt: info.mtime.toISOString()
    });
  }

  return backups.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
}

async function pruneStoreBackups(backupDir: string): Promise<void> {
  const backups = await listStoreBackups(path.dirname(backupDir));
  for (const backup of backups.slice(maxStoreBackups)) {
    await rm(backup.path, { force: true }).catch(() => undefined);
  }
}

function normalizeStoreFile(parsed: Partial<StoreFile>): StoreFile {
  const audit = parsed.audit || [];
  return {
    version: 1,
    secrets: (parsed.secrets || []).map((secret) => normalizeSecretRecord(secret)),
    requests: migrateRequestApprovalSources(parsed.requests || [], audit),
    audit,
    approvalSettings: normalizeApprovalSettings(parsed.approvalSettings),
    approvalGrants: Array.isArray(parsed.approvalGrants)
      ? parsed.approvalGrants.filter(isValidApprovalGrant)
      : [],
    approvalPolicyRules: storedApprovalPolicyRules(parsed.approvalPolicyRules)
  };
}

function storedApprovalPolicyRules(value: unknown): ApprovalPolicyRule[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error("approvalPolicyRules must be an array.");
  }
  return value.map((rule, index) => storedApprovalPolicyRule(rule, index));
}

function storedApprovalPolicyRule(value: unknown, index: number): ApprovalPolicyRule {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalidStoredApprovalPolicyRule(index, "rule must be an object.");
  }

  const rule = value as Partial<ApprovalPolicyRule>;
  if (typeof rule.id !== "string" || !rule.id.trim()) {
    throw invalidStoredApprovalPolicyRule(index, "id must be a non-empty string.");
  }
  if (typeof rule.name !== "string" || !rule.name.trim()) {
    throw invalidStoredApprovalPolicyRule(index, "name must be a non-empty string.");
  }
  if (typeof rule.enabled !== "boolean") {
    throw invalidStoredApprovalPolicyRule(index, "enabled must be a boolean.");
  }
  if (typeof rule.priority !== "number" || !Number.isFinite(rule.priority) || rule.priority < 0) {
    throw invalidStoredApprovalPolicyRule(index, "priority must be a non-negative finite number.");
  }
  if (!isApprovalPolicyDecision(rule.decision)) {
    throw invalidStoredApprovalPolicyRule(index, "decision must be allow, ask, or deny.");
  }
  if (!rule.conditions || typeof rule.conditions !== "object" || Array.isArray(rule.conditions)) {
    throw invalidStoredApprovalPolicyRule(index, "conditions must be an object.");
  }
  if (!isCanonicalPolicyTimestamp(rule.createdAt) || !isCanonicalPolicyTimestamp(rule.updatedAt)) {
    throw invalidStoredApprovalPolicyRule(index, "createdAt and updatedAt must be ISO timestamps.");
  }
  if (rule.expiresAt !== undefined && !isCanonicalPolicyTimestamp(rule.expiresAt)) {
    throw invalidStoredApprovalPolicyRule(index, "expiresAt must be an ISO timestamp.");
  }

  try {
    normalizeApprovalPolicyConditions(rule.conditions, true);
  } catch (error) {
    throw invalidStoredApprovalPolicyRule(index, errorMessage(error));
  }

  return rule as ApprovalPolicyRule;
}

function invalidStoredApprovalPolicyRule(index: number, message: string): Error {
  return new Error(`Invalid approval policy at index ${index}: ${message}`);
}

function migrateRequestApprovalSources(requests: RequestRecord[], auditLog: AuditEvent[]): RequestRecord[] {
  const sources = new Map<string, "grant" | "policy">();
  for (const event of auditLog) {
    if (!event.requestId) {
      continue;
    }
    if (event.type === "request.auto_approved") {
      sources.set(event.requestId, "grant");
    }
    if (event.type === "request.auto_approved_by_policy") {
      sources.set(event.requestId, "policy");
    }
  }

  return requests.map((request) => {
    if (request.approvalSource === "manual" || request.approvalSource === "grant" || request.approvalSource === "policy") {
      return request;
    }
    const source = sources.get(request.id);
    return source ? { ...request, approvalSource: source } : request;
  });
}

function normalizeSecretRecord(secret: SecretRecord): SecretRecord {
  if (!secret.cache || isValidSecretCache(secret.cache)) {
    return secret;
  }

  const clone = { ...secret };
  delete clone.cache;
  return clone;
}

function keychainRefPayload(ref: MacKeychainItemRef): Pick<MacKeychainItemRef, "service" | "account"> {
  return {
    service: ref.service,
    account: ref.account
  };
}

function keychainRefFromRecord(record: SecretRecord): MacKeychainItemRef {
  try {
    const decoded = JSON.parse(decryptSecret(record.encrypted)) as Partial<MacKeychainItemRef>;
    if (typeof decoded.service === "string" && typeof decoded.account === "string") {
      return {
        service: decoded.service,
        account: decoded.account,
        label: keychainSecretLabel(record.name)
      };
    }
  } catch {
    // Older experimental records may only have used the handle as account.
  }

  return {
    service: defaultSecretKeychainService(),
    account: record.handle,
    label: keychainSecretLabel(record.name)
  };
}

function keychainSecretLabel(name: string): string {
  const trimmed = name.trim();
  return `s-gw secret: ${trimmed || "credential"}`.slice(0, 128);
}

function credentialStoreProvider(): string {
  if (process.platform === "win32") return "windows-credential-manager";
  return process.platform === "linux" ? "linux-secret-service" : "macos-keychain";
}

function normalizeApprovalSettings(input?: Partial<ApprovalSettings>): ApprovalSettings {
  const mode = isApprovalMode(input?.mode) ? input.mode : defaultApprovalSettings.mode;
  return {
    mode,
    durationMs: clampApprovalDuration(input?.durationMs)
  };
}

function isApprovalMode(value: unknown): value is ApprovalMode {
  return value === "per-transaction" || value === "timed-session" || value === "login-session" || value === "always";
}

function isApprovalAgentScope(value: unknown): value is ApprovalAgentScope {
  return value === "same-agent" || value === "any-agent";
}

function clampApprovalDuration(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return defaultApprovalSettings.durationMs;
  }

  return Math.min(Math.max(Math.floor(value), 60_000), maxApprovalDurationMs);
}

function isValidApprovalGrant(grant: ApprovalGrant): boolean {
  return (
    Boolean(grant) &&
    typeof grant.id === "string" &&
    typeof grant.handle === "string" &&
    typeof grant.actionKey === "string" &&
    (grant.mode === "timed-session" || grant.mode === "login-session" || grant.mode === "always") &&
    typeof grant.loginSessionId === "string"
  );
}

function isValidSecretCache(cache: SecretValueCache): boolean {
  const approvalAuthorities = Number(typeof cache.approvalGrantId === "string") +
    Number(typeof cache.approvalPolicyRuleId === "string");
  return (
    Boolean(cache) &&
    cache.backend === "onepassword" &&
    typeof cache.fingerprint === "string" &&
    approvalAuthorities === 1 &&
    typeof cache.createdAt === "string" &&
    typeof cache.updatedAt === "string" &&
    isEncryptedBox(cache.encrypted)
  );
}

function isEncryptedBox(value: unknown): boolean {
  if (!value || typeof value !== "object") {
    return false;
  }

  const box = value as Record<string, unknown>;
  return (
    box.alg === "aes-256-gcm" &&
    box.kdf === "scrypt" &&
    typeof box.salt === "string" &&
    typeof box.iv === "string" &&
    typeof box.authTag === "string" &&
    typeof box.ciphertext === "string"
  );
}

function isTerminalRequestState(state: RequestState): boolean {
  return state === "denied" || state === "executed" || state === "failed";
}

function cachedOnePasswordValue(record: SecretRecord, request?: RequestRecord): string | undefined {
  const cache = record.cache;
  if (record.backend !== "onepassword" || !cache || !request) {
    return undefined;
  }

  const now = new Date().toISOString();
  const matchingGrant = Boolean(request.approvalGrantId && cache.approvalGrantId === request.approvalGrantId);
  const matchingPolicy = Boolean(
    request.approvalPolicyRuleId && cache.approvalPolicyRuleId === request.approvalPolicyRuleId
  );
  if (!isValidSecretCache(cache) || (!matchingGrant && !matchingPolicy)) {
    return undefined;
  }

  if (cache.expiresAt && cache.expiresAt <= now) {
    return undefined;
  }

  if (cache.loginSessionId && cache.loginSessionId !== currentLoginSessionId()) {
    return undefined;
  }

  return decryptSecret(cache.encrypted);
}

function grantAllowsCache(grant: ApprovalGrant, nowIso: string): boolean {
  if (!isValidApprovalGrant(grant)) {
    return false;
  }

  if (grant.expiresAt && grant.expiresAt <= nowIso) {
    return false;
  }

  return grant.mode === "always" || grant.loginSessionId === currentLoginSessionId();
}

function clearOnePasswordCaches(store: StoreFile, grantIds?: Set<string>): void {
  for (const secret of store.secrets) {
    if (!secret.cache?.approvalGrantId) {
      continue;
    }

    if (!grantIds || grantIds.has(secret.cache.approvalGrantId)) {
      delete secret.cache;
    }
  }
}

function clearOnePasswordPolicyCaches(store: StoreFile): void {
  for (const secret of store.secrets) {
    if (secret.cache?.approvalPolicyRuleId) {
      delete secret.cache;
    }
  }
}

function activeApprovalGrant(
  store: StoreFile,
  handle: string,
  action: CommandAction,
  agentName: string,
  nowIso: string,
  loginSessionId = currentLoginSessionId()
): ApprovalGrant | undefined {
  const settings = normalizeApprovalSettings(store.approvalSettings);
  store.approvalSettings = settings;

  const actionKey = approvalActionKey(handle, action);
  return store.approvalGrants.find((grant) => {
    if (grant.handle !== handle || grant.actionKey !== actionKey) {
      return false;
    }
    if (grant.mode !== "always" && grant.loginSessionId !== loginSessionId) {
      return false;
    }
    if ((grant.agentScope || "same-agent") === "same-agent" && grant.agentName !== agentName) {
      return false;
    }
    return !grant.expiresAt || grant.expiresAt > nowIso;
  });
}

function createApprovalGrant(
  store: StoreFile,
  request: RequestRecord,
  nowIso: string,
  options: ApproveRequestOptions = {}
): ApprovalGrant | undefined {
  const settings = normalizeApprovalSettings(store.approvalSettings);
  store.approvalSettings = settings;
  const mode = options.mode && isApprovalMode(options.mode) ? options.mode : settings.mode;
  if (mode === "per-transaction") {
    return undefined;
  }

  pruneExpiredApprovalGrants(store, nowIso);

  const loginSessionId = mode === "always" ? "" : request.loginSessionId;
  if (!loginSessionId && mode !== "always") {
    store.audit.push(audit(
      "approval.grant.skipped",
      `Approved legacy request ${request.id} once because it has no requester login-session identity.`,
      request.handle,
      request.id
    ));
    return undefined;
  }
  const actionKey = approvalActionKey(request.handle, request.action);
  const durationMs = clampApprovalDuration(options.durationMs ?? settings.durationMs);
  const expiresAt = mode === "timed-session"
    ? new Date(Date.parse(nowIso) + durationMs).toISOString()
    : undefined;
  const agentScope = isApprovalAgentScope(options.agentScope) ? options.agentScope : "same-agent";
  const agentName = request.agentName || requestAgentName(request.reason);
  const existing = store.approvalGrants.find((grant) => {
    return (
      grant.mode === mode &&
      grant.handle === request.handle &&
      grant.actionKey === actionKey &&
      grant.loginSessionId === loginSessionId &&
      (grant.agentScope || "same-agent") === agentScope &&
      (agentScope === "any-agent" || grant.agentName === agentName)
    );
  });

  if (existing) {
    existing.updatedAt = nowIso;
    existing.expiresAt = expiresAt;
    existing.lastRequestId = request.id;
    store.audit.push(audit("approval.grant.updated", `Updated approval grant ${existing.id}.`, request.handle, request.id));
    return existing;
  }

  const grant: ApprovalGrant = {
    id: shortId("grant"),
    handle: request.handle,
    actionKey,
    mode,
    agentScope,
    agentName: agentScope === "same-agent" ? agentName : undefined,
    loginSessionId: loginSessionId || "",
    createdAt: nowIso,
    updatedAt: nowIso,
    expiresAt,
    lastRequestId: request.id
  };

  store.approvalGrants.push(grant);
  store.audit.push(audit("approval.grant.created", `Created approval grant ${grant.id}.`, request.handle, request.id));
  return grant;
}

function requestReferencesHandle(request: RequestRecord, handle: string): boolean {
  return request.handle === handle || (request.action.env || []).some((binding) => binding.handle === handle);
}

interface ExecutionAdmissionContext {
  secret: SecretRecord;
  action: CommandAction;
  agent: AgentIdentity;
  loginSessionId?: string;
  now: string;
  policyRule?: ApprovalPolicyRule;
  grant?: ApprovalGrant;
}

function createRequestInStore(
  store: StoreFile,
  handle: string,
  action: CommandAction,
  reason: string,
  agentContext: AgentIdentityContext,
  options: { coalesce?: boolean } = {}
): RequestRecord {
  const now = new Date().toISOString();
  pruneExpiredApprovalGrants(store, now);
  const admission = executionAdmissionContext(store, handle, action, reason, agentContext, now);
  const { secret, agent, policyRule, grant } = admission;
  const deniedByPolicy = policyRule?.decision === "deny";
  const allowedByPolicy = policyRule?.decision === "allow";

  if (options.coalesce && deniedByPolicy && policyRule) {
    const existing = matchingDeniedRequest(
      store,
      handle,
      admission.action,
      agent.name,
      admission.loginSessionId,
      policyRule.id
    );
    if (existing) {
      return existing;
    }
  }

  if (options.coalesce && !deniedByPolicy && !allowedByPolicy && !grant) {
    const existing = matchingPendingRequest(
      store,
      handle,
      admission.action,
      agent.name,
      admission.loginSessionId
    );
    if (existing) {
      return existing;
    }
  }

  const record: RequestRecord = {
    id: shortId("req"),
    handle,
    reason: reason || "No reason supplied.",
    agentName: agent.name,
    agentSource: agent.source,
    loginSessionId: admission.loginSessionId,
    action: admission.action,
    state: deniedByPolicy ? "denied" : (grant || allowedByPolicy ? "approved" : "pending"),
    createdAt: now,
    updatedAt: now,
    approvedAt: grant || allowedByPolicy ? now : undefined,
    approvalSource: allowedByPolicy ? "policy" : (grant ? "grant" : undefined),
    approvalGrantId: grant?.id,
    approvalPolicyRuleId: policyRule?.id,
    deniedAt: deniedByPolicy ? now : undefined,
    error: deniedByPolicy ? `Denied by approval policy ${policyRule?.name || policyRule?.id}.` : undefined
  };

  if (grant) {
    grant.lastRequestId = record.id;
    grant.updatedAt = now;
  }

  store.requests.push(record);
  const superseded = record.state === "pending" ? supersedeOlderPendingDuplicates(store, record, now) : [];
  const eventType = deniedByPolicy
    ? "request.denied_by_policy"
    : (allowedByPolicy ? "request.auto_approved_by_policy" : (grant ? "request.auto_approved" : "request.created"));
  const message = requestCreationMessage(record, grant, policyRule, superseded.length);
  store.audit.push(audit(eventType, message, secret.handle, record.id));
  return record;
}

function oneShotExecutionAdmission(
  home: string,
  store: StoreFile,
  handle: string,
  action: CommandAction,
  reason: string,
  agentContext: AgentIdentityContext
): OneShotExecutionAdmission {
  const now = new Date().toISOString();
  pruneExpiredApprovalGrants(store, now);
  const admission = executionAdmissionContext(store, handle, action, reason, agentContext, now);
  if (admission.action.kind !== "env_command") {
    return {
      kind: "request",
      request: createRequestInStore(store, handle, action, reason, agentContext, { coalesce: true })
    };
  }
  const { policyRule, grant } = admission;
  if (policyRule?.decision === "deny") {
    return {
      kind: "request",
      request: createRequestInStore(store, handle, action, reason, agentContext, { coalesce: true })
    };
  }

  if (policyRule?.decision === "allow") {
    return {
      kind: "reusable",
      permit: reusableExecutionPermit(home, store, handle, admission.action, reason, admission.agent, admission.now, {
        kind: "policy",
        id: policyRule.id
      })
    };
  }

  if (grant) {
    return {
      kind: "reusable",
      permit: reusableExecutionPermit(home, store, handle, admission.action, reason, admission.agent, admission.now, {
        kind: "grant",
        id: grant.id
      })
    };
  }

  return {
    kind: "request",
    request: createRequestInStore(store, handle, action, reason, agentContext, { coalesce: true })
  };
}

function executionAdmissionContext(
  store: StoreFile,
  handle: string,
  action: CommandAction,
  reason: string,
  agentContext: AgentIdentityContext,
  now = new Date().toISOString()
): ExecutionAdmissionContext {
  const secret = store.secrets.find((item) => item.handle === handle);
  if (!secret) {
    throw new Error(`Unknown secret handle: ${handle}`);
  }

  const normalizedAction = normalizeAction(action);
  const agent = requestAgentIdentity(reason, agentContext);
  const loginSessionId = currentLoginSessionId();
  assertActionAllowed(secret, normalizedAction);
  assertBoundHandlesAllowed(store, handle, normalizedAction);
  const admittedAction = actionForAdmission(normalizedAction);
  const policyRule = matchingApprovalPolicyRuleForAction(store, secret, admittedAction, agent.name, now);
  const grant = activeApprovalGrant(store, handle, admittedAction, agent.name, now, loginSessionId);
  return { secret, action: admittedAction, agent, loginSessionId, now, policyRule, grant };
}

function automaticRequestAuthorizationError(
  store: StoreFile,
  request: RequestRecord,
  nowIso: string
): string | undefined {
  if (request.approvalSource === "grant") {
    const agentName = request.agentName || requestAgentName(request.reason);
    const grant = activeApprovalGrant(store, request.handle, request.action, agentName, nowIso);
    if (!request.approvalGrantId || !grant || grant.id !== request.approvalGrantId) {
      return "The reusable approval for this request was revoked or expired; request approval again.";
    }
  }

  if (request.approvalSource === "policy") {
    const secret = store.secrets.find((item) => item.handle === request.handle);
    const agentName = request.agentName || requestAgentName(request.reason);
    const policyRule = secret
      ? matchingApprovalPolicyRuleForAction(store, secret, request.action, agentName, nowIso)
      : undefined;
    if (
      !request.approvalPolicyRuleId ||
      policyRule?.decision !== "allow" ||
      policyRule.id !== request.approvalPolicyRuleId
    ) {
      return "The approval policy for this request changed or no longer allows it; request approval again.";
    }
  }

  return undefined;
}

function validatedReusableExecutionRequest(store: StoreFile, permit: ReusableExecutionPermit): RequestRecord {
  if (controlPlaneFingerprint(store) !== permit.controlFingerprint) {
    throw new Error("s-gw execution authorization changed before the command started; retry the command.");
  }

  const secret = store.secrets.find((item) => item.handle === permit.handle);
  if (!secret) {
    throw new Error(`Unknown secret handle: ${permit.handle}`);
  }

  const action = actionReadyForExecution(permit.action);
  assertActionAllowed(secret, action);
  assertBoundHandlesAllowed(store, permit.handle, action);

  const now = new Date().toISOString();
  const policyRule = matchingApprovalPolicyRuleForAction(store, secret, action, permit.agentName, now);
  if (policyRule?.decision === "deny") {
    throw new Error(`Execution is denied by approval policy ${policyRule.name}.`);
  }

  if (permit.authorization.kind === "policy") {
    if (policyRule?.decision !== "allow" || policyRule.id !== permit.authorization.id) {
      throw new Error("s-gw approval policy changed before the command started; retry the command.");
    }
  } else {
    if (policyRule?.decision === "allow") {
      throw new Error("s-gw approval policy changed before the command started; retry the command.");
    }
    const grant = activeApprovalGrant(store, permit.handle, action, permit.agentName, now);
    if (!grant || grant.id !== permit.authorization.id) {
      throw new Error("s-gw approval grant is no longer valid; request approval again.");
    }
  }

  return {
    id: permit.id,
    handle: permit.handle,
    reason: permit.reason,
    agentName: permit.agentName,
    agentSource: permit.agentSource,
    action,
    state: "approved",
    createdAt: permit.createdAt,
    updatedAt: now,
    approvedAt: now,
    approvalSource: permit.authorization.kind,
    approvalGrantId: permit.authorization.kind === "grant" ? permit.authorization.id : undefined,
    approvalPolicyRuleId: permit.authorization.kind === "policy" ? permit.authorization.id : undefined
  };
}

function reusableExecutionPermit(
  home: string,
  store: StoreFile,
  handle: string,
  action: CommandAction,
  reason: string,
  agent: AgentIdentity,
  createdAt: string,
  authorization: ReusableExecutionPermit["authorization"]
): ReusableExecutionPermit {
  const frozenAction = freezeAction(action);
  const permit = Object.freeze({
    id: shortId("run"),
    handle,
    reason: reason || "No reason supplied.",
    agentName: agent.name,
    agentSource: agent.source,
    action: frozenAction,
    createdAt,
    controlFingerprint: controlPlaneFingerprint(store),
    authorization: Object.freeze({ ...authorization })
  }) as ReusableExecutionPermit;
  reusableExecutionPermits.set(permit, path.resolve(home));
  return permit;
}

function freezeAction(action: CommandAction): CommandAction {
  const env = (action.env || []).map((binding) => Object.freeze({ ...binding }));
  const ssh = action.ssh ? Object.freeze({ ...action.ssh }) : undefined;
  const copy = {
    ...action,
    args: Object.freeze([...action.args]),
    env: Object.freeze(env),
    ssh
  };
  return Object.freeze(copy) as CommandAction;
}

function matchingPendingRequest(
  store: StoreFile,
  handle: string,
  action: CommandAction,
  agentName: string,
  loginSessionId?: string
): RequestRecord | undefined {
  const key = requestDuplicateKeyFor(handle, action, agentName, loginSessionId);
  for (let index = store.requests.length - 1; index >= 0; index -= 1) {
    const request = store.requests[index];
    if (request.state === "pending" && requestDuplicateKey(request) === key) {
      return request;
    }
  }
  return undefined;
}

function matchingDeniedRequest(
  store: StoreFile,
  handle: string,
  action: CommandAction,
  agentName: string,
  loginSessionId: string | undefined,
  policyRuleId: string
): RequestRecord | undefined {
  const key = requestDuplicateKeyFor(handle, action, agentName, loginSessionId);
  for (let index = store.requests.length - 1; index >= 0; index -= 1) {
    const request = store.requests[index];
    if (
      request.state === "denied" &&
      request.approvalPolicyRuleId === policyRuleId &&
      requestDuplicateKey(request) === key
    ) {
      return request;
    }
  }
  return undefined;
}

function requestDuplicateKey(request: RequestRecord): string {
  return requestDuplicateKeyFor(
    request.handle,
    request.action,
    request.agentName || requestAgentName(request.reason),
    request.loginSessionId || ""
  );
}

function requestDuplicateKeyFor(
  handle: string,
  action: CommandAction,
  agentName: string,
  loginSessionId?: string
): string {
  return JSON.stringify({
    handle,
    actionKey: approvalActionKey(handle, action),
    agentName,
    loginSessionId: loginSessionId || ""
  });
}

function assertReusableExecutionPermit(permit: ReusableExecutionPermit, home: string): void {
  if (
    !permit ||
    reusableExecutionPermits.get(permit) !== path.resolve(home) ||
    typeof permit.id !== "string" || !permit.id ||
    typeof permit.handle !== "string" || !permit.handle ||
    typeof permit.reason !== "string" ||
    typeof permit.agentName !== "string" || !permit.agentName ||
    !isAgentIdentitySource(permit.agentSource) ||
    typeof permit.createdAt !== "string" ||
    typeof permit.controlFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(permit.controlFingerprint) ||
    !permit.authorization ||
    (permit.authorization.kind !== "grant" && permit.authorization.kind !== "policy") ||
    typeof permit.authorization.id !== "string" || !permit.authorization.id
  ) {
    throw new Error("Invalid s-gw reusable execution permit.");
  }
}

function isAgentIdentitySource(value: unknown): value is AgentIdentitySource {
  return value === "configured" ||
    value === "mcp-client" ||
    value === "runtime" ||
    value === "process" ||
    value === "reason" ||
    value === "manual" ||
    value === "unknown";
}

function supersedeOlderPendingDuplicates(store: StoreFile, latest: RequestRecord, nowIso: string): RequestRecord[] {
  const latestKey = requestDuplicateKey(latest);
  const superseded: RequestRecord[] = [];
  for (const request of store.requests) {
    if (request.id === latest.id || request.state !== "pending") {
      continue;
    }
    if (requestDuplicateKey(request) !== latestKey) {
      continue;
    }

    request.state = "failed";
    request.updatedAt = nowIso;
    request.error = `Superseded by newer duplicate pending request ${latest.id}.`;
    superseded.push(request);
    store.audit.push(
      audit("request.superseded", `Request ${request.id} was superseded by newer duplicate ${latest.id}.`, request.handle, request.id)
    );
  }

  return superseded;
}

function cleanupDuplicatePendingRequests(store: StoreFile, nowIso: string): RequestRecord[] {
  const newestByKey = new Map<string, RequestRecord>();
  const pending = store.requests
    .filter((request) => request.state === "pending")
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

  const cleaned: RequestRecord[] = [];
  for (const request of pending) {
    const key = requestDuplicateKey(request);
    const newest = newestByKey.get(key);
    if (!newest) {
      newestByKey.set(key, request);
      continue;
    }

    request.state = "failed";
    request.updatedAt = nowIso;
    request.error = `Superseded by newer duplicate pending request ${newest.id}.`;
    cleaned.push(request);
    store.audit.push(
      audit("request.superseded", `Cleaned duplicate pending request ${request.id}; newest is ${newest.id}.`, request.handle, request.id)
    );
  }

  return cleaned;
}

function cleanupOldRequests(
  store: StoreFile,
  nowIso: string,
  pendingOlderThanMs: number,
  approvedOlderThanMs: number
): RequestRecord[] {
  const now = Date.parse(nowIso);
  const cleaned: RequestRecord[] = [];
  for (const request of store.requests) {
    if (request.state !== "pending" && request.state !== "approved") {
      continue;
    }

    const timestamp = request.state === "approved" && request.approvedAt
      ? Date.parse(request.approvedAt)
      : Date.parse(request.createdAt);
    if (!Number.isFinite(timestamp)) {
      continue;
    }

    const ttl = request.state === "approved" ? approvedOlderThanMs : pendingOlderThanMs;
    if (!Number.isFinite(ttl) || ttl <= 0 || now - timestamp < ttl) {
      continue;
    }

    const oldState = request.state;
    request.state = "failed";
    request.updatedAt = nowIso;
    request.error = oldState === "approved"
      ? "Approved request expired before execution. Create a fresh request to retry."
      : "Pending request expired before approval. Create a fresh request to retry.";
    cleaned.push(request);
    store.audit.push(audit("request.expired", `Cleaned stale ${oldState} request ${request.id}.`, request.handle, request.id));
  }

  return cleaned;
}

function sortRequestsForOperators(requests: RequestRecord[]): RequestRecord[] {
  const rank: Record<RequestState, number> = {
    pending: 0,
    approved: 1,
    executing: 2,
    failed: 3,
    denied: 4,
    executed: 5
  };

  return [...requests].sort((a, b) => {
    const rankOrder = rank[a.state] - rank[b.state];
    return rankOrder || b.updatedAt.localeCompare(a.updatedAt);
  });
}

function normalizeListLimit(value?: number): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Number.isFinite(value) || value <= 0) {
    return undefined;
  }

  return Math.min(Math.floor(value), 1000);
}

function reapStaleExecutions(store: StoreFile, nowIso: string): RequestRecord[] {
  const cutoff = Date.parse(nowIso) - staleExecutionMs;
  const recovered: RequestRecord[] = [];

  for (const request of store.requests) {
    if (request.state !== "executing") {
      continue;
    }

    const claimedAt = Date.parse(request.updatedAt);
    // Leave a NaN timestamp alone rather than failing a request we cannot reason about.
    if (Number.isFinite(claimedAt) && claimedAt > cutoff) {
      continue;
    }

    request.state = "failed";
    request.updatedAt = nowIso;
    request.error = "Execution was interrupted before it finished. Create a new request to retry.";
    store.audit.push(
      audit("request.recovered", `Recovered stranded execution request ${request.id}.`, request.handle, request.id)
    );
    recovered.push(request);
  }

  return recovered;
}

function pruneExpiredApprovalGrants(store: StoreFile, nowIso: string): void {
  migrateApprovalGrantActionKeys(store);

  const active = (store.approvalGrants || []).filter((grant) => {
    return isValidApprovalGrant(grant) && (!grant.expiresAt || grant.expiresAt > nowIso);
  });
  const byIdentity = new Map<string, ApprovalGrant>();
  for (const grant of active) {
    const key = approvalGrantIdentityKey(grant);
    const existing = byIdentity.get(key);
    if (!existing || approvalGrantIsNewer(grant, existing)) {
      byIdentity.set(key, grant);
    }
  }
  store.approvalGrants = [...byIdentity.values()];
  pruneOnePasswordCaches(store, nowIso);
}

function pruneOnePasswordCaches(store: StoreFile, nowIso: string): void {
  const liveGrantIds = new Set(
    store.approvalGrants
      .filter((grant) => grantAllowsCache(grant, nowIso))
      .map((grant) => grant.id)
  );

  for (const secret of store.secrets) {
    const cache = secret.cache;
    if (!cache) {
      continue;
    }
    const policy = cache.approvalPolicyRuleId
      ? (store.approvalPolicyRules || []).find((rule) => rule.id === cache.approvalPolicyRuleId)
      : undefined;
    const policyIsLive = Boolean(
      policy &&
      isValidApprovalPolicyRule(policy) &&
      policy.enabled &&
      policy.decision === "allow" &&
      (!policy.expiresAt || policy.expiresAt > nowIso)
    );
    const authorityIsLive = cache.approvalGrantId
      ? liveGrantIds.has(cache.approvalGrantId)
      : policyIsLive;

    if (
      !isValidSecretCache(cache) ||
      !authorityIsLive ||
      (cache.expiresAt && cache.expiresAt <= nowIso) ||
      (cache.loginSessionId && cache.loginSessionId !== currentLoginSessionId())
    ) {
      delete secret.cache;
    }
  }
}

function migrateApprovalGrantActionKeys(store: StoreFile): void {
  const requestsById = new Map(store.requests.map((request) => [request.id, request]));
  for (const grant of store.approvalGrants || []) {
    if (!isValidApprovalGrant(grant) || !grant.lastRequestId) {
      continue;
    }

    const request = requestsById.get(grant.lastRequestId);
    if (!request || request.handle !== grant.handle) {
      continue;
    }

    grant.actionKey = approvalActionKey(request.handle, request.action);
  }
}

function approvalGrantIdentityKey(grant: ApprovalGrant): string {
  return JSON.stringify({
    handle: grant.handle,
    actionKey: grant.actionKey,
    mode: grant.mode,
    agentScope: grant.agentScope || "same-agent",
    agentName: grant.agentScope === "any-agent" ? "" : grant.agentName || "",
    loginSessionId: grant.mode === "always" ? "" : grant.loginSessionId
  });
}

function approvalGrantIsNewer(candidate: ApprovalGrant, current: ApprovalGrant): boolean {
  const candidateExpires = candidate.expiresAt ? Date.parse(candidate.expiresAt) : Number.POSITIVE_INFINITY;
  const currentExpires = current.expiresAt ? Date.parse(current.expiresAt) : Number.POSITIVE_INFINITY;
  if (candidateExpires !== currentExpires) {
    return candidateExpires > currentExpires;
  }
  return candidate.updatedAt > current.updatedAt;
}

function approvalActionKey(handle: string, action: CommandAction): string {
  const normalized = normalizeAction(action);
  const payload = {
    handle,
    kind: normalized.kind,
    command: normalizeCommandGrant(normalized.command),
    resolvedCommand: normalized.kind === "env_command" ? normalized.resolvedCommand || "" : "",
    injectEnv: normalized.injectEnv,
    env: normalized.env || [],
    workingDir: normalized.workingDir ? path.resolve(normalized.workingDir) : "",
    ssh: normalized.kind === "ssh_session" && normalized.ssh ? sshSessionIdentity(normalized) : ""
  };

  return createHash("sha256").update(JSON.stringify(payload)).digest("base64url");
}

function matchingApprovalPolicyRule(
  store: StoreFile,
  secret: SecretRecord,
  action: CommandAction,
  agentName: string,
  nowIso: string,
  envBindings: CommandEnvBinding[]
): ApprovalPolicyRule | undefined {
  const rules = sortApprovalPolicyRules(store.approvalPolicyRules || []);
  for (const rule of rules) {
    if (!rule.enabled || !isValidApprovalPolicyRule(rule)) {
      continue;
    }
    if (rule.expiresAt && rule.expiresAt <= nowIso) {
      continue;
    }
    if (approvalPolicyMatches(rule, secret, action, agentName, envBindings)) {
      return rule;
    }
  }

  return undefined;
}

function matchingApprovalPolicyRuleForAction(
  store: StoreFile,
  primarySecret: SecretRecord,
  action: CommandAction,
  agentName: string,
  nowIso: string
): ApprovalPolicyRule | undefined {
  const envBindings = policyEnvBindingsForAction(primarySecret.handle, action);
  const matched = [
    matchingApprovalPolicyRule(store, primarySecret, policyActionForBinding(action, action.injectEnv), agentName, nowIso, envBindings)
  ];
  for (const binding of action.env || []) {
    const secret = store.secrets.find((item) => item.handle === binding.handle);
    if (!secret) {
      throw new Error(`Unknown secret handle: ${binding.handle}`);
    }
    matched.push(
      matchingApprovalPolicyRule(store, secret, policyActionForBinding(action, binding.injectEnv), agentName, nowIso, envBindings)
    );
  }

  const denied = matched.find((rule) => rule?.decision === "deny");
  if (denied) {
    return denied;
  }

  const primaryRule = matched[0];
  if (primaryRule?.decision !== "allow") {
    return primaryRule;
  }

  return matched.every((rule) => rule?.decision === "allow" && rule.id === primaryRule.id)
    ? primaryRule
    : undefined;
}

function blockingDenyPolicyRuleForAction(
  store: StoreFile,
  primarySecret: SecretRecord,
  action: CommandAction,
  agentName: string,
  nowIso: string
): ApprovalPolicyRule | undefined {
  const envBindings = policyEnvBindingsForAction(primarySecret.handle, action);
  const secrets = [
    { secret: primarySecret, action: policyActionForBinding(action, action.injectEnv) },
    ...(action.env || []).map((binding) => {
      const secret = store.secrets.find((item) => item.handle === binding.handle);
      if (!secret) {
        throw new Error(`Unknown secret handle: ${binding.handle}`);
      }
      return { secret, action: policyActionForBinding(action, binding.injectEnv) };
    })
  ];

  for (const rule of sortApprovalPolicyRules(store.approvalPolicyRules || [])) {
    if (!rule.enabled || rule.decision !== "deny" || !isValidApprovalPolicyRule(rule)) {
      continue;
    }
    if (rule.expiresAt && rule.expiresAt <= nowIso) {
      continue;
    }
    if (secrets.some((item) => approvalPolicyMatches(rule, item.secret, item.action, agentName, envBindings))) {
      return rule;
    }
  }

  return undefined;
}

function policyActionForBinding(action: CommandAction, injectEnv: string): CommandAction {
  return { ...action, injectEnv, env: [] };
}

function approvalPolicyMatches(
  rule: ApprovalPolicyRule,
  secret: SecretRecord,
  action: CommandAction,
  agentName: string,
  envBindings: CommandEnvBinding[]
): boolean {
  const conditions = normalizeApprovalPolicyConditions(rule.conditions);
  if (conditions.handles?.length && !conditions.handles.includes(secret.handle)) {
    return false;
  }
  if (conditions.envBindings?.length && !samePolicyEnvBindings(conditions.envBindings, envBindings)) {
    return false;
  }
  if (conditions.secretTypes?.length && !conditions.secretTypes.includes(secret.type)) {
    return false;
  }
  if (conditions.providers?.length && !conditions.providers.includes((secret.provider || "").toLowerCase())) {
    return false;
  }
  if (conditions.minSeverity && severityRank(secret.severity || "low") < severityRank(conditions.minSeverity)) {
    return false;
  }

  if (conditions.agents?.length && !conditions.agents.includes(agentName.toLowerCase())) {
    return false;
  }
  if (conditions.actionKinds?.length && !conditions.actionKinds.includes(action.kind)) {
    return false;
  }
  if (conditions.commands?.length) {
    const requested = normalizeCommandGrant(action.command);
    if (!conditions.commands.includes(requested)) {
      return false;
    }
  }
  if (action.kind === "env_command") {
    const resolved = action.resolvedCommand;
    if (rule.decision === "allow" && !conditions.resolvedCommands?.length) {
      return false;
    }
    if (conditions.resolvedCommands?.length &&
        (!resolved || !conditions.resolvedCommands.some((candidate) => samePolicyExecutable(candidate, resolved)))) {
      return false;
    }
  } else if (conditions.resolvedCommands?.length) {
    return false;
  }
  if (conditions.injectEnvs?.length) {
    if (!conditions.injectEnvs.includes(action.injectEnv)) {
      return false;
    }
  }
  if (conditions.workingDirs?.length) {
    const cwd = action.workingDir ? path.resolve(action.workingDir) : "";
    if (!conditions.workingDirs.includes(cwd)) {
      return false;
    }
  }
  if (conditions.sshTargets?.length) {
    const target = action.ssh?.target ? normalizeSshTarget(action.ssh.target) : "";
    if (!conditions.sshTargets.includes(target)) {
      return false;
    }
  }
  if (conditions.sshPorts?.length) {
    const port = action.ssh?.port ? normalizeSshPort(action.ssh.port) : undefined;
    if (!port || !conditions.sshPorts.includes(port)) {
      return false;
    }
  }

  return true;
}

function policyEnvBindingsForAction(primaryHandle: string, action: CommandAction): CommandEnvBinding[] {
  return normalizePolicyEnvBindings([
    { handle: primaryHandle, injectEnv: action.injectEnv },
    ...(action.env || [])
  ], true);
}

function samePolicyEnvBindings(expected: CommandEnvBinding[], actual: CommandEnvBinding[]): boolean {
  if (expected.length !== actual.length) {
    return false;
  }

  return expected.every((binding, index) => {
    const candidate = actual[index];
    return candidate?.handle === binding.handle && candidate.injectEnv === binding.injectEnv;
  });
}

function requestCreationMessage(
  record: RequestRecord,
  grant: ApprovalGrant | undefined,
  policyRule: ApprovalPolicyRule | undefined,
  supersededCount: number
): string {
  if (policyRule?.decision === "deny") {
    return `Denied execution request ${record.id} by approval policy ${policyRule.name}.`;
  }
  if (policyRule?.decision === "allow") {
    return `Created execution request ${record.id} using approval policy ${policyRule.name}.`;
  }
  if (grant) {
    return `Created execution request ${record.id} using approval grant ${grant.id}.`;
  }
  return `Created execution request ${record.id}${supersededCount ? ` and superseded ${supersededCount} older duplicate(s)` : ""}.`;
}

function addApprovalPolicyRuleInStore(
  store: StoreFile,
  input: AddApprovalPolicyRuleInput,
  now: string,
  auditContext: { handle?: string; requestId?: string } = {}
): ApprovalPolicyRule {
  const decision = requireApprovalPolicyDecision(input.decision);
  const rule = normalizeApprovalPolicyRule(
    {
      id: shortId("policy"),
      name: policyRuleName(input.name, decision),
      enabled: input.enabled === undefined ? true : requirePolicyEnabled(input.enabled),
      priority: input.priority === undefined ? nextPolicyPriority(store) : requirePolicyPriority(input.priority),
      decision,
      conditions: normalizeApprovalPolicyConditions(input.conditions, true),
      expiresAt: policyExpiresAt(input, now),
      createdAt: now,
      updatedAt: now
    },
    now
  );

  store.approvalPolicyRules = sortApprovalPolicyRules([...(store.approvalPolicyRules || []), rule]);
  store.audit.push(audit("approval.policy.created", `Created approval policy ${rule.name}.`, auditContext.handle, auditContext.requestId));
  return rule;
}

function approvePendingRequest(
  store: StoreFile,
  request: RequestRecord,
  id: string,
  options: ApproveRequestOptions,
  now = new Date().toISOString(),
  policyRule?: ApprovalPolicyRule
): void {
  if (request.state === "approved" || request.state === "executing" || request.state === "executed") {
    return;
  }
  if (request.state !== "pending") {
    throw new Error(`Only pending requests can be approved. Current state: ${request.state}`);
  }

  request.state = "approved";
  request.approvedAt = now;
  request.updatedAt = now;
  request.approvalSource = policyRule ? "policy" : "manual";
  request.approvalPolicyRuleId = policyRule?.id;
  const grant = createApprovalGrant(store, request, now, options);
  request.approvalGrantId = grant?.id;
  store.audit.push(
    policyRule
      ? audit("request.approved_by_policy", `Approved execution request ${id} with approval policy ${policyRule.name}.`, request.handle, id)
      : audit("request.approved", `Approved execution request ${id}.`, request.handle, id)
  );
}

function durablePolicyAgentName(request: RequestRecord): string {
  const stored = request.agentName?.trim();
  if (stored && (stored !== "Agent" || request.agentSource !== "unknown")) {
    return stored;
  }

  const derived = agentNameFromReason(request.reason);
  if (derived !== "Agent") {
    return derived;
  }

  throw new Error("s-gw could not identify the requesting agent. Approve once or create a policy with an explicit agent condition.");
}

function scopedAllowPolicyInput(request: RequestRecord, agent: string): AddApprovalPolicyRuleInput {
  const action = request.action;
  if (action.kind === "env_command" && !action.resolvedCommand) {
    throw new Error("This legacy request has no pinned executable. Create a new request before creating an allow policy.");
  }
  const bindings = policyEnvBindingsForAction(request.handle, action);
  const handles = uniqueStrings(bindings.map((binding) => binding.handle));
  const injectEnvs = uniqueStrings(bindings.map((binding) => binding.injectEnv));
  const actionLabel = action.kind === "ssh_session"
    ? `SSH ${action.ssh?.target || "session"}`
    : path.basename(action.command);

  return {
    name: `Allow ${agent || "agent"} to use ${actionLabel}`.slice(0, 120),
    decision: "allow",
    conditions: {
      handles,
      envBindings: bindings,
      agents: [agent],
      actionKinds: [action.kind],
      commands: [action.command],
      resolvedCommands: action.kind === "env_command" ? [action.resolvedCommand!] : [],
      injectEnvs,
      workingDirs: action.workingDir ? [action.workingDir] : [],
      sshTargets: action.ssh?.target ? [action.ssh.target] : [],
      sshPorts: action.ssh?.port ? [action.ssh.port] : []
    }
  };
}

function normalizeApprovalPolicyRule(rule: Partial<ApprovalPolicyRule>, nowIso = new Date().toISOString()): ApprovalPolicyRule {
  const decision = isApprovalPolicyDecision(rule.decision) ? rule.decision : "ask";
  return {
    id: typeof rule.id === "string" && rule.id.trim() ? rule.id.trim() : shortId("policy"),
    name: typeof rule.name === "string" && rule.name.trim() ? rule.name.trim().slice(0, 120) : defaultPolicyRuleName(decision),
    enabled: rule.enabled !== false,
    priority: normalizePolicyPriority(rule.priority),
    decision,
    conditions: normalizeApprovalPolicyConditions(rule.conditions),
    expiresAt: normalizePolicyExpiresAt(rule.expiresAt),
    createdAt: typeof rule.createdAt === "string" && rule.createdAt ? rule.createdAt : nowIso,
    updatedAt: typeof rule.updatedAt === "string" && rule.updatedAt ? rule.updatedAt : nowIso
  };
}

function normalizeApprovalPolicyConditions(
  input?: Partial<ApprovalPolicyConditions>,
  strict = false
): ApprovalPolicyConditions {
  if (input !== undefined && (!input || typeof input !== "object" || Array.isArray(input))) {
    if (strict) {
      throw new Error("conditions must be an object.");
    }
    return {};
  }

  const secretTypes = policyStringValues(input?.secretTypes, "secretTypes", strict);
  const actionKinds = policyStringValues(input?.actionKinds, "actionKinds", strict);
  const commands = policyStringValues(input?.commands, "commands", strict);
  const resolvedCommands = policyStringValues(input?.resolvedCommands, "resolvedCommands", strict);
  const minSeverity = normalizePolicySeverity(input?.minSeverity, strict);

  return {
    handles: policyStringValues(input?.handles, "handles", strict),
    envBindings: normalizePolicyEnvBindings(input?.envBindings, strict),
    secretTypes: normalizePolicySecretTypes(secretTypes, strict),
    providers: policyStringValues(input?.providers, "providers", strict).map((provider) => provider.toLowerCase()),
    minSeverity,
    agents: policyStringValues(input?.agents, "agents", strict).map((agent) => agent.toLowerCase()),
    actionKinds: normalizePolicyActionKinds(actionKinds, strict),
    commands: strict
      ? commands.map((command) => normalizeCommandGrant(command))
      : commands.map((command) => safeNormalizeCommandGrant(command)).filter(Boolean) as string[],
    resolvedCommands: strict
      ? resolvedCommands.map(normalizeResolvedPolicyCommand)
      : resolvedCommands.map(safeNormalizeResolvedPolicyCommand).filter(Boolean) as string[],
    injectEnvs: policyStringValues(input?.injectEnvs, "injectEnvs", strict),
    workingDirs: policyStringValues(input?.workingDirs, "workingDirs", strict).map((dir) => path.resolve(dir)),
    sshTargets: policyStringValues(input?.sshTargets, "sshTargets", strict).map((target) => normalizeSshTarget(target)),
    sshPorts: normalizePolicyPorts(input?.sshPorts, strict)
  };
}

function mergeApprovalPolicyConditions(
  existing: ApprovalPolicyConditions,
  patch: Partial<ApprovalPolicyConditions>
): ApprovalPolicyConditions {
  const current = normalizeApprovalPolicyConditions(existing);
  const normalizedPatch = normalizeApprovalPolicyConditions(patch, true);
  const merged: ApprovalPolicyConditions = { ...current };
  for (const field of approvalPolicyConditionFields) {
    if (hasOwn(patch, field)) {
      merged[field] = normalizedPatch[field] as never;
    }
  }

  return merged;
}

function hasApprovalPolicyUpdate(input: UpdateApprovalPolicyRuleInput): boolean {
  if (
    input.name !== undefined ||
    input.enabled !== undefined ||
    input.priority !== undefined ||
    input.decision !== undefined ||
    input.expiresAt !== undefined ||
    input.durationMs !== undefined
  ) {
    return true;
  }

  const conditions = input.conditions;
  if (conditions === undefined) {
    return false;
  }
  if (!conditions || typeof conditions !== "object" || Array.isArray(conditions)) {
    return true;
  }

  return approvalPolicyConditionFields.some((field) => hasOwn(conditions, field));
}

function exactBindingsWouldConflict(
  existing: ApprovalPolicyConditions,
  patch: Partial<ApprovalPolicyConditions> | undefined
): boolean {
  if (!existing.envBindings?.length || !patch || typeof patch !== "object" || Array.isArray(patch)) {
    return false;
  }

  return hasOwn(patch, "envBindings") || hasOwn(patch, "handles") || hasOwn(patch, "injectEnvs");
}

function sameApprovalPolicyRuleContent(left: ApprovalPolicyRule, right: ApprovalPolicyRule): boolean {
  return left.name === right.name &&
    left.enabled === right.enabled &&
    left.priority === right.priority &&
    left.decision === right.decision &&
    left.expiresAt === right.expiresAt &&
    JSON.stringify(normalizeApprovalPolicyConditions(left.conditions)) ===
      JSON.stringify(normalizeApprovalPolicyConditions(right.conditions));
}

function policyStringValues(value: unknown, field: string, strict: boolean): string[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    if (strict) {
      throw new Error(`${field} must be an array of strings.`);
    }
    return [];
  }
  if (strict && value.some((item) => !item.trim())) {
    throw new Error(`${field} must not contain empty strings.`);
  }

  return uniqueStrings(value);
}

function normalizePolicyEnvBindings(value: unknown, strict: boolean): CommandEnvBinding[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    if (strict) {
      throw new Error("envBindings must be an array of handle and environment-variable pairs.");
    }
    return [];
  }

  const bindings: CommandEnvBinding[] = [];
  const seenEnvs = new Set<string>();
  const seenPairs = new Set<string>();
  for (const item of value) {
    const handle = typeof item?.handle === "string" ? item.handle.trim() : "";
    const injectEnv = typeof item?.injectEnv === "string" ? item.injectEnv.trim() : "";
    if (!handle || handle.includes("\0") || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(injectEnv)) {
      if (strict) {
        throw new Error("envBindings must contain non-empty handles and valid environment-variable names.");
      }
      continue;
    }
    if (seenEnvs.has(injectEnv)) {
      if (strict) {
        throw new Error(`Environment variable ${injectEnv} is bound more than once.`);
      }
      continue;
    }

    const key = `${handle}\0${injectEnv}`;
    if (seenPairs.has(key)) {
      continue;
    }
    seenEnvs.add(injectEnv);
    seenPairs.add(key);
    bindings.push({ handle, injectEnv });
  }

  return bindings.sort((left, right) => {
    const envOrder = left.injectEnv.localeCompare(right.injectEnv);
    return envOrder || left.handle.localeCompare(right.handle);
  });
}

function normalizePolicySecretTypes(values: string[], strict: boolean): SecretType[] {
  const types = values.filter(isSecretType);
  if (strict && types.length !== values.length) {
    throw new Error("secretTypes contains an unsupported credential type.");
  }
  return types;
}

function normalizePolicyActionKinds(values: string[], strict: boolean): ApprovalPolicyActionKind[] {
  const kinds = values.filter((value): value is ApprovalPolicyActionKind => value === "env_command" || value === "ssh_session");
  if (strict && kinds.length !== values.length) {
    throw new Error("actionKinds must contain env_command or ssh_session.");
  }
  return kinds;
}

function normalizePolicySeverity(value: unknown, strict: boolean): SecretSeverity | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  if (isSecretSeverity(value)) {
    return value;
  }
  if (strict) {
    throw new Error("minSeverity must be low, medium, high, or critical.");
  }
  return undefined;
}

function normalizePolicyPorts(value: unknown, strict: boolean): number[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    if (strict) {
      throw new Error("sshPorts must be an array of port numbers.");
    }
    return [];
  }

  const ports: number[] = [];
  for (const item of value) {
    const port = Number(item);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      if (strict) {
        throw new Error("sshPorts must contain integers from 1 through 65535.");
      }
      continue;
    }
    if (!ports.includes(port)) {
      ports.push(port);
    }
  }
  return ports;
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function safeNormalizeCommandGrant(command: string): string | undefined {
  try {
    return normalizeCommandGrant(command);
  } catch {
    return undefined;
  }
}

function normalizeResolvedPolicyCommand(command: string): string {
  const normalized = normalizeCommandGrant(command);
  if (!path.isAbsolute(normalized) || /[\r\n]/.test(normalized)) {
    throw new Error(`Resolved command policy paths must be absolute executable paths: ${command}`);
  }
  return path.normalize(normalized);
}

function safeNormalizeResolvedPolicyCommand(command: string): string | undefined {
  try {
    return normalizeResolvedPolicyCommand(command);
  } catch {
    return undefined;
  }
}

function samePolicyExecutable(left: string, right: string): boolean {
  const normalizedLeft = path.normalize(left);
  const normalizedRight = path.normalize(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function isValidApprovalPolicyRule(rule: ApprovalPolicyRule): boolean {
  return (
    Boolean(rule) &&
    typeof rule.id === "string" &&
    typeof rule.name === "string" &&
    typeof rule.enabled === "boolean" &&
    typeof rule.priority === "number" &&
    isApprovalPolicyDecision(rule.decision) &&
    Boolean(rule.conditions) &&
    typeof rule.createdAt === "string" &&
    typeof rule.updatedAt === "string"
  );
}

function isApprovalPolicyDecision(value: unknown): value is ApprovalPolicyDecision {
  return value === "ask" || value === "allow" || value === "deny";
}

function sortApprovalPolicyRules(rules: ApprovalPolicyRule[]): ApprovalPolicyRule[] {
  return [...rules].sort(compareApprovalPolicyRules);
}

function nextPolicyPriority(store: StoreFile): number {
  const priorities = (store.approvalPolicyRules || []).map((rule) => rule.priority).filter(Number.isFinite);
  return priorities.length ? Math.max(...priorities) + 10 : 100;
}

function defaultPolicyRuleName(decision: ApprovalPolicyDecision): string {
  switch (decision) {
  case "allow":
    return "Allow matching agent access";
  case "deny":
    return "Deny matching agent access";
  case "ask":
    return "Require approval for matching access";
  }
}

function policyExpiresAt(input: AddApprovalPolicyRuleInput, nowIso: string): string | undefined {
  const explicit = requirePolicyExpiresAt(input.expiresAt);
  if (explicit) {
    return explicit;
  }
  if (input.durationMs === undefined) {
    return undefined;
  }
  return new Date(Date.parse(nowIso) + requirePolicyDuration(input.durationMs)).toISOString();
}

function normalizePolicyExpiresAt(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) {
    return undefined;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : undefined;
}

function isCanonicalPolicyTimestamp(value: unknown): value is string {
  return typeof value === "string" && normalizePolicyExpiresAt(value) === value;
}

function resolveUpdatedPolicyExpiresAt(
  existing: ApprovalPolicyRule,
  input: UpdateApprovalPolicyRuleInput,
  nowIso: string
): string | undefined {
  if (input.expiresAt === null) {
    return undefined;
  }
  if (input.expiresAt !== undefined) {
    return requirePolicyExpiresAt(input.expiresAt);
  }
  if (input.durationMs !== undefined) {
    return new Date(Date.parse(nowIso) + requirePolicyDuration(input.durationMs)).toISOString();
  }
  return existing.expiresAt;
}

function requirePolicyExpiresAt(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const normalized = normalizePolicyExpiresAt(value);
  if (!normalized) {
    throw new Error("expiresAt must be a valid ISO timestamp.");
  }
  return normalized;
}

function policyRuleName(name: string | undefined, decision: ApprovalPolicyDecision): string {
  if (name === undefined) {
    return defaultPolicyRuleName(decision);
  }
  return requirePolicyName(name);
}

function requirePolicyName(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) {
    throw new Error("Policy name is required.");
  }
  return trimmed.slice(0, 120);
}

function requireApprovalPolicyDecision(value: unknown): ApprovalPolicyDecision {
  if (!isApprovalPolicyDecision(value)) {
    throw new Error("decision must be allow, ask, or deny.");
  }
  return value;
}

function requirePolicyEnabled(value: unknown): boolean {
  if (typeof value !== "boolean") {
    throw new Error("enabled must be a boolean.");
  }
  return value;
}

function requirePolicyPriority(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error("priority must be a non-negative finite number.");
  }
  return Math.min(Math.floor(value), 10_000);
}

function requirePolicyDuration(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error("durationMs must be a positive finite number.");
  }
  return clampApprovalDuration(value);
}

function normalizePolicyPriority(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return 100;
  }
  return Math.max(0, Math.min(10_000, Math.floor(value)));
}

function isSecretType(value: unknown): value is SecretType {
  return (
    value === "api-token" ||
    value === "ssh-key" ||
    value === "private-key" ||
    value === "password" ||
    value === "credential" ||
    value === "access-key" ||
    value === "unknown"
  );
}

function isSecretSeverity(value: unknown): value is SecretSeverity {
  return value === "low" || value === "medium" || value === "high" || value === "critical";
}

function severityRank(value: SecretSeverity): number {
  switch (value) {
  case "low":
    return 0;
  case "medium":
    return 1;
  case "high":
    return 2;
  case "critical":
    return 3;
  }
}

function currentLoginSessionId(): string | undefined {
  return getSgwLoginSessionId();
}

function normalizePolicy(input?: Partial<SecretPolicy>, existing?: SecretPolicy): SecretPolicy {
  const allowedCommands = input?.allowedCommands ?? existing?.allowedCommands ?? [];
  const injectEnv = input?.injectEnv ?? existing?.injectEnv;
  if (injectEnv && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(injectEnv)) {
    throw new Error(`Invalid environment variable name: ${injectEnv}`);
  }
  return {
    injectEnv,
    allowedCommands: uniqueStrings(allowedCommands),
    maxOutputBytes: input?.maxOutputBytes ?? existing?.maxOutputBytes ?? 16_384
  };
}

function normalizeAction(action: CommandAction): CommandAction {
  const kind = action.kind === "ssh_session" ? "ssh_session" : "env_command";
  if (kind === "ssh_session") {
    return {
      kind,
      command: SGW_SSH_SESSION_COMMAND,
      args: Array.isArray(action.args) ? action.args : [],
      injectEnv: action.injectEnv || "SGW_SSH_CREDENTIAL",
      env: [],
      workingDir: action.workingDir,
      timeoutMs: clampTimeout(action.timeoutMs),
      ssh: {
        target: normalizeSshTarget(action.ssh?.target || ""),
        port: normalizeSshPort(action.ssh?.port)
      }
    };
  }

  return {
    kind,
    command: action.command,
    resolvedCommand: action.resolvedCommand,
    args: Array.isArray(action.args) ? action.args : [],
    injectEnv: action.injectEnv,
    env: normalizeEnvBindings(action.env),
    workingDir: action.workingDir,
    timeoutMs: clampTimeout(action.timeoutMs)
  };
}

function actionForAdmission(action: CommandAction): CommandAction {
  if (action.kind !== "env_command") return action;
  return {
    ...action,
    resolvedCommand: resolveCommandExecutable(action.command)
  };
}

function actionReadyForExecution(action: CommandAction, allowLegacyAbsolute = false): CommandAction {
  const normalized = normalizeAction(action);
  if (normalized.kind !== "env_command") return normalized;

  if (!normalized.resolvedCommand) {
    if (!allowLegacyAbsolute || !isAbsoluteCommand(normalized.command)) {
      verifyPinnedCommand(normalized.command, undefined);
    }
    return {
      ...normalized,
      resolvedCommand: resolveCommandExecutable(normalized.command)
    };
  }

  return {
    ...normalized,
    resolvedCommand: verifyPinnedCommand(normalized.command, normalized.resolvedCommand)
  };
}

function migrateRequestGrantToPinnedAction(store: StoreFile, request: RequestRecord): void {
  if (!request.approvalGrantId) return;
  const grant = store.approvalGrants.find((item) => item.id === request.approvalGrantId);
  if (!grant || grant.handle !== request.handle) return;
  grant.actionKey = approvalActionKey(request.handle, request.action);
}

function normalizeEnvBindings(bindings?: CommandEnvBinding[]): CommandEnvBinding[] {
  if (!Array.isArray(bindings) || bindings.length === 0) {
    return [];
  }

  const seenEnv = new Set<string>();
  const normalized: CommandEnvBinding[] = [];
  for (const binding of bindings) {
    const handle = binding?.handle?.trim();
    const injectEnv = binding?.injectEnv?.trim();
    if (!handle) {
      throw new Error("Additional env bindings require a handle.");
    }
    if (!injectEnv || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(injectEnv)) {
      throw new Error(`Invalid environment variable name: ${injectEnv || "(empty)"}`);
    }
    if (handle.includes("\0") || injectEnv.includes("\0")) {
      throw new Error("Additional env bindings cannot contain null bytes.");
    }
    if (seenEnv.has(injectEnv)) {
      throw new Error(`Environment variable ${injectEnv} is bound more than once.`);
    }

    seenEnv.add(injectEnv);
    normalized.push({ handle, injectEnv });
  }

  normalized.sort((a, b) => {
    const envOrder = a.injectEnv.localeCompare(b.injectEnv);
    return envOrder || a.handle.localeCompare(b.handle);
  });
  return normalized;
}

function assertBoundHandlesAllowed(store: StoreFile, primaryHandle: string, action: CommandAction): void {
  const seenEnv = new Set([action.injectEnv]);
  for (const binding of action.env || []) {
    if (binding.handle === primaryHandle) {
      throw new Error(`Additional env binding ${binding.injectEnv} repeats the primary handle ${primaryHandle}.`);
    }
    if (seenEnv.has(binding.injectEnv)) {
      throw new Error(`Environment variable ${binding.injectEnv} is bound more than once.`);
    }

    const secret = store.secrets.find((item) => item.handle === binding.handle);
    if (!secret) {
      throw new Error(`Unknown secret handle: ${binding.handle}`);
    }

    assertActionAllowed(secret, {
      ...action,
      injectEnv: binding.injectEnv,
      env: []
    });
    seenEnv.add(binding.injectEnv);
  }
}

export function assertActionAllowed(secret: SecretRecord, action: CommandAction): void {
  if (action.kind !== "env_command" && action.kind !== "ssh_session") {
    throw new Error("Unsupported request action kind.");
  }

  if (!action.command || action.command.includes("\0")) {
    throw new Error("Command is required.");
  }

  for (const arg of action.args) {
    if (arg.includes("\0")) {
      throw new Error("Command arguments cannot contain null bytes.");
    }
  }

  if (!action.injectEnv) {
    throw new Error("injectEnv is required so the secret has a narrow local binding.");
  }

  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(action.injectEnv)) {
    throw new Error(`Invalid environment variable name: ${action.injectEnv}`);
  }

  if (secret.policy.injectEnv && action.injectEnv !== secret.policy.injectEnv) {
    throw new Error(`Handle ${secret.handle} can only be injected as ${secret.policy.injectEnv}.`);
  }

  const allowed = secret.policy.allowedCommands.map((cmd) => normalizeCommandGrant(cmd));
  if (action.kind === "ssh_session") {
    normalizeSshTarget(action.ssh?.target || "");
    normalizeSshPort(action.ssh?.port);
    if (allowed.length === 0 || !allowed.some(commandAllowsSshSession)) {
      throw new Error(`Handle ${secret.handle} is not allowed for s-gw-owned SSH sessions. Add ${SGW_SSH_SESSION_COMMAND} to the handle policy.`);
    }
    return;
  }

  const requestedCommand = normalizeCommandGrant(action.command);
  if (allowed.length === 0 || !allowed.includes(requestedCommand)) {
    throw new Error(`Command '${action.command}' is not allowed for handle ${secret.handle}.`);
  }
}

function commandAllowsSshSession(command: string): boolean {
  return command === SGW_SSH_SESSION_COMMAND || path.basename(command) === "ssh";
}

export function normalizeCommandGrant(command: string): string {
  const trimmed = command.trim();
  if (!trimmed) {
    throw new Error("Command grant cannot be empty.");
  }

  if (trimmed.includes("\0")) {
    throw new Error("Command grant cannot contain null bytes.");
  }

  if (path.isAbsolute(trimmed)) {
    return path.normalize(trimmed);
  }

  if (trimmed.includes("/") || trimmed.includes("\\")) {
    throw new Error(`Relative command paths are not allowed: ${trimmed}`);
  }

  return trimmed;
}

function summarizeSecret(secret: SecretRecord): HandleSummary {
  return {
    handle: secret.handle,
    name: secret.name,
    type: secret.type,
    backend: secret.backend || "local",
    provider: secret.provider,
    ruleId: secret.ruleId,
    severity: secret.severity,
    confidence: secret.confidence,
    createdAt: secret.createdAt,
    updatedAt: secret.updatedAt,
    source: secret.source,
    fingerprint: secret.fingerprint,
    policy: secret.policy
  };
}

function makeHandle(type: SecretType): string {
  return `s-gw:${type}:${shortId()}`;
}

function uniqueStrings(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }

    seen.add(trimmed);
    out.push(trimmed);
  }

  return out;
}

function clampTimeout(timeoutMs: number): number {
  if (!Number.isFinite(timeoutMs)) {
    return 30_000;
  }

  if (timeoutMs === 0) {
    return 0;
  }

  if (timeoutMs < 0) {
    return 30_000;
  }

  return Math.min(Math.floor(timeoutMs), 24 * 60 * 60 * 1000);
}

function audit(type: string, message: string, handle?: string, requestId?: string): AuditEvent {
  return {
    id: shortId("audit"),
    ts: new Date().toISOString(),
    type,
    handle,
    requestId,
    message
  };
}

function storeLockTimeoutMs(): number {
  if (process.env.SGW_TEST_MODE !== "1") {
    return lockTimeoutMs;
  }

  const configured = Number(process.env.SGW_TEST_LOCK_TIMEOUT_MS);
  if (!Number.isFinite(configured) || configured <= 0) {
    return lockTimeoutMs;
  }
  return Math.min(Math.floor(configured), lockTimeoutMs);
}

async function removeAbandonedStoreLock(lockPath: string): Promise<void> {
  const inspection = await inspectStoreLock(lockPath);
  if (inspection?.empty) {
    if (Date.now() - (inspection.modifiedAtMs || 0) >= emptyStoreLockStaleMs) {
      await removeEmptyStoreLock(lockPath);
    }
    return;
  }
  if (!inspection?.state || !inspection.markerPath || !processIsDefinitelyDead(inspection.state.pid)) {
    return;
  }
  await retireStoreLock(lockPath, inspection.state.token);
}

async function assertStoreLockOwnership(lockPath: string, token: string): Promise<void> {
  const state = await readStoreLockState(lockPath);
  if (!state || state.token !== token) {
    throw new Error("s-gw store lock ownership was lost; retry the operation.");
  }
}

async function releaseStoreLock(lockPath: string, token: string): Promise<void> {
  const inspection = await inspectStoreLock(lockPath);
  if (!inspection?.state || !inspection.markerPath || inspection.state.token !== token) {
    return;
  }
  const claimed = await removeStoreLockMarker(inspection.markerPath);
  if (!claimed) return;
  await removeEmptyStoreLock(lockPath).catch(() => false);
}

async function retireStoreLock(lockPath: string, token: string): Promise<void> {
  const markerPath = path.join(lockPath, storeLockMarkerName(token));
  const claimed = await removeStoreLockMarker(markerPath);
  if (!claimed) return;
  await removeEmptyStoreLock(lockPath);
}

async function removeStoreLockMarker(markerPath: string): Promise<boolean> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await unlink(markerPath);
      return true;
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return false;
      if (!shouldRetryWindowsLockOperation(error) || attempt + 1 >= windowsLockRenameAttempts) {
        throw error;
      }
      await sleep(windowsLockRenameDelayMs);
    }
  }
}

async function removeEmptyStoreLock(lockPath: string): Promise<boolean> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await rmdir(lockPath);
      await syncDirectory(path.dirname(lockPath));
      return true;
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return false;
      if (isNodeError(error) && (error.code === "ENOTEMPTY" || error.code === "EEXIST")) return false;
      if (!shouldRetryWindowsLockOperation(error)) {
        throw error;
      }
      if (attempt + 1 >= windowsLockRenameAttempts) return false;
      await sleep(windowsLockRenameDelayMs);
    }
  }
}

async function readStoreLockState(lockPath: string): Promise<StoreLockState | undefined> {
  return (await inspectStoreLock(lockPath))?.state;
}

async function publishStoreLock(lockPath: string, state: StoreLockState): Promise<boolean> {
  const tempPath = `${lockPath}.tmp-${process.pid}-${state.token}`;
  const markerPath = path.join(tempPath, storeLockMarkerName(state.token));
  let marker: Awaited<ReturnType<typeof open>> | undefined;
  let published = false;

  try {
    await mkdir(tempPath, { mode: 0o700 });
    marker = await open(markerPath, "wx", 0o600);
    await marker.writeFile(`${JSON.stringify(state)}\n`);
    await marker.sync();
    await marker.close();
    marker = undefined;
    await syncDirectory(tempPath);

    const acquired = await publishPreparedStoreLock(tempPath, lockPath);
    if (!acquired) return false;
    await syncDirectory(path.dirname(lockPath));
    published = true;
    return true;
  } finally {
    await marker?.close().catch(() => undefined);
    if (!published) {
      await rm(tempPath, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

async function publishPreparedStoreLock(tempPath: string, lockPath: string): Promise<boolean> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await rename(tempPath, lockPath);
      return true;
    } catch (error) {
      if (await isStoreLockExistsError(error, lockPath)) return false;
      if (!shouldRetryWindowsLockOperation(error) || attempt + 1 >= windowsLockRenameAttempts) {
        throw error;
      }
      await sleep(windowsLockRenameDelayMs);
    }
  }
}

async function inspectStoreLock(lockPath: string): Promise<StoreLockInspection | undefined> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await inspectStoreLockOnce(lockPath);
    } catch (error) {
      if (!shouldRetryWindowsLockOperation(error)) throw error;
      if (attempt + 1 >= windowsLockRenameAttempts) return {};
      await sleep(windowsLockRenameDelayMs);
    }
  }
}

async function inspectStoreLockOnce(lockPath: string): Promise<StoreLockInspection | undefined> {
  let lockInfo: Awaited<ReturnType<typeof lstat>>;
  try {
    lockInfo = await lstat(lockPath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }

  if (lockInfo.isSymbolicLink() || !lockInfo.isDirectory()) {
    return {};
  }

  let entries: string[];
  try {
    entries = await readdir(lockPath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  if (entries.length === 0) {
    return { empty: true, modifiedAtMs: lockInfo.mtimeMs };
  }
  if (entries.length !== 1) {
    return {};
  }

  const markerPath = path.join(lockPath, entries[0]);
  let marker;
  try {
    marker = await open(markerPath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return {};
    }
    if (isNodeError(error) && error.code === "ELOOP") return {};
    throw error;
  }
  try {
    const markerInfo = await marker.stat();
    const current = await lstat(markerPath).catch(() => undefined);
    if (!markerInfo.isFile() || !current || current.isSymbolicLink() || !current.isFile() ||
        markerInfo.dev !== current.dev || markerInfo.ino !== current.ino) {
      return {};
    }

    const raw = await marker.readFile({ encoding: "utf8" }).catch(() => "");
    const state = parseStoreLockState(raw);
    if (!state || entries[0] !== storeLockMarkerName(state.token)) {
      return {};
    }
    return { state, markerPath };
  } finally {
    await marker.close().catch(() => undefined);
  }
}

function parseStoreLockState(raw: string): StoreLockState | undefined {
  try {
    const value = JSON.parse(raw) as Partial<StoreLockState>;
    const pid = value.pid;
    const token = value.token;
    const createdAt = value.createdAt;
    if (
      value.version !== 1 ||
      typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0 ||
      typeof token !== "string" || token.length < 16 ||
      typeof createdAt !== "string"
    ) {
      return undefined;
    }
    return { version: 1, pid, token, createdAt };
  } catch {
    return undefined;
  }
}

function storeLockMarkerName(token: string): string {
  return `owner-${token}.json`;
}

async function isStoreLockExistsError(error: unknown, lockPath: string): Promise<boolean> {
  if (!isNodeError(error)) return false;
  if (error.code === "EEXIST" || error.code === "ENOTEMPTY") return true;
  if (error.code !== "EPERM" && error.code !== "EACCES" && error.code !== "EBUSY") return false;
  return fileExists(lockPath);
}

function shouldRetryWindowsLockOperation(error: unknown): boolean {
  return process.platform === "win32" && isNodeError(error)
    && (error.code === "EPERM" || error.code === "EACCES" || error.code === "EBUSY");
}

function processIsDefinitelyDead(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return isNodeError(error) && error.code === "ESRCH";
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
