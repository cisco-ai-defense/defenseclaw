export type SecretType =
  | "api-token"
  | "ssh-key"
  | "private-key"
  | "password"
  | "credential"
  | "access-key"
  | "unknown";

export type SecretSeverity = "low" | "medium" | "high" | "critical";

export type RequestState = "pending" | "approved" | "executing" | "denied" | "executed" | "failed";
export type RequestApprovalSource = "manual" | "grant" | "policy";

export type ApprovalMode = "per-transaction" | "timed-session" | "login-session" | "always";
export type ApprovalAgentScope = "same-agent" | "any-agent";
export type ApprovalPolicyDecision = "ask" | "allow" | "deny";
export type ApprovalPolicyActionKind = "env_command" | "ssh_session";
export type AgentIdentitySource = "configured" | "mcp-client" | "runtime" | "process" | "reason" | "manual" | "unknown";

export interface ApprovalSettings {
  mode: ApprovalMode;
  durationMs: number;
}

export interface ApprovalGrant {
  id: string;
  handle: string;
  actionKey: string;
  mode: Exclude<ApprovalMode, "per-transaction">;
  agentScope?: ApprovalAgentScope;
  agentName?: string;
  loginSessionId: string;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
  lastRequestId?: string;
}

export interface ApprovalPolicyConditions {
  handles?: string[];
  envBindings?: CommandEnvBinding[];
  secretTypes?: SecretType[];
  providers?: string[];
  minSeverity?: SecretSeverity;
  agents?: string[];
  actionKinds?: ApprovalPolicyActionKind[];
  commands?: string[];
  resolvedCommands?: string[];
  injectEnvs?: string[];
  workingDirs?: string[];
  sshTargets?: string[];
  sshPorts?: number[];
}

export interface ApprovalPolicyRule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  decision: ApprovalPolicyDecision;
  conditions: ApprovalPolicyConditions;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface EncryptedBox {
  alg: "aes-256-gcm";
  kdf: "scrypt";
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface SecretPolicy {
  injectEnv?: string;
  allowedCommands: string[];
  maxOutputBytes: number;
}

export type SecretBackend = "local" | "onepassword" | "keychain";

export interface SecretValueCache {
  backend: "onepassword";
  encrypted: EncryptedBox;
  fingerprint: string;
  approvalGrantId?: string;
  approvalPolicyRuleId?: string;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
  loginSessionId?: string;
}

export interface SecretRecord {
  handle: string;
  name: string;
  type: SecretType;
  backend?: SecretBackend;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  createdAt: string;
  updatedAt: string;
  source?: string;
  fingerprint: string;
  encrypted: EncryptedBox;
  cache?: SecretValueCache;
  policy: SecretPolicy;
}

export interface HandleSummary {
  handle: string;
  name: string;
  type: SecretType;
  backend?: SecretBackend;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  createdAt: string;
  updatedAt: string;
  source?: string;
  fingerprint: string;
  policy: SecretPolicy;
}

export interface SshSessionSpec {
  target: string;
  port: number;
}

export interface CommandEnvBinding {
  handle: string;
  injectEnv: string;
}

export interface CommandAction {
  kind: "env_command" | "ssh_session";
  command: string;
  resolvedCommand?: string;
  args: string[];
  injectEnv: string;
  env?: CommandEnvBinding[];
  workingDir?: string;
  timeoutMs: number;
  ssh?: SshSessionSpec;
}

export interface ExecutionSummary {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  proof: string;
  durationMs: number;
  timeoutMs: number;
  timedOut: boolean;
  sanitized: boolean;
}

export interface RequestRecord {
  id: string;
  handle: string;
  reason: string;
  agentName?: string;
  agentSource?: AgentIdentitySource;
  loginSessionId?: string;
  action: CommandAction;
  state: RequestState;
  createdAt: string;
  updatedAt: string;
  approvedAt?: string;
  approvalSource?: RequestApprovalSource;
  approvalGrantId?: string;
  approvalPolicyRuleId?: string;
  deniedAt?: string;
  executedAt?: string;
  resultSummary?: ExecutionSummary;
  error?: string;
}

export interface AuditEvent {
  id: string;
  ts: string;
  type: string;
  handle?: string;
  requestId?: string;
  message: string;
}

export interface StoreFile {
  version: 1;
  secrets: SecretRecord[];
  requests: RequestRecord[];
  audit: AuditEvent[];
  approvalSettings: ApprovalSettings;
  approvalGrants: ApprovalGrant[];
  approvalPolicyRules: ApprovalPolicyRule[];
}

export interface ScanCandidate {
  type: SecretType;
  label: string;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  value: string;
  start: number;
  end: number;
}

export interface ScanFinding {
  type: SecretType;
  label: string;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  handle: string;
  token: string;
  start: number;
  end: number;
}

export interface ScanResult {
  tokenizedText: string;
  findings: ScanFinding[];
}
