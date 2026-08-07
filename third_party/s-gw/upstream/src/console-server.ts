import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  agentIntegrationStatus,
  installAgentIntegrations,
  mcpAuthorityEnvironment,
  resolvePackagedMcpCommand,
  uninstallAgentIntegrations,
  type AgentIntegrationOptions
} from "./agent-install.js";
import { executeApprovedRequest } from "./executor.js";
import { requestAgentName } from "./agent-context.js";
import {
  addLocalSecret,
  buildEnvCommandAction,
  preferredLocalSecretBackend,
  scanLocalText,
  type LocalSecretBackend
} from "./gateway.js";
import { getAgentCodeGuardPlan, listAgentProfiles, renderAgentMcpSnippet, resolveAgentProfile } from "./agents.js";
import { assertMacRuntimeForManagedSurfaces, getPackageLayout, readinessForUnlock } from "./install.js";
import { getSgwInstanceKey } from "./paths.js";
import { SecretStore, type AddApprovalPolicyRuleInput, type UpdateApprovalPolicyRuleInput } from "./store.js";
import { unlockStatus } from "./unlock.js";
import { ReleaseChecker, UPDATE_CHECK_INTERVAL_MS, type UpdateCheckResult } from "./update-check.js";
import { CURRENT_VERSION } from "./version.js";
import type {
  AuditEvent,
  ApprovalAgentScope,
  ApprovalMode,
  ApprovalPolicyActionKind,
  ApprovalPolicyConditions,
  ApprovalPolicyDecision,
  CommandEnvBinding,
  HandleSummary,
  RequestRecord,
  RequestState,
  SecretSeverity,
  SecretType
} from "./types.js";

const version = CURRENT_VERSION;
const maxBodyBytes = 1024 * 1024;

export interface ConsoleServerOptions {
  host?: string;
  port?: number;
  store?: SecretStore;
  token?: string;
  uiDir?: string;
  updateChecker?: Pick<ReleaseChecker, "check" | "current">;
  agentHomeDir?: string;
  agentPathEnv?: string;
  agentSkillSourcePath?: string;
}

export interface RunningConsoleServer {
  url: string;
  token: string;
  server: Server;
  close: () => Promise<void>;
}

interface ProviderSummary {
  provider: string;
  label: string;
  prefix: string;
  secrets: number;
  severity: SecretSeverity;
  lastUsed?: string;
}

type UsageFlowNodeKind = "agent" | "auth" | "target";

interface UsageFlowNode {
  id: string;
  kind: UsageFlowNodeKind;
  label: string;
  detail?: string;
  count: number;
}

interface UsageFlowLink {
  source: string;
  target: string;
  value: number;
}

interface UsageFlowRow {
  agentId: string;
  agent: string;
  authTypeId: string;
  authType: string;
  targetTypeId: string;
  targetType: string;
  handle: string;
  credential: string;
  action: string;
  command: string;
  target: string;
  handles: string[];
  credentials: string[];
  actions: string[];
  targets: string[];
  count: number;
  lastSeen: string;
  states: Record<RequestState, number>;
}

interface UsageFlowEntry {
  requestId: string;
  agentId: string;
  agent: string;
  authTypeId: string;
  authType: string;
  targetTypeId: string;
  targetType: string;
  credential: string;
  action: string;
  command: string;
  target: string;
  state: RequestState;
  lastSeen: string;
}

interface UsageFlow {
  generatedAt: string;
  totalRequests: number;
  nodes: UsageFlowNode[];
  links: UsageFlowLink[];
  rows: UsageFlowRow[];
  entries: UsageFlowEntry[];
}

export async function startConsoleServer(options: ConsoleServerOptions = {}): Promise<RunningConsoleServer> {
  const host = options.host || "127.0.0.1";
  const port = options.port ?? 8718;
  const token = options.token || randomBytes(24).toString("base64url");
  const store = options.store || new SecretStore();
  const uiDir = options.uiDir || defaultUiDir();
  const updateChecker = options.updateChecker || new ReleaseChecker();
  const agentOptions: AgentIntegrationOptions = {
    homeDir: options.agentHomeDir,
    pathEnv: options.agentPathEnv,
    sgwHome: process.env.SGW_HOME,
    skillSourcePath: options.agentSkillSourcePath
  };

  await store.init();
  const instanceKey = getSgwInstanceKey(path.dirname(store.storePath));
  void updateChecker.check();
  const updateTimer = setInterval(() => void updateChecker.check(true), UPDATE_CHECK_INTERVAL_MS);
  updateTimer.unref();

  const server = createServer((req, res) => {
    handleRequest(req, res, store, token, uiDir, updateChecker, agentOptions, instanceKey).catch((error) => {
      sendError(res, error);
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const address = server.address() as AddressInfo;
  const shownHost = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const url = `http://${shownHost}:${address.port}/`;

  return {
    url,
    token,
    server,
    close: () => {
      clearInterval(updateTimer);
      return closeServer(server);
    }
  };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
    server.closeIdleConnections();
    setTimeout(() => {
      server.closeAllConnections();
    }, 250).unref();
  });
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  store: SecretStore,
  token: string,
  uiDir: string,
  updateChecker: Pick<ReleaseChecker, "check" | "current">,
  agentOptions: AgentIntegrationOptions,
  instanceKey: string
): Promise<void> {
  const url = new URL(req.url || "/", "http://127.0.0.1");
  if (url.pathname.startsWith("/api/")) {
    if (url.pathname !== "/api/health" && !validConsoleToken(req, token)) {
      throw new HttpError(403, "Missing or invalid local console token.");
    }

    await handleApi(req, res, url, store, updateChecker, agentOptions, instanceKey);
    return;
  }

  if (url.pathname === "/favicon.ico") {
    res.writeHead(204, { "Cache-Control": "no-store" });
    res.end();
    return;
  }

  await serveUi(req, res, url.pathname, uiDir, token);
}

async function handleApi(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  store: SecretStore,
  updateChecker: Pick<ReleaseChecker, "check" | "current">,
  agentOptions: AgentIntegrationOptions,
  instanceKey: string
): Promise<void> {
  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, 200, {
      ok: true,
      name: "s-gw",
      version,
      instanceKey
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/state") {
    sendJson(res, 200, await buildState(store, updateChecker.current(), agentOptions));
    return;
  }

  const agentMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/(install|uninstall)$/);
  if (req.method === "POST" && agentMatch) {
    if (process.platform === "darwin") assertMacRuntimeForManagedSurfaces();
    const body = await readJson(req);
    const options = {
      ...agentOptions,
      agentIds: [decodeURIComponent(agentMatch[1])],
      dryRun: body.dryRun === true
    };
    const results = agentMatch[2] === "install"
      ? installAgentIntegrations(options)
      : uninstallAgentIntegrations(options);
    sendJson(res, 200, { ok: results[0]?.state !== "conflict", result: results[0] });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/audit.csv") {
    sendCsv(res, await auditCsv(store));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/approval") {
    sendJson(res, 200, await store.getApprovalSettings());
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/approval/grants") {
    sendJson(res, 200, await store.listApprovalGrants());
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/approval/policies") {
    sendJson(res, 200, await store.listApprovalPolicyRules());
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/approval/policies") {
    const body = await readJson(req);
    sendJson(res, 200, await store.addApprovalPolicyRule(policyRuleInput(body)));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/approval/policies/arrange") {
    sendJson(res, 200, await store.arrangeApprovalPolicyRules());
    return;
  }

  if (req.method === "DELETE" && url.pathname === "/api/approval/grants") {
    sendJson(res, 200, await store.clearApprovalGrants());
    return;
  }

  const approvalGrantMatch = url.pathname.match(/^\/api\/approval\/grants\/([^/]+)$/);
  if (req.method === "DELETE" && approvalGrantMatch) {
    sendJson(res, 200, await store.revokeApprovalGrant(decodeURIComponent(approvalGrantMatch[1])));
    return;
  }

  const approvalPolicyMatch = url.pathname.match(/^\/api\/approval\/policies\/([^/]+)$/);
  if (approvalPolicyMatch) {
    const id = decodeURIComponent(approvalPolicyMatch[1]);
    if (req.method === "DELETE") {
      sendJson(res, 200, await store.deleteApprovalPolicyRule(id));
      return;
    }
    if (req.method === "PATCH") {
      const body = await readJson(req);
      if (typeof body.enabled !== "boolean") {
        throw new HttpError(400, "enabled must be a boolean.");
      }
      sendJson(res, 200, await store.setApprovalPolicyRuleEnabled(id, body.enabled));
      return;
    }
    if (req.method === "PUT") {
      const body = await readJson(req);
      sendJson(res, 200, await store.updateApprovalPolicyRule(id, policyRuleUpdateInput(body)));
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/approval") {
    const body = await readJson(req);
    sendJson(
      res,
      200,
      await store.setApprovalSettings({
        mode: approvalMode(body.mode),
        durationMs: numberValue(body.durationMs, 15 * 60 * 1000)
      })
    );
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/scan") {
    const body = await readJson(req);
    const text = stringValue(body.text, "text");
    const persist = body.persist === true;
    const source = optionalString(body.source);
    sendJson(res, 200, await scanLocalText(store, text, { persist, source, backend: localBackendValue(body.backend) }));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/secrets") {
    const body = await readJson(req);
    const record = await addLocalSecret(store, {
      name: stringValue(body.name, "name"),
      type: secretType(body.type),
      provider: optionalString(body.provider),
      value: stringValue(body.value, "value"),
      source: optionalString(body.source),
      service: optionalString(body.service),
      policy: {
        injectEnv: optionalString(body.injectEnv),
        allowedCommands: stringList(body.allowedCommands),
        maxOutputBytes: numberValue(body.maxOutputBytes, 16_384)
      }
    }, localBackendValue(body.backend));

    sendJson(res, 201, {
      handle: record.handle,
      name: record.name,
      type: record.type,
      provider: record.provider,
      backend: record.backend,
      policy: record.policy
    });
    return;
  }

  const secretMatch = url.pathname.match(/^\/api\/secrets\/([^/]+)$/);
  if (req.method === "DELETE" && secretMatch) {
    const handle = decodeURIComponent(secretMatch[1]);
    sendJson(res, 200, await store.deleteSecret(handle));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/requests") {
    const body = await readJson(req);
    const action = buildEnvCommandAction({
      command: stringValue(body.command, "command"),
      args: stringList(body.args),
      injectEnv: stringValue(body.injectEnv, "injectEnv"),
      env: envBindingList(body.env),
      workingDir: optionalString(body.workingDir),
      timeoutMs: numberValue(body.timeoutMs, 30_000)
    });
    const request = await store.createRequest(
      stringValue(body.handle, "handle"),
      action,
      optionalString(body.reason) || "Local console request",
      {
        agentName: optionalString(body.agentName),
        env: {}
      }
    );

    sendJson(res, 201, request);
    return;
  }

  const match = url.pathname.match(/^\/api\/requests\/([^/]+)\/(approve|approve-policy|deny|execute|recover)$/);
  if (req.method === "POST" && match) {
    const id = decodeURIComponent(match[1]);
    const action = match[2];
    if (action === "approve") {
      const body = await readJson(req);
      sendJson(
        res,
        200,
        await store.approveRequest(id, {
          mode: optionalApprovalMode(body.mode),
          durationMs: optionalNumberValue(body.durationMs),
          agentScope: optionalApprovalAgentScope(body.agentScope)
        })
      );
      return;
    }

    if (action === "approve-policy") {
      sendJson(res, 200, await store.approveRequestWithScopedPolicy(id));
      return;
    }

    if (action === "deny") {
      sendJson(res, 200, await store.denyRequest(id));
      return;
    }

    if (action === "recover") {
      const recovered = await store.forceRecoverExecutions(id);
      sendJson(res, 200, recovered[0]);
      return;
    }

    sendJson(res, 200, await executeApprovedRequest(store, id));
    return;
  }

  throw new HttpError(404, "Unknown console API route.");
}

async function buildState(store: SecretStore, update: UpdateCheckResult | null, agentOptions: AgentIntegrationOptions) {
  const handles = await store.listHandles();
  const requests = await store.listRequests();
  const audit = await store.auditLog();
  const approvalSettings = await store.getApprovalSettings();
  const approvalGrants = await store.listApprovalGrants();
  const approvalPolicyRules = await store.listApprovalPolicyRules();
  const pending = requests.filter((request) => request.state === "pending");
  const highRisk = handles.filter((handle) => handle.severity === "high" || handle.severity === "critical");
  const agents = listAgentProfiles();
  const integrations = agentIntegrationStatus(agentOptions);
  const integrationById = new Map(integrations.map((item) => [item.agentId, item]));
  const unlock = unlockStatus();
  const readiness = readinessForUnlock(unlock.activeSource !== "none");
  const usageFlow = buildUsageFlow(requests, handles);
  const mcp = consoleMcpSnippet(agentOptions);

  return {
    version,
    update,
    ready: readiness.ok,
    readiness,
    status: {
      daemonRunning: true,
      storePath: store.storePath,
      unlock
    },
    metrics: {
      localSecrets: handles.length,
      pendingApprovals: pending.length,
      activeAgents: integrations.filter((item) => item.mcp.state === "installed" || item.mcp.state === "existing").length,
      highRiskFindings: highRisk.length
    },
    handles,
    approvalSettings,
    approvalGrants,
    approvalPolicyRules,
    usageFlow,
    credentials: groupHandles(handles),
    requests: sortRequests(requests),
    pendingRequests: sortRequests(pending),
    audit: [...audit].reverse(),
    agents: agents.map((agent) => {
      const profile = resolveAgentProfile(agent.id);
      const integration = integrationById.get(agent.id);
      return {
        id: agent.id,
        name: agent.displayName,
        status: agent.mcpStatus,
        aliases: profile.aliases,
        integration,
        mcp: {
          supported: profile.mcp.supported,
          format: profile.mcp.snippet,
          writeMode: profile.mcp.writeMode,
          configPaths: profile.mcp.configPaths,
          notes: profile.mcp.notes,
          snippet: profile.mcp.supported ? renderAgentMcpSnippet(profile.id, mcp.options) : null
        },
        skills: profile.skills,
        plugins: profile.plugins,
        hooks: {
          supported: profile.hooks?.supported || false,
          kind: profile.hooks?.kind || "none",
          configPaths: profile.hooks?.configPaths || [],
          events: profile.hooks?.events || [],
          notes: profile.hooks?.notes || []
        },
        limitations: profile.limitations,
        codeGuard: getAgentCodeGuardPlan(profile.id),
        snippetCommand: `${mcp.cliCommand} agent mcp-snippet ${profile.id}`,
        guardCommand: `${mcp.cliCommand} run ${profile.id}`
      };
    })
  };
}

export function consoleMcpSnippet(
  agentOptions: AgentIntegrationOptions,
  layout: Pick<ReturnType<typeof getPackageLayout>, "packageRoot" | "nodePath" | "isSelfContainedMacApp" | "mcpPath"> = getPackageLayout()
): {
  options: { command: string; args: string[]; env?: Record<string, string> };
  cliCommand: string;
} {
  const launch = resolvePackagedMcpCommand(layout, {
    platform: agentOptions.platform || process.platform,
    pathEnv: agentOptions.pathEnv || process.env.PATH || "",
    env: process.env,
    mcpServerPath: layout.mcpPath
  });
  const env = mcpAuthorityEnvironment(agentOptions);
  const launcher = layout.isSelfContainedMacApp
    ? path.posix.join(path.posix.dirname(layout.packageRoot), "bin", "s-gw")
    : "s-gw";

  return {
    options: {
      command: launch.command,
      args: launch.args,
      env
    },
    cliCommand: shellCommandArg(launcher)
  };
}

function shellCommandArg(value: string): string {
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function groupHandles(handles: HandleSummary[]): ProviderSummary[] {
  const grouped = new Map<string, ProviderSummary>();
  for (const handle of handles) {
    const provider = handle.provider || providerForType(handle.type);
    const existing = grouped.get(provider);
    if (!existing) {
      grouped.set(provider, {
        provider,
        label: providerLabel(provider),
        prefix: handlePrefix(provider, handle.type),
        secrets: 1,
        severity: handle.severity || "low",
        lastUsed: handle.updatedAt
      });
      continue;
    }

    existing.secrets += 1;
    existing.severity = higherSeverity(existing.severity, handle.severity || "low");
    if (!existing.lastUsed || handle.updatedAt > existing.lastUsed) {
      existing.lastUsed = handle.updatedAt;
    }
  }

  return [...grouped.values()].sort((a, b) => a.label.localeCompare(b.label));
}

function sortRequests(requests: RequestRecord[]): RequestRecord[] {
  return [...requests].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function buildUsageFlow(requests: RequestRecord[], handles: HandleSummary[]): UsageFlow {
  const handlesById = new Map(handles.map((handle) => [handle.handle, handle]));
  const nodeCounts = new Map<string, UsageFlowNode>();
  const linkCounts = new Map<string, UsageFlowLink>();
  const rowCounts = new Map<string, UsageFlowRow>();
  const entries: UsageFlowEntry[] = [];

  for (const request of requests) {
    const handle = handlesById.get(request.handle);
    const agent = request.agentName || requestAgentName(request.reason);
    const credential = handle?.name || request.handle;
    const authType = authTypeLabel(handle);
    const authTypeId = `auth:${authTypeKey(handle)}`;
    const targetType = targetTypeLabel(request.action);
    const targetTypeId = `target:${targetTypeKey(request.action)}`;
    const action = actionLabel(request.action);
    const command = commandBase(request.action.command);
    const target = actionTarget(request.action);

    const agentId = `agent:${agent}`;
    bumpNode(nodeCounts, agentId, "agent", agent, "Requesting agent");
    bumpNode(nodeCounts, authTypeId, "auth", authType, authTypeDetail(handle));
    bumpNode(nodeCounts, targetTypeId, "target", targetType, targetTypeDetail(request.action));
    bumpLink(linkCounts, agentId, authTypeId);
    bumpLink(linkCounts, authTypeId, targetTypeId);

    entries.push({
      requestId: request.id,
      agentId,
      agent,
      authTypeId,
      authType,
      targetTypeId,
      targetType,
      credential,
      action,
      command,
      target,
      state: request.state,
      lastSeen: request.updatedAt
    });

    const rowKey = `${agent}\n${authType}\n${targetType}`;
    let row = rowCounts.get(rowKey);
    if (!row) {
      row = {
        agentId,
        agent,
        authTypeId,
        authType,
        targetTypeId,
        targetType,
        handle: request.handle,
        credential,
        action,
        command,
        target,
        handles: [],
        credentials: [],
        actions: [],
        targets: [],
        count: 0,
        lastSeen: request.updatedAt,
        states: emptyStateCounts()
      };
      rowCounts.set(rowKey, row);
    }

    row.count += 1;
    row.states[request.state] += 1;
    addFlowExample(row.handles, shortHandle(request.handle));
    addFlowExample(row.credentials, credential);
    addFlowExample(row.actions, action);
    addFlowExample(row.targets, target);
    if (request.updatedAt > row.lastSeen) {
      row.lastSeen = request.updatedAt;
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    totalRequests: requests.length,
    nodes: [...nodeCounts.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)),
    links: [...linkCounts.values()].sort((a, b) => b.value - a.value || a.source.localeCompare(b.source)),
    rows: [...rowCounts.values()].sort((a, b) => b.count - a.count || b.lastSeen.localeCompare(a.lastSeen)),
    entries: entries.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen))
  };
}

function emptyStateCounts(): Record<RequestState, number> {
  return {
    pending: 0,
    approved: 0,
    executing: 0,
    denied: 0,
    executed: 0,
    failed: 0
  };
}

function bumpNode(
  nodes: Map<string, UsageFlowNode>,
  id: string,
  kind: UsageFlowNodeKind,
  label: string,
  detail?: string
): void {
  const existing = nodes.get(id);
  if (existing) {
    existing.count += 1;
    return;
  }

  nodes.set(id, { id, kind, label, detail, count: 1 });
}

function bumpLink(links: Map<string, UsageFlowLink>, source: string, target: string): void {
  const key = `${source}\n${target}`;
  const existing = links.get(key);
  if (existing) {
    existing.value += 1;
    return;
  }

  links.set(key, { source, target, value: 1 });
}

function addFlowExample(values: string[], value: string): void {
  const cleaned = String(value || "").trim();
  if (!cleaned || values.includes(cleaned) || values.length >= 4) {
    return;
  }

  values.push(cleaned);
}

function authTypeKey(handle?: HandleSummary): string {
  return normalizeFlowKey(authTypeLabel(handle));
}

function authTypeLabel(handle?: HandleSummary): string {
  const provider = String(handle?.provider || "").toLowerCase();
  const name = String(handle?.name || "").toLowerCase();
  const source = String(handle?.source || "").toLowerCase();
  const envName = String(handle?.policy.injectEnv || "").toLowerCase();
  const haystack = `${provider} ${name} ${source} ${envName}`;

  if (provider === "aws" || handle?.type === "access-key" || /\baws\b|amazon|access[_ -]?key|secret[_ -]?access/.test(haystack)) {
    return "AWS access key";
  }
  if (provider === "github" || /\bgithub\b|\bgh\b|ghp_|github[_ -]?token/.test(haystack)) {
    return "GitHub token";
  }
  if (provider === "openai" || /openai|sk-/.test(haystack)) {
    return "OpenAI API key";
  }
  if (provider === "ssh" || /ssh|bastion|private[_ -]?key|rsa|ed25519/.test(haystack)) {
    return handle?.type === "password" ? "SSH password" : "SSH private key";
  }
  if (handle?.type === "private-key" || handle?.type === "ssh-key") {
    return "Private key";
  }
  if (handle?.type === "password") {
    return "Password";
  }
  if (handle?.type === "api-token") {
    return "API token";
  }
  if (handle?.type === "credential") {
    return "Credential pair";
  }
  return "Unknown credential";
}

function authTypeDetail(handle?: HandleSummary): string {
  const parts = [];
  if (handle?.severity) {
    parts.push(`${handle.severity} risk`);
  }
  if (handle?.backend) {
    parts.push(`stored in ${flowProviderLabel(handle.backend)}`);
  }
  return parts.join(" / ") || "Authentication type";
}

function targetTypeKey(action: RequestRecord["action"]): string {
  return normalizeFlowKey(targetTypeLabel(action));
}

function targetTypeLabel(action: RequestRecord["action"]): string {
  if (sshDestination(action)) {
    return "SSH server";
  }

  const command = commandBase(action.command).toLowerCase();
  const target = actionTarget(action).toLowerCase();
  const args = action.args.join(" ").toLowerCase();
  const envName = action.injectEnv.toLowerCase();
  const haystack = `${command} ${target} ${args} ${envName}`;

  if (command === "aws" || /\baws\b|\bec2\b|\bs3\b|\bsts\b|cloudformation|securityhub|iam\b/.test(haystack)) {
    return "AWS API";
  }
  if (command === "gh" || command === "github" || /github|pull request|\brepo\b/.test(haystack)) {
    return "GitHub repository";
  }
  if (command === "kubectl" || /kubernetes|kubeconfig|namespace/.test(haystack)) {
    return "Kubernetes cluster";
  }
  if (command === "docker" || command === "podman" || /container|image|compose/.test(haystack)) {
    return "Container runtime";
  }
  if (command === "curl" || command === "wget" || target.startsWith("http://") || target.startsWith("https://") || args.includes("http://") || args.includes("https://")) {
    return "Web API";
  }
  if (command === "psql" || command === "mysql" || command === "redis-cli" || /database|postgres|mysql|redis/.test(haystack)) {
    return "Database";
  }
  if (/\bnas\b|network.?attached.?storage|storage.?appliance|file.?server/.test(haystack)) {
    return "NAS / appliance";
  }
  if (action.kind === "env_command") {
    return "Local command";
  }

  return "Other target";
}

function targetTypeDetail(action: RequestRecord["action"]): string {
  const target = actionTarget(action);
  if (target && target !== "local command") {
    return target;
  }
  return commandBase(action.command);
}

function flowProviderLabel(provider?: string): string {
  const value = provider || "generic";
  if (value === "aws") return "AWS";
  if (value === "github") return "GitHub";
  if (value === "openai") return "OpenAI";
  if (value === "ssh") return "SSH";
  if (value === "onepassword") return "1Password";
  if (value === "keychain" || value === "macos-keychain") return "macOS Keychain";
  if (value === "linux-secret-service") return "Linux Secret Service";
  if (value === "windows-credential-manager") return "Windows Credential Manager";
  return titleCase(value);
}

function normalizeFlowKey(value: string): string {
  return String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "unknown";
}

function titleCase(value: string): string {
  return String(value || "unknown")
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function actionLabel(action: RequestRecord["action"]): string {
  const command = action.kind === "ssh_session" ? "ssh" : commandBase(action.command);
  const target = actionTarget(action);
  if (!target || target === "local command") {
    return command;
  }

  return `${command} -> ${target}`;
}

function actionTarget(action: RequestRecord["action"]): string {
  const sshTarget = sshDestination(action);
  if (sshTarget) return sshTarget;

  if (action.workingDir) {
    return action.workingDir;
  }

  if (action.args[0] === "-e") {
    return `${commandBase(action.command)} inline script`;
  }

  for (const arg of action.args) {
    if (arg && !arg.startsWith("-")) {
      return arg;
    }
  }

  return action.injectEnv || "local command";
}

const sshOptionsWithValue = new Set([
  "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"
]);

function sshDestination(action: RequestRecord["action"]): string | undefined {
  if (action.kind === "ssh_session" && action.ssh?.target) {
    return action.ssh.port && action.ssh.port !== 22 ? `${action.ssh.target}:${action.ssh.port}` : action.ssh.target;
  }
  if (commandBase(action.command).toLowerCase() !== "ssh") return undefined;

  let skipNext = false;
  for (const arg of action.args) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (sshOptionsWithValue.has(arg)) {
      skipNext = true;
      continue;
    }
    if (arg === "--" || arg.startsWith("-")) continue;
    return arg;
  }
  return undefined;
}

function commandBase(command: string): string {
  const normalized = String(command || "").replace(/\\/g, "/");
  const parts = normalized.split("/");
  return parts[parts.length - 1] || normalized || "local command";
}

function shortHandle(handle: string): string {
  if (handle.length <= 34) {
    return handle;
  }

  return `${handle.slice(0, 18)}...${handle.slice(-8)}`;
}

async function auditCsv(store: SecretStore): Promise<string> {
  const audit = await store.auditLog();
  const rows = [["time", "event", "handle", "request", "message"]];
  for (const event of audit) {
    rows.push([event.ts, event.type, event.handle || "", event.requestId || "", event.message]);
  }

  return rows.map((row) => row.map(csvCell).join(",")).join("\n") + "\n";
}

async function serveUi(
  req: IncomingMessage,
  res: ServerResponse,
  pathname: string,
  uiDir: string,
  token: string
): Promise<void> {
  if (req.method !== "GET" && req.method !== "HEAD") {
    throw new HttpError(405, "Only GET is supported for local console assets.");
  }

  const safeRoot = path.resolve(uiDir);
  let relative = uiRelativePath(pathname, uiDir);
  let target = path.resolve(uiDir, relative);
  if (target !== safeRoot && !target.startsWith(`${safeRoot}${path.sep}`)) {
    throw new HttpError(403, "Path is outside the local console directory.");
  }

  if (!existsSync(target) && shouldServeSpaFallback(pathname, uiDir)) {
    relative = "index.html";
    target = path.resolve(uiDir, relative);
  }

  let body = await readFile(target);
  if (path.basename(target) === "local-console.html" || path.basename(target) === "index.html") {
    body = Buffer.from(injectConsoleToken(body.toString("utf8"), token));
  }

  res.writeHead(200, {
    "Content-Type": contentType(target),
    "Cache-Control": "no-store"
  });

  if (req.method === "HEAD") {
    res.end();
    return;
  }

  res.end(body);
}

function uiRelativePath(pathname: string, uiDir: string): string {
  if (pathname === "/" || pathname === "") {
    return existsSync(path.join(uiDir, "index.html")) ? "index.html" : "local-console.html";
  }

  let cleaned = decodeURIComponent(pathname).replace(/^\/+/, "");
  cleaned = cleaned.replace(/^docs\/ui\//, "");
  return cleaned || (existsSync(path.join(uiDir, "index.html")) ? "index.html" : "local-console.html");
}

function shouldServeSpaFallback(pathname: string, uiDir: string): boolean {
  if (!existsSync(path.join(uiDir, "index.html"))) {
    return false;
  }

  const cleaned = decodeURIComponent(pathname || "").replace(/^\/+/, "");
  if (!cleaned) {
    return true;
  }

  const ext = path.extname(cleaned);
  return ext === "";
}

function injectConsoleToken(html: string, token: string): string {
  const script = `<script>window.SGW_CONSOLE_TOKEN=${JSON.stringify(token)};window.SGW_CONSOLE_LIVE=true;</script>`;
  return html.includes("</head>") ? html.replace("</head>", `${script}\n</head>`) : `${script}\n${html}`;
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > maxBodyBytes) {
      throw new HttpError(413, "Request body is too large.");
    }

    chunks.push(buffer);
  }

  if (chunks.length === 0) {
    return {};
  }

  const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpError(400, "JSON body must be an object.");
  }

  return parsed as Record<string, unknown>;
}

function validConsoleToken(req: IncomingMessage, expected: string): boolean {
  const header = req.headers["x-sgw-console-token"];
  const token = Array.isArray(header) ? header[0] : header;
  if (!token || token.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

function stringValue(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(400, `${name} is required.`);
  }

  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function localBackendValue(value: unknown): LocalSecretBackend {
  if (value === undefined || value === null || value === "") {
    return preferredLocalSecretBackend();
  }

  if (value === "local" || value === "keychain") {
    return value;
  }

  throw new HttpError(400, "backend must be either local or keychain.");
}

function stringList(value: unknown): string[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new HttpError(400, "Expected an array of strings.");
  }

  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") {
      throw new HttpError(400, "Expected an array of strings.");
    }
    out.push(item);
  }

  return out;
}

function envBindingList(value: unknown): CommandEnvBinding[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new HttpError(400, "env must be an array of {handle, injectEnv} objects.");
  }

  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "env must be an array of {handle, injectEnv} objects.");
    }

    const record = item as Record<string, unknown>;
    return {
      handle: stringValue(record.handle, "env.handle"),
      injectEnv: stringValue(record.injectEnv, "env.injectEnv")
    };
  });
}

function numberValue(value: unknown, fallback: number): number {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new HttpError(400, "Expected a finite number.");
  }

  return parsed;
}

function secretType(input: unknown): SecretType {
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

function approvalMode(input: unknown): ApprovalMode {
  if (input === "per-transaction" || input === "timed-session" || input === "login-session" || input === "always") {
    return input;
  }

  throw new HttpError(400, "mode must be per-transaction, timed-session, login-session, or always.");
}

function approvalPolicyDecision(input: unknown): ApprovalPolicyDecision {
  if (input === "ask" || input === "allow" || input === "deny") {
    return input;
  }

  throw new HttpError(400, "decision must be ask, allow, or deny.");
}

function approvalPolicyActionKind(input: string): ApprovalPolicyActionKind {
  if (input === "env_command" || input === "env-command" || input === "command") {
    return "env_command";
  }
  if (input === "ssh_session" || input === "ssh-session" || input === "ssh") {
    return "ssh_session";
  }

  throw new HttpError(400, "actionKinds must contain env_command or ssh_session.");
}

function optionalApprovalMode(input: unknown): ApprovalMode | undefined {
  if (input === undefined || input === null || input === "") {
    return undefined;
  }

  return approvalMode(input);
}

function optionalApprovalAgentScope(input: unknown): ApprovalAgentScope | undefined {
  if (input === undefined || input === null || input === "") {
    return undefined;
  }

  if (input === "same-agent" || input === "any-agent") {
    return input;
  }

  throw new HttpError(400, "agentScope must be same-agent or any-agent.");
}

function optionalSecretSeverity(input: unknown): SecretSeverity | undefined {
  if (input === undefined || input === null || input === "") {
    return undefined;
  }

  if (input === "low" || input === "medium" || input === "high" || input === "critical") {
    return input;
  }

  throw new HttpError(400, "minSeverity must be low, medium, high, or critical.");
}

function policyStringArray(body: Record<string, unknown>, field: string): string[] {
  if (!hasBodyField(body, field)) {
    return [];
  }
  const value = body[field];
  if (Array.isArray(value) && value.every((item) => typeof item === "string" && item.trim())) {
    return value;
  }

  throw new HttpError(400, `${field} must be an array of non-empty strings.`);
}

function policyNumberArray(body: Record<string, unknown>, field: string): number[] {
  if (!hasBodyField(body, field)) {
    return [];
  }
  return numberArray(body[field], field);
}

function policyOptionalNumberValue(body: Record<string, unknown>, field: string): number | undefined {
  if (!hasBodyField(body, field)) {
    return undefined;
  }
  const value = body[field];
  if (value === null || (typeof value === "string" && !value.trim())) {
    throw new HttpError(400, `${field} must be a finite number.`);
  }
  if (typeof value !== "number" && typeof value !== "string") {
    throw new HttpError(400, `${field} must be a finite number.`);
  }
  return optionalNumberValue(value);
}

function optionalNumberValue(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new HttpError(400, "Expected a finite number.");
  }

  return parsed;
}

function policyRuleInput(body: Record<string, unknown>): AddApprovalPolicyRuleInput {
  assertKnownPolicyFields(body);
  return {
    name: hasBodyField(body, "name") ? policyNameValue(body.name) : undefined,
    enabled: booleanValue(body.enabled, "enabled", true),
    priority: policyOptionalNumberValue(body, "priority"),
    decision: approvalPolicyDecision(body.decision),
    expiresAt: policyExpiresAtValue(body, false) ?? undefined,
    durationMs: policyOptionalNumberValue(body, "durationMs"),
    conditions: policyConditionsFromBody(body)
  };
}

function policyRuleUpdateInput(body: Record<string, unknown>): UpdateApprovalPolicyRuleInput {
  assertKnownPolicyFields(body);
  const input: UpdateApprovalPolicyRuleInput = {};
  if (hasBodyField(body, "name")) input.name = policyNameValue(body.name);
  if (hasBodyField(body, "enabled")) input.enabled = booleanValue(body.enabled, "enabled");
  if (hasBodyField(body, "priority")) input.priority = policyOptionalNumberValue(body, "priority");
  if (hasBodyField(body, "decision")) input.decision = approvalPolicyDecision(body.decision);
  if (hasBodyField(body, "expiresAt")) input.expiresAt = policyExpiresAtValue(body, true);
  if (hasBodyField(body, "durationMs")) input.durationMs = policyOptionalNumberValue(body, "durationMs");

  const conditions = policyConditionPatchFromBody(body);
  if (conditions) input.conditions = conditions;
  if (Object.keys(input).length === 0) {
    throw new HttpError(400, "Approval policy update must include at least one change.");
  }
  return input;
}

function policyConditionsFromBody(body: Record<string, unknown>): ApprovalPolicyConditions {
  return {
    handles: policyStringArray(body, "handles"),
    envBindings: policyEnvBindings(body.envBindings),
    secretTypes: policyStringArray(body, "secretTypes").map(policySecretType),
    providers: policyStringArray(body, "providers"),
    minSeverity: optionalSecretSeverity(body.minSeverity),
    agents: policyStringArray(body, "agents"),
    actionKinds: policyStringArray(body, "actionKinds").map(approvalPolicyActionKind),
    commands: policyStringArray(body, "commands"),
    resolvedCommands: policyStringArray(body, "resolvedCommands"),
    injectEnvs: policyStringArray(body, "injectEnvs"),
    workingDirs: policyStringArray(body, "workingDirs"),
    sshTargets: policyStringArray(body, "sshTargets"),
    sshPorts: policyNumberArray(body, "sshPorts")
  };
}

function policyConditionPatchFromBody(body: Record<string, unknown>): Partial<ApprovalPolicyConditions> | undefined {
  const fields = [
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
  if (!fields.some((field) => hasBodyField(body, field))) {
    return undefined;
  }

  const patch: Partial<ApprovalPolicyConditions> = {};
  if (hasBodyField(body, "handles")) patch.handles = policyStringArray(body, "handles");
  if (hasBodyField(body, "envBindings")) patch.envBindings = policyEnvBindings(body.envBindings);
  if (hasBodyField(body, "secretTypes")) patch.secretTypes = policyStringArray(body, "secretTypes").map(policySecretType);
  if (hasBodyField(body, "providers")) patch.providers = policyStringArray(body, "providers");
  if (hasBodyField(body, "minSeverity")) patch.minSeverity = body.minSeverity === null ? undefined : optionalSecretSeverity(body.minSeverity);
  if (hasBodyField(body, "agents")) patch.agents = policyStringArray(body, "agents");
  if (hasBodyField(body, "actionKinds")) patch.actionKinds = policyStringArray(body, "actionKinds").map(approvalPolicyActionKind);
  if (hasBodyField(body, "commands")) patch.commands = policyStringArray(body, "commands");
  if (hasBodyField(body, "resolvedCommands")) patch.resolvedCommands = policyStringArray(body, "resolvedCommands");
  if (hasBodyField(body, "injectEnvs")) patch.injectEnvs = policyStringArray(body, "injectEnvs");
  if (hasBodyField(body, "workingDirs")) patch.workingDirs = policyStringArray(body, "workingDirs");
  if (hasBodyField(body, "sshTargets")) patch.sshTargets = policyStringArray(body, "sshTargets");
  if (hasBodyField(body, "sshPorts")) patch.sshPorts = policyNumberArray(body, "sshPorts");
  return patch;
}

function policyExpiresAtValue(body: Record<string, unknown>, allowClear: boolean): string | null | undefined {
  if (!hasBodyField(body, "expiresAt")) {
    return undefined;
  }
  if (body.expiresAt === null && allowClear) {
    return null;
  }
  if (typeof body.expiresAt !== "string") {
    throw new HttpError(400, "expiresAt must be an ISO timestamp.");
  }
  return body.expiresAt;
}

function policyNameValue(value: unknown): string {
  if (typeof value !== "string") {
    throw new HttpError(400, "name must be a string.");
  }
  return value;
}

function assertKnownPolicyFields(body: Record<string, unknown>): void {
  const known = new Set([
    "name",
    "enabled",
    "priority",
    "decision",
    "expiresAt",
    "durationMs",
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
  ]);
  const unknown = Object.keys(body).filter((field) => !known.has(field));
  if (unknown.length) {
    throw new HttpError(400, `Unsupported approval policy field: ${unknown.join(", ")}.`);
  }
}

function booleanValue(value: unknown, field: string, fallback?: boolean): boolean {
  if (value === undefined && fallback !== undefined) {
    return fallback;
  }
  if (typeof value === "boolean") {
    return value;
  }
  throw new HttpError(400, `${field} must be a boolean.`);
}

function policySecretType(value: string): SecretType {
  const type = secretType(value);
  if (type === "unknown" && value !== "unknown") {
    throw new HttpError(400, `Unsupported secret type: ${value}.`);
  }
  return type;
}

function numberArray(value: unknown, field: string): number[] {
  if (!Array.isArray(value)) {
    throw new HttpError(400, `${field} must be an array of numbers.`);
  }

  return value.map((item) => {
    const number = typeof item === "number" || typeof item === "string" ? Number(item) : Number.NaN;
    if (!Number.isFinite(number)) {
      throw new HttpError(400, `${field} must contain finite numbers.`);
    }
    return number;
  });
}

function policyEnvBindings(value: unknown): CommandEnvBinding[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new HttpError(400, "envBindings must be an array of {handle, injectEnv} objects.");
  }

  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "envBindings must be an array of {handle, injectEnv} objects.");
    }
    const binding = item as Record<string, unknown>;
    return {
      handle: stringValue(binding.handle, "envBindings.handle"),
      injectEnv: stringValue(binding.injectEnv, "envBindings.injectEnv")
    };
  });
}

function hasBodyField(body: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(body, field);
}

function providerForType(type: SecretType): string {
  if (type === "private-key" || type === "ssh-key") {
    return "ssh";
  }

  if (type === "unknown") {
    return "generic";
  }

  return type;
}

function providerLabel(provider: string): string {
  const known: Record<string, string> = {
    aws: "AWS",
    github: "GitHub",
    openai: "OpenAI",
    ssh: "SSH",
    "1password": "1Password",
    onepassword: "1Password",
    generic: "Generic",
    keychain: "macOS Keychain",
    "macos-keychain": "macOS Keychain",
    "linux-secret-service": "Linux Secret Service",
    "windows-credential-manager": "Windows Credential Manager",
    "api-token": "API Tokens",
    credential: "Credentials"
  };

  return known[provider] || provider.replace(/(^|-)([a-z])/g, (_match, dash: string, char: string) => {
    return `${dash ? " " : ""}${char.toUpperCase()}`;
  });
}

function handlePrefix(provider: string, type: SecretType): string {
  if (provider && provider !== "generic") {
    return `s-gw:${provider}`;
  }

  return `s-gw:${type}`;
}

function higherSeverity(a: SecretSeverity, b: SecretSeverity): SecretSeverity {
  const rank: Record<SecretSeverity, number> = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3
  };

  return rank[b] > rank[a] ? b : a;
}

function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

function contentType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".html") {
    return "text/html; charset=utf-8";
  }
  if (ext === ".css") {
    return "text/css; charset=utf-8";
  }
  if (ext === ".js") {
    return "text/javascript; charset=utf-8";
  }
  if (ext === ".png") {
    return "image/png";
  }
  if (ext === ".svg") {
    return "image/svg+xml";
  }
  if (ext === ".woff2") {
    return "font/woff2";
  }
  if (ext === ".md") {
    return "text/markdown; charset=utf-8";
  }

  return "application/octet-stream";
}

function defaultUiDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const builtReactCandidates = [
    path.resolve(here, "console-ui"),
    path.resolve(here, "..", "dist", "console-ui")
  ];
  for (const candidate of builtReactCandidates) {
    if (isBuiltReactUi(candidate)) {
      return candidate;
    }
  }

  return path.resolve(here, "..", "docs", "ui");
}

function isBuiltReactUi(candidate: string): boolean {
  return existsSync(path.join(candidate, "index.html")) && existsSync(path.join(candidate, "assets"));
}

function sendJson(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(`${JSON.stringify(value, null, 2)}\n`);
}

function sendCsv(res: ServerResponse, csv: string): void {
  res.writeHead(200, {
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Disposition": 'attachment; filename="s-gw-audit.csv"',
    "Cache-Control": "no-store"
  });
  res.end(csv);
}

function sendError(res: ServerResponse, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  const status = error instanceof HttpError ? error.status : statusForErrorMessage(message);
  sendJson(res, status, { error: message });
}

function statusForErrorMessage(message: string): number {
  if (/unknown (secret handle|request|approval policy)/i.test(message)) {
    return 404;
  }

  if (/approval|approved|pending|denied|executed|failed|takes precedence/i.test(message)) {
    return 409;
  }

  if (/not allowed|invalid|required|missing|empty|must be|must contain|must include|unsupported|expected/i.test(message)) {
    return 400;
  }

  return 500;
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}
