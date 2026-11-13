/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * DefenseClaw OpenClaw Plugin
 *
 * Integrates DefenseClaw security into the OpenClaw plugin lifecycle:
 *
 * Runtime:
 *  - before_tool_call: intercepts tool calls via the Go sidecar inspect API
 *
 * Slash commands:
 *  - /scan <path>: scan a skill directory
 *  - /block <type> <name> [reason]: block a skill, MCP, or plugin
 *  - /allow <type> <name> [reason]: allow-list a skill, MCP, or plugin
 *
 * The plugin uses:
 *  1. CLI shell-out to `defenseclaw` for plugin/skill/code scans (full scanner suite)
 *  2. Native TS scanner for MCP configs (in-process, fast)
 *  3. REST API to the Go sidecar for tool inspection and audit logging
 */

import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import type { PluginApi, ToolContext } from "@openclaw/plugin-sdk";
import {
  bootstrapPluginIdentity,
  createGlobalStateStorage,
  createInMemoryStorage,
  type BootstrapPluginIdentityResult,
  type KeyValueStorage,
} from "./agent_identity.js";
import { DaemonClient } from "./client.js";
import {
  HEADER_DEFENSECLAW_AGENT_ID,
  HEADER_DEFENSECLAW_AGENT_INSTANCE_ID,
  HEADER_DEFENSECLAW_AGENT_NAME,
  HEADER_DEFENSECLAW_POLICY_ID,
  HEADER_DEFENSECLAW_RUN_ID,
  HEADER_DEFENSECLAW_SESSION_BOUND,
  HEADER_DEFENSECLAW_SESSION_ID,
  HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID,
  HEADER_DEFENSECLAW_TRACE_ID,
} from "./correlation-headers.js";

/** OpenClaw passes full gateway config and the defenseclaw plugin entry config. */
type DefenseClawPluginHost = PluginApi & {
  config?: unknown;
  pluginConfig?: {
    awsHttp1Shim?: "auto" | "on" | "off";
    agent?: { id?: unknown; name?: unknown; policyId?: unknown };
  };
};
import { PolicyEnforcer, runSkillScan, runPluginScan, runCodeScan } from "./policy/enforcer.js";
import { scanMCPServer } from "./scanners/mcp-scanner.js";
import type {
  ScanResult,
  Finding,
  OutboundSidecarRequestLog,
} from "./types.js";
import { compareSeverity, maxSeverity } from "./types.js";
import { patchAwsSdkHttp1ForGuardrail } from "./aws-sdk-http1-for-guardrail.js";
import {
  configureSidecarConnection,
  getRuntimeSettings,
  loadOpenClawOutageMode,
  loadSidecarConfig,
  setRuntimeSettings,
} from "./sidecar-config.js";
import { isLoopbackHost } from "./listener-proof.js";
import { createFetchInterceptor, MODEL_OUTAGE_WARNING } from "./fetch-interceptor.js";
import { HealthMonitor } from "./health-monitor.js";

const INSPECT_ACTIONS = new Set(["allow", "alert", "confirm", "block"]);
const INSPECT_MODES = new Set(["action", "observe"]);

type InspectVerdict = {
  action: "allow" | "alert" | "confirm" | "block";
  raw_action?: string;
  severity: string;
  reason: string;
  mode: "action" | "observe";
  approval_timeout_ms?: number;
};

// toolCallIdOf is the id OpenClaw gave this call. The gateway keys the block
// notice shown on the next model reply by it (GAP-0644); empty when the host
// sent none.
function toolCallIdOf(event: { toolCallId?: unknown }): { tool_call_id?: string } {
  const id = event.toolCallId;
  return typeof id === "string" && id !== "" ? { tool_call_id: id } : {};
}

function hasValidInspectActionContract(verdict: Record<string, unknown>): boolean {
  if (verdict.mode === "observe" && verdict.action !== "allow") return false;
  return verdict.raw_action === undefined || typeof verdict.raw_action === "string";
}

function isInspectVerdict(value: unknown): value is InspectVerdict {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const verdict = value as Record<string, unknown>;
  return (
    typeof verdict.action === "string" &&
    INSPECT_ACTIONS.has(verdict.action) &&
    typeof verdict.mode === "string" &&
    INSPECT_MODES.has(verdict.mode) &&
    typeof verdict.severity === "string" &&
    verdict.severity.length > 0 &&
    typeof verdict.reason === "string" &&
    hasValidInspectActionContract(verdict) &&
    (verdict.approval_timeout_ms === undefined ||
      (typeof verdict.approval_timeout_ms === "number" &&
        Number.isSafeInteger(verdict.approval_timeout_ms) &&
        verdict.approval_timeout_ms >= 0))
  );
}

// A present but unusable sidecar response is never an availability
// failure: non-2xx, malformed JSON, and invalid envelopes fail closed
// even when the operator opted into transport fail-open.
function failClosedVerdict(reason: string): InspectVerdict {
  return {
    action: "block",
    severity: "HIGH",
    reason: `defenseclaw failing closed: ${reason}`,
    mode: "action",
  };
}

function normalizeWorkspaceAgentId(raw?: string): string {
  const value = raw?.trim() ?? "";
  if (!value) return "main";
  if (/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(value)) return value.toLowerCase();
  return value.toLowerCase().replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "").slice(0, 64) || "main";
}

function openClawWorkspaceHome(): string {
  const osHome = process.env.HOME?.trim() || process.env.USERPROFILE?.trim() || homedir();
  const configured = process.env.OPENCLAW_HOME?.trim();
  if (!configured || configured === "undefined" || configured === "null") return resolve(osHome);
  if (configured === "~") return resolve(osHome);
  if (configured.startsWith("~/") || configured.startsWith("~\\")) {
    return resolve(osHome, configured.slice(2));
  }
  return resolve(configured);
}

// OpenClaw runs file and exec tools from the agent workspace by default.
// The extension's process directory can differ from that workspace, so use
// the host's agent config when deciding relative targets during an outage.
function toolWorkspaceCwd(api: DefenseClawPluginHost, ctx?: ToolContext): string {
  const runtimeWorkspace = (ctx as ToolContext & { workspaceDir?: string } | undefined)?.workspaceDir;
  if (runtimeWorkspace && isAbsolute(runtimeWorkspace)) return runtimeWorkspace;

  const config = api.config as {
    agents?: { defaults?: { workspace?: string }; list?: Array<{ id?: string; default?: boolean; workspace?: string }> };
  } | undefined;
  const entries = Array.isArray(config?.agents?.list) ? config.agents.list : [];
  const defaultId = normalizeWorkspaceAgentId(entries.find((entry) => entry?.default)?.id ?? entries[0]?.id);
  const sessionId = ctx?.sessionKey?.match(/^agent:([^:]+):/i)?.[1];
  const agentId = normalizeWorkspaceAgentId(ctx?.agentId ?? sessionId ?? defaultId);

  const home = openClawWorkspaceHome();
  const userPath = (path: string): string => path === "~" ? home :
    path.startsWith("~/") || path.startsWith("~\\") ? resolve(home, path.slice(2)) : resolve(path);
  const configured = entries.find((entry) => normalizeWorkspaceAgentId(entry?.id) === agentId)?.workspace?.trim();
  if (configured) return userPath(configured);
  if (agentId === defaultId) {
    const defaultWorkspace = config?.agents?.defaults?.workspace?.trim();
    if (defaultWorkspace) return userPath(defaultWorkspace);
    const profile = process.env.OPENCLAW_PROFILE?.trim();
    return join(home, ".openclaw", profile && profile.toLowerCase() !== "default" ? `workspace-${profile}` : "workspace");
  }
  const stateDir = process.env.OPENCLAW_STATE_DIR?.trim();
  const newStateDir = join(home, ".openclaw");
  const legacyStateDir = process.env.OPENCLAW_TEST_FAST === "1" || existsSync(newStateDir)
    ? undefined : [join(home, ".clawdbot"), join(home, ".moldbot")].find(existsSync);
  return join(stateDir ? userPath(stateDir) : legacyStateDir ?? newStateDir, `workspace-${agentId}`);
}

// Only a classified outage or timeout can use the account's saved mode.
function unavailableVerdict(reason: string, payload: Record<string, unknown>, cwd: string): InspectVerdict {
  const tool = typeof payload.tool === "string" ? payload.tool : "";
  const args = payload.args && typeof payload.args === "object" && !Array.isArray(payload.args)
    ? payload.args as Record<string, unknown> : {};
  const mode = loadOpenClawOutageMode({ name: tool, args, cwd });
  if (mode === "protected") return failClosedVerdict("tool targets protected state");
  if (mode === "open") {
    const warning = `DefenseClaw warning: ${reason}; tool call is running without inspection.`;
    console.warn(warning);
    return {
      action: "allow",
      severity: "NONE",
      reason: warning,
      mode: "observe",
    };
  }
  return failClosedVerdict(reason);
}

function approvalSeverity(severity: string): "info" | "warning" | "critical" {
  return severity.toUpperCase() === "CRITICAL" ? "critical" : severity.toUpperCase() === "NONE" ? "info" : "warning";
}

function logInspectWarning(toolName: string, verdict: InspectVerdict): void {
  if (verdict.action === "allow" && verdict.severity === "WARN") {
    console.warn(`[defenseclaw] tool:${toolName} warning:${verdict.reason}`);
  }
}

function approvalDescription(toolName: string, verdict: InspectVerdict): string {
  const text = `DefenseClaw flagged ${toolName}: ${verdict.reason || "matched guardrail policy"}`;
  return text.length <= 256 ? text : `${text.slice(0, 253)}...`;
}

function approvalTimeoutMs(verdict: InspectVerdict): number | undefined {
  const timeout = verdict.approval_timeout_ms;
  return typeof timeout === "number" && Number.isSafeInteger(timeout) && timeout > 0
    ? timeout
    : undefined;
}

// OpenClaw shows a plugin approval in its Control UI, on chat channels that
// forward /approve, and in openclaw tui from OpenClaw 2026.10.9 (GAP-0597).
// Where no request is shown, it runs out and OpenClaw denies the call with a
// bare "Approval timed out" (GAP-1958). Say where it could have been answered.
export const APPROVAL_SURFACES_HINT =
  "answer DefenseClaw approvals in the OpenClaw Control UI (openclaw dashboard), on a chat channel that forwards /approve, or in openclaw tui from OpenClaw 2026.10.9";

export function approvalResolutionLines(toolName: string, severity: string, decision: string): string[] {
  const lines = [`[defenseclaw] approval:${decision} tool:${toolName} severity:${severity}`];
  if (decision === "timeout" || decision === "cancelled") {
    lines.push(`[defenseclaw] ${toolName} was denied: nobody answered its approval request (${decision}); ${APPROVAL_SURFACES_HINT}`);
  }
  return lines;
}

function buildApprovalRequest(toolName: string, verdict: InspectVerdict) {
  return {
    requireApproval: {
      title: "DefenseClaw approval required",
      description: approvalDescription(toolName, verdict),
      severity: approvalSeverity(verdict.severity),
      timeoutMs: approvalTimeoutMs(verdict),
      timeoutBehavior: "deny" as const,
      onResolution: (decision: string) => {
        const [line, hint] = approvalResolutionLines(toolName, verdict.severity, decision);
        console.log(line);
        if (hint) console.warn(hint);
      },
    },
  };
}

// OpenClaw hands the plugin its `plugins.entries.defenseclaw.config` object as
// `api.pluginConfig`. It has no `getPluginConfig()` (GAP-0598).
async function readPluginAgentSection(api: DefenseClawPluginHost): Promise<{
  id?: string;
  name?: string;
  policyId?: string;
}> {
  try {
    const agent = api.pluginConfig?.agent;
    if (!agent || typeof agent !== "object") return {};
    const id = agent.id;
    const name = agent.name;
    const policyId = agent.policyId;
    return {
      id: typeof id === "string" && id.trim() ? id.trim() : undefined,
      name: typeof name === "string" && name ? name : undefined,
      policyId:
        typeof policyId === "string" && policyId ? policyId : undefined,
    };
  } catch {
    return {};
  }
}

function resolveIdentityStorage(api: PluginApi): KeyValueStorage {
  const ext = api as PluginApi & {
    globalState?: {
      get(key: string): unknown;
      update(key: string, value: unknown): Promise<void>;
    };
  };
  if (ext.globalState && typeof ext.globalState.get === "function") {
    return createGlobalStateStorage(ext.globalState);
  }
  return createInMemoryStorage();
}

function formatFindings(findings: Finding[], limit = 15): string[] {
  const lines: string[] = [];
  const sorted = [...findings].sort(
    (a, b) => compareSeverity(b.severity, a.severity),
  );

  for (const f of sorted.slice(0, limit)) {
    const loc = f.location ? ` (${f.location})` : "";
    lines.push(`- **[${f.severity}]** ${f.title}${loc}`);
  }

  if (findings.length > limit) {
    lines.push(`- ... and ${findings.length - limit} more`);
  }

  return lines;
}

export default function (api: DefenseClawPluginHost) {
  // Before any BedrockRuntimeClient: AWS SDK v3 uses HTTP/2 unless
  // AWS_BEDROCK_FORCE_HTTP1=1; we set that plus an optional Smithy patch so
  // Bedrock traffic hits our https.request hook (the guardrail proxy).
  patchAwsSdkHttp1ForGuardrail({
    openclawConfig: api.config,
    pluginConfig: api.pluginConfig,
  });

  // ─── Runtime: tool call interception ───

  configureSidecarConnection(api.pluginConfig);
  // Setup writes hookMode from connectors.openclaw.hooks.mode and the
  // OpenClaw version: hybrid (native hooks and the guardrail proxy), native
  // (native hooks only, Windows) or none (the proxy, OpenClaw before
  // 2026.8.35).
  const pluginCfg = (api.pluginConfig as Record<string, unknown> | undefined) ?? {};
  const configuredHookMode = pluginCfg.hookMode;
  // native (no interceptor, no proxy) is honoured only on Windows, where
  // DefenseClaw hosts no proxy: elsewhere openclaw.json is writable by the
  // agent account, and one key must not turn off model-traffic inspection.
  const hookMode: "proxy" | "hybrid" | "native" =
    configuredHookMode === "native" && process.platform === "win32"
      ? "native"
      : configuredHookMode === "hybrid" || configuredHookMode === "native"
        ? "hybrid"
        : "proxy";
  // The prompt gate: always on in native mode (the only request-side check
  // there); otherwise what the gateway reports, and until it first answers,
  // what setup wrote into openclaw.json.
  const promptGateOn = (): boolean => {
    if (hookMode === "native") return true;
    const runtime = getRuntimeSettings();
    return runtime.inspectTimeoutMs > 0 ? runtime.promptGate : pluginCfg.promptGate === true;
  };
  const sidecarConfig = loadSidecarConfig();
  const SIDECAR_API = sidecarConfig.baseUrl;
  if (!isLoopbackHost(sidecarConfig.host)) {
    // The plugin sends its token only to a loopback listener that proves it
    // is this account's gateway (GAP-0594).
    console.warn(
      `[defenseclaw] gateway.host ${sidecarConfig.host} is not a loopback address: the plugin sends nothing to it, so tool checks are blocked`,
    );
  }
  // OpenClaw blocks a gate hook (before_tool_call, before_agent_run) that
  // throws or runs out of its budget, whatever the DefenseClaw policy says.
  // The plugin gives each gate hook this budget and waits for a verdict at
  // most 3 s less, so the plugin, not the host, applies the outage mode.
  // OpenClaw allows a gate budget up to 600 s; the plugin bounds its own
  // wait (inspectTimeoutMs) well inside it, so the host never times out first.
  const hostGateBudgetMs = 600_000;
  const HOST_MARGIN_MS = 10_000;
  // The verdict wait comes from the gateway (judge budget, approvals), read
  // per call; before it answers, the config.yaml approval settings apply.
  const inspectTimeoutMs = (): number => {
    const runtime = getRuntimeSettings();
    const live = loadSidecarConfig();
    const wanted = runtime.inspectTimeoutMs > 0
      ? runtime.inspectTimeoutMs
      : live.hiltEnabled ? Math.max(2_000, (live.approvalTimeoutS + 5) * 1_000) : 10_000;
    return Math.min(wanted, hostGateBudgetMs - HOST_MARGIN_MS);
  };

  let identityCache: BootstrapPluginIdentityResult | undefined;
  let pluginAgentExtras: { name?: string; policyId?: string } = {};

  const identityReady = (async () => {
    const section = await readPluginAgentSection(api);
    pluginAgentExtras = { name: section.name, policyId: section.policyId };
    const result = await bootstrapPluginIdentity({
      storage: resolveIdentityStorage(api),
      getConfigAgentId: async () => section.id,
    });
    identityCache = result;
    return result;
  })();

  const logOutboundRequest = (entry: OutboundSidecarRequestLog): void => {
    console.log(
      JSON.stringify({
        message: "defenseclaw.plugin.sidecar_request",
        ...entry,
      }),
    );
  };

  // No token here: the client reads the current sidecar token per request,
  // so a token that `setup openclaw` rewrites is picked up live (GAP-2286).
  const daemonClient = new DaemonClient({
    baseUrl: sidecarConfig.baseUrl,
    identityReady,
    getCorrelation: () => ({
      agentId: identityCache?.agentId ?? "unknown",
      agentInstanceId: identityCache?.sessionAgentInstanceId,
      agentName: pluginAgentExtras.name,
      policyId: pluginAgentExtras.policyId,
      traceId: randomUUID(),
    }),
    logOutboundRequest,
  });

  const enforcer = new PolicyEnforcer(
    { daemonUrl: sidecarConfig.baseUrl },
    daemonClient,
  );

  // The verdict budget and the prompt gate come from the gateway (and, in
  // the separate-user layout, the approval settings), read when the service
  // starts and every minute until it stops.
  let runtimeTimer: ReturnType<typeof setInterval> | undefined;
  let runtimeFailureLogged = false;
  const refreshRuntime = (): Promise<void> =>
    Promise.resolve()
      .then(() => daemonClient.runtime())
      .then((res) => {
        if (res.ok && res.data) {
          setRuntimeSettings(res.data);
          runtimeFailureLogged = false;
        } else if (!runtimeFailureLogged) {
          runtimeFailureLogged = true;
          console.warn(`[defenseclaw] could not read the guardrail settings from the gateway (status ${res.status}); the prompt gate follows openclaw.json until it answers`);
        }
      })
      .catch(() => {});
  const startRuntimeRefresh = (): void => {
    if (runtimeTimer) return;
    void refreshRuntime();
    runtimeTimer = setInterval(() => void refreshRuntime(), 60_000);
    runtimeTimer.unref?.();
  };

  // ─── Health monitor ───
  // Polls the sidecar /status endpoint and warns when protection is down.
  const healthMonitor = new HealthMonitor({
    statusUrl: `${SIDECAR_API}/status`,
    // Authorization comes from daemonClient.buildOutboundHeaders().
    buildSidecarHeaders: () => daemonClient.buildOutboundHeaders(),
    onFetchResponse: (res) => daemonClient.applyStickyFromHttpResponse(res),
    logOutboundRequest,
    getLogAgentId: () => identityCache?.agentId ?? "unknown",
    getOutageMode: () => loadOpenClawOutageMode(),
  });

  // Last-seen tool context, captured on every before_tool_call so the
  // fetch interceptor can attach session_id / run_id to LLM traffic that
  // is emitted from unrelated code paths later in the same agent turn.
  // Snapshot-only: never carries payload data, only the correlation keys
  // that the sidecar's CorrelationMiddleware already validates and
  // length-caps.
  let currentToolContext: { sessionId?: string; runId?: string } = {};
  // True from a tool call until the next intercepted model request is stamped.
  // The session header is the last-seen context and can be stale; only the one
  // request that follows a tool call is marked as having observed it, which is
  // the only request the gateway lets claim a tool block notice (GAP-0644).
  let toolContextUnclaimed = false;

  const trackToolContext = (ctx?: ToolContext): void => {
    if (!ctx) return;
    const sessionId = ctx.sessionId ?? ctx.sessionKey;
    const runId = ctx.runId;
    if (sessionId || runId) {
      currentToolContext = { sessionId, runId };
      toolContextUnclaimed = true;
    }
  };

  // Build the v7 X-DefenseClaw-* correlation header snapshot for a single
  // intercepted LLM call. Returns {} if identity has not yet bootstrapped;
  // the proxy treats missing headers as "unknown" rather than failing the
  // request. A fresh trace_id per call gives the proxy something to pivot
  // on even when OpenClaw did not provide one.
  const getFetchCorrelationHeaders = (): Record<string, string> => {
    const h: Record<string, string> = {};
    const agentId = identityCache?.agentId;
    if (agentId) h[HEADER_DEFENSECLAW_AGENT_ID] = agentId;

    const agentInstanceId =
      daemonClient.getStickyAgentInstanceId() ??
      identityCache?.sessionAgentInstanceId;
    if (agentInstanceId) {
      h[HEADER_DEFENSECLAW_AGENT_INSTANCE_ID] = agentInstanceId;
    }

    const sidecarInstanceId = daemonClient.getEchoedSidecarInstanceId();
    if (sidecarInstanceId) {
      h[HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID] = sidecarInstanceId;
    }

    if (pluginAgentExtras.name) {
      h[HEADER_DEFENSECLAW_AGENT_NAME] = pluginAgentExtras.name;
    }
    if (pluginAgentExtras.policyId) {
      h[HEADER_DEFENSECLAW_POLICY_ID] = pluginAgentExtras.policyId;
    }

    if (currentToolContext.sessionId) {
      h[HEADER_DEFENSECLAW_SESSION_ID] = currentToolContext.sessionId;
      if (toolContextUnclaimed) h[HEADER_DEFENSECLAW_SESSION_BOUND] = "1";
    }
    toolContextUnclaimed = false;
    if (currentToolContext.runId) {
      h[HEADER_DEFENSECLAW_RUN_ID] = currentToolContext.runId;
    }

    // Mint a fresh trace id per call so the proxy has at least one
    // correlation key it did not have to derive itself. Downstream
    // sinks dedupe on request_id (set by the proxy) rather than
    // trace_id so there is no risk of collapsing rows.
    h[HEADER_DEFENSECLAW_TRACE_ID] = randomUUID();
    return h;
  };

  // ─── LLM fetch interceptor ───
  // Patches globalThis.fetch to redirect all outbound LLM API calls through
  // the guardrail proxy regardless of which provider/model OpenClaw uses.
  let recentModelOutage = 0;
  const interceptor = createFetchInterceptor({
    guardrailPort: sidecarConfig.guardrailPort,
    getCorrelationHeaders: getFetchCorrelationHeaders,
    getOutageMode: () => loadOpenClawOutageMode(),
    onOutageWarning: () => { recentModelOutage = Date.now(); },
  });
  // OpenClaw includes this text in the agent's current prompt when the
  // monitor has confirmed an outage and the saved tier permits continuation.
  api.on("before_prompt_build", async () => {
    if (loadOpenClawOutageMode() !== "open") return;
    await healthMonitor.refresh();
    if (!healthMonitor.isUnprotected) recentModelOutage = 0;
    if (healthMonitor.isGatewayDown || Date.now() - recentModelOutage < 30_000) {
      return { prependContext: healthMonitor.getWarningMessage() ?? MODEL_OUTAGE_WARNING };
    }
  });
  // Start immediately so gateway model prewarm (before plugin services) also
  // routes through the guardrail when Bedrock is the primary model.
  if (hookMode !== "native") interceptor.start();

  // Stops the interceptor and the health monitor. OpenClaw calls the service
  // `stop` when it replaces or removes the plugin; it ignores what start()
  // returns, so without it every reload left the previous copy patching the
  // transport and polling the gateway (GAP-0745).
  const stopService = (): void => {
    interceptor.stop();
    healthMonitor.stop();
    if (runtimeTimer) clearInterval(runtimeTimer);
    runtimeTimer = undefined;
  };

  api.registerService({
    id: "llm-interceptor",
    stop: stopService,
    start: async () => {
      startRuntimeRefresh();
      if (hookMode === "native") {
        // No guardrail proxy: the native hooks guard OpenClaw.
        healthMonitor.start();
        return { stop: stopService };
      }
      interceptor.start();
      const layers = interceptor.describeLayers();
      if (!layers.fetch || !layers.httpsRequest || !layers.httpRequest || !layers.httpGet) {
        console.warn(
          "[defenseclaw] interceptor layer missing after service start: " +
            `fetch=${layers.fetch} https.request=${layers.httpsRequest} ` +
            `http.request=${layers.httpRequest} http.get=${layers.httpGet} ` +
            `undici=${layers.undiciDispatcher}`,
        );
      }
      // Start health monitoring first: runSelfTest() performs network I/O with
      // no timeout of its own, so awaiting it here allowed a replaced
      // globalThis.fetch to stall service startup indefinitely. The self-test
      // still publishes its result, it just no longer gates the service.
      healthMonitor.start();
      void interceptor.runSelfTest().catch((error) => {
        console.warn(
          `[defenseclaw] interception self-test failed to complete: ${String(error)}`,
        );
      });
      // Older OpenClaw releases take the stop handle from the return value.
      return { stop: stopService };
    },
  });

  async function inspectTool(
    payload: Record<string, unknown>,
    toolCtx?: ToolContext,
  ): Promise<InspectVerdict> {
    const sessionId = toolCtx?.sessionId ?? toolCtx?.sessionKey;
    const bodyPayload = sessionId
      ? { ...payload, session_id: sessionId, approval_surface: "native" }
      : { ...payload, approval_surface: "native" };
    // The check goes over a connection that proved it reaches this account's
    // gateway, and its verdict comes back on that connection (GAP-0594). The
    // budget counts from the proven connection, so the proof does not use it.
    const res = await daemonClient.postRaw("/api/v1/inspect/tool", bodyPayload, {
      timeoutMs: inspectTimeoutMs(),
      correlation: { runId: toolCtx?.runId, sessionId },
    });
    if (res.status === 0) {
      // No verdict is available. Only a gateway that did not answer (nothing
      // listening, a timeout, or a proven connection that broke off) follows
      // the saved outage mode. A listener that did not prove it is this
      // account's gateway, a non-loopback gateway.host and a missing token
      // stay closed in every tier; nothing was sent to them.
      const msg = res.error ?? "no answer";
      return res.outage
        ? unavailableVerdict(`sidecar unreachable: ${msg}`, payload, toolWorkspaceCwd(api, toolCtx))
        : failClosedVerdict(`sidecar request failed: ${msg}`);
    }
    if (res.status < 200 || res.status >= 300) {
      return failClosedVerdict(`sidecar returned ${res.status}`);
    }
    let verdict: unknown;
    try {
      verdict = JSON.parse(res.body);
    } catch {
      // Structurally unreadable JSON stays fail-closed.
      return failClosedVerdict("sidecar returned malformed verdict");
    }
    return isInspectVerdict(verdict)
      ? verdict
      : failClosedVerdict("sidecar returned invalid verdict");
  }

  const outageWarnings = new Map<string, string>();
  const outageWarningKey = (toolCallId?: string, sessionKey?: string, toolName?: string): string =>
    toolCallId ? `call:${toolCallId}` : sessionKey && toolName ? `session:${sessionKey}:${toolName}` : "";
  const rememberOutageWarning = (
    event: { toolCallId?: string; toolName: string }, ctx: ToolContext | undefined, verdict: InspectVerdict,
  ): void => {
    if (!verdict.reason.startsWith("DefenseClaw warning:")) return;
    const key = outageWarningKey(event.toolCallId ?? ctx?.toolCallId, ctx?.sessionKey, event.toolName);
    if (!key) return;
    if (outageWarnings.size >= 256) outageWarnings.delete(outageWarnings.keys().next().value ?? "");
    outageWarnings.set(key, verdict.reason);
  };

  // OpenClaw writes this tool result into the agent transcript. Attach the
  // outage notice there so the agent and its user can see it with the call.
  api.on("tool_result_persist", (event, ctx) => {
    const key = outageWarningKey(event.toolCallId ?? ctx?.toolCallId, ctx?.sessionKey, event.toolName ?? ctx?.toolName);
    const warning = outageWarnings.get(key);
    if (!warning) return;
    outageWarnings.delete(key);
    const message = event.message;
    if (!message || typeof message !== "object" || Array.isArray(message)) return;
    const record = message as Record<string, unknown>;
    if (record.role !== "toolResult" || !Array.isArray(record.content)) return;
    return { message: { ...record, content: [...record.content, { type: "text", text: warning }] } };
  });

  api.on("before_tool_call", async (event, ctx) => {
    // Cache the current session/run so subsequent LLM fetch interceptions
    // emitted from the same agent turn can stamp them on outbound
    // X-DefenseClaw-* headers. Without this, intercepted LLM traffic
    // arrives at the guardrail proxy with no session/run correlation and
    // every guardrail-* audit row in SQLite ends up NULL on those columns.
    trackToolContext(ctx);

    if (event.toolName === "message") {
      const content =
        (event.params?.content as string) || (event.params?.body as string) || "";
      if (!content) return;

      const verdict = await inspectTool(
        {
          tool: "message",
          args: event.params,
          content,
          direction: "outbound",
          ...toolCallIdOf(event),
        },
        ctx,
      );

      rememberOutageWarning(event, ctx, verdict);

      console.log(
        `[defenseclaw] message-tool verdict:${verdict.action} severity:${verdict.severity}`,
      );
      logInspectWarning("message", verdict);

      if (verdict.action === "block" && verdict.mode === "action") {
        return { block: true, blockReason: `DefenseClaw: outbound blocked — ${verdict.reason}` };
      }
      if (verdict.action === "confirm" && verdict.mode === "action") {
        return buildApprovalRequest("outbound message", verdict);
      }
      return;
    }

    const verdict = await inspectTool(
      {
        tool: event.toolName,
        args: event.params,
        ...toolCallIdOf(event),
      },
      ctx,
    );

    rememberOutageWarning(event, ctx, verdict);

    console.log(
      `[defenseclaw] tool:${event.toolName} verdict:${verdict.action} severity:${verdict.severity}`,
    );
    logInspectWarning(event.toolName, verdict);

    if (verdict.action === "block" && verdict.mode === "action") {
      return { block: true, blockReason: `DefenseClaw: ${verdict.reason}` };
    }
    if (verdict.action === "confirm" && verdict.mode === "action") {
      return buildApprovalRequest(event.toolName, verdict);
    }
  }, { timeoutMs: hostGateBudgetMs });

  // ─── Native hooks (hookMode hybrid or native, OpenClaw 2026.8.35+) ───

  // A verdict from an inspect route, with the outage rule of before_tool_call:
  // only a gateway that did not answer follows the saved outage mode; an
  // unproven listener, a refused request and a malformed answer stay closed.
  async function postForVerdict(
    path: string,
    body: Record<string, unknown>,
    correlation: { runId?: string; sessionId?: string },
    onOutage: (reason: string) => InspectVerdict,
  ): Promise<InspectVerdict> {
    const res = await daemonClient.postRaw(path, body, { timeoutMs: inspectTimeoutMs(), correlation });
    if (res.status === 0) {
      const msg = res.error ?? "no answer";
      return res.outage ? onOutage(`sidecar unreachable: ${msg}`) : failClosedVerdict(`sidecar request failed: ${msg}`);
    }
    if (res.status < 200 || res.status >= 300) return failClosedVerdict(`sidecar returned ${res.status}`);
    try {
      const verdict: unknown = JSON.parse(res.body);
      return isInspectVerdict(verdict) ? verdict : failClosedVerdict("sidecar returned invalid verdict");
    } catch {
      return failClosedVerdict("sidecar returned malformed verdict");
    }
  }

  // Outage of a prompt check: open tiers let the prompt through with a
  // warning, strict and managed tiers block it.
  const promptOutageVerdict = (reason: string): InspectVerdict => {
    if (loadOpenClawOutageMode() === "open") {
      const warning = `DefenseClaw warning: ${reason}; the prompt runs without inspection.`;
      console.warn(warning);
      return { action: "allow", severity: "NONE", reason: warning, mode: "observe" };
    }
    return failClosedVerdict(reason);
  };

  const MAX_OBSERVED_TEXT = 256 * 1024;
  const sessionOf = (ctx?: { sessionKey?: string; sessionId?: string }) => ctx?.sessionKey ?? ctx?.sessionId;

  if (hookMode !== "proxy") {
    // Prompt gate (connectors.openclaw.hooks.prompt_gate, off by default):
    // the user prompt is inspected before the model reads it. OpenClaw keeps
    // only the replacement message in the transcript of a blocked run.
    api.on("before_agent_run", async (event, ctx) => {
      if (!promptGateOn()) return;
      const prompt = typeof event?.prompt === "string" ? event.prompt : "";
      if (!prompt) return;
      const sessionId = sessionOf(ctx);
      const verdict = await postForVerdict(
        "/api/v1/inspect/request",
        {
          content: prompt.slice(0, MAX_OBSERVED_TEXT),
          // A cut prompt is reviewed as a bounded prefix, never as complete.
          ...(prompt.length > MAX_OBSERVED_TEXT ? { bounded_prefix_review: true } : {}),
          ...(sessionId ? { session_id: sessionId } : {}),
        },
        { runId: ctx?.runId, sessionId },
        promptOutageVerdict,
      );
      console.log(`[defenseclaw] prompt verdict:${verdict.action} severity:${verdict.severity}`);
      if (verdict.action === "block" && verdict.mode === "action") {
        return {
          outcome: "block",
          reason: `defenseclaw: ${verdict.reason}`,
          message: `DefenseClaw blocked this message: ${verdict.reason}`,
        };
      }
      return undefined;
    }, { timeoutMs: hostGateBudgetMs });
  }

  if (hookMode === "native") {
    // No guardrail proxy sees the traffic, so the observation hooks feed the
    // response and tool-result scans (audit and findings; they cannot block).
    api.on("after_tool_call", (event, ctx) => {
      const output = event?.error !== undefined ? { error: event.error } : event?.result;
      const sessionId = sessionOf(ctx);
      void daemonClient.postRaw("/api/v1/inspect/tool-response", {
        tool: event?.toolName,
        output: output === undefined ? null : output,
        ...(sessionId ? { session_id: sessionId } : {}),
      }, { timeoutMs: inspectTimeoutMs(), correlation: { runId: event?.runId ?? ctx?.runId, sessionId } }).catch(() => {});
    });
    api.on("llm_output", (event, ctx) => {
      const texts = Array.isArray(event?.assistantTexts) ? event.assistantTexts.filter((t: unknown) => typeof t === "string") : [];
      const content = texts.join("\n").slice(0, MAX_OBSERVED_TEXT);
      if (!content) return;
      const sessionId = event?.sessionId ?? sessionOf(ctx);
      void daemonClient.postRaw("/api/v1/inspect/response", {
        content,
        model: event?.model,
        ...(sessionId ? { session_id: sessionId } : {}),
      }, { timeoutMs: inspectTimeoutMs(), correlation: { runId: event?.runId, sessionId } }).catch(() => {});
    });
  }

  // ─── Slash command: /scan ───

  api.registerCommand({
    name: "scan",
    acceptsArgs: true,
    requireAuth: true,
    description: "Scan a skill, plugin, MCP config, or source code with DefenseClaw",
    args: [
      { name: "target", description: "Path to skill/plugin directory, MCP config, or source code", required: true },
      { name: "type", description: "Scan type: skill (default), plugin, mcp, code", required: false },
    ],
    handler: async (cmd) => {
      const args = commandArgs(cmd.args, ["target", "type"]);
      const target = args.target;
      if (!target) {
        return { text: "Usage: /scan <path> [skill|plugin|mcp|code]" };
      }

      const scanType = args.type ?? "skill";

      if (scanType === "plugin") {
        return handlePluginScan(target);
      }

      if (scanType === "mcp") {
        return handleMCPScan(target);
      }

      if (scanType === "code") {
        return handleCodeScan(
          target,
          SIDECAR_API,
          loadSidecarConfig().token,
          daemonClient,
          logOutboundRequest,
          () => identityCache?.agentId ?? "unknown",
        );
      }

      return handleSkillScan(target);
    },
  });

  // ─── Slash commands: /block, /allow ───
  // Block and allow lists live in config.yaml and change only with the
  // DefenseClaw CLI in a terminal. A chat command could be sent by anyone who
  // can message the agent, and the plugin credential cannot write the lists.
  for (const [name, verb] of [["block", "Block"], ["allow", "Allow-list"]] as const) {
    api.registerCommand({
      name,
      description: `${verb} a skill, MCP server, or plugin (prints the DefenseClaw command to run in a terminal)`,
      args: [
        { name: "type", description: "Target type: skill, mcp, plugin", required: true },
        { name: "name", description: "Name of the target", required: true },
      ],
      acceptsArgs: true,
      handler: async (cmd) => {
        const args = commandArgs(cmd.args, ["type", "name"]);
        // Anyone who can message the agent can type these arguments: only a
        // known type and a plain name are echoed into the command to copy.
        const rawType = args.type;
        const rawName = args.name;
        const targetType = rawType && ["skill", "mcp", "plugin"].includes(rawType) ? rawType : "<skill|mcp|plugin>";
        const target = rawName && /^[A-Za-z0-9@._/:-]{1,128}$/.test(rawName) ? rawName : "<name>";
        return {
          text: `DefenseClaw changes block and allow lists only from a terminal: run \`defenseclaw ${targetType} ${name} ${target}\`.`,
        };
      },
    });
  }
}

// ─── Scan handlers ───

async function handlePluginScan(
  target: string,
): Promise<{ text: string }> {
  try {
    const result = await runPluginScan(target);
    return { text: formatScanOutput("Plugin", target, result) };
  } catch (err) {
    return {
      text: `Plugin scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function handleMCPScan(target: string): Promise<{ text: string }> {
  try {
    const result = await scanMCPServer(target);
    return { text: formatScanOutput("MCP", target, result) };
  } catch (err) {
    return {
      text: `MCP scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function handleCodeScan(
  target: string,
  sidecarApi: string,
  sidecarToken: string,
  client: DaemonClient,
  logOutboundRequestFn: (entry: OutboundSidecarRequestLog) => void,
  getLogAgentId: () => string,
): Promise<{ text: string }> {
  try {
    const result = await runCodeScan(target, sidecarApi, sidecarToken, {
      buildSidecarHeaders: () => client.buildOutboundHeaders(),
      onSidecarResponse: (res) => client.applyStickyFromHttpResponse(res),
      logOutboundRequest: logOutboundRequestFn,
      getLogAgentId,
    });
    return { text: formatScanOutput("Code", target, result) };
  } catch (err) {
    return {
      text: `Code scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function handleSkillScan(target: string): Promise<{ text: string }> {
  try {
    const result = await runSkillScan(target);
    return { text: formatScanOutput("Skill", target, result) };
  } catch (err) {
    return {
      text: `Skill scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function formatScanOutput(
  scanType: string,
  target: string,
  result: ScanResult,
): string {
  const lines: string[] = [`**DefenseClaw ${scanType} Scan: ${target}**\n`];

  if (result.findings.length === 0) {
    lines.push("Verdict: **CLEAN** — no findings");
    return lines.join("\n");
  }

  const max = maxSeverity(result.findings.map((f) => f.severity));
  lines.push(
    `Verdict: **${max}** (${result.findings.length} finding${result.findings.length === 1 ? "" : "s"})\n`,
  );
  lines.push(...formatFindings(result.findings));

  return lines.join("\n");
}

/**
 * Named command arguments. OpenClaw passes the raw text after the command
 * (2026.8.35 and later, with acceptsArgs); older releases passed an object.
 * Before rel-1-0-10 GAP-0065 the plugin read only the object form and set no
 * acceptsArgs, so a command with arguments went to the model as chat text.
 */
export function commandArgs(raw: unknown, names: string[]): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  if (typeof raw === "string") {
    const words = raw.trim().split(/\s+/).filter(Boolean);
    names.forEach((name, i) => {
      out[name] = words[i];
    });
  } else if (raw && typeof raw === "object") {
    for (const name of names) {
      const v = (raw as Record<string, unknown>)[name];
      out[name] = typeof v === "string" ? v : undefined;
    }
  }
  return out;
}
