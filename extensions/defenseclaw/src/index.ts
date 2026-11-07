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
  InstallType,
  OutboundSidecarRequestLog,
} from "./types.js";
import { compareSeverity, maxSeverity } from "./types.js";
import { patchAwsSdkHttp1ForGuardrail } from "./aws-sdk-http1-for-guardrail.js";
import { loadSidecarConfig } from "./sidecar-config.js";
import { isLoopbackHost } from "./listener-proof.js";
import { createFetchInterceptor } from "./fetch-interceptor.js";
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

// DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN applies only when no sidecar
// verdict is available because the request itself failed.
function unavailableVerdict(reason: string): InspectVerdict {
  const failOpen =
    (process.env.DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN || "")
      .trim()
      .toLowerCase() === "1";
  if (failOpen) {
    return {
      action: "allow",
      severity: "NONE",
      reason: `${reason} (fail-open opt-in)`,
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

  const sidecarConfig = loadSidecarConfig();
  const SIDECAR_API = sidecarConfig.baseUrl;
  if (!isLoopbackHost(sidecarConfig.host)) {
    // The plugin sends its token only to a loopback listener that proves it
    // is this account's gateway (GAP-0594).
    console.warn(
      `[defenseclaw] gateway.host ${sidecarConfig.host} is not a loopback address: the plugin sends nothing to it, so tool checks follow the outage mode`,
    );
  }
  const INSPECT_TIMEOUT_MS = sidecarConfig.hiltEnabled
    ? Math.max(2_000, (sidecarConfig.approvalTimeoutS + 5) * 1_000)
    : 2_000;

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

  // ─── Health monitor ───
  // Polls the sidecar /status endpoint and warns when protection is down.
  const healthMonitor = new HealthMonitor({
    statusUrl: `${SIDECAR_API}/status`,
    // Authorization comes from daemonClient.buildOutboundHeaders().
    buildSidecarHeaders: () => daemonClient.buildOutboundHeaders(),
    onFetchResponse: (res) => daemonClient.applyStickyFromHttpResponse(res),
    logOutboundRequest,
    getLogAgentId: () => identityCache?.agentId ?? "unknown",
  });

  // Last-seen tool context, captured on every before_tool_call so the
  // fetch interceptor can attach session_id / run_id to LLM traffic that
  // is emitted from unrelated code paths later in the same agent turn.
  // Snapshot-only: never carries payload data, only the correlation keys
  // that the sidecar's CorrelationMiddleware already validates and
  // length-caps.
  let currentToolContext: { sessionId?: string; runId?: string } = {};

  const trackToolContext = (ctx?: ToolContext): void => {
    if (!ctx) return;
    const sessionId = ctx.sessionId ?? ctx.sessionKey;
    const runId = ctx.runId;
    if (sessionId || runId) {
      currentToolContext = { sessionId, runId };
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
    }
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
  const interceptor = createFetchInterceptor({
    guardrailPort: sidecarConfig.guardrailPort,
    getCorrelationHeaders: getFetchCorrelationHeaders,
  });
  // Start immediately so gateway model prewarm (before plugin services) also
  // routes through the guardrail when Bedrock is the primary model.
  interceptor.start();

  api.registerService({
    id: "llm-interceptor",
    start: async () => {
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
      return {
        stop: () => {
          interceptor.stop();
          healthMonitor.stop();
        },
      };
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
      timeoutMs: INSPECT_TIMEOUT_MS,
      correlation: { runId: toolCtx?.runId, sessionId },
    });
    if (res.status === 0) {
      // No verdict is available: the request failed, the listener did not
      // prove itself, or the body broke off. This follows
      // DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN.
      return unavailableVerdict(`sidecar unreachable: ${res.error ?? "no answer"}`);
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
          tool_call_id: (event as { toolCallId?: string }).toolCallId,
        },
        ctx,
      );

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
        // The gateway keys a block notice by this id, so the proxy can show
        // the block on the model reply that follows it (GAP-0644).
        tool_call_id: (event as { toolCallId?: string }).toolCallId,
      },
      ctx,
    );

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
  });

  // ─── Slash command: /scan ───

  api.registerCommand({
    name: "scan",
    description: "Scan a skill, plugin, MCP config, or source code with DefenseClaw",
    args: [
      { name: "target", description: "Path to skill/plugin directory, MCP config, or source code", required: true },
      { name: "type", description: "Scan type: skill (default), plugin, mcp, code", required: false },
    ],
    handler: async ({ args }) => {
      const target = args.target as string | undefined;
      if (!target) {
        return { text: "Usage: /scan <path> [skill|plugin|mcp|code]" };
      }

      const scanType = (args.type ?? "skill") as string;

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

  // ─── Slash command: /block ───

  api.registerCommand({
    name: "block",
    description: "Block a skill, MCP server, or plugin",
    args: [
      { name: "type", description: "Target type: skill, mcp, plugin", required: true },
      { name: "name", description: "Name of the target to block", required: true },
      { name: "reason", description: "Reason for blocking", required: false },
    ],
    handler: async ({ args }) => {
      const targetType = args.type as InstallType | undefined;
      const name = args.name as string | undefined;
      if (!targetType || !name) {
        return { text: "Usage: /block <skill|mcp|plugin> <name> [reason]" };
      }

      const reason = (args.reason as string) || "Blocked via /block command";

      await enforcer.block(targetType, name, reason);
      return {
        text: `Blocked ${targetType} **${name}**: ${reason}`,
      };
    },
  });

  // ─── Slash command: /allow ───

  api.registerCommand({
    name: "allow",
    description: "Allow-list a skill, MCP server, or plugin",
    args: [
      { name: "type", description: "Target type: skill, mcp, plugin", required: true },
      { name: "name", description: "Name of the target to allow", required: true },
      { name: "reason", description: "Reason for allowing", required: false },
    ],
    handler: async ({ args }) => {
      const targetType = args.type as InstallType | undefined;
      const name = args.name as string | undefined;
      if (!targetType || !name) {
        return { text: "Usage: /allow <skill|mcp|plugin> <name> [reason]" };
      }

      const reason = (args.reason as string) || "Allowed via /allow command";

      await enforcer.allow(targetType, name, reason);
      return {
        text: `Allow-listed ${targetType} **${name}**: ${reason}`,
      };
    },
  });
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
