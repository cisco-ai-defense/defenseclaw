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
  HEADER_HTTP_CONTENT_TYPE,
} from "./correlation-headers.js";

/** OpenClaw passes full gateway config and the defenseclaw plugin entry config. */
type DefenseClawPluginHost = PluginApi & {
  config?: unknown;
  pluginConfig?: { awsHttp1Shim?: "auto" | "on" | "off" };
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
import { createFetchInterceptor } from "./fetch-interceptor.js";
import { HealthMonitor } from "./health-monitor.js";

async function readPluginAgentSection(api: PluginApi): Promise<{
  id?: string;
  name?: string;
  policyId?: string;
}> {
  const ext = api as PluginApi & {
    getPluginConfig?: () => Promise<Record<string, unknown>>;
  };
  if (typeof ext.getPluginConfig !== "function") return {};
  try {
    const c = await ext.getPluginConfig();
    const agent = c?.agent as Record<string, unknown> | undefined;
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
  const SIDECAR_TOKEN = sidecarConfig.token;
  const INSPECT_TIMEOUT_MS = 2_000;

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

  const daemonClient = new DaemonClient({
    baseUrl: sidecarConfig.baseUrl,
    token: sidecarConfig.token,
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
    token: SIDECAR_TOKEN,
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
      healthMonitor.start();
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
  ): Promise<{ action: string; severity: string; reason: string; mode: string }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), INSPECT_TIMEOUT_MS);
    const started = performance.now();
    try {
      const base = await daemonClient.buildOutboundHeaders({
        runId: toolCtx?.runId,
        sessionId: toolCtx?.sessionId ?? toolCtx?.sessionKey,
      });
      const headers: Record<string, string> = {
        ...base,
        [HEADER_HTTP_CONTENT_TYPE]: "application/json",
      };
      const res = await fetch(`${SIDECAR_API}/api/v1/inspect/tool`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      daemonClient.applyStickyFromHttpResponse(res);
      const duration_ms = Math.round(performance.now() - started);
      logOutboundRequest({
        runId: toolCtx?.runId,
        sessionId: toolCtx?.sessionId ?? toolCtx?.sessionKey,
        agentId: identityCache?.agentId ?? "unknown",
        status_code: res.status,
        duration_ms,
      });
      if (!res.ok) {
        return { action: "allow", severity: "NONE", reason: `sidecar returned ${res.status}`, mode: "observe" };
      }
      return (await res.json()) as {
        action: string;
        severity: string;
        reason: string;
        mode: string;
      };
    } catch {
      const duration_ms = Math.round(performance.now() - started);
      logOutboundRequest({
        runId: toolCtx?.runId,
        sessionId: toolCtx?.sessionId ?? toolCtx?.sessionKey,
        agentId: identityCache?.agentId ?? "unknown",
        status_code: 0,
        duration_ms,
      });
      return { action: "allow", severity: "NONE", reason: "sidecar unreachable", mode: "observe" };
    } finally {
      clearTimeout(timer);
    }
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
        },
        ctx,
      );

      console.log(
        `[defenseclaw] message-tool verdict:${verdict.action} severity:${verdict.severity}`,
      );

      if (verdict.action === "block" && verdict.mode === "action") {
        return { block: true, blockReason: `DefenseClaw: outbound blocked — ${verdict.reason}` };
      }
      return;
    }

    const verdict = await inspectTool(
      {
        tool: event.toolName,
        args: event.params,
      },
      ctx,
    );

    console.log(
      `[defenseclaw] tool:${event.toolName} verdict:${verdict.action} severity:${verdict.severity}`,
    );

    if (verdict.action === "block" && verdict.mode === "action") {
      return { block: true, blockReason: `DefenseClaw: ${verdict.reason}` };
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
          SIDECAR_TOKEN,
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
