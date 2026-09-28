// defenseclaw-managed-plugin v7
// DefenseClaw opencode bridge plugin — DO NOT EDIT.
//
// opencode auto-loads JS/TS plugins from ~/.config/opencode/plugins/ at
// startup (https://opencode.ai/docs/plugins/). This dependency-free
// bridge forwards each tool call to the local DefenseClaw gateway and
// aborts the tool — by throwing, exactly like opencode's own
// .env-protection example — when the gateway returns a block decision.
//
{{if .Sandbox}}// OpenShell sandbox variant: DefenseClaw's overlay image installs this file
// root-owned and registers it from the managed /etc/opencode/opencode.json,
// which user and project config cannot remove (OpenCode merges plugin lists).
// The hook ingress address and the fail mode are baked at image build and
// hooks always fail closed. The only runtime input is the per-sandbox binding
// token, an OpenShell provider placeholder read from the process environment
// for every request; the supervisor swaps in the real credential only on the
// ingress endpoint. Each request carries a fresh idempotency key and is
// retried once on a transport failure or relay 502/503/504, because the
// OpenShell relay occasionally drops a request.
{{else}}// The gateway address, stable scoped-token sidecar path, and fail mode are
// substituted in at setup time. The token itself is loaded and validated for
// every request, so a transactional rotation never leaves a replacement
// credential in this longer-lived plugin. DefenseClaw's Teardown removes this
// file (managed-file backup heal).
{{end}}//
// Wire contract: POST {hook_event_name, tool_name, tool_input,
// tool_response, cwd} to
// /api/v1/opencode/hook; the response carries hook_output={decision,
// reason}; decision "deny"/"block" aborts the tool.

{{if .Sandbox}}import { randomUUID } from "node:crypto";
{{else}}import { open } from "node:fs/promises";
{{end}}import { userInfo } from "node:os";

// DC_-prefixed constants are non-secret values baked in at setup time, not
// env-var reads — the envvars registry gate scans for DEFENSECLAW_* tokens.
const DC_API_ADDR = "{{.APIAddr}}";
{{if .Sandbox}}const DC_FAIL_MODE = "closed"; // sandbox hooks always fail closed
const DC_TIMEOUT_MS = {{.SandboxMaxTime}}000;
const DC_RETRY_TIMEOUT_MS = {{.SandboxRetryMaxTime}}000;
const DC_PLUGIN_URL = import.meta.url;
// OpenShell placeholders (openshell:resolve:env:v<revision>_<KEY>) and the
// host token alphabet; anything else is never sent.
const DC_TOKEN_PATTERN = /^[A-Za-z0-9:._-]{1,512}$/;
{{else}}const DC_TOKEN_FILE = "{{.TokenFileJS}}";
const DC_FAIL_MODE = "{{.FailMode}}"; // "open" or "closed"
const DC_TIMEOUT_MS = 10000;
const DC_PLUGIN_URL = import.meta.url;
const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const DC_MAX_TOKEN_FILE_BYTES = 4096;
{{end}}
// OpenCode v1.18.10-v1.18.19 passes the effective config (including its derived
// plugin_origins list) to every plugin's config hook after external plugins
// have loaded. Hooks then run sequentially in that same order. DefenseClaw's
// global plugin is authoritative over final args only when no external plugin
// follows it. Start conservative until the config hook proves that condition.
let DC_ARGUMENTS_AUTHORITATIVE = false;
let DC_LATER_PLUGIN_COUNT = 0;
let DC_MCP_SERVERS = [];
let DC_MCP_IDENTITY_STATUS = "unverified";

// defenseclawIdentityHeaders reports which end user this plugin runs as.
//
// Under a managed install the gateway runs as a service account, so it cannot
// see whose session a request belongs to; the plugin is in-session and can.
// A value that is not a safe header field is dropped rather than sanitized, so
// a hostile account name cannot smuggle a second header into every hook call.
function defenseclawIdentityHeaders() {
  const headers = {};
  let info;
  try {
    info = userInfo();
  } catch (_) {
    // No identity is a supported outcome: the record is emitted unattributed
    // rather than wrongly attributed.
    return headers;
  }
  // uid is -1 on Windows, where no POSIX uid exists. Reporting it would put a
  // value in user.id that belongs to neither identifier namespace.
  if (typeof info.uid === "number" && info.uid >= 0) {
    headers["X-DefenseClaw-User-Id"] = String(info.uid);
  }
  if (defenseclawSafeIdentityValue(info.username)) {
    headers["X-DefenseClaw-User-Name"] = info.username;
  }
  return headers;
}

// defenseclawSafeIdentityValue mirrors the account-name allowlist the POSIX
// hooks apply in their shared hardening helper.
function defenseclawSafeIdentityValue(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 256 &&
    /^[A-Za-z0-9._-]+$/.test(value);
}

function defenseclawPluginSpecifier(origin) {
  const spec = origin && origin.spec;
  if (Array.isArray(spec)) return typeof spec[0] === "string" ? spec[0] : "";
  return typeof spec === "string" ? spec : "";
}

function defenseclawNormalizedPluginURL(spec) {
  if (!spec || !spec.startsWith("file:")) return "";
  try {
    return new URL(spec).href;
  } catch (_) {
    return "";
  }
}

// This is OpenCode v1.18.10-v1.18.19's published MCP tool-name sanitizer, mirrored
// exactly from packages/opencode/src/mcp/catalog.ts.
function defenseclawSanitizeMCPName(value) {
  return String(value || "").replace(/[^a-zA-Z0-9_-]/g, "_");
}

function defenseclawConfigure(config) {
  const origins = config && Array.isArray(config.plugin_origins) ? config.plugin_origins : [];
  const selfURL = defenseclawNormalizedPluginURL(DC_PLUGIN_URL);
  const ownIndex = origins.findIndex(
    (origin) => defenseclawNormalizedPluginURL(defenseclawPluginSpecifier(origin)) === selfURL,
  );
  DC_LATER_PLUGIN_COUNT = ownIndex >= 0 ? origins.length - ownIndex - 1 : origins.length;
  DC_ARGUMENTS_AUTHORITATIVE = ownIndex >= 0 && DC_LATER_PLUGIN_COUNT === 0;

  const mcp = config && config.mcp;
  if (!mcp || typeof mcp !== "object" || Array.isArray(mcp)) {
    DC_MCP_SERVERS = [];
    DC_MCP_IDENTITY_STATUS = "authoritative";
    return;
  }
  DC_MCP_SERVERS = Object.keys(mcp)
    .filter((name) => mcp[name] && typeof mcp[name] === "object" && mcp[name].enabled !== false)
    .map((name) => ({ name, sanitized: defenseclawSanitizeMCPName(name) }))
    .filter((entry) => entry.sanitized);
  const seen = new Set();
  DC_MCP_IDENTITY_STATUS = "authoritative";
  for (const entry of DC_MCP_SERVERS) {
    if (seen.has(entry.sanitized)) {
      DC_MCP_IDENTITY_STATUS = "collision";
      break;
    }
    seen.add(entry.sanitized);
  }
}

function defenseclawResolveMCPServer(toolName) {
  const tool = String(toolName || "");
  const candidates = DC_MCP_SERVERS.filter((entry) => tool.startsWith(entry.sanitized + "_"));
  if (candidates.length === 0) return { status: "not_mcp", name: "" };
  if (DC_MCP_IDENTITY_STATUS !== "authoritative" || candidates.length !== 1) {
    return { status: "ambiguous", name: "" };
  }
  return { status: "authoritative", name: candidates[0].name };
}

{{if .Sandbox}}async function defenseclawToken() {
  const token = String(process.env.DEFENSECLAW_SANDBOX_TOKEN || "");
  if (!DC_TOKEN_PATTERN.test(token)) throw new Error("missing or malformed sandbox binding token");
  return token;
}

// defenseclawFetch POSTs to the baked ingress: one attempt, then exactly one
// retry with the same idempotency key after a transport failure (no
// connection, reset, timeout) or a relay 502/503/504. The ingress answers a
// retried key from its dedupe window instead of evaluating the event twice.
async function defenseclawFetch(headers, body) {
  const key = randomUUID();
  let last;
  for (let attempt = 0; attempt < 2; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), attempt === 0 ? DC_TIMEOUT_MS : DC_RETRY_TIMEOUT_MS);
    try {
      const res = await fetch("http://" + DC_API_ADDR + "/api/v1/opencode/hook", {
        method: "POST",
        headers: { ...headers, "X-DefenseClaw-Hook-Idempotency-Key": key },
        body,
        signal: controller.signal,
      });
      if (attempt === 0 && (res.status === 502 || res.status === 503 || res.status === 504)) {
        last = res;
        continue;
      }
      return res;
    } catch (err) {
      last = err;
    } finally {
      clearTimeout(timer);
    }
  }
  if (last instanceof Error) throw last;
  return last;
}
{{else}}async function defenseclawToken() {
  const file = await open(DC_TOKEN_FILE, "r");
  try {
    const raw = new Uint8Array(DC_MAX_TOKEN_FILE_BYTES + 1);
    let offset = 0;
    while (offset < raw.byteLength) {
      const { bytesRead } = await file.read(raw, offset, raw.byteLength - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > DC_MAX_TOKEN_FILE_BYTES) throw new Error("oversized scoped hook credential");
    const token = new TextDecoder("utf-8", { fatal: true }).decode(raw.subarray(0, offset)).trim();
    if (!DC_TOKEN_PATTERN.test(token)) throw new Error("invalid scoped hook credential");
    return token;
  } finally {
    await file.close();
  }
}
{{end}}
async function defenseclawPost(event, toolName, toolInput, cwd, context, toolResult, mcpIdentity, actionable) {
  let token;
  try {
    token = await defenseclawToken();
  } catch (_) {
    // Missing, unreadable, or malformed credentials are never safe at a
    // pre-execution boundary, even when transport fail-open was selected.
    if (actionable) return { reason: "DefenseClaw hook credential is unavailable." };
    return null;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DC_TIMEOUT_MS);
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...defenseclawIdentityHeaders() };
  headers["Authorization"] = "Bearer " + token;
  try {
    const payload = {
      hook_event_name: event,
      tool_name: toolName || "",
      tool_input: toolInput || {},
      session_id: context && (context.sessionID || context.sessionId) || "",
      turn_id: context && (context.messageID || context.messageId) || "",
      tool_call_id: context && (context.callID || context.callId) || "",
      agent_name: context && context.agent || "",
      cwd: cwd || "",
      load_heartbeat: true,
      arguments_authoritative: DC_ARGUMENTS_AUTHORITATIVE,
      mcp_identity_status: mcpIdentity && mcpIdentity.status || "not_mcp",
    };
    if (mcpIdentity && mcpIdentity.status === "authoritative") {
      payload.mcp_server_name = mcpIdentity.name;
    }
    if (toolResult !== undefined) {
      payload.tool_response = toolResult;
      payload.tool_result = toolResult;
    }
    const res = await {{if .Sandbox}}defenseclawFetch(headers, JSON.stringify(payload));{{else}}fetch("http://" + DC_API_ADDR + "/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    });{{end}}
    if (!res.ok) {
      // Gateway answered with a bad status (auth/5xx). Honor fail mode.
      if (DC_FAIL_MODE === "closed") {
        return { reason: "DefenseClaw hook failed closed (HTTP " + res.status + ")" };
      }
      return null;
    }
    const data = await res.json();
{{if .Sandbox}}    // A reply without a known verdict is as untrustworthy as no reply.
    if (!data || !["allow", "block", "confirm", "alert"].includes(data.action)) {
      return { reason: "DefenseClaw hook failed closed (invalid gateway verdict)" };
    }
{{end}}    const out = data && data.hook_output;
    if (out && (out.decision === "deny" || out.decision === "block")) {
      return { reason: out.reason || "DefenseClaw blocked this tool call.", mode: data.mode || "" };
    }
{{if .Sandbox}}    if (data.action === "block") {
      return { reason: data.reason || "DefenseClaw blocked this tool call.", mode: data.mode || "" };
    }
{{end}}    return { reason: "", mode: data && data.mode || "" };
  } catch (err) {
    // Transport failure (gateway unreachable / timeout). Honor fail mode:
    // closed → block, open → allow.
    if (DC_FAIL_MODE === "closed") {
      return { reason: "DefenseClaw hook failed closed (" + (err && err.message ? err.message : String(err)) + ")" };
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function defenseclawPostLoadHeartbeat(cwd) {
  let token;
  try {
    token = await defenseclawToken();
  } catch (_) {
    // Load health is diagnostic only; tool hooks enforce credential failures.
    return;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DC_TIMEOUT_MS);
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...defenseclawIdentityHeaders() };
  headers["Authorization"] = "Bearer " + token;
  try {
{{if .Sandbox}}    await defenseclawFetch(headers, JSON.stringify({
      hook_event_name: "defenseclaw.plugin.loaded",
      load_heartbeat: true,
      arguments_authoritative: DC_ARGUMENTS_AUTHORITATIVE,
      later_plugin_count: DC_LATER_PLUGIN_COUNT,
      mcp_identity_status: DC_MCP_IDENTITY_STATUS,
      cwd: cwd || "",
    }));
{{else}}    await fetch("http://" + DC_API_ADDR + "/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body: JSON.stringify({
        hook_event_name: "defenseclaw.plugin.loaded",
        load_heartbeat: true,
        arguments_authoritative: DC_ARGUMENTS_AUTHORITATIVE,
        later_plugin_count: DC_LATER_PLUGIN_COUNT,
        mcp_identity_status: DC_MCP_IDENTITY_STATUS,
        cwd: cwd || "",
      }),
      signal: controller.signal,
    });
{{end}}  } catch (_) {
    // Load health is diagnostic only; tool hooks still apply the configured
    // fail mode independently when the gateway cannot be reached.
  } finally {
    clearTimeout(timer);
  }
}

async function defenseclawPostLifecycle(event, cwd) {
  if (!event || !event.type) return;
  let token;
  try {
    token = await defenseclawToken();
  } catch (_) {
    // Lifecycle telemetry is observe-only; an unavailable credential skips it.
    return;
  }
  const properties = event.properties || {};
  const info = properties.info || {};
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DC_TIMEOUT_MS);
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...defenseclawIdentityHeaders() };
  headers["Authorization"] = "Bearer " + token;
  try {
    await {{if .Sandbox}}defenseclawFetch(headers, JSON.stringify({
        hook_event_name: event.type,
        event_type: event.type,
        source_event_id: event.id || "",
        session_id: properties.sessionID || properties.sessionId || info.id || "",
        parent_session_id: properties.parentID || properties.parentId || info.parentID || info.parentId || "",
        agent_id: properties.agentID || properties.agentId || info.agentID || info.agentId || "",
        agent_name: properties.agent || info.agent || "",
        status: event.type === "session.error" ? "error" : (properties.status || info.status || ""),
        cwd: cwd || "",
        load_heartbeat: true,
        event: properties,
      }));
{{else}}fetch("http://" + DC_API_ADDR + "/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body: JSON.stringify({
        hook_event_name: event.type,
        event_type: event.type,
        source_event_id: event.id || "",
        session_id: properties.sessionID || properties.sessionId || info.id || "",
        parent_session_id: properties.parentID || properties.parentId || info.parentID || info.parentId || "",
        agent_id: properties.agentID || properties.agentId || info.agentID || info.agentId || "",
        agent_name: properties.agent || info.agent || "",
        status: event.type === "session.error" ? "error" : (properties.status || info.status || ""),
        cwd: cwd || "",
        load_heartbeat: true,
        event: properties,
      }),
      signal: controller.signal,
    });
{{end}}  } catch (_) {
    // Lifecycle telemetry is observe-only and never blocks OpenCode.
  } finally {
    clearTimeout(timer);
  }
}

{{if .Sandbox}}// OpenCode's TUI shows a tool the plugin refused as its bare command line;
// the thrown reason reaches only the model. A toast shows the user why.
// Best effort and never awaited: a headless run has no TUI, and a missing
// client or a failed request never changes the verdict.
function defenseclawToast(client, reason) {
  try {
    const shown = client && client.tui && typeof client.tui.showToast === "function" &&
      client.tui.showToast({ body: { title: "DefenseClaw blocked this tool call", message: reason, variant: "error", duration: 15000 } });
    if (shown && typeof shown.catch === "function") shown.catch(() => {});
  } catch (_) {
    // No TUI to tell.
  }
}

{{end}}export const DefenseClaw = async ({ directory, worktree{{if .Sandbox}}, client{{end}} }) => {
  const cwd = directory || worktree || "";
  return {
    config: async (config) => {
      defenseclawConfigure(config);
      await defenseclawPostLoadHeartbeat(cwd);
    },
    // OpenCode publishes its session lifecycle through the generic event
    // hook. OpenCode does not await this hook dispatch, so lifecycle delivery
    // is best-effort telemetry only. Child sessions carry info.parentID, which
    // DefenseClaw maps to a parent-agent relationship while preserving the
    // child session ID.
    event: async ({ event }) => {
      if (!event || ![
        "session.created", "session.updated", "session.status", "session.idle",
        "session.compacted", "session.error", "session.deleted",
      ].includes(event.type)) return;
      await defenseclawPostLifecycle(event, cwd);
    },
    // tool.execute.before is opencode's pre-tool hook. Throwing here
    // aborts the tool (same mechanism as the .env-protection example).
    // The decision is resolved BEFORE the throw so a fail-open transport
    // error never turns into an accidental block.
    "tool.execute.before": async (input, output) => {
      const mcpIdentity = defenseclawResolveMCPServer(input && input.tool);
      const verdict = await defenseclawPost(
        "tool.execute.before",
        input && input.tool,
        output && output.args,
        cwd,
        input,
        undefined,
        mcpIdentity,
        true,
      );
{{if .Sandbox}}      if (verdict && verdict.reason) defenseclawToast(client, verdict.reason);
{{end}}      if (verdict && verdict.reason) throw new Error(verdict.reason);
      if (verdict && verdict.mode === "action" && mcpIdentity.status === "ambiguous") {
        throw new Error("DefenseClaw refused an OpenCode tool with ambiguous MCP server identity.");
      }
      if (verdict && verdict.mode === "action" && !DC_ARGUMENTS_AUTHORITATIVE) {
        throw new Error(
          "DefenseClaw refused an OpenCode action because later plugin argument mutations are not observable.",
        );
      }
    },
    // tool.execute.after is observe-only telemetry. Await delivery so the
    // gateway can attribute this outcome to the exact call before a later tool
    // starts; transport and fail-mode results remain advisory and are ignored.
    "tool.execute.after": async (input, output) => {
      const result = output && {
        title: output.title,
        output: output.output,
        metadata: output.metadata,
      };
      await defenseclawPost(
        "tool.execute.after",
        input && input.tool,
        input && input.args,
        cwd,
        input,
        result,
        defenseclawResolveMCPServer(input && input.tool),
        false,
      );
    },
  };
};
