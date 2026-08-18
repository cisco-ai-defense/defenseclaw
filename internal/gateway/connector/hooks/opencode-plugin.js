// defenseclaw-managed-plugin v7
// DefenseClaw opencode bridge plugin — DO NOT EDIT.
//
// opencode auto-loads JS/TS plugins from ~/.config/opencode/plugins/ at
// startup (https://opencode.ai/docs/plugins/). This dependency-free
// bridge forwards each tool call to the local DefenseClaw gateway and
// aborts the tool — by throwing, exactly like opencode's own
// .env-protection example — when the gateway returns a block decision.
//
// The gateway address, stable scoped-token sidecar path, and fail mode are
// substituted in at setup time. The token itself is loaded and validated for
// every request, so a transactional rotation never leaves a replacement
// credential in this longer-lived plugin. DefenseClaw's Teardown removes this
// file (managed-file backup heal).
//
// Wire contract: POST {hook_event_name, tool_name, tool_input,
// tool_response, cwd} to
// /api/v1/opencode/hook; the response carries hook_output={decision,
// reason}; decision "deny"/"block" aborts the tool.

import { open } from "node:fs/promises";

// DC_-prefixed constants are non-secret values baked in at setup time, not
// env-var reads — the envvars registry gate scans for DEFENSECLAW_* tokens.
const DC_API_ADDR = "{{.APIAddr}}";
const DC_TOKEN_FILE = "{{.TokenFileJS}}";
const DC_FAIL_MODE = "{{.FailMode}}"; // "open" or "closed"
const DC_TIMEOUT_MS = 10000;
const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const DC_MAX_TOKEN_FILE_BYTES = 4096;

async function defenseclawToken() {
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

async function defenseclawPost(event, toolName, toolInput, toolResponse, cwd, context, actionable) {
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
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0" };
  headers["Authorization"] = "Bearer " + token;
  try {
    const res = await fetch("http://" + DC_API_ADDR + "/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body: JSON.stringify({
        hook_event_name: event,
        tool_name: toolName || "",
        tool_input: toolInput || {},
        tool_response: toolResponse || null,
        session_id: context && (context.sessionID || context.sessionId) || "",
        turn_id: context && (context.messageID || context.messageId) || "",
        tool_call_id: context && (context.callID || context.callId) || "",
        agent_name: context && context.agent || "",
        cwd: cwd || "",
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      // Gateway answered with a bad status (auth/5xx). Honor fail mode.
      if (DC_FAIL_MODE === "closed") {
        return { reason: "DefenseClaw hook failed closed (HTTP " + res.status + ")" };
      }
      return null;
    }
    const data = await res.json();
    const out = data && data.hook_output;
    if (out && (out.decision === "deny" || out.decision === "block")) {
      return { reason: out.reason || "DefenseClaw blocked this tool call." };
    }
    return null;
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
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0" };
  headers["Authorization"] = "Bearer " + token;
  try {
    await fetch("http://" + DC_API_ADDR + "/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body: JSON.stringify({
        hook_event_name: event.type,
        event_type: event.type,
        session_id: properties.sessionID || properties.sessionId || info.id || "",
        parent_session_id: properties.parentID || properties.parentId || info.parentID || info.parentId || "",
        agent_id: properties.agentID || properties.agentId || info.agentID || info.agentId || "",
        agent_name: properties.agent || info.agent || "",
        status: event.type === "session.error" ? "error" : (properties.status || info.status || ""),
        cwd: cwd || "",
        event: properties,
      }),
      signal: controller.signal,
    });
  } catch (_) {
    // Lifecycle telemetry is observe-only and never blocks OpenCode.
  } finally {
    clearTimeout(timer);
  }
}

export const DefenseClaw = async ({ directory, worktree }) => {
  const cwd = directory || worktree || "";
  return {
    // OpenCode publishes its session lifecycle through the generic event
    // hook. Child sessions carry info.parentID, which DefenseClaw maps to
    // a parent-agent relationship while preserving the child session ID.
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
      const verdict = await defenseclawPost(
        "tool.execute.before",
        input && input.tool,
        output && output.args,
        null,
        cwd,
        input,
        true,
      );
      if (verdict) throw new Error(verdict.reason);
    },
    // tool.execute.after is observe-only telemetry. Await delivery so the
    // gateway can attribute this successful outcome to the exact call before
    // a later tool starts; failures remain fail-open because the bridge never
    // throws on an after-hook transport error.
    "tool.execute.after": async (input, output) => {
      await defenseclawPost(
        "tool.execute.after",
        input && input.tool,
        input && input.args,
        output,
        cwd,
        input,
        false,
      );
    },
  };
};
