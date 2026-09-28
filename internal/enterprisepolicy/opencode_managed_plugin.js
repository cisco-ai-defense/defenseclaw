// defenseclaw-managed-opencode-plugin v1
// DefenseClaw managed OpenCode plugin (machine policy) — DO NOT EDIT.
//
// The standalone profile installs this file at
// <InstallRoot>/share/opencode/defenseclaw.js and names it in OpenCode's
// managed config (/etc/opencode, %ProgramData%\opencode or
// /Library/Application Support/opencode), which standard users cannot
// change, so it runs in every user's OpenCode. It is the same file on every
// host and holds no per-user value: each call goes through the
// administrator-owned hook binary next to it
// (<InstallRoot>/bin/defenseclaw-hook). The hook binary resolves the user's
// gateway transport from protected machine state (the peer-authorized hook
// socket on Linux and macOS, the user's protected runtime on Windows),
// applies the organization's foreign-plugin guard, and fails closed.
//
// Wire contract: the hook binary receives {hook_event_name, tool_name,
// tool_input, tool_response, cwd, ...} on stdin, posts it to
// /api/v1/opencode/hook and prints the gateway's JSON response; a
// hook_output decision of "deny" or "block" aborts the tool.

import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DC_PLUGIN_URL = import.meta.url;
const DC_PLUGIN_FILE = fileURLToPath(DC_PLUGIN_URL);
// <InstallRoot>/share/opencode/defenseclaw.js -> <InstallRoot>/bin.
const DC_HOOK_BINARY = join(
  dirname(dirname(dirname(DC_PLUGIN_FILE))),
  "bin",
  process.platform === "win32" ? "defenseclaw-hook.exe" : "defenseclaw-hook",
);
// Above the hook binary's own request budget, so it can always deliver its
// fail-closed answer before this plugin gives up on it.
const DC_HOOK_TIMEOUT_MS = 30000;
const DC_MAX_HOOK_OUTPUT = 1048576;

// OpenCode passes the effective config (including its derived plugin_origins
// list) to every plugin's config hook after external plugins have loaded, and
// then runs hooks in that order. This plugin is authoritative over the final
// tool arguments only when no plugin follows it. Start conservative until the
// config hook proves that.
let DC_ARGUMENTS_AUTHORITATIVE = false;
let DC_LATER_PLUGIN_COUNT = 0;
let DC_MCP_SERVERS = [];
let DC_MCP_IDENTITY_STATUS = "unverified";

function defenseclawPluginSpecifier(origin) {
  const spec = origin && origin.spec;
  if (Array.isArray(spec)) return typeof spec[0] === "string" ? spec[0] : "";
  return typeof spec === "string" ? spec : "";
}

function defenseclawNormalizedPluginURL(spec) {
  if (!spec) return "";
  let url;
  try {
    if (spec.startsWith("file:")) {
      url = new URL(spec);
    } else if (spec.startsWith("/") || /^[A-Za-z]:[\\/]/.test(spec)) {
      // The managed config names this plugin by its absolute path.
      url = pathToFileURL(spec);
    } else {
      return "";
    }
  } catch (_) {
    return "";
  }
  url.search = "";
  url.hash = "";
  const href = url.href;
  // Windows paths are case-insensitive.
  return process.platform === "win32" ? href.toLowerCase() : href;
}

// OpenCode's published MCP tool-name sanitizer
// (packages/opencode/src/mcp/catalog.ts).
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

// defenseclawDeploymentRemoved reports whether DefenseClaw was uninstalled:
// uninstall removes this file with the rest of the payload, and a standard
// user cannot remove it. Any other inspection result keeps enforcing.
async function defenseclawDeploymentRemoved() {
  try {
    await lstat(DC_PLUGIN_FILE);
    return false;
  } catch (err) {
    return !!err && err.code === "ENOENT";
  }
}

// defenseclawRunHook runs the administrator-owned hook binary with args and
// the JSON payload on stdin. It resolves to {ok, code, stdout, error}; ok is
// false only when the binary could not be run to completion.
function defenseclawRunHook(args, payload) {
  return new Promise((resolve) => {
    try {
      const child = execFile(
        DC_HOOK_BINARY,
        args,
        { timeout: DC_HOOK_TIMEOUT_MS, maxBuffer: DC_MAX_HOOK_OUTPUT, windowsHide: true },
        (err, stdout) => {
          const text = String(stdout || "");
          if (err && typeof err.code !== "number") {
            // Spawn failure, timeout (signal) or an oversized answer.
            resolve({ ok: false, code: -1, stdout: text, error: err.message || String(err) });
            return;
          }
          resolve({ ok: true, code: err ? err.code : 0, stdout: text, error: "" });
        },
      );
      if (child.stdin) {
        child.stdin.on("error", () => {});
        child.stdin.end(JSON.stringify(payload));
      }
    } catch (err) {
      resolve({ ok: false, code: -1, stdout: "", error: err && err.message ? err.message : String(err) });
    }
  });
}

function defenseclawLastJSON(stdout) {
  const lines = String(stdout || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) return undefined;
  try {
    const value = JSON.parse(lines[lines.length - 1]);
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch (_) {
    return null;
  }
}

// defenseclawForeignHookCheck runs the hook binary's foreign-plugin guard
// for event; the gateway records each denial (connector, user and file). It
// sends no session ID: a block belongs to the agent process, so a restarted
// agent that resumes the session starts clean.
function defenseclawForeignHookCheck(event, cwd) {
  return defenseclawRunHook(
    ["hook", "--connector", "opencode", "--foreign-hook-check"],
    { hook_event_name: event, cwd: cwd || "" },
  );
}

// defenseclawStartupGuard asks the hook binary for the foreign-plugin
// guard's decision once at load: a foreign plugin present now keeps running
// for this process even if its file is deleted later. It resolves to a block
// reason or "".
async function defenseclawStartupGuard(cwd) {
  const result = await defenseclawForeignHookCheck("defenseclaw.plugin.loaded", cwd);
  if (!result.ok || result.code !== 0) {
    if (await defenseclawDeploymentRemoved()) return "";
    // OpenCode loads plugins once, so this block holds for the life of the
    // process: say to restart the agent.
    const detail = String(result.error || "exit " + result.code).split(/\r?\n/)[0].trim();
    return "DefenseClaw could not check for unapproved plugins when the agent started (" + detail +
      "), so this tool call is blocked. Restart the agent once DefenseClaw is available.";
  }
  const verdict = defenseclawLastJSON(result.stdout);
  if (verdict && verdict.deny === false) return "";
  return verdict && typeof verdict.reason === "string" && verdict.reason
    ? verdict.reason
    : "DefenseClaw blocked this tool call because an unapproved plugin is present.";
}

// defenseclawBlockError is the error a blocked tool call fails with. OpenCode
// shows it as the tool's error and hands it to the model, so it says that
// DefenseClaw blocked the call under policy and that the call did not run.
function defenseclawBlockError(reason) {
  const text = String(reason || "").trim();
  if (/^DefenseClaw\b/.test(text)) return new Error(text);
  return new Error("DefenseClaw blocked this tool call under your organization's policy, so it did not run: " + (text || "no reason was given"));
}

// defenseclawBlock returns the error a blocked tool call fails with, after
// showing the same text as a best-effort error notice: some OpenCode
// versions show a failed tool with no text, or as successful, so the error
// alone did not reliably tell the user DefenseClaw blocked the call.
function defenseclawBlock(client, reason) {
  const error = defenseclawBlockError(reason);
  defenseclawShowNotice(client, error.message, "error");
  return error;
}

// defenseclawConfirmNotice is the notice for a verdict that asks for the
// user's confirmation (human-in-the-loop). This plugin cannot ask, so the
// call runs; the notice keeps that from happening silently. A reason that
// already comes from DefenseClaw (it names the rule) leads the notice.
function defenseclawConfirmNotice(data) {
  if (!data || String(data.raw_action || "").toLowerCase() !== "confirm" || data.action === "block") return "";
  const reason = String(data.reason || "").trim();
  const severity = data.severity && data.severity !== "NONE" ? " (" + data.severity + ")" : "";
  const lead = /^DefenseClaw\b/.test(reason)
    ? reason.replace(/\.$/, "")
    : "DefenseClaw flagged this tool call for review" + severity + (reason ? ": " + reason : "");
  return lead + ". OpenCode cannot ask you to confirm it here, so it runs; DefenseClaw recorded it.";
}

// defenseclawShowNotice shows a notice in the OpenCode TUI. It is best
// effort: without a TUI client, or when the notice cannot be shown, nothing
// else changes.
function defenseclawShowNotice(client, message, variant) {
  if (!message) return;
  try {
    const shown = client && client.tui && typeof client.tui.showToast === "function"
      ? client.tui.showToast({ body: { message, variant: variant || "warning" } })
      : undefined;
    if (shown && typeof shown.catch === "function") shown.catch(() => {});
  } catch (_) {
    // A notice never blocks or fails the tool call.
  }
}

// defenseclawSend forwards one event through the hook binary and resolves
// to {reason, mode, notice}: reason is non-empty when the call must be
// blocked, and notice when it runs with a confirm verdict.
// Every failure blocks, except after uninstall (the hook binary answers
// nothing, or cannot run while this file is gone too).
async function defenseclawSend(event, payload) {
  const result = await defenseclawRunHook(
    ["hook", "--connector", "opencode", "--enterprise-managed", "--event", event],
    payload,
  );
  if (!result.ok) {
    if (await defenseclawDeploymentRemoved()) return { reason: "", mode: "" };
    return { reason: "DefenseClaw hook failed closed (" + result.error + ")", mode: "" };
  }
  const data = defenseclawLastJSON(result.stdout);
  if (data === undefined && result.code === 0) {
    // The hook is a no-op only after an administrator removed DefenseClaw.
    return { reason: "", mode: "" };
  }
  const out = data && data.hook_output;
  if (out && (out.decision === "deny" || out.decision === "block")) {
    return { reason: out.reason || "DefenseClaw blocked this tool call.", mode: data.mode || "" };
  }
  if (!data || result.code !== 0) {
    return { reason: "DefenseClaw hook failed closed (exit " + result.code + ")", mode: "" };
  }
  return { reason: "", mode: data.mode || "", notice: defenseclawConfirmNotice(data) };
}

function defenseclawToolPayload(event, toolName, toolInput, cwd, context, toolResult, mcpIdentity) {
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
  return payload;
}

function defenseclawLifecyclePayload(event, cwd) {
  const properties = event.properties || {};
  const info = properties.info || {};
  return {
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
  };
}

export const DefenseClawManaged = async ({ client, directory, worktree }) => {
  const cwd = directory || worktree || "";
  const startupGuard = defenseclawStartupGuard(cwd);
  return {
    config: async (config) => {
      defenseclawConfigure(config);
      // Load health is diagnostic only; tool hooks enforce on their own.
      await defenseclawSend("defenseclaw.plugin.loaded", {
        hook_event_name: "defenseclaw.plugin.loaded",
        load_heartbeat: true,
        arguments_authoritative: DC_ARGUMENTS_AUTHORITATIVE,
        later_plugin_count: DC_LATER_PLUGIN_COUNT,
        mcp_identity_status: DC_MCP_IDENTITY_STATUS,
        cwd,
      });
    },
    // Session lifecycle telemetry; OpenCode does not await this hook and
    // the result never blocks anything.
    event: async ({ event }) => {
      if (!event || ![
        "session.created", "session.updated", "session.status", "session.idle",
        "session.compacted", "session.error", "session.deleted",
      ].includes(event.type)) return;
      await defenseclawSend(event.type, defenseclawLifecyclePayload(event, cwd));
    },
    // Throwing aborts the tool. The decision is resolved before the throw.
    "tool.execute.before": async (input, output) => {
      const blocked = await startupGuard;
      if (blocked) {
        // The load-time block holds for this process; checking again only
        // lets the gateway record this denied call.
        await defenseclawForeignHookCheck("tool.execute.before", cwd);
        throw defenseclawBlock(client, blocked);
      }
      const mcpIdentity = defenseclawResolveMCPServer(input && input.tool);
      const verdict = await defenseclawSend(
        "tool.execute.before",
        defenseclawToolPayload("tool.execute.before", input && input.tool, output && output.args, cwd, input, undefined, mcpIdentity),
      );
      if (verdict.reason) throw defenseclawBlock(client, verdict.reason);
      if (verdict.notice) defenseclawShowNotice(client, verdict.notice);
      if (verdict.mode === "action" && mcpIdentity.status === "ambiguous") {
        throw defenseclawBlock(client, "DefenseClaw refused an OpenCode tool with ambiguous MCP server identity.");
      }
      if (verdict.mode === "action" && !DC_ARGUMENTS_AUTHORITATIVE) {
        throw defenseclawBlock(
          client,
          "DefenseClaw refused an OpenCode action because later plugin argument mutations are not observable.",
        );
      }
    },
    // Observe-only telemetry, awaited so the gateway can attribute this
    // outcome to its call before a later tool starts.
    "tool.execute.after": async (input, output) => {
      const result = output && { title: output.title, output: output.output, metadata: output.metadata };
      await defenseclawSend(
        "tool.execute.after",
        defenseclawToolPayload("tool.execute.after", input && input.tool, input && input.args, cwd, input, result,
          defenseclawResolveMCPServer(input && input.tool)),
      );
    },
  };
};
