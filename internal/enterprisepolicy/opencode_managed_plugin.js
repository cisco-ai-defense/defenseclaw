// defenseclaw-managed-opencode-plugin v1
// DefenseClaw managed OpenCode plugin (machine policy) — DO NOT EDIT.
//
// The standalone profile installs this file at
// <InstallRoot>/share/opencode/index.js and names it in OpenCode's
// managed config (/etc/opencode, %ProgramData%\opencode or
// /Library/Application Support/opencode), which standard users cannot
// change, so it runs in every user's OpenCode. It is the same file on every
// host and holds no per-user value: each call goes through the
// administrator-owned hook binary next to it
// (<InstallRoot>/bin/defenseclaw-hook). The hook binary resolves the user's
// gateway transport from protected machine state (the peer-authorized hook
// socket on Linux and macOS, the user's protected runtime on Windows),
// applies the organization's foreign-plugin guard, and fails closed unless
// the administrator chose fail mode open; then it answers an explicit allow
// that carries a notice, never an empty answer.
//
// Wire contract: the hook binary receives {hook_event_name, tool_name,
// tool_input, tool_response, cwd, ...} on stdin, posts it to
// /api/v1/opencode/hook and prints the gateway's JSON response; a
// hook_output decision of "deny" or "block" aborts the tool.

import { AsyncLocalStorage } from "node:async_hooks";
import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DC_PLUGIN_URL = import.meta.url;
const DC_PLUGIN_FILE = fileURLToPath(DC_PLUGIN_URL);
// <InstallRoot>/share/opencode/index.js -> <InstallRoot>/bin.
const DC_HOOK_BINARY = join(
  dirname(dirname(dirname(DC_PLUGIN_FILE))),
  "bin",
  process.platform === "win32" ? "defenseclaw-hook.exe" : "defenseclaw-hook",
);
// Above the hook binary's own request budget, so it can always deliver its
// fail-closed answer before this plugin gives up on it.
const DC_HOOK_TIMEOUT_MS = 30000;
const DC_MAX_HOOK_OUTPUT = 1048576;

// V2 pins each inspected tool event before awaiting any verdict.
let DC_ARGUMENTS_AUTHORITATIVE = false;
let DC_LATER_PLUGIN_COUNT = 0;
let DC_MCP_IDENTITY_STATUS = "unverified";

// V2's MCP catalog uses this sanitizer for exposed tool names.
function defenseclawSanitizeMCPName(value) {
  return String(value || "").replace(/[^a-zA-Z0-9_-]/g, "_");
}

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
// guard's decision at load: a foreign plugin present now keeps running for
// this process even if its file is deleted later. It resolves to
// { reason, retryable }. Only a confirmed decision holds for the process; a
// check that could not run, or a deny the guard marks retryable (its gateway
// could not answer and its scan found no unapproved plugin), is asked again
// on the next tool call, so a session started during an outage runs again
// once the gateway is back (GAP-1017, GAP-1180, GAP-1520).
async function defenseclawStartupGuard(cwd) {
  const result = await defenseclawForeignHookCheck("defenseclaw.plugin.loaded", cwd);
  if (!result.ok || result.code !== 0) {
    if (await defenseclawDeploymentRemoved()) return { reason: "", retryable: false };
    const detail = String(result.error || "exit " + result.code).split(/\r?\n/)[0].trim();
    return {
      reason: "DefenseClaw could not check for unapproved plugins when the agent started (" + detail +
        "), so this tool call is blocked. Try again once DefenseClaw is available.",
      retryable: true,
    };
  }
  const verdict = defenseclawLastJSON(result.stdout);
  if (verdict && verdict.deny === false) {
    // foreign_hooks report: the unapproved plugin runs, and the guard names
    // its file and digest for the user (GAP-0697).
    return { reason: "", retryable: false, warnings: Array.isArray(verdict.warnings) ? verdict.warnings.map(String) : [] };
  }
  return {
    reason: verdict && typeof verdict.reason === "string" && verdict.reason
      ? verdict.reason
      : "DefenseClaw blocked this tool call because an unapproved plugin is present.",
    retryable: Boolean(verdict && verdict.retryable === true),
  };
}

// defenseclawBlockError is the error a blocked tool call fails with. OpenCode
// shows it as the tool's error and hands it to the model, so it says that
// DefenseClaw blocked the call under policy and that the call did not run.
// The foreign-plugin guard's reason code is left out; the audit keeps it.
function defenseclawBlockError(reason) {
  const text = String(reason || "").trim();
  if (/^DefenseClaw\b/.test(text)) return new Error(text);
  return new Error("DefenseClaw blocked this tool call under your organization's policy, so it did not run: " + (text.replace(/^enterprise_foreign_hook_blocked:\s*/, "") || "no reason was given"));
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

// defenseclawFailOpenNotice is the notice of a call the hook binary let
// through without a check because the fail mode is open (GAP-0351). The
// hook answers it with an explicit allow; an empty answer stays closed.
function defenseclawFailOpenNotice(data) {
  return data && data.fail_open === true && typeof data.notice === "string" ? data.notice.trim() : "";
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
    // A cached plugin must fail closed while its deployment artifact exists.
    if (await defenseclawDeploymentRemoved()) return { reason: "", mode: "" };
    return { reason: "DefenseClaw hook failed closed (empty response)", mode: "" };
  }
  if (result.code !== 0) {
    // A fail-closed hook names why in its deny body (a stopped gateway and
    // what to do, GAP-0850, GAP-1080); keep that text, not only the status.
    const denied = data && data.hook_output;
    if (denied && (denied.decision === "deny" || denied.decision === "block") && typeof denied.reason === "string" && denied.reason.trim()) {
      return { reason: denied.reason.trim(), mode: "" };
    }
    return { reason: "DefenseClaw hook failed closed (exit " + result.code + ")", mode: "" };
  }
  if (!data || !["allow", "block", "confirm", "alert"].includes(data.action)) {
    return { reason: "DefenseClaw hook failed closed (invalid gateway verdict)", mode: "" };
  }
  const out = data && data.hook_output;
  if (out && (out.decision === "deny" || out.decision === "block")) {
    return { reason: out.reason || "DefenseClaw blocked this tool call.", mode: data.mode || "" };
  }
  if (data.action === "block" || data.action === "confirm") {
    return { reason: "DefenseClaw hook failed closed (missing native deny)", mode: data.mode || "" };
  }
  return { reason: "", mode: data.mode || "", notice: defenseclawFailOpenNotice(data) || defenseclawConfirmNotice(data) };
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

async function defenseclawHooks({ client, directory, worktree }) {
  const cwd = directory || worktree || "";
  let startupGuard = defenseclawStartupGuard(cwd);
  let warned = false;
  return {
    initialize: async () => {
      DC_ARGUMENTS_AUTHORITATIVE = true;
      DC_MCP_IDENTITY_STATUS = "authoritative";
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
        "session.created", "session.status", "session.idle",
        "session.error", "session.deleted",
      ].includes(event.type)) return;
      await defenseclawSend(event.type, defenseclawLifecyclePayload(event, cwd));
    },
    // Throwing aborts the tool. The decision is resolved before the throw.
    "tool.execute.before": async (input, output) => {
      const toolCwd = input.cwd;
      let startup = await startupGuard;
      if (startup.retryable) {
        // The load-time check could not get an answer: ask again now.
        startupGuard = defenseclawStartupGuard(cwd);
        startup = await startupGuard;
      }
      if (startup.reason) {
        // A confirmed load-time block holds for this process; checking
        // again only lets the gateway record this denied call.
        if (!startup.retryable) await defenseclawForeignHookCheck("tool.execute.before", toolCwd);
        throw defenseclawBlock(client, startup.reason);
      }
      if (!warned && startup.warnings && startup.warnings.length) {
        warned = true;
        defenseclawShowNotice(client, "DefenseClaw warning: " + startup.warnings.join("; "), "warning");
      }
      const mcpIdentity = input.mcpIdentity;
      const verdict = await defenseclawSend(
        "tool.execute.before",
        defenseclawToolPayload("tool.execute.before", input && input.tool, output && output.args, toolCwd, input, undefined, mcpIdentity),
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
      const result = output;
      await defenseclawSend(
        "tool.execute.after",
        defenseclawToolPayload("tool.execute.after", input && input.tool, input && input.args, input.cwd, input, result,
          input.mcpIdentity),
      );
    },
  };
}

// Only OpenCode V2 can load this plugin definition.

export default {
  id: "cisco.defenseclaw",
  setup: (context) => defenseclawV2Setup(context, defenseclawHooks),
};

// BEGIN GENERATED OPENCODE V2 ADAPTER
// OpenCode v2 Promise plugin adapter. Reviewed against f669c46c9604ea3d70b8a7ed1f0c10f3a5ac1f61.
// The host awaits execute.before and propagates a rejected Promise before
// executing the tool. No OpenCode SDK package is needed at runtime.

function defenseclawPinV2Event(event) {
  if (!event || typeof event !== "object") throw new Error("DefenseClaw refused an incomplete OpenCode v2 tool event.");
  // The copy has no size cap: strings are immutable and shared, and an
  // oversized call must reach the bridge's bounded review, which audits it in
  // observe mode and blocks it in action mode. A cap here blocked a large
  // write in every mode. Only pathological nesting is refused.
  let nodes = 0;
  const copy = (value, depth) => {
    if (++nodes > 1048576 || depth > 128) throw new Error("DefenseClaw refused OpenCode tool arguments nested too deeply to inspect.");
    if (typeof value === "string") return value;
    if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return value;
    if (!value || typeof value !== "object" || (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
      throw new Error("DefenseClaw refused non-JSON OpenCode tool arguments.");
    }
    const result = Array.isArray(value) ? [] : Object.create(null);
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (Array.isArray(value) && key === "length") continue;
      if (!descriptor.enumerable) continue;
      if (!("value" in descriptor)) throw new Error("DefenseClaw refused accessor tool arguments.");
      Object.defineProperty(result, key, { value: copy(descriptor.value, depth + 1), enumerable: true });
    }
    return Object.freeze(result);
  };
  // Pin both the tool identity and a detached, deeply immutable argument
  // snapshot BEFORE awaiting the verdict. A later hook cannot substitute
  // uninspected arguments, including by retaining the original nested object.
  event.input = copy(event.input, 0);
  Object.freeze(event);
}

async function defenseclawV2Bounded(operation) {
  let timer;
  try {
    return await Promise.race([
      operation(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("DefenseClaw could not resolve OpenCode v2 context in time.")), 2000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function defenseclawV2Context(ctx, event) {
  if (!event || typeof event.tool !== "string" || !event.tool || typeof event.id !== "string" || !event.id || typeof event.sessionID !== "string" || !event.sessionID) {
    throw new Error("DefenseClaw refused an incomplete OpenCode v2 tool event.");
  }
  const [session, response] = await defenseclawV2Bounded(() => Promise.all([
    ctx.session.get({ sessionID: event.sessionID }), ctx.mcp.list(),
  ]));
  const directory = session && session.location && session.location.directory;
  if (session?.id !== event.sessionID || typeof directory !== "string" || !directory || directory !== ctx.location?.directory || session.location.workspaceID !== ctx.location.workspaceID) {
    throw new Error("DefenseClaw refused an OpenCode tool outside this plugin's verified session location.");
  }
  const servers = Array.isArray(response) ? response : response && response.data;
  if (!Array.isArray(servers) || servers.length > 4096 || (response?.location && (response.location.directory !== directory || response.location.workspaceID !== ctx.location.workspaceID))) {
    throw new Error("DefenseClaw could not resolve OpenCode MCP server identity.");
  }
  const names = servers.map((server) => {
    if (!server || typeof server.name !== "string" || !server.name || server.name.length > 4096) throw new Error("DefenseClaw received an invalid OpenCode MCP server identity.");
    return { name: server.name, sanitized: defenseclawSanitizeMCPName(server.name) };
  });
  const candidates = names.filter((server) => event.tool.startsWith(server.sanitized + "_"));
  const mcpIdentity = candidates.length === 0 ? { status: "not_mcp", name: "" }
    : candidates.length === 1 ? { status: "authoritative", name: candidates[0].name }
    : { status: "ambiguous", name: "" };
  return {
    tool: event.tool, args: event.input, sessionID: event.sessionID,
    messageID: event.messageID, callID: event.id, agent: event.agent,
    cwd: directory, mcpIdentity,
  };
}

function defenseclawV2Result(event) {
  if (event.status === "error") return { opencode_v2_status: "error", error: { message: String(event.error?.message || "OpenCode tool failed") } };
  if (event.status !== "completed" || !event.result || typeof event.result !== "object" || Array.isArray(event.result)) return { opencode_v2_status: "unknown" };
  return { ...event.result, opencode_v2_status: "completed" };
}

// defenseclawV2AppendNotice adds the call's DefenseClaw notices to its
// completed result as one more text part (V2 results carry content parts);
// a result in another shape is left as it is.
function defenseclawV2AppendNotice(event, pending) {
  try {
    const result = event && event.status === "completed" && event.result;
    if (!result || typeof result !== "object") return;
    const note = pending.join("\n");
    if (Array.isArray(result.content)) event.result = { ...result, content: [...result.content, { type: "text", text: note }] };
    else if (typeof result.content === "string") event.result = { ...result, content: result.content + "\n\n" + note };
  } catch (_) {
    // A notice never changes the outcome of a call that already ran.
  }
}

function defenseclawV2SameLocation(ctx, location) {
  return location?.directory === ctx.location?.directory && location?.workspaceID === ctx.location?.workspaceID;
}

function defenseclawV2Remember(sessions, id, location) {
  if (sessions.size >= 4096 && !sessions.has(id)) sessions.delete(sessions.keys().next().value);
  sessions.set(id, location);
}

async function defenseclawV2Lifecycle(ctx, event, sessions, hooks) {
  const types = {
    "session.created": "session.created", "session.deleted": "session.deleted",
    "session.status": "session.status", "session.idle": "session.idle",
    "session.execution.started": "session.status",
    "session.execution.succeeded": "session.idle",
    "session.execution.failed": "session.error",
    "session.execution.interrupted": "session.idle",
  };
  const type = types[event.type];
  const data = event.data;
  if (!type || !data || typeof data.sessionID !== "string") return;
  // Durable execution events can omit location. Resolve the session rather
  // than attributing every event on the global bus to this plugin's project.
  let location = event.location || data.location || sessions.get(data.sessionID);
  if (!location) {
    const session = await defenseclawV2Bounded(() => ctx.session.get({ sessionID: data.sessionID }));
    if (session?.id !== data.sessionID) return;
    location = session.location;
  }
  if (!defenseclawV2SameLocation(ctx, location)) return;
  defenseclawV2Remember(sessions, data.sessionID, location);
  const properties = { ...data, opencode_event_type: event.type };
  if (event.type === "session.execution.started") properties.status = { type: "busy" };
  await hooks.event({ event: { ...event, type, properties } });
  if (event.type === "session.execution.failed") {
    const id = typeof event.id === "string" && event.id ? event.id + ":idle" : event.id;
    await hooks.event({ event: { ...event, id, type: "session.idle", properties } });
  }
  if (type === "session.deleted") sessions.delete(data.sessionID);
}

async function defenseclawV2Setup(ctx, createHooks) {
  // V2 server plugins have no TUI toast API, and the TUI never shows their
  // console output. A notice raised while a tool call is checked (a gateway
  // outage that let the call run, a confirm verdict, a foreign-hook warning)
  // is appended to that call's result, which the TUI shows under the tool;
  // blocking reasons travel in the rejected tool Promise. The log line stays.
  const noticeScope = new AsyncLocalStorage();
  const notices = new Map();
  const client = { tui: { showToast: ({ body }) => {
    const text = String(body.message).startsWith("DefenseClaw") ? body.message : (body.title || "DefenseClaw") + ": " + body.message;
    console.warn(text);
    const pending = noticeScope.getStore();
    if (!pending) return false;
    pending.push(text);
    return true;
  } } };
  const hooks = await createHooks({ client, directory: ctx.location?.directory });
  const registrations = [];
  const sessions = new Map();
  const calls = new Map();
  const controller = new AbortController();
  const cleanup = async () => {
    controller.abort();
    sessions.clear();
    calls.clear();
    notices.clear();
    await Promise.allSettled(registrations.map((registration) => registration.dispose()));
  };
  try {
    registrations.push(await ctx.tool.hook("execute.before", async (event) => {
      calls.delete(event?.id);
      notices.delete(event?.id);
      defenseclawPinV2Event(event);
      const input = await defenseclawV2Context(ctx, event);
      defenseclawV2Remember(sessions, input.sessionID, ctx.location);
      const pending = [];
      await noticeScope.run(pending, () => hooks["tool.execute.before"](input, { args: event.input }));
      if (pending.length) defenseclawV2Remember(notices, event.id, pending);
      // Retain only verified metadata, never the potentially large tool input.
      const { args, ...context } = input;
      defenseclawV2Remember(calls, event.id, context);
    }));
    registrations.push(await ctx.tool.hook("execute.after", async (event) => {
      const pending = notices.get(event?.id);
      notices.delete(event?.id);
      if (pending) defenseclawV2AppendNotice(event, pending);
      // A telemetry failure cannot undo an already executed tool.
      try {
        const cached = calls.get(event?.id);
        calls.delete(event?.id);
        const paired = cached && cached.sessionID === event.sessionID && cached.tool === event.tool
          && cached.messageID === event.messageID && cached.agent === event.agent;
        const input = paired ? { ...cached, args: event.input } : await defenseclawV2Context(ctx, event);
        await hooks["tool.execute.after"](input, defenseclawV2Result(event));
      } catch (_) {}
    }));
    // In v2 authority comes from the pinned event above, independently of
    // registration order. Initialize the common verdict/heartbeat path with that fact.
    await hooks.initialize();
    // Convert native data/location into the gateway event envelope.
    // The subscription belongs to this plugin instance and stops on unload.
    void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
          if (controller.signal.aborted) break;
          try { await defenseclawV2Lifecycle(ctx, event, sessions, hooks); } catch (_) {}
        }
      } catch (_) {}
    })();
    return cleanup;
  } catch (error) {
    await cleanup();
    throw error;
  }
}
// END GENERATED OPENCODE V2 ADAPTER
