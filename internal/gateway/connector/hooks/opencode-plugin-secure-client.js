// defenseclaw-managed-plugin v7
// DefenseClaw opencode bridge plugin — DO NOT EDIT.
//
// opencode auto-loads JS/TS plugins from ~/.config/opencode/plugins/ at
// startup (https://opencode.ai/docs/plugins/). This dependency-free
// bridge sends each tool call through the administrator-owned native peer
// verifier to the local DefenseClaw gateway and
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

import { execFile, execFileSync } from "node:child_process";
import { lstat, open } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname } from "node:path";

// DC_-prefixed constants are non-secret values baked in at setup time, not
// env-var reads — the envvars registry gate scans for DEFENSECLAW_* tokens.
const DC_API_ADDR = "{{.APIAddr}}";
const DC_TOKEN_FILE = "{{.TokenFileJS}}";
const DC_NATIVE_POST_BINARY = "{{.NativePostBinaryJS}}";
const DC_FAIL_MODE = "{{.FailMode}}"; // "open" or "closed"
// Standalone managed installs talk to the gateway's peer-authorized unix
// hook socket instead of the TCP API: the gateway identifies the caller by
// kernel-verified uid, so no bearer token leaves this process, and a user
// who binds the TCP port during a gateway restart receives nothing. Empty
// keeps the TCP transport (per-user installs).
const DC_HOOK_SOCKET = "{{.HookSocketJS}}";
const DC_SERVICE_UID = Number("{{.ServiceUID}}");
// Standalone managed installs also run the administrator-owned hook binary
// before each tool call: it applies the organization's foreign-hook guard
// (unapproved project or user plugins that could change a tool call after
// DefenseClaw checks it). Empty skips the check (per-user installs).
const DC_FOREIGN_GUARD = "{{.ForeignHookGuardJS}}";
// Windows standalone installs name an administrator-owned directory that
// exists exactly while the deployment is installed. Uninstall removes it but
// cannot remove this plugin from a signed-out user's profile, so once the
// gateway is unreachable or the credential is gone AND the marker is gone,
// the deployment was uninstalled and this plugin stops failing closed. A
// standard user cannot remove the marker. Empty keeps the fail mode.
const DC_INSTALL_MARKER = "{{.InstallMarkerJS}}";
const DC_TIMEOUT_MS = 10000;
const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const DC_MAX_TOKEN_FILE_BYTES = 4096;

// V2 pins each inspected tool event before awaiting any verdict.
let DC_ARGUMENTS_AUTHORITATIVE = false;
let DC_LATER_PLUGIN_COUNT = 0;
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

// V2's MCP catalog uses this sanitizer for exposed tool names.
function defenseclawSanitizeMCPName(value) {
  return String(value || "").replace(/[^a-zA-Z0-9_-]/g, "_");
}

async function defenseclawDeploymentRemoved() {
  if (!DC_INSTALL_MARKER) return false;
  try {
    await lstat(DC_INSTALL_MARKER);
    return false;
  } catch (err) {
    return !!err && err.code === "ENOENT";
  }
}

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

function defenseclawTrustedSocketOwner(uid) {
  return uid === 0 || (DC_SERVICE_UID > 0 && uid === DC_SERVICE_UID);
}

// defenseclawVerifyHookSocket refuses a hook socket (or its directory, or the
// directory's parent) that root or the gateway service account does not own,
// or that another account could write. Only root or the service account can
// create a socket there, so a verified path cannot be an impostor listener.
async function defenseclawVerifyHookSocket() {
  const dir = dirname(DC_HOOK_SOCKET);
  for (const path of [dirname(dir), dir]) {
    const info = await lstat(path);
    if (!info.isDirectory() || !defenseclawTrustedSocketOwner(info.uid) || (info.mode & 0o022) !== 0) {
      throw new Error("the DefenseClaw hook socket directory is not trusted");
    }
  }
  const socket = await lstat(DC_HOOK_SOCKET);
  if (!socket.isSocket() || !defenseclawTrustedSocketOwner(socket.uid)) {
    throw new Error("the DefenseClaw hook socket is not trusted");
  }
}

// defenseclawSocketRequest sends one request over the verified unix socket
// with node:http when the Bun unix fetch option is unavailable.
async function defenseclawSocketRequest(path, init) {
  const { request } = await import("node:http");
  return await new Promise((resolve, reject) => {
    const req = request({ socketPath: DC_HOOK_SOCKET, path, method: init.method || "POST", headers: init.headers }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > 1048576) {
          req.destroy(new Error("oversized DefenseClaw gateway response"));
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          json: async () => JSON.parse(text),
        });
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    if (init.signal) init.signal.addEventListener("abort", () => req.destroy(new Error("DefenseClaw gateway timeout")), { once: true });
    req.end(init.body);
  });
}

function defenseclawUnverifiedPeer(reason) {
  const error = new Error(reason);
  error.code = "DC_UNVERIFIED_PEER";
  return error;
}

// Secure Client uses its administrator-owned native binary to prove the
// connected gateway service before sending a bearer or tool event.
function defenseclawNativePost(path, init) {
  if (!DC_NATIVE_POST_BINARY) throw defenseclawUnverifiedPeer("the DefenseClaw gateway listener has no service peer verifier");
  let output;
  try {
    output = execFileSync(DC_NATIVE_POST_BINARY,
      ["hook-post", "--api-addr", DC_API_ADDR, "--secure-client-service", "--max-time", "10"],
      { input: JSON.stringify({ path, headers: init.headers, body: init.body }),
        timeout: DC_TIMEOUT_MS + 1000, maxBuffer: 2 << 20, windowsHide: true });
  } catch (_) {
    throw defenseclawUnverifiedPeer("the DefenseClaw gateway listener could not be verified by its service");
  }
  let answer;
  try {
    answer = JSON.parse(String(output));
  } catch (_) {
    throw defenseclawUnverifiedPeer("the DefenseClaw native gateway verifier returned an invalid reply");
  }
  if (!answer || !Number.isInteger(answer.status) || answer.status < 100 || answer.status > 599 || typeof answer.body !== "string") {
    throw defenseclawUnverifiedPeer("the DefenseClaw native gateway verifier returned an invalid reply");
  }
  return { ok: answer.status >= 200 && answer.status < 300, status: answer.status,
    json: async () => JSON.parse(answer.body) };
}

// The Secure Client profile uses the native service peer verifier on TCP.
// A configured Unix socket keeps its path and owner checks.
async function defenseclawFetch(path, init, token) {
  if (!DC_HOOK_SOCKET) {
    return defenseclawNativePost(path, init);
  }
  await defenseclawVerifyHookSocket();
  if (globalThis.Bun) return fetch("http://localhost" + path, { ...init, unix: DC_HOOK_SOCKET });
  return defenseclawSocketRequest(path, init);
}

// defenseclawForeignHookCheck asks the administrator-owned hook binary for
// the foreign-hook guard's decision and resolves to a block reason, or ""
// when no unapproved plugin or hook is present. A binary that cannot be
// run, times out, or answers anything but {"deny": false} blocks, unless
// the managed deployment was uninstalled (its install marker is gone):
// uninstall removes the hook binary too, and this plugin then stops failing
// closed as it does for the gateway call.
function defenseclawForeignHookCheck(event, cwd) {
  if (!DC_FOREIGN_GUARD) return Promise.resolve("");
  return new Promise((resolve) => {
    const fail = (why) => {
      void defenseclawDeploymentRemoved().then((removed) => resolve(removed
        ? ""
        : "DefenseClaw could not check for unapproved plugins (" + why + "), so this tool call is blocked."));
    };
    try {
      const child = execFile(
        DC_FOREIGN_GUARD,
        ["hook", "--connector", "opencode", "--foreign-hook-check"],
        { timeout: DC_TIMEOUT_MS, maxBuffer: 65536, windowsHide: true },
        (err, stdout) => {
          if (err) {
            fail(err && err.message ? err.message : String(err));
            return;
          }
          let verdict;
          try {
            verdict = JSON.parse(String(stdout));
          } catch (_) {
            fail("invalid response");
            return;
          }
          if (verdict && verdict.deny === false) {
            resolve("");
            return;
          }
          resolve(verdict && typeof verdict.reason === "string" && verdict.reason
            ? verdict.reason
            : "DefenseClaw blocked this tool call because an unapproved plugin is present.");
        },
      );
      if (child.stdin) {
        child.stdin.on("error", () => {});
        child.stdin.end(JSON.stringify({ hook_event_name: event, cwd: cwd || "" }));
      }
    } catch (err) {
      fail(err && err.message ? err.message : String(err));
    }
  });
}

async function defenseclawPost(event, toolName, toolInput, cwd, context, toolResult, mcpIdentity, actionable) {
  let token;
  try {
    token = DC_HOOK_SOCKET ? "" : await defenseclawToken();
  } catch (_) {
    // Missing, unreadable, or malformed credentials are never safe at a
    // pre-execution boundary, even when transport fail-open was selected,
    // unless the managed deployment itself was uninstalled.
    if (await defenseclawDeploymentRemoved()) return null;
    if (actionable) return { reason: "DefenseClaw hook credential is unavailable." };
    return null;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DC_TIMEOUT_MS);
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...defenseclawIdentityHeaders() };
  if (token) headers["Authorization"] = "Bearer " + token;
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
    const res = await defenseclawFetch("/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    }, token);
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
      return { reason: out.reason || "DefenseClaw blocked this tool call.", mode: data.mode || "" };
    }
    return { reason: "", mode: data && data.mode || "" };
  } catch (err) {
    if (err && err.code === "DC_UNVERIFIED_PEER") {
      return { reason: "DefenseClaw hook failed closed (" + err.message + ")" };
    }
    // Transport failure (gateway unreachable / timeout). Honor fail mode:
    // closed → block, open → allow. An uninstalled deployment allows.
    if (await defenseclawDeploymentRemoved()) return null;
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
    token = DC_HOOK_SOCKET ? "" : await defenseclawToken();
  } catch (_) {
    // Load health is diagnostic only; tool hooks enforce credential failures.
    return;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DC_TIMEOUT_MS);
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...defenseclawIdentityHeaders() };
  if (token) headers["Authorization"] = "Bearer " + token;
  try {
    await defenseclawFetch("/api/v1/opencode/hook", {
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
    }, token);
  } catch (_) {
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
    token = DC_HOOK_SOCKET ? "" : await defenseclawToken();
  } catch (_) {
    // Lifecycle telemetry is observe-only; an unavailable credential skips it.
    return;
  }
  const properties = event.properties || {};
  const info = properties.info || {};
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DC_TIMEOUT_MS);
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...defenseclawIdentityHeaders() };
  if (token) headers["Authorization"] = "Bearer " + token;
  try {
    await defenseclawFetch("/api/v1/opencode/hook", {
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
    }, token);
  } catch (_) {
    // Lifecycle telemetry is observe-only and never blocks OpenCode.
  } finally {
    clearTimeout(timer);
  }
}

async function defenseclawHooks({ directory, worktree }) {
  const cwd = directory || worktree || "";
  // OpenCode loads plugins once at startup: a foreign plugin present now
  // keeps running for this process even if its file is deleted later, so a
  // block found at load holds for the whole process.
  const defenseclawStartupGuard = defenseclawForeignHookCheck("defenseclaw.plugin.loaded", cwd);
  return {
    initialize: async () => {
      DC_ARGUMENTS_AUTHORITATIVE = true;
      DC_MCP_IDENTITY_STATUS = "authoritative";
      await defenseclawPostLoadHeartbeat(cwd);
    },
    // OpenCode publishes its session lifecycle through the generic event
    // hook. OpenCode does not await this hook dispatch, so lifecycle delivery
    // is best-effort telemetry only. Child sessions carry info.parentID, which
    // DefenseClaw maps to a parent-agent relationship while preserving the
    // child session ID.
    event: async ({ event }) => {
      if (!event || ![
        "session.created", "session.status", "session.idle",
        "session.error", "session.deleted",
      ].includes(event.type)) return;
      await defenseclawPostLifecycle(event, cwd);
    },
    // tool.execute.before is opencode's pre-tool hook. Throwing here
    // aborts the tool (same mechanism as the .env-protection example).
    // The decision is resolved BEFORE the throw so a fail-open transport
    // error never turns into an accidental block.
    "tool.execute.before": async (input, output) => {
      const blocked = (await defenseclawStartupGuard) || (await defenseclawForeignHookCheck("tool.execute.before", input.cwd));
      if (blocked) throw new Error(blocked);
      const mcpIdentity = input.mcpIdentity;
      const verdict = await defenseclawPost(
        "tool.execute.before",
        input && input.tool,
        output && output.args,
        input.cwd,
        input,
        undefined,
        mcpIdentity,
        true,
      );
      if (verdict && verdict.reason) throw new Error(verdict.reason);
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
      const result = output;
      await defenseclawPost(
        "tool.execute.after",
        input && input.tool,
        input && input.args,
        input.cwd,
        input,
        result,
        input.mcpIdentity,
        false,
      );
    },
  };
}

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
  let nodes = 0;
  let characters = 0;
  const copy = (value, depth) => {
    if (++nodes > 16384 || depth > 64) throw new Error("DefenseClaw refused oversized OpenCode tool arguments.");
    if (typeof value === "string") {
      characters += value.length;
      if (characters > 1048576) throw new Error("DefenseClaw refused oversized OpenCode tool arguments.");
      return value;
    }
    if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return value;
    if (!value || typeof value !== "object" || (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
      throw new Error("DefenseClaw refused non-JSON OpenCode tool arguments.");
    }
    const result = Array.isArray(value) ? [] : Object.create(null);
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (Array.isArray(value) && key === "length") continue;
      if (!descriptor.enumerable) continue;
      if (!("value" in descriptor)) throw new Error("DefenseClaw refused accessor tool arguments.");
      characters += key.length;
      if (characters > 1048576) throw new Error("DefenseClaw refused oversized OpenCode tool arguments.");
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
  // V2 server plugins have no TUI toast API. Preserve notices in the host's
  // log/stderr and return blocking reasons through the rejected tool Promise.
  const client = { tui: { showToast: ({ body }) => { console.warn(String(body.message).startsWith("DefenseClaw") ? body.message : (body.title || "DefenseClaw") + ": " + body.message); } } };
  const hooks = await createHooks({ client, directory: ctx.location?.directory });
  const registrations = [];
  const sessions = new Map();
  const calls = new Map();
  const controller = new AbortController();
  const cleanup = async () => {
    controller.abort();
    sessions.clear();
    calls.clear();
    await Promise.allSettled(registrations.map((registration) => registration.dispose()));
  };
  try {
    registrations.push(await ctx.tool.hook("execute.before", async (event) => {
      calls.delete(event?.id);
      defenseclawPinV2Event(event);
      const input = await defenseclawV2Context(ctx, event);
      defenseclawV2Remember(sessions, input.sessionID, ctx.location);
      await hooks["tool.execute.before"](input, { args: event.input });
      // Retain only verified metadata, never the potentially large tool input.
      const { args, ...context } = input;
      defenseclawV2Remember(calls, event.id, context);
    }));
    registrations.push(await ctx.tool.hook("execute.after", async (event) => {
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
