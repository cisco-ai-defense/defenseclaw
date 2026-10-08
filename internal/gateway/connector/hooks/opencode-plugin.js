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

import { execFile{{if not .Sandbox}}, execFileSync{{end}} } from "node:child_process";
{{if .Sandbox}}import { randomUUID } from "node:crypto";
import { lstat } from "node:fs/promises";
{{else}}import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lstat, open } from "node:fs/promises";
{{end}}import { {{if not .Sandbox}}homedir, {{end}}userInfo } from "node:os";
{{if not .Sandbox}}import { dirname, join } from "node:path";
{{end}}
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
// The standalone managed-install hook socket, foreign-hook guard and install
// marker never apply in a sandbox: the plugin always posts to the ingress.
const DC_HOOK_SOCKET = "";
const DC_FOREIGN_GUARD = "";
const DC_INSTALL_MARKER = "";
{{else}}const DC_TOKEN_FILE = "{{.TokenFileJS}}";
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
// Windows standalone installs reach the gateway over loopback TCP, where a
// local user can hold the port while the gateway restarts, and this plugin
// cannot compare the listener with the gateway service the way the hook
// binary does. "1" makes it ask the listener to prove it can derive this
// user's credential before sending that credential or any hook payload: the
// proof request carries only the credential's SHA-256 and a fresh nonce, so
// an impostor gets nothing to replay and no chance to answer with a
// verdict. Empty skips the proof (per-user installs, Secure Client, and the
// hook socket, whose owner is verified instead).
const DC_LISTENER_PROOF = "{{.ListenerProofJS}}";
const DC_LISTENER_PROOF_DOMAIN = "defenseclaw.listener-proof.v1";
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
  const facts = defenseclawSessionFactsHeader();
  if (facts !== "") {
    headers["X-DefenseClaw-Session-Facts"] = facts;
  }
  return headers;
}

{{if not .Sandbox}}// The Kerberos principal of this login sits in a credential cache the plugin
// cannot read (a KCM cache is a socket protocol), so a DefenseClaw binary reads
// it: `hook session-facts` prints the whole X-DefenseClaw-Session-Facts value,
// the principal included, and keeps its own five-minute cache in
// ~/.defenseclaw. A managed install runs its administrator-owned hook binary
// (DC_FOREIGN_GUARD); a per-user install runs the gateway binary the installer
// puts in ~/.local/bin. No answer is a supported outcome: the SSH and logind
// variables alone follow.
const DC_SESSION_FACTS_TTL_MS = 300000;
const DC_SESSION_FACTS_RETRY_MS = 30000;
let DC_SESSION_FACTS = { key: "", value: "", until: 0 };

function defenseclawFullSessionFacts() {
  const env = process.env;
  const key = [env.KRB5CCNAME, env.XDG_SESSION_ID, env.SSH_CONNECTION, env.SSH_TTY].map((v) => String(v || "")).join("|");
  const now = Date.now();
  if (DC_SESSION_FACTS.key === key && now < DC_SESSION_FACTS.until) return DC_SESSION_FACTS.value;
  let value = "";
  try {
    const binary = DC_FOREIGN_GUARD ||
      join(homedir(), ".local", "bin", process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway");
    const out = String(execFileSync(binary, ["hook", "session-facts"], {
      timeout: 3000, maxBuffer: 4096, windowsHide: true, stdio: ["ignore", "pipe", "ignore"],
    })).trim();
    if (out.startsWith("v1;") && out.length <= 1024 && /^[A-Za-z0-9._@\/:;=-]+$/.test(out)) value = out;
  } catch (_) {
    // No binary or no answer: the caller falls back to the SSH variables.
  }
  DC_SESSION_FACTS = { key, value, until: now + (value ? DC_SESSION_FACTS_TTL_MS : DC_SESSION_FACTS_RETRY_MS) };
  return value;
}

{{end}}// defenseclawSessionFactsHeader renders the claimed SSH and logind session
// facts as the X-DefenseClaw-Session-Facts value the hook runner also sends.
// Each value is dropped unless it matches the header's allowlisted charset.
function defenseclawSessionFactsHeader() {
{{if not .Sandbox}}  const full = defenseclawFullSessionFacts();
  if (full !== "") return full;
{{end}}  const env = process.env;
  const address = String(env.SSH_CONNECTION || "").trim().split(/\s+/)[0] || "";
  const tty = String(env.SSH_TTY || "").replace(/^\/dev\//, "");
  const session = String(env.XDG_SESSION_ID || "");
  const kind = address !== "" || tty !== "" ? "ssh" : (session !== "" ? "local" : "");
  const parts = ["v1"];
  for (const [key, value] of [["k", kind], ["tty", tty], ["ls", session], ["ca", address]]) {
    if (value.length > 0 && value.length <= 256 && /^[A-Za-z0-9._@\/:-]+$/.test(value)) {
      parts.push(key + "=" + value);
    }
  }
  return parts.length > 1 ? parts.join(";") : "";
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

// defenseclawDeploymentRemoved reports whether the managed deployment that
// rendered this plugin was uninstalled: its install marker is definitively
// absent. Any other inspection result keeps the plugin enforcing.
async function defenseclawDeploymentRemoved() {
  if (!DC_INSTALL_MARKER) return false;
  try {
    await lstat(DC_INSTALL_MARKER);
    return false;
  } catch (err) {
    return !!err && err.code === "ENOENT";
  }
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
          headers: { get: (name) => res.headers[String(name).toLowerCase()] ?? null },
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

// defenseclawProveListener resolves once the TCP listener has proven it can
// derive token (the gateway's listener proof); anything else rejects, and
// the caller then sends the listener nothing else.
async function defenseclawProveListener(token, signal) {
  if (!DC_TOKEN_PATTERN.test(token || "")) throw new Error("invalid scoped hook credential");
  const nonce = randomBytes(32).toString("hex");
  const res = await fetch("http://" + DC_API_ADDR + "/api/v1/hook-listener-proof", {
    method: "GET",
    headers: {
      "X-DefenseClaw-Connector": "opencode",
      "X-DefenseClaw-Listener-Key-Id": createHash("sha256").update(token).digest("hex"),
      "X-DefenseClaw-Listener-Nonce": nonce,
    },
    signal,
  });
  const proof = String(res.headers.get("x-defenseclaw-listener-proof") || "");
  if (res.body) {
    try {
      await res.body.cancel();
    } catch (_) {
      // Nothing is read from the proof response body.
    }
  }
  const want = createHmac("sha256", token)
    .update(DC_LISTENER_PROOF_DOMAIN + "\u0000opencode\u0000" + nonce)
    .digest("hex");
  if (res.status !== 204 || proof.length !== want.length || !timingSafeEqual(Buffer.from(proof), Buffer.from(want))) {
    throw new Error("the DefenseClaw gateway listener did not prove its identity");
  }
}

// defenseclawFetch posts to the gateway over the managed hook socket when one
// is configured (after verifying it), and over TCP otherwise; a TCP request
// that carries a per-user credential first requires the listener proof.
async function defenseclawFetch(path, init, token) {
  if (!DC_HOOK_SOCKET) {
    if (DC_LISTENER_PROOF) await defenseclawProveListener(token, init.signal);
    return fetch("http://" + DC_API_ADDR + path, init);
  }
  await defenseclawVerifyHookSocket();
  if (globalThis.Bun) return fetch("http://localhost" + path, { ...init, unix: DC_HOOK_SOCKET });
  return defenseclawSocketRequest(path, init);
}

// defenseclawRetryBusy sends the call again while the gateway answers 429: it
// is taking all the hook calls it can, or this account is over its budget,
// and has not evaluated the call. It waits the Retry-After the gateway asks
// for (1 to 3 s) at most 3 times; the caller's abort signal keeps the whole
// exchange inside the plugin timeout. The native hook runner does the same
// (GAP-0205); without it a short burst failed the tool call (GAP-0535).
async function defenseclawRetryBusy(send, signal) {
  let res = await send();
  for (let retry = 0; retry < 3 && res && res.status === 429; retry++) {
    const asked = Number.parseInt(String((res.headers && res.headers.get("retry-after")) || ""), 10);
    const delay = Math.min(Math.max(Number.isFinite(asked) ? asked : 1, 1), 3) * 1000;
    await new Promise((resolve, reject) => {
      if (signal && signal.aborted) return reject(new Error("DefenseClaw gateway busy"));
      const timer = setTimeout(resolve, delay);
      if (signal) signal.addEventListener("abort", () => { clearTimeout(timer); reject(new Error("DefenseClaw gateway busy")); }, { once: true });
    });
    res = await send();
  }
  return res;
}
{{end}}
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
        : defenseclawForeignCheckFailure(event, why)));
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

// defenseclawForeignCheckFailure is the block reason when the foreign-plugin
// check itself could not run. OpenCode loads plugins once, so a check that
// failed at load keeps blocking for the life of this process; that reason
// says to restart the agent.
function defenseclawForeignCheckFailure(event, why) {
  const detail = String(why || "").split(/\r?\n/)[0].trim() || "no answer";
  if (event === "defenseclaw.plugin.loaded") {
    return "DefenseClaw could not check for unapproved plugins when the agent started (" + detail +
      "), so this tool call is blocked. Restart the agent once DefenseClaw is available.";
  }
  return "DefenseClaw could not check for unapproved plugins (" + detail + "), so this tool call is blocked.";
}

// defenseclawBlockError is the error a blocked tool call fails with. OpenCode
// shows it as the tool's error and hands it to the model, so it says that
// DefenseClaw blocked the call under policy and that the call did not run.
// The foreign-plugin guard's reason code is left out; the audit keeps it.
function defenseclawBlockError(reason) {
  const text = String(reason || "").trim();
  if (/^DefenseClaw\b/.test(text)) return new Error(text);
  return new Error("DefenseClaw blocked this tool call under policy, so it did not run: " + (text.replace(/^enterprise_foreign_hook_blocked:\s*/, "") || "no reason was given"));
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
// user's confirmation (human-in-the-loop). This bridge cannot ask, so the
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
    const res = await {{if .Sandbox}}defenseclawFetch(headers, JSON.stringify(payload));{{else}}defenseclawRetryBusy(() => defenseclawFetch("/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    }, token), controller.signal);{{end}}
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
{{end}}    return { reason: "", mode: data && data.mode || "", notice: defenseclawConfirmNotice(data) };
  } catch (err) {
    // Transport failure (gateway unreachable / timeout). Honor fail mode:
    // closed → block, open → allow. An uninstalled deployment allows.
    if (await defenseclawDeploymentRemoved()) return null;
    if (DC_FAIL_MODE === "closed") {
      if ((DC_HOOK_SOCKET || DC_FOREIGN_GUARD) && defenseclawGatewayStopped(err)) return { reason: DC_GATEWAY_STOPPED_TEXT };
      return { reason: "DefenseClaw hook failed closed (" + (err && err.message ? err.message : String(err)) + ")" };
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// DC_GATEWAY_STOPPED_TEXT is what a managed install says when its gateway
// service is stopped, in the words of the native hook (GAP-0578).
const DC_GATEWAY_STOPPED_TEXT = "DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running on this computer. " +
  "Try again in a moment; if this continues, ask your administrator to start the DefenseClaw gateway service. " +
  "(enterprise_managed_gateway_not_running)";

// defenseclawGatewayStopped reports a transport failure that means the
// gateway is not running: its hook socket is missing, or nothing accepts
// the connection.
function defenseclawGatewayStopped(err) {
  const codes = [err && err.code, err && err.cause && err.cause.code];
  return codes.some((code) => code === "ENOENT" || code === "ECONNREFUSED" || code === "ConnectionRefused");
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
{{if .Sandbox}}    await defenseclawFetch(headers, JSON.stringify({
      hook_event_name: "defenseclaw.plugin.loaded",
      load_heartbeat: true,
      arguments_authoritative: DC_ARGUMENTS_AUTHORITATIVE,
      later_plugin_count: DC_LATER_PLUGIN_COUNT,
      mcp_identity_status: DC_MCP_IDENTITY_STATUS,
      cwd: cwd || "",
    }));
{{else}}    await defenseclawFetch("/api/v1/opencode/hook", {
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
{{else}}defenseclawFetch("/api/v1/opencode/hook", {
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
{{end}}  } catch (_) {
    // Lifecycle telemetry is observe-only and never blocks OpenCode.
  } finally {
    clearTimeout(timer);
  }
}

{{if .Sandbox}}// OpenCode's TUI (1.18.31) draws a tool the plugin refused as its bare
// command line in the error color, and shows the thrown reason, which the
// model gets, only once that line is clicked; a pre-tool hook cannot set
// the tool's visible output. A toast shows the user why at once, and says
// where the reason stays. Best effort and never awaited: a headless run has
// no TUI, and a missing client or a failed request never changes the
// verdict.
const DC_TOAST_AGAIN = "Click the tool's red line in the conversation to show this again.";
function defenseclawToast(client, reason) {
  try {
    const shown = client && client.tui && typeof client.tui.showToast === "function" &&
      client.tui.showToast({ body: { title: "DefenseClaw blocked this tool call", message: reason + "\n\n" + DC_TOAST_AGAIN, variant: "error", duration: 15000 } });
    if (shown && typeof shown.catch === "function") shown.catch(() => {});
  } catch (_) {
    // No TUI to tell.
  }
}

{{end}}export const DefenseClaw = async ({ client, directory, worktree }) => {
  const cwd = directory || worktree || "";
  // OpenCode loads plugins once at startup: a foreign plugin present now
  // keeps running for this process even if its file is deleted later, so a
  // block found at load holds for the whole process.
  const defenseclawStartupGuard = defenseclawForeignHookCheck("defenseclaw.plugin.loaded", cwd);
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
      // Every call runs the check, also after a block at load (which holds
      // for the process), so the gateway records each denied call.
      const startupBlock = await defenseclawStartupGuard;
      const callBlock = await defenseclawForeignHookCheck("tool.execute.before", cwd);
      const blocked = startupBlock || callBlock;
      if (blocked) throw defenseclawBlock(client, blocked);
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
      if (verdict && verdict.reason) throw new Error(verdict.reason);
{{else}}      if (verdict && verdict.reason) throw defenseclawBlock(client, verdict.reason);
{{end}}      if (verdict && verdict.notice) defenseclawShowNotice(client, verdict.notice);
      if (verdict && verdict.mode === "action" && mcpIdentity.status === "ambiguous") {
        throw defenseclawBlock(client, "DefenseClaw refused an OpenCode tool with ambiguous MCP server identity.");
      }
      if (verdict && verdict.mode === "action" && !DC_ARGUMENTS_AUTHORITATIVE) {
        throw defenseclawBlock(
          client,
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
