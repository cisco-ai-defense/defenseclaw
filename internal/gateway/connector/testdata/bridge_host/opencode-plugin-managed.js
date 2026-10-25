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

import { execFile, execFileSync } from "node:child_process";
import { lstatSync } from "node:fs";

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lstat, mkdir, open } from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import { stat } from "node:fs/promises";
import { dirname, join } from "node:path";

// DC_-prefixed constants are non-secret values baked in at setup time, not
// env-var reads — the envvars registry gate scans for DEFENSECLAW_* tokens.
const DC_API_ADDR = "{{.APIAddr}}";
const DC_TOKEN_FILE = "{{.TokenFileJS}}";
const DC_FAIL_MODE = "{{.FailMode}}"; // per-user and standalone hooks stay closed
// The installed mode is the fail mode: DEFENSECLAW_FAIL_MODE in the process
// environment is not read (GAP-0315). As in the shell hooks,
// DEFENSECLAW_STRICT_AVAILABILITY closes a gateway outage (GAP-0035); it can
// never open a closed plugin.
const DC_TRANSPORT_FAIL_MODE = ["1", "true", "TRUE", "yes", "YES"].includes(String(process.env.DEFENSECLAW_STRICT_AVAILABILITY || "")) ? "closed" : DC_FAIL_MODE;
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
// The standalone Unix lifecycle publishes this public, root-owned marker
// before it can stop the gateway and removes it after readiness or recovery.
const DC_LIFECYCLE_MARKER = "{{.LifecycleMarkerJS}}";
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
// Per-user plugins ask the native gateway binary to verify the connected
// listener's account before each request. The proof above serves managed TCP.
const DC_PER_USER_NATIVE_POST = "";
const DC_LISTENER_PROOF_DOMAIN = "defenseclaw.listener-proof.v1";
const DC_TIMEOUT_MS = 10000;
const DC_PLUGIN_URL = import.meta.url;
const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const DC_MAX_TOKEN_FILE_BYTES = 4096;

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
async function defenseclawIdentityHeaders() {
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
  const facts = await defenseclawSessionFactsHeader();
  if (facts !== "") {
    headers["X-DefenseClaw-Session-Facts"] = facts;
  }
  return headers;
}

// The Kerberos principal of this login sits in a credential cache the plugin
// cannot read (a KCM cache is a socket protocol), so a DefenseClaw binary reads
// it: `hook session-facts` prints the whole X-DefenseClaw-Session-Facts value,
// the principal included, and keeps its own five-minute cache in
// ~/.defenseclaw. A managed install runs its administrator-owned hook binary
// (DC_FOREIGN_GUARD); a per-user install runs the gateway binary the installer
// puts in ~/.local/bin. No answer is a supported outcome: the SSH and logind
// variables alone follow.
const DC_SESSION_FACTS_TTL_MS = 300000;
const DC_SESSION_FACTS_RETRY_MS = 30000;
const DC_SESSION_FACTS_READ_MS = 250;
let DC_SESSION_FACTS = { key: "", value: "", until: 0 };

// The modification time of this login's FILE or DIR Kerberos credential
// cache is part of the session facts key: a new kinit into the same cache
// changes the principal while every session variable stays the same
// (GAP-1139). KCM, KEYRING and API caches have no file; the variables alone
// key them. The stat runs off the event loop and gets
// DC_CREDENTIAL_CACHE_STAT_MS; calls share one stat, and one still
// unanswered after that (a stalled network or FUSE mount) reads as null: the
// call sends the session variables alone.
const DC_CREDENTIAL_CACHE_STAT_MS = 250;
let DC_CREDENTIAL_CACHE_STAT = { pending: null, since: 0 };

async function defenseclawCredentialCacheStamp() {
  const name = String(process.env.KRB5CCNAME || "");
  let path = name;
  if (name === "") path = typeof process.getuid === "function" ? "/tmp/krb5cc_" + process.getuid() : "";
  else if (name.startsWith("FILE:")) path = name.slice(5);
  else if (name.startsWith("DIR::")) path = name.slice(5);
  else if (name.startsWith("DIR:")) path = name.slice(4);
  if (!path.startsWith("/")) return "";
  const now = Date.now();
  if (DC_CREDENTIAL_CACHE_STAT.pending === null) {
    const pending = stat(path).then((info) => String(info.mtimeMs), () => "");
    DC_CREDENTIAL_CACHE_STAT = { pending, since: now };
    pending.then(() => {
      if (DC_CREDENTIAL_CACHE_STAT.pending === pending) DC_CREDENTIAL_CACHE_STAT = { pending: null, since: 0 };
    });
  }
  const left = DC_CREDENTIAL_CACHE_STAT.since + DC_CREDENTIAL_CACHE_STAT_MS - now;
  if (left <= 0) return null;
  let timer;
  const overdue = new Promise((resolve) => { timer = setTimeout(resolve, left, null); });
  try {
    return await Promise.race([DC_CREDENTIAL_CACHE_STAT.pending, overdue]);
  } finally {
    clearTimeout(timer);
  }
}

async function defenseclawFullSessionFacts() {
  const env = process.env;
  const stamp = await defenseclawCredentialCacheStamp();
  // The binary would wait on a stalled credential cache too.
  if (stamp === null) return "";
  const key = [env.KRB5CCNAME, env.XDG_SESSION_ID, env.SSH_CONNECTION, env.SSH_TTY, stamp]
    .map((v) => String(v || "")).join("|");
  const now = Date.now();
  if (DC_SESSION_FACTS.key === key && now < DC_SESSION_FACTS.until) return DC_SESSION_FACTS.value;
  let value = "";
  try {
    const binary = DC_FOREIGN_GUARD || (DC_PER_USER_NATIVE_POST
      ? defenseclawPerUserNativePostBinary()
      : join(homedir(), ".local", "bin", process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway"));
    let child;
    let timer;
    const read = new Promise((resolve) => {
      child = execFile(binary, ["hook", "session-facts"], {
        timeout: DC_SESSION_FACTS_READ_MS, maxBuffer: 4096, windowsHide: true,
      }, (err, stdout) => resolve(err ? "" : String(stdout).trim()));
    });
    const deadline = new Promise((resolve) => {
      timer = setTimeout(() => { if (child) child.kill(); resolve(""); }, DC_SESSION_FACTS_READ_MS);
    });
    const out = await Promise.race([read, deadline]);
    clearTimeout(timer);
    if (out.startsWith("v1;") && out.length <= 1024 && /^[A-Za-z0-9._@\/:;=-]+$/.test(out)) value = out;
  } catch (_) {
    // No binary or no answer: the caller falls back to the SSH variables.
  }
  DC_SESSION_FACTS = { key, value, until: now + (value ? DC_SESSION_FACTS_TTL_MS : DC_SESSION_FACTS_RETRY_MS) };
  return value;
}

// defenseclawSessionFactsHeader renders the claimed SSH and logind session
// facts as the X-DefenseClaw-Session-Facts value the hook runner also sends.
// Each value is dropped unless it matches the header's allowlisted charset.
async function defenseclawSessionFactsHeader() {
  const full = await defenseclawFullSessionFacts();
  if (full !== "") return full;
  const env = process.env;
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

async function defenseclawManagedLifecycleHeld() {
  if (!DC_LIFECYCLE_MARKER) return false;
  try {
    await lstat(DC_LIFECYCLE_MARKER);
    return true;
  } catch (err) {
    // Only a definite absence ends the install window.
    return !err || err.code !== "ENOENT";
  }
}

const DC_MANAGED_LIFECYCLE_TEXT = "DefenseClaw is being installed or upgraded on this computer; try again in a moment.";

// defenseclawGatewayJSON parses a gateway answer and refuses one that
// repeats a key in any object. JSON.parse keeps the last copy, so
// {"action":"block","action":"allow"} would read as allow; the native and
// shell hooks refuse such an answer too (GAP-1007). The caller's catch closes
// the call.
function defenseclawGatewayJSON(text) {
  const value = JSON.parse(text);
  const objects = [];
  let keyNext = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let end = i + 1;
      while (text[end] !== '"') end += text[end] === "\\" ? 2 : 1;
      const keys = objects[objects.length - 1];
      if (keyNext && keys) {
        const key = JSON.parse(text.slice(i, end + 1));
        if (keys.has(key)) throw new Error("ambiguous gateway answer (repeated key)");
        keys.add(key);
      }
      keyNext = false;
      i = end;
    } else if (c === "{" || c === "[") {
      objects.push(c === "{" ? new Set() : null);
      keyNext = c === "{";
    } else if (c === "}" || c === "]") {
      objects.pop();
      keyNext = false;
    } else if (c === ",") {
      keyNext = objects[objects.length - 1] instanceof Set;
    }
  }
  return value;
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
          headers: { get: (name) => res.headers[String(name).toLowerCase()] ?? null },
          text: async () => text,
        });
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    if (init.signal) init.signal.addEventListener("abort", () => req.destroy(new Error("DefenseClaw gateway timeout")), { once: true });
    req.end(init.body);
  });
}

function defenseclawPeerError(reason) {
  const error = new Error(reason);
  error.code = "DC_PEER_UNVERIFIED";
  return error;
}

// A proof for a listener authorizes only the TCP connection that answered
// it. Keep that socket in one HTTP agent and refuse a later socket before
// writing a bearer or payload; the gateway may stop between the two calls.
async function defenseclawProvenTCPRequest(path, init, token) {
  if (!DC_TOKEN_PATTERN.test(token || "")) throw new Error("invalid scoped hook credential");
  const { Agent, request } = await import("node:http");
  const endpoint = new URL("http://" + DC_API_ADDR);
  const agent = new Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 });
  let provenSocket;
  const send = (requestPath, method, headers, body, requiredSocket) => new Promise((resolve, reject) => {
    const req = request({
      hostname: endpoint.hostname.replace(/^\[|\]$/g, ""), port: endpoint.port,
      path: requestPath, method, headers, agent, signal: init.signal,
    }, (res) => {
      const chunks = [];
      let length = 0;
      res.on("data", (chunk) => {
        length += chunk.length;
        if (length > 1048576) {
          req.destroy(new Error("oversized DefenseClaw gateway response"));
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.on("socket", (socket) => {
      if (requiredSocket && socket !== requiredSocket) {
        req.destroy(defenseclawPeerError("the DefenseClaw gateway listener changed after proving its identity"));
        return;
      }
      if (!requiredSocket) provenSocket = socket;
      req.end(body);
    });
  });
  const nonce = randomBytes(32).toString("hex");
  try {
    const challenge = await send("/api/v1/hook-listener-proof", "GET", {
      "X-DefenseClaw-Connector": "opencode",
      "X-DefenseClaw-Listener-Key-Id": createHash("sha256").update(token).digest("hex"),
      "X-DefenseClaw-Listener-Nonce": nonce,
    }, undefined, undefined);
    const proof = String(challenge.headers["x-defenseclaw-listener-proof"] || "");
    const want = createHmac("sha256", token)
      .update(DC_LISTENER_PROOF_DOMAIN + "\u0000opencode\u0000" + nonce)
      .digest("hex");
    if (challenge.status !== 204 || !/^[0-9a-f]{64}$/.test(proof) ||
        !timingSafeEqual(Buffer.from(proof, "hex"), Buffer.from(want, "hex"))) {
      throw defenseclawPeerError("the DefenseClaw gateway listener did not prove its identity");
    }
    const response = await send(path, init.method || "POST", init.headers, init.body, provenSocket);
    if (response.status >= 300 && response.status < 400) {
      throw defenseclawPeerError("the DefenseClaw gateway redirected a proven hook request");
    }
    return { ok: response.status >= 200 && response.status < 300, status: response.status,
      headers: { get: (name) => response.headers[String(name).toLowerCase()] ?? null },
      text: async () => response.body,
      json: async () => JSON.parse(response.body) };
  } finally {
    agent.destroy();
  }
}

function defenseclawPerUserNativePostBinary() {
  const home = homedir();
  const directory = join(home, ".local", "bin");
  const binary = join(directory, process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway");
  const paths = [home, join(home, ".local"), directory, binary];
  const uid = userInfo().uid;
  for (let index = 0; index < paths.length; index++) {
    const info = lstatSync(paths[index]);
    if (info.isSymbolicLink() || (index === paths.length - 1 ? !info.isFile() : !info.isDirectory())) {
      throw new Error("per-user gateway helper path is untrusted");
    }
    if (process.platform !== "win32" && (info.uid !== uid || (info.mode & 0o022) !== 0)) {
      throw new Error("per-user gateway helper path is writable by another account");
    }
  }
  return binary;
}

// defenseclawFetch posts to the gateway over the managed hook socket when one
// is configured. A per-user post goes through the native helper, which
// verifies the same connected socket it sends on.
async function defenseclawFetch(path, init, token) {
  if (!DC_HOOK_SOCKET) {
    if (DC_PER_USER_NATIVE_POST) {
      const binary = defenseclawPerUserNativePostBinary();
      const output = execFileSync(binary, ["hook-post", "--api-addr", DC_API_ADDR], {
        input: JSON.stringify({ path, headers: init.headers || {}, body: String(init.body || "") }),
        timeout: DC_TIMEOUT_MS, maxBuffer: 2 * 1024 * 1024, windowsHide: true, encoding: "utf8",
      });
      const reply = JSON.parse(output);
      if (!Number.isInteger(reply.status) || reply.status < 100 || reply.status > 599 || typeof reply.body !== "string") {
        throw new Error("invalid native gateway response");
      }
      return {
        ok: reply.status >= 200 && reply.status < 300,
        status: reply.status,
        headers: { get: (name) => name.toLowerCase() === "retry-after" ? reply.retry_after || null : null },
        text: async () => reply.body,
      };
    }
    if (DC_LISTENER_PROOF) return defenseclawProvenTCPRequest(path, init, token);
    throw defenseclawPeerError("the DefenseClaw gateway listener has no account proof");
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

// defenseclawForeignHookCheck asks the administrator-owned hook binary for
// the foreign-hook guard's decision and resolves to { reason, retryable }: a
// block reason, or "" when no unapproved plugin or hook is present, and
// whether the block is an availability failure (the check could not run, or
// the guard says the gateway could not answer for the session). A confirmed
// foreign plugin loaded with OpenCode stays loaded for this process, so only
// an availability failure lets a later call retry the load-time check. A binary that cannot be
// run, times out, or answers anything but {"deny": false} blocks, unless
// the managed deployment was uninstalled (its install marker is gone):
// uninstall removes the hook binary too, and this plugin then stops failing
// closed as it does for the gateway call.
function defenseclawForeignHookCheck(event, cwd) {
  if (!DC_FOREIGN_GUARD) return Promise.resolve({ reason: "", retryable: false });
  return new Promise((resolve) => {
    const fail = (why) => {
      void defenseclawDeploymentRemoved().then((removed) => resolve(removed
        ? { reason: "", retryable: false }
        : { reason: defenseclawForeignCheckFailure(event, why), retryable: true }));
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
            resolve({ reason: "", retryable: false });
            return;
          }
          resolve({
            reason: verdict && typeof verdict.reason === "string" && verdict.reason
              ? verdict.reason
              : "DefenseClaw blocked this tool call because an unapproved plugin is present.",
            // Only the guard's structured answer marks a deny as the gateway
            // not answering, never the text of its reason.
            retryable: Boolean(verdict && verdict.retryable === true),
          });
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
// check itself could not run. A later tool call retries this startup check.
function defenseclawForeignCheckFailure(event, why) {
  const detail = String(why || "").split(/\r?\n/)[0].trim() || "no answer";
  if (event === "defenseclaw.plugin.loaded") {
    return "DefenseClaw could not check for unapproved plugins when the agent started (" + detail +
      "), so this tool call is blocked. Retry when DefenseClaw is available.";
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

// defenseclawLogFailOpen appends the hook-failures.jsonl line the shell and
// native hooks write, for a call that went ahead because DefenseClaw could
// not check it (fail mode open), in this install's data directory (the one
// that holds the hook credential). The gateway's fail-open report reads it,
// so such a call is never silent (rel-1-0-2 GAP-0446). Best effort: a log
// that cannot be written never changes the verdict.
async function defenseclawLogFailOpen(reason, category) {
  try {
    const dir = join(dirname(dirname(DC_TOKEN_FILE)), "logs");
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const file = await open(join(dir, "hook-failures.jsonl"), "a", 0o600);
    try {
      await file.appendFile(JSON.stringify({
        ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        connector: "opencode",
        hook: "opencode-plugin",
        reason: String(reason || "unknown"),
        category,
        fail_mode: "open",
        outcome: "fail_open",
      }) + "\n");
    } finally {
      await file.close();
    }
  } catch (_) {
    // A notice of a failure never fails the tool call.
  }
}

async function defenseclawPerUserInstallInProgress() {
  return false;
}

// defenseclawFailModeNow is the fail mode a failed tool check answers with,
// read when it answers: closed while this account's installer holds its
// data directory (.install.lock). A call that was waiting for the gateway
// when an install or upgrade began answers closed too; a mode read when the
// call started let it run (GAP-0893).
async function defenseclawFailModeNow(mode, actionable) {
  if (mode !== "open" || !actionable) return mode;
  return await defenseclawPerUserInstallInProgress() ? "closed" : mode;
}

async function defenseclawPost(event, toolName, toolInput, cwd, context, toolResult, mcpIdentity, actionable) {
  if (actionable && await defenseclawManagedLifecycleHeld()) return { reason: DC_MANAGED_LIFECYCLE_TEXT };
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
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...(await defenseclawIdentityHeaders()) };
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
    const body = JSON.stringify(payload);
    const res = await defenseclawRetryBusy(() => defenseclawFetch("/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    }, token), controller.signal);
    if (!res.ok) {

      // Gateway answered with a bad status (auth/5xx). Honor fail mode. A 5xx
      // is an outage, as in the shell hooks, so strict availability closes it.
      if (await defenseclawFailModeNow(res.status >= 500 ? DC_TRANSPORT_FAIL_MODE : DC_FAIL_MODE, actionable) === "closed") {
        return { reason: "DefenseClaw hook failed closed (HTTP " + res.status + ")" };
      }
      if (actionable) await defenseclawLogFailOpen("gateway returned HTTP " + res.status, res.status >= 500 ? "transport" : "response");
      return null;
    }
    const data = defenseclawGatewayJSON(await res.text());
    if (actionable && await defenseclawManagedLifecycleHeld()) return { reason: DC_MANAGED_LIFECYCLE_TEXT };

    if (!data || !["allow", "block", "confirm", "alert"].includes(data.action)) {
      return { reason: "DefenseClaw hook failed closed (invalid gateway verdict)" };
    }
    const out = data && data.hook_output;
    if (out && (out.decision === "deny" || out.decision === "block")) {
      return { reason: out.reason || "DefenseClaw blocked this tool call.", mode: data.mode || "" };
    }
    if (data.action === "block" || data.action === "confirm") {
      return { reason: data.reason || "DefenseClaw hook failed closed (missing native deny)", mode: data.mode || "" };
    }
    return { reason: "", mode: data && data.mode || "", notice: defenseclawConfirmNotice(data) };
  } catch (err) {
    if (err && err.code === "DC_PEER_UNVERIFIED") {
      return { reason: "DefenseClaw hook failed closed (" + err.message + ")" };
    }
    if (DC_PER_USER_NATIVE_POST) return { reason: "DefenseClaw hook failed closed (per-user gateway peer unverified)" };
    // Transport failure (gateway unreachable / timeout). Honor fail mode:
    // closed → block, open → allow. An uninstalled deployment allows.
    if (await defenseclawDeploymentRemoved()) return null;
    if (await defenseclawFailModeNow(DC_TRANSPORT_FAIL_MODE, actionable) === "closed") {
      if ((DC_HOOK_SOCKET || DC_FOREIGN_GUARD) && defenseclawGatewayStopped(err)) return { reason: DC_GATEWAY_STOPPED_TEXT };
      return { reason: "DefenseClaw hook failed closed (" + (err && err.message ? err.message : String(err)) + ")" };
    }
    if (actionable) await defenseclawLogFailOpen(err && err.message ? err.message : String(err), "transport");
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
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...(await defenseclawIdentityHeaders()) };
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
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0", ...(await defenseclawIdentityHeaders()) };
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

export const DefenseClaw = async ({ client, directory, worktree }) => {
  const cwd = directory || worktree || "";
  // OpenCode loads plugins once at startup: a foreign plugin present now
  // keeps running for this process even if its file is deleted later, so a
  // block found at load holds for the whole process.
  let defenseclawStartupGuard = defenseclawForeignHookCheck("defenseclaw.plugin.loaded", cwd);
  return {
    config: async (config) => {
      defenseclawConfigure(config);
      if (await defenseclawManagedLifecycleHeld()) return;
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
      if (await defenseclawManagedLifecycleHeld()) throw defenseclawBlock(client, DC_MANAGED_LIFECYCLE_TEXT);
      // Every call runs the check, also after a block at load (which holds
      // for the process), so the gateway records each denied call.
      if (!defenseclawStartupGuard) {
        defenseclawStartupGuard = defenseclawForeignHookCheck("defenseclaw.plugin.loaded", cwd);
      }
      const startup = await defenseclawStartupGuard;
      if (startup.retryable) defenseclawStartupGuard = null;
      const callBlock = (await defenseclawForeignHookCheck("tool.execute.before", cwd)).reason;
      const blocked = startup.reason || callBlock;
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
      if (verdict && verdict.reason) throw defenseclawBlock(client, verdict.reason);
      if (verdict && verdict.notice) defenseclawShowNotice(client, verdict.notice);
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
