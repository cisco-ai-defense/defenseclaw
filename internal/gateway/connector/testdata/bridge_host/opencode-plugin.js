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
import { lstatSync, readFileSync } from "node:fs";

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lstat, mkdir, open } from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import { stat } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";

// DC_-prefixed constants are non-secret values baked in at setup time, not
// env-var reads — the envvars registry gate scans for DEFENSECLAW_* tokens.
const DC_API_ADDR = "{{.APIAddr}}";
const DC_TOKEN_FILE = "{{.TokenFileJS}}";
const DC_FAIL_MODE = "closed"; // per-user and standalone hooks stay closed
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
const DC_PER_USER_NATIVE_POST = "1";
// The Windows PowerShell that checks the helper's owner and DACL: setup
// resolves the system directory with GetSystemDirectoryW, so a Windows
// installed outside C:\Windows runs its own copy.
const DC_WINDOWS_POWERSHELL = "{{.WindowsPowerShellJS}}";
// The gateway binary of the install that rendered this plugin, which a
// per-user plugin runs for hook-post and session facts: native Windows Setup
// renders the one in its install root's bin folder (GAP-1847). Empty keeps the
// .gateway-helper record that install.sh and install.ps1 write for ~/.local/bin.
const DC_GATEWAY_BINARY = "{{.GatewayBinaryJS}}";
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
// (DC_FOREIGN_GUARD); a per-user install runs its install's gateway binary
// (DC_GATEWAY_BINARY, or ~/.local/bin). No answer is a supported outcome: the SSH and logind
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
  const account = userInfo();
  if (DC_GATEWAY_BINARY) {
    // Windows Setup (GAP-1847): its install root has no ~/.local/bin and no
    // .gateway-helper record; the rendered gateway's folders are checked as 1.0.4 does.
    const directory = dirname(DC_GATEWAY_BINARY);
    const setupPaths = [dirname(directory), directory, DC_GATEWAY_BINARY];
    for (let index = 0; index < setupPaths.length; index++) {
      const info = lstatSync(setupPaths[index]);
      if (info.isSymbolicLink() || (index === setupPaths.length - 1 ? !info.isFile() : !info.isDirectory())) throw new Error("per-user gateway helper path is untrusted");
      if (process.platform !== "win32" && (info.uid !== account.uid || (info.mode & 0o022) !== 0)) throw new Error("per-user gateway helper path is writable by another account");
    }
    return DC_GATEWAY_BINARY;
  }
  const hookDir = dirname(DC_TOKEN_FILE);
  const record = join(hookDir, ".gateway-helper");
  const recordInfo = lstatSync(record);
  if (!recordInfo.isFile() || recordInfo.isSymbolicLink() || recordInfo.size > 4096) throw new Error("per-user gateway helper record is untrusted");
  const content = readFileSync(record, "utf8");
  if (!content.endsWith("\n") || /[\r\n\0]/.test(content.slice(0, -1))) throw new Error("per-user gateway helper record is malformed");
  const binary = content.slice(0, -1);
  const home = dirname(dirname(dirname(binary)));
  if (!isAbsolute(binary) || binary !== join(home, ".local", "bin", process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway")) throw new Error("per-user gateway helper path is untrusted");
  const paths = [dirname(hookDir), hookDir, record, home, join(home, ".local"), join(home, ".local", "bin"), binary];
  for (let index = 0; index < paths.length; index++) {
    const info = lstatSync(paths[index]);
    if (info.isSymbolicLink() || ([2, 6].includes(index) ? !info.isFile() : !info.isDirectory())) throw new Error("per-user gateway helper path is untrusted");
    if (process.platform !== "win32" && (info.uid !== account.uid || (info.mode & 0o022) !== 0)) throw new Error("per-user gateway helper path is writable by another account");
  };
  if (process.platform === "win32") {
    // A data directory nested deeper in the profile has its parents up to
    // the profile checked too.
    const root = home.toLowerCase() + "\\";
    for (let dir = dirname(dirname(hookDir)); dir.toLowerCase().startsWith(root); dir = dirname(dir)) paths.push(dir);
    defenseclawCheckWindowsHelperACL(paths);
  }
  return binary;
}

// defenseclawPerUserHookPostBinary picks the small hook-post helper the POSIX
// installer puts beside the gateway (in the same folder), so a hook event does not start the full
// gateway CLI; both read the same JSON request and run the same
// connected-peer check. An install without it (Windows, or an older
// installer's roll-forward) keeps the verified gateway CLI. A present but
// untrusted helper is refused, never bypassed.
function defenseclawPerUserHookPostBinary() {
  const gateway = defenseclawPerUserNativePostBinary();
  const helper = join(dirname(gateway), process.platform === "win32" ? "defenseclaw-hook-post.exe" : "defenseclaw-hook-post");
  let info;
  try {
    info = lstatSync(helper);
  } catch (error) {
    if (error && error.code === "ENOENT") return gateway;
    throw error;
  }
  if (info.isSymbolicLink() || !info.isFile()) {
    throw new Error("per-user hook helper path is untrusted");
  }
  if (process.platform !== "win32" && (info.uid !== userInfo().uid || (info.mode & 0o022) !== 0)) {
    throw new Error("per-user hook helper path is writable by another account");
  }
  return helper;
}

function defenseclawCheckWindowsHelperACL(paths) {
  // Windows stat mode bits do not represent the DACL. The system
  // PowerShell (DC_WINDOWS_POWERSHELL) checks every path before a
  // bearer-bearing helper launch: its owner is this account, SYSTEM,
  // Administrators (an elevated install) or TrustedInstaller, and no other
  // principal may write it. An inherit-only entry does not apply to the
  // path itself; its children carry it.
  // execFileSync opens the helper by this path, so every folder above a
  // checked path, up to its volume root, must not let another principal
  // rename or replace what it holds (a custom data root's parent, for one):
  // a trusted owner and no delete-child, delete, change-permissions or
  // take-ownership grant to anyone else. A volume root cannot be renamed, so
  // delete is not checked there.
  const checked = new Set(paths.map((path) => path.toLowerCase()));
  const entries = paths.map((p) => [0x500D0156, p]);
  for (const path of paths) {
    for (let dir = dirname(path), top = false; !top; dir = dirname(dir)) {
      top = dirname(dir) === dir;
      if (checked.has(dir.toLowerCase())) continue;
      checked.add(dir.toLowerCase());
      entries.push([top ? 0x100C0040 : 0x100D0040, dir]);
    }
  }
  // PowerShell finds a cmdlet through PSModulePath, which the agent's
  // environment sets: a module planted in a folder it names first could
  // answer for ConvertFrom-Json or Get-Acl and pass every path. The script
  // calls no cmdlet, only .NET methods and language statements, runs with
  // PSModulePath set to the system PowerShell's own module folder (and no
  // .NET profiler or COMPlus setting), and the check passes only when it
  // reports every entry checked. Each path goes as base64 UTF-8, so a
  // non-ASCII path is not mangled by the console code page.
  const script = [
    "$ErrorActionPreference='Stop'",
    "$current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$trusted=@($current,'S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')",
    "$inheritOnly=[int][System.Security.AccessControl.PropagationFlags]::InheritOnly",
    "$sid=[System.Security.Principal.SecurityIdentifier]",
    "$count=0",
    "foreach($line in [Console]::In.ReadToEnd().Split([char]10)) {",
    "  $entry=$line.Split([char]32)",
    "  if($entry.Length -ne 2) { throw 'entry' }",
    "  $writeMask=[int64]$entry[0]",
    "  $p=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($entry[1]))",
    "  if([System.IO.Directory]::Exists($p)) { $acl=[System.IO.Directory]::GetAccessControl($p) } elseif([System.IO.File]::Exists($p)) { $acl=[System.IO.File]::GetAccessControl($p) } else { throw 'missing' }",
    "  if($trusted -notcontains $acl.GetOwner($sid).Value) { throw 'owner' }",
    "  foreach($ace in $acl.GetAccessRules($true,$true,$sid)) {",
    "    if($ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and (([int]$ace.PropagationFlags -band $inheritOnly) -eq 0) -and $trusted -notcontains $ace.IdentityReference.Value -and (([int64]$ace.FileSystemRights -band $writeMask) -ne 0)) { throw 'writable' }",
    "  }",
    "  $count++",
    "}",
    "[Console]::Out.Write('checked ' + $count)",
  ].join("\n");
  const env = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (value !== undefined && !/^(psmodulepath|psmoduleanalysiscachepath|cor_|complus_)/i.test(name)) env[name] = value;
  }
  env.PSModulePath = join(dirname(DC_WINDOWS_POWERSHELL), "Modules");
  let output = "";
  try {
    output = execFileSync(DC_WINDOWS_POWERSHELL, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
      input: entries.map(([mask, path]) => mask + " " + Buffer.from(path, "utf8").toString("base64")).join("\n"),
      env, timeout: 5000, windowsHide: true, encoding: "utf8", stdio: ["pipe", "pipe", "ignore"],
    });
  } catch {
    output = "";
  }
  if (output.trim() !== "checked " + entries.length) throw new Error("per-user gateway helper path has an untrusted Windows owner or DACL");
}
// defenseclawFetch posts to the gateway over the managed hook socket when one
// is configured. A per-user post goes through the native helper, which
// verifies the same connected socket it sends on.
async function defenseclawFetch(path, init, token) {
  if (!DC_HOOK_SOCKET) {
    if (DC_PER_USER_NATIVE_POST) {
      const binary = defenseclawPerUserHookPostBinary();
      const post = () => execFileSync(binary, ["hook-post", "--api-addr", DC_API_ADDR], {
        input: JSON.stringify({ path, headers: init.headers || {}, body: String(init.body || "") }),
        // The helper's diagnostics (a refused connection during an outage)
        // stay in the error the caller classifies; inherited, they reached
        // the agent's screen over the one outage warning (GAP-1314).
        timeout: DC_TIMEOUT_MS, maxBuffer: 2 * 1024 * 1024, windowsHide: true, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
      });
      let output;
      try {
        output = post();
      } catch (err) {
        // A helper that ran and failed for another reason than an outage
        // (exit 7) or the time limit, a connected-peer proof that raced the
        // gateway for one, gets one more try; a second failure blocks with
        // its cause (GAP-1236).
        if (!err || !Number.isInteger(err.status) || err.status === 0 || err.status === 7 || err.signal) throw err;
        output = post();
      }
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
            // foreign_hooks report names the unapproved plugin's file and
            // digest for the user (GAP-0697).
            resolve({ reason: "", retryable: false, warnings: Array.isArray(verdict.warnings) ? verdict.warnings.map(String) : [] });
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

// defenseclawShowNotice asks OpenCode's documented TUI surface to display a
// notice. A failed request leaves an outage session eligible for the next
// call's warning; it never changes the tool verdict.
async function defenseclawShowNotice(client, message, variant) {
  if (!message || !client || !client.tui || typeof client.tui.showToast !== "function") return false;
  try {
    const shown = await client.tui.showToast({ body: {
      title: "DefenseClaw", message, variant: variant || "warning", duration: 15000,
    } });
    return shown === true || !!(shown && shown.data === true);
  } catch (_) {
    return false;
  }
}

// defenseclawLogFailOpen appends the hook-failures.jsonl line the shell and
// native hooks write, for a call that went ahead because DefenseClaw could
// not check it (fail mode open), in this install's data directory (the one
// that holds the hook credential). The gateway's fail-open report reads it,
// so such a call is never silent (rel-1-0-2 GAP-0446). Best effort: a log
// that cannot be written never changes the verdict.
// defenseclawPerUserFailureCause is the cause of a failed per-user check, for
// the block text: the helper's last stderr line without its program prefix,
// else the plugin's own error (an answer it refused), bounded and on one line.
function defenseclawPerUserFailureCause(err) {
  const lines = String(err && err.stderr || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  let cause = lines.length ? lines[lines.length - 1].replace(/^defenseclaw-(gateway|hook-post)( hook-post)?: /, "") : "";
  if (!cause && err && !Number.isInteger(err.status) && err.message) cause = String(err.message);
  cause = cause.replace(/[\u0000-\u001f]+/g, " ").slice(0, 240);
  return cause || "per-user gateway peer unverified";
}

async function defenseclawLogFailOpen(reason, category, context, closed) {
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
        fail_mode: closed ? "closed" : "open",
		session_id: String(context && (context.sessionID || context.sessionId) || "").slice(0, 256),
		call_id: String(context && (context.callID || context.callId) || randomBytes(16).toString("hex")).slice(0, 256),
        outcome: closed ? "fail_closed" : "fail_open",
      }) + "\n");
    } finally {
      await file.close();
    }
  } catch (_) {
    // A notice of a failure never fails the tool call.
  }
}

// The installer holds this data-directory lock while it replaces this
// account's stopped gateway. An open outage mode cannot bypass that upgrade:
// a failure blocks, while a call the gateway answered keeps its answer in the
// default and permissive tiers (owner decision 2026-10-24, GAP-1372).
const DC_INSTALL_WINDOW_TEXT = "DefenseClaw blocked this tool call: DefenseClaw is being installed or upgraded for this account, " +
  "and its gateway starts again when that is done. Try again in a moment; if the installer has stopped, run the installer again to finish or undo the interrupted install. `defenseclaw-gateway status` shows its state.";

// defenseclawInstallLockDirs are the folders an installer of this account
// locks: the gateway's data_dir (the folder that holds the hook credential)
// and the folder install.sh and install.ps1 lock, DEFENSECLAW_HOME or else
// ~/.defenseclaw, which differ when data_dir is set apart from it
// (GAP-1002); the shell hooks check the same two (GAP-0948).
function defenseclawInstallLockDirs() {
  return [dirname(dirname(DC_TOKEN_FILE)), String(process.env.DEFENSECLAW_HOME || "") || join(homedir(), ".defenseclaw")];
}

// defenseclawInstallLockNumber reads the lock's pid file: "absent" (missing,
// empty or not a positive number), "valid", or "unreadable" (not a small
// regular file, or a read error but its absence).
async function defenseclawInstallLockNumber(path) {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.size > 64) return { state: "unreadable", value: 0 };
    const text = String(readFileSync(path, "utf8")).trim();
    return /^[1-9][0-9]{0,11}$/.test(text) ? { state: "valid", value: Number(text) } : { state: "absent", value: 0 };
  } catch (err) {
    return { state: err && err.code === "ENOENT" ? "absent" : "unreadable", value: 0 };
  }
}

// defenseclawProcessIdentity names process pid as install.sh and install.ps1
// record their own in a lock (proc-start; hookexec procidentity), from what
// the system keeps of its creation, which no clock step moves: on Linux
// "<boot_id> <starttime>" (field 22 of /proc/<pid>/stat), on macOS its
// creation second as `LC_ALL=C TZ=UTC ps -o lstart=` prints it, on Windows
// its creation FILETIME; null when the system does not say.
function defenseclawProcessIdentity(pid) {
  try {
    if (process.platform === "linux") {
      const boot = String(readFileSync("/proc/sys/kernel/random/boot_id", "utf8")).trim();
      const stat = String(readFileSync("/proc/" + pid + "/stat", "utf8"));
      const end = stat.lastIndexOf(")");
      const fields = stat.slice(end + 1).trim().split(/\s+/);
      if (end < 0 || fields.length < 20 || !/^[0-9]+$/.test(fields[19]) || !/^[0-9a-f-]+$/.test(boot)) return null;
      return boot + " " + fields[19];
    }
    if (process.platform === "darwin") {
      const fields = String(execFileSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)],
        { encoding: "utf8", timeout: 5000, env: { LC_ALL: "C", TZ: "UTC", PATH: "/usr/bin:/bin" }, stdio: ["ignore", "pipe", "ignore"] })).trim().split(/\s+/);
      return fields.length === 5 ? fields.join(" ") : null;
    }
    if (process.platform === "win32") {
      // Arguments apart: the helper ACL check is the plugin's one inline PowerShell call (its repair marker).
      const identityArgs = ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-Process -Id " + Number(pid) + " -ErrorAction Stop).StartTime.ToFileTimeUtc()"];
      const text = String(execFileSync(DC_WINDOWS_POWERSHELL, identityArgs,
        { encoding: "utf8", timeout: 10000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] })).trim();
      return /^[1-9][0-9]{0,19}$/.test(text) ? text : null;
    }
  } catch (_) {
    // Fall through: the system does not say.
  }
  return null;
}

// defenseclawProcessStartMs is when process pid started (ms since the epoch),
// from the identity the system keeps (defenseclawProcessIdentity), or null.
function defenseclawProcessStartMs(pid) {
  const identity = defenseclawProcessIdentity(pid);
  if (identity === null) return null;
  try {
    if (process.platform === "linux") {
      const line = String(readFileSync("/proc/stat", "utf8")).split("\n").find((entry) => entry.startsWith("btime "));
      const boot = line ? Number(line.slice(6).trim()) : NaN;
      const ticks = Number(identity.split(" ")[1]);
      return Number.isFinite(boot) && Number.isFinite(ticks) ? boot * 1000 + ticks * 10 : null;
    }
    if (process.platform === "darwin") {
      const [, month, day, time, year] = identity.split(" ");
      const started = Date.parse(month + " " + day + ", " + year + " " + time + " UTC");
      return Number.isFinite(started) ? started : null;
    }
    if (process.platform === "win32") return Number(BigInt(identity) / 10000n - 11644473600000n);
  } catch (_) {
    // The system does not say.
  }
  return null;
}

// defenseclawProcessEnded reports a process that has exited but keeps its
// pid: a zombie its parent has not reaped (hookexec procidentity.Ended). It
// keeps its start but runs nothing. On Windows process.kill already reads
// the exit code of a process object a handle keeps. False when the system
// does not say.
function defenseclawProcessEnded(pid) {
  try {
    if (process.platform === "linux") {
      const stat = String(readFileSync("/proc/" + pid + "/stat", "utf8"));
      const end = stat.lastIndexOf(")");
      const state = end < 0 ? "" : stat.slice(end + 1).trim().split(/\s+/)[0];
      return state === "Z" || state === "X" || state === "x";
    }
    if (process.platform === "darwin") {
      const state = String(execFileSync("/bin/ps", ["-o", "stat=", "-p", String(pid)],
        { encoding: "utf8", timeout: 5000, env: { LC_ALL: "C", PATH: "/usr/bin:/bin" }, stdio: ["ignore", "pipe", "ignore"] })).trim();
      return state.startsWith("Z");
    }
  } catch (_) {
    // Fall through: the system does not say.
  }
  return false;
}

// defenseclawInstallLockRecord reads the lock's proc-start record: "absent",
// "valid" (with its trimmed text), or "unreadable" (not a small regular
// file, empty, or a read error but its absence).
async function defenseclawInstallLockRecord(path) {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.size > 128) return { state: "unreadable", value: "" };
    const text = String(readFileSync(path, "utf8")).trim();
    return text ? { state: "valid", value: text } : { state: "unreadable", value: "" };
  } catch (err) {
    return { state: err && err.code === "ENOENT" ? "absent" : "unreadable", value: "" };
  }
}

// defenseclawInstallLockState is the one install-lock rule of every
// per-user hook (hookexec installLockStale, the shell hooks, the Amp
// plugin) and of `defenseclaw doctor` (_install_lock_state). It reads no
// clock and keeps no answer between calls: "none" when dir has no
// .install.lock and is a folder or absent; "stale" when the lock is a
// folder, no interrupted-install record sits beside it and its installer is
// proven gone: its pid names no process, or this plugin's own (no plugin
// writes a lock), or another process than its proc-start record names (a
// reused pid); "held" for a live install however long it runs, a lock
// without a valid pid, a lock without a proc-start record whose pid names a
// process (1.0.2, 1.0.3), and an owner whose identity cannot be read. A
// stale lock is no lock; `defenseclaw doctor --fix` or the next installer
// run removes it.
async function defenseclawInstallLockState(dir) {
  const missing = (err) => Boolean(err) && err.code === "ENOENT";
  const lock = join(dir, ".install.lock");
  let info;
  try {
    info = await lstat(lock);
  } catch (err) {
    if (!missing(err)) return "held";
    try {
      // A folder that is not one cannot be looked in (Windows reports its
      // child as absent).
      if (!(await lstat(dir)).isDirectory()) return "held";
    } catch (inner) {
      if (!missing(inner)) return "held";
    }
    return "none";
  }
  if (!info.isDirectory()) return "held";
  const owner = await defenseclawInstallLockNumber(join(lock, "pid"));
  if (owner.state !== "valid" || owner.value > 2147483647) return "held";
  // A live installer's pid names no other process: this one is reused.
  if (owner.value === process.pid) return "stale";
  try {
    process.kill(owner.value, 0);
  } catch (err) {
    if (err && err.code === "ESRCH") return "stale";
  }
  if (defenseclawProcessEnded(owner.value)) return "stale";
  const identity = await defenseclawInstallLockRecord(join(lock, "proc-start"));
  if (identity.state === "absent") {
    // A 1.0.2/1.0.3 lock has no identity record: its pid names a later
    // process when that process started after the lock (GAP-1465).
    const started = defenseclawProcessStartMs(owner.value);
    return started !== null && started > info.mtimeMs + 2000 ? "stale" : "held";
  }
  if (identity.state !== "valid") return "held";
  const current = defenseclawProcessIdentity(owner.value);
  return current !== null && current !== identity.value ? "stale" : "held";
}

// defenseclawInstallLocks reads the lock of every folder an installer of
// this account locks: whether one is held, and whether one is stale.
async function defenseclawInstallLocks() {
  const states = [];
  for (const dir of defenseclawInstallLockDirs()) states.push(await defenseclawInstallLockState(dir));
  return { held: states.includes("held"), stale: states.includes("stale") };
}

// defenseclawInstallLockHeld reports an install that may be running: a lock
// that is not stale. Every failure and every outage stays closed under it.
async function defenseclawInstallLockHeld() {
  return (await defenseclawInstallLocks()).held;
}

const DC_INSTALL_WINDOW_NOTICE = "DefenseClaw is being installed or upgraded for this account. Its gateway checked this tool call, " +
  "so it runs (the default and permissive policies let checked calls run during an install; any failure blocks). `defenseclaw-gateway status` shows its state.";
const DC_STALE_INSTALL_LOCK_NOTICE = "DefenseClaw found an install lock whose installer is no longer running, so it ignores it and checks tool calls as usual. " +
  "Run `defenseclaw doctor --fix` (or the installer again) to remove it.";
let defenseclawStaleLockNoticeShown = false;

// defenseclawInstallWindow is what an install does to a call the gateway
// answers: "closed" holds it back while an installer holds this account's
// data directory and the outage mode the config gives OpenCode for an
// install window is not open (the strict tier, a saved closed, any doubt:
// hook-outage-mode --install-window); "open" lets the answer through with a
// warning (the default and permissive tiers, or a saved open); "stale" when
// only a stale lock is there; "none" otherwise.
async function defenseclawInstallWindow() {
  const locks = await defenseclawInstallLocks();
  if (locks.held) return defenseclawConfigOutageOpen(true) ? "open" : "closed";
  return locks.stale ? "stale" : "none";
}

// defenseclawInstallWindowNotice is the warning of a call that ran during
// an install, or the one warning of this process about a stale lock.
function defenseclawInstallWindowNotice(window) {
  if (window === "open") return DC_INSTALL_WINDOW_NOTICE;
  if (window !== "stale" || defenseclawStaleLockNoticeShown) return "";
  defenseclawStaleLockNoticeShown = true;
  return DC_STALE_INSTALL_LOCK_NOTICE;
}

async function defenseclawPerUserInstallInProgress() {
  if (DC_FAIL_MODE !== "open") return false;
  return await defenseclawInstallLockHeld();
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


// Command and target fields the bounded review of an oversized call keeps
// verbatim at any depth (Bash "command" or "cmd", argv arrays, patches,
// scripts and every path or target form); other strings keep an 8 KiB head.
// Every value of the call's arguments (tool_input) is kept the same way,
// whatever its key (an MCP server may act on any argument, and the gateway
// reads all of them), except its file text and description
// (DC_REVIEW_BULK_KEYS), which keep a head. Keys are compared lower-case
// without "_" and "-".
const DC_REVIEW_KEYS = new Set(["cmd", "command", "commands", "commandline", "args", "arguments", "argv", "toolargs", "script", "code", "input", "patch", "patchtext", "diff", "filepath", "path", "paths", "file", "files", "filename", "target", "targetfile", "targetpath", "targets", "destination", "dest", "source", "sourcepath", "oldpath", "newpath", "absolutepath", "relativepath", "url", "uri", "cwd", "workdir", "workingdirectory", "directory", "dir"]);
const DC_REVIEW_BULK_KEYS = new Set(["content", "oldstring", "newstring", "oldstr", "newstr", "edits", "newsource", "filetext", "description"]);

// defenseclawBoundedReview reduces an oversized payload to a request under
// the gateway's 1 MiB cap that keeps every key of the call, so the gateway
// judges its command and target as at normal size. Every review is marked
// oversize_command_not_inspected: it keeps only a head of the call's file
// text, prompt or tool result, where a configured rule may match past the
// head, so the gateway warns and audits it in observe mode and blocks it in
// action mode. It returns null only when even the last pass, which keeps no
// value whole, stays over the cap.
function defenseclawBoundedReview(payload, originalBytes) {
  for (let pass = 0; pass <= 4; pass++) {
    // Command and target values are kept whole while they fit; only the
    // context heads shrink when the review is too large. The last pass keeps
    // none whole.
    let keep = pass === 4 ? 0 : 832 * 1024;
    let heads = (192 * 1024) >> Math.min(pass, 3);
    const walk = (value, inKeep, depth, atArgs = false) => {
      if (typeof value === "string") {
        if (inKeep && value.length <= keep) { keep -= value.length; return value; }
        if (inKeep && depth < 128 && /^\s*[[{]/.test(value)) {
          try { return JSON.stringify(walk(JSON.parse(value), true, depth + 1)); } catch (_) { /* not JSON */ }
        }
        // A command or target value that does not fit whole: only a head.
        const n = Math.max(0, Math.min(value.length, 8192, heads));
        heads -= n;
        return n > 0 || value === "" ? value.slice(0, n) : undefined;
      }
      if (value === null || typeof value !== "object") return value;
      if (depth >= 128) return undefined;
      if (Array.isArray(value)) return value.map((item) => walk(item, inKeep, depth + 1));
      const out = {};
      for (const [key, item] of Object.entries(value)) {
        const name = String(key).toLowerCase().replace(/[_-]/g, "");
        const args = depth === 0 && name === "toolinput";
        const keepChild = args || (atArgs && DC_REVIEW_BULK_KEYS.has(name) ? false : inKeep || DC_REVIEW_KEYS.has(name));
        out[key] = walk(item, keepChild, depth + 1, args);
      }
      return out;
    };
    const review = walk(payload, false, 0) || {};
    review.oversize_command_not_inspected = true;
    review.content_truncated = true;
    review.bounded_prefix_review = true;
    review.original_body_bytes = originalBytes;
    const body = JSON.stringify(review);
    // The native helper's transport refuses a body over 900 KiB.
    if (Buffer.byteLength(body, "utf8") <= 900 * 1024) return body;
  }
  return null;
}

async function defenseclawPost(event, toolName, toolInput, cwd, context, toolResult, mcpIdentity, actionable) {
  if (actionable && await defenseclawManagedLifecycleHeld()) return { reason: DC_MANAGED_LIFECYCLE_TEXT };
  if (actionable && await defenseclawInstallWindow() === "closed") return { reason: DC_INSTALL_WINDOW_TEXT };
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
    let body = JSON.stringify(payload);
    const originalBytes = Buffer.byteLength(body, "utf8");
    let oversizedReview = false;
    if (originalBytes > (1 << 20)) {
      if (await defenseclawInstallLockHeld()) return { reason: DC_INSTALL_WINDOW_TEXT };
      if (defenseclawConfigOutageOpen(false)) {
        const review = defenseclawBoundedReview(payload, originalBytes);
        if (review) {
          body = review;
          oversizedReview = true;
        }
      }
      if (!oversizedReview && actionable) {
        return { reason: "DefenseClaw hook payload too large" };
      }
    }
    const res = await defenseclawRetryBusy(() => defenseclawFetch("/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    }, token), controller.signal);
    if (!res.ok) {
      // During an install an error status blocks (GAP-1372).
      if (actionable && await defenseclawInstallLockHeld()) return { reason: DC_INSTALL_WINDOW_TEXT };
      if (oversizedReview) return { reason: "DefenseClaw hook failed closed (gateway refused bounded payload review)" };
      // Gateway answered with a bad status (auth/5xx). Honor fail mode. A 5xx
      // is an outage, as in the shell hooks, so strict availability closes it.
      if (await defenseclawFailModeNow(res.status >= 500 ? DC_TRANSPORT_FAIL_MODE : DC_FAIL_MODE, actionable) === "closed") {
        if (res.status >= 500) return { reason: await defenseclawPerUserGatewayDownText(null, res.status) };
        return { reason: "DefenseClaw hook failed closed (HTTP " + res.status + ")" };
      }
      if (actionable) await defenseclawLogFailOpen("gateway returned HTTP " + res.status, res.status >= 500 ? "transport" : "response", context);
      return null;
    }
    const data = defenseclawGatewayJSON(await res.text());
    if (actionable && await defenseclawManagedLifecycleHeld()) return { reason: DC_MANAGED_LIFECYCLE_TEXT };

    if (!data || !["allow", "block", "confirm", "alert"].includes(data.action)) {
      if (actionable && await defenseclawInstallLockHeld()) return { reason: DC_INSTALL_WINDOW_TEXT };
      return { reason: "DefenseClaw hook failed closed (invalid gateway verdict)" };
    }
    const installWindow = actionable ? await defenseclawInstallWindow() : "none";
    if (installWindow === "closed") return { reason: DC_INSTALL_WINDOW_TEXT };
    const out = data && data.hook_output;
    if (out && (out.decision === "deny" || out.decision === "block")) {
      return { reason: out.reason || "DefenseClaw blocked this tool call.", mode: data.mode || "" };
    }
    if (data.action === "block" || data.action === "confirm") {
      return { reason: data.reason || "DefenseClaw hook failed closed (missing native deny)", mode: data.mode || "" };
    }
    if (oversizedReview) {
      await defenseclawLogFailOpen("stdin body exceeded cap; oversize, command not inspected", "transport");
      return { reason: "", mode: data && data.mode || "", notice: "DefenseClaw warning: this hook payload exceeded the bounded inspection cap (oversize, command not inspected); the gateway allowed and audited this call.", outage_notice: defenseclawInstallWindowNotice(installWindow) };
    }
    return { reason: "", mode: data && data.mode || "", notice: defenseclawConfirmNotice(data), outage_notice: defenseclawInstallWindowNotice(installWindow) };
  } catch (err) {
    if (err && err.code === "DC_PEER_UNVERIFIED") {
      return { reason: "DefenseClaw hook failed closed (" + err.message + ")" };
    }
    if (DC_PER_USER_NATIVE_POST) {
      if (await defenseclawPerUserOutageOpen(err)) {
        if (actionable) await defenseclawLogFailOpen("gateway unreachable", "transport", context);
        return { reason: "", outage_notice: actionable ? await defenseclawPerUserOutageNotice() : "" };
      }
      if (err && err.status === 7) return { reason: await defenseclawPerUserGatewayDownText(err, 0) };
      // Name the cause (the helper's own line, or the answer the plugin
      // refused, such as a repeated key) and record the call (GAP-1898,
      // GAP-1236).
      const cause = defenseclawPerUserFailureCause(err);
      if (actionable) await defenseclawLogFailOpen(cause, "response", context, true);
      return { reason: "DefenseClaw hook failed closed (" + cause + ")" };
    }
    // Transport failure (gateway unreachable / timeout). Honor fail mode:
    // closed → block, open → allow. An uninstalled deployment allows.
    if (await defenseclawDeploymentRemoved()) return null;
    if (actionable && await defenseclawInstallLockHeld()) return { reason: DC_INSTALL_WINDOW_TEXT };
    if (await defenseclawFailModeNow(DC_TRANSPORT_FAIL_MODE, actionable) === "closed") {
      if ((DC_HOOK_SOCKET || DC_FOREIGN_GUARD) && defenseclawGatewayStopped(err)) return { reason: DC_GATEWAY_STOPPED_TEXT };
      return { reason: await defenseclawPerUserGatewayDownText(err, 0) };
    }
    if (actionable) await defenseclawLogFailOpen(err && err.message ? err.message : String(err), "transport", context);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// defenseclaw-call-time-outage-v1: defenseclawPerUserOutageOpen reports a per-user tool check that may run
// unchecked: the native helper exited 7 (hookexec.PerUserPostOutageExit:
// this account's gateway refused or dropped the connection before any
// status), strict availability is off, no install holds the data directory,
// and the config on disk gives the open outage mode. An answer the gateway gave, an unverified listener and
// every other error keep the call blocked.
async function defenseclawPerUserOutageOpen(err) {
  if (!err || err.status !== 7) return false;
  if (["1", "true", "TRUE", "yes", "YES"].includes(String(process.env.DEFENSECLAW_STRICT_AVAILABILITY || ""))) return false;
  return !(await defenseclawInstallLockHeld()) && defenseclawConfigOutageOpen();
}

// defenseclawConfigOutageOpen asks the per-user helper (`hook-outage-mode`,
// which only reads the config.yaml of this plugin's data directory, never one
// the agent's DEFENSECLAW_CONFIG or DEFENSECLAW_HOME names) for OpenCode's
// outage mode now. A helper that cannot run or answers anything but "open"
// keeps it closed.
function defenseclawConfigOutageOpen(installWindow) {
  try {
    const args = ["hook-outage-mode", "--connector", "opencode", "--hook-dir", dirname(DC_TOKEN_FILE)];
    if (installWindow) args.push("--install-window");
    const output = execFileSync(defenseclawPerUserNativePostBinary(), args, {
      timeout: 3000, maxBuffer: 4096, windowsHide: true, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    });
    return String(output).trim() === "open";
  } catch (_) {
    return false;
  }
}

// defenseclawPerUserOutageNotice is the one warning of a tool call that ran
// because this account's gateway is down: the cause and the fix.
async function defenseclawPerUserOutageNotice() {
  let stopped = false;
  try {
    await lstat(join(dirname(dirname(DC_TOKEN_FILE)), "gateway.stopped"));
    stopped = true;
  } catch (_) {
    // No marker: the gateway is down for another reason.
  }
  const cause = stopped
    ? "this account's gateway was stopped with `defenseclaw-gateway stop`"
    : "this account's gateway is not running";
  return "DefenseClaw is not checking this session: " + cause + ", so tool calls run unchecked (fail mode open for an outage). " +
    "Run `defenseclaw-gateway start` to resume protection. `defenseclaw-gateway status` shows its state. " +
    "If it does not start, run `defenseclaw doctor`.";
}

// defenseclawPerUserGatewayDownText is what a per-user install that fails
// closed says when its gateway gave no usable answer: why (an install or
// upgrade, a `defenseclaw-gateway stop`, a stopped, busy or failing gateway)
// and what brings it back, in the words of the native and shell hooks.
// OpenCode shows only this reason, and the runtime's network error ("fetch
// failed", "Unable to connect") named neither the gateway nor the fix
// (GAP-0850). The runtime's own error stays at the end for diagnosis.
async function defenseclawPerUserGatewayDownText(err, status) {
  const data = dirname(dirname(DC_TOKEN_FILE));
  const present = async (name) => {
    try {
      await lstat(join(data, name));
      return true;
    } catch (_) {
      return false;
    }
  };
  let text;
  if (await defenseclawInstallLockHeld()) {
    text = "DefenseClaw is being installed or upgraded for this account, and its gateway starts again when that is done (fail mode closed). " +
      "Try again in a moment; if the installer has stopped, run the installer again to finish or undo the interrupted install.";
  } else if (await present("gateway.stopped")) {
    text = "the DefenseClaw gateway was stopped with `defenseclaw-gateway stop` (fail mode closed). " +
      "Start it with `defenseclaw-gateway start`, then try again.";
  } else if (status) {
    text = "this account's DefenseClaw gateway answered HTTP " + status + " (fail mode closed); it may be starting or overloaded. " +
      "Try again in a moment.";
  } else if (defenseclawGatewayStopped(err)) {
    text = "this account's DefenseClaw gateway is not running (fail mode closed). " +
      "Start it with `defenseclaw-gateway start`, then try again.";
  } else if (err && (err.name === "AbortError" || err.name === "TimeoutError")) {
    text = "this account's DefenseClaw gateway did not answer in time (a call the gateway took and did not answer is blocked in every fail mode); it may be restarting or busy. " +
      "Try again in a moment.";
  } else {
    text = "the DefenseClaw gateway is not running or not answering (fail mode closed). " +
      "Start it with `defenseclaw-gateway start`, then try again.";
  }
  const detail = status ? "HTTP " + status : (err && err.message ? err.message : String(err));
  return "DefenseClaw blocked this tool call: " + text + " `defenseclaw-gateway status` shows its state. (" + detail + ")";
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
  // The per-user native helper exits 7 for a gateway that is not running.
  if (err && err.status === 7) return true;
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
  const warnedOutageSessions = new Set();
  // OpenCode loads plugins once at startup: a foreign plugin present now
  // keeps running for this process even if its file is deleted later, so a
  // block found at load holds for the whole process.
  let defenseclawStartupGuard = defenseclawForeignHookCheck("defenseclaw.plugin.loaded", cwd);
  let defenseclawForeignWarned = false;
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
      const callCheck = await defenseclawForeignHookCheck("tool.execute.before", cwd);
      const blocked = startup.reason || callCheck.reason;
      if (blocked) throw defenseclawBlock(client, blocked);
      const warnings = (callCheck.warnings && callCheck.warnings.length ? callCheck.warnings : startup.warnings) || [];
      if (!defenseclawForeignWarned && warnings.length) {
        defenseclawForeignWarned = true;
        void defenseclawShowNotice(client, "DefenseClaw warning: " + warnings.join("; "), "warning");
      }
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
      if (verdict && verdict.notice) await defenseclawShowNotice(client, verdict.notice);
      if (verdict && verdict.outage_notice) {
        const sessionID = String(input && (input.sessionID || input.sessionId) || "");
        if (!sessionID || !warnedOutageSessions.has(sessionID)) {
          const shown = await defenseclawShowNotice(client, verdict.outage_notice);
          if (sessionID && shown) {
            warnedOutageSessions.add(sessionID);
            if (warnedOutageSessions.size > 1024) warnedOutageSessions.delete(warnedOutageSessions.values().next().value);
          }
        }
      }
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
