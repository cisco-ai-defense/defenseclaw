// defenseclaw-managed-plugin v2
// DefenseClaw Amp policy bridge — DO NOT EDIT.
//
// Amp loads system plugins from ~/.config/amp/plugins on macOS/Linux and
// %USERPROFILE%\.config\amp\plugins on Windows. This dependency-free plugin
// forwards all five documented lifecycle events to the authenticated local
// DefenseClaw hook endpoint. tool.call is a synchronous pre-execution policy
// boundary. tool.result can replace unsafe output before Amp sends it back to
// the model, but cannot undo tool side effects that already occurred.
// DefenseClaw may allow, reject, or ask through Amp's native confirmation UI.
// Amp does not define ordering across sibling plugin handlers.
//
// The file is rendered at setup time with a stable scoped-token sidecar path.
// It loads and validates the credential for every request, so rotation never
// leaves a replacement credential in this longer-lived plugin. It deliberately
// does not read secrets or policy from process environment variables.

import type { Agent, PluginAPI, ThreadMessage, ToolCallResult, ToolResultResult } from '@ampcode/plugin'
import { execFile, execFileSync } from 'node:child_process'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { lstatSync } from 'node:fs'

import { lstat, stat } from 'node:fs/promises'
import { homedir, userInfo } from 'node:os'
import { dirname, join } from 'node:path'

const DC_API_ADDR = "{{.APIAddr}}"
const DC_TOKEN_FILE = "{{.TokenFileJS}}"
const DC_FAIL_MODE: string = "{{.FailMode}}" // per-user and standalone hooks stay closed
// Standalone managed installs talk to the gateway's peer-authorized unix hook
// socket instead of the TCP API: the gateway identifies the caller by
// kernel-verified uid, so no bearer token leaves this process, and a user who
// binds the TCP port during a gateway restart receives nothing. Empty keeps
// the TCP transport (per-user installs).
const DC_HOOK_SOCKET: string = "{{.HookSocketJS}}"
const DC_SERVICE_UID = Number("{{.ServiceUID}}")
// Standalone managed installs also run the administrator-owned hook binary
// before each tool call: it applies the organization's foreign-hook guard
// (unapproved project or user plugins that could change a tool call after
// DefenseClaw checks it, since Amp does not order sibling handlers). Empty
// skips the check (per-user installs).
const DC_FOREIGN_GUARD: string = "{{.ForeignHookGuardJS}}"
// Windows standalone installs name an administrator-owned directory that
// exists exactly while the deployment is installed. Uninstall removes it but
// cannot remove this plugin from a signed-out user's profile, so once the
// gateway is unreachable or the credential is gone AND the marker is gone,
// the deployment was uninstalled and this plugin stops failing closed. A
// standard user cannot remove the marker. Empty keeps the fail mode.
const DC_INSTALL_MARKER: string = "{{.InstallMarkerJS}}"
// The standalone Unix lifecycle holds this public, root-owned marker while
// install, upgrade or recovery may stop the gateway.
const DC_LIFECYCLE_MARKER: string = "{{.LifecycleMarkerJS}}"
// Windows standalone installs reach the gateway over loopback TCP, where a
// local user can hold the port while the gateway restarts, and this plugin
// cannot compare the listener with the gateway service the way the hook
// binary does. "1" makes it ask the listener to prove it can derive this
// user's credential before sending that credential or any hook payload: the
// proof request carries only the credential's SHA-256 and a fresh nonce, so
// an impostor gets nothing to replay and no chance to answer with a
// verdict. Empty skips the proof (per-user installs, Secure Client, and the
// hook socket, whose owner is verified instead).
const DC_LISTENER_PROOF: string = "{{.ListenerProofJS}}"
// Per-user plugins ask the native gateway binary to verify the connected
// listener's account before each request. The proof above serves managed TCP.
const DC_PER_USER_NATIVE_POST: string = ""
const DC_LISTENER_PROOF_DOMAIN = "defenseclaw.listener-proof.v1"
const DC_TIMEOUT_MS = 10000
const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/
const DC_MAX_TOKEN_FILE_BYTES = 4096
// Gateway maxBodyMiddleware accepts 1 MiB. Leave headroom for UTF-8 encoding
// differences and future envelope fields.
const DC_MAX_BODY_BYTES = 900 * 1024

// identityHeaders reports which end user this plugin runs as.
//
// Under a managed install the gateway runs as a service account, so it cannot
// see whose session a request belongs to; the plugin is in-session and can.
// A value that is not a safe header field is dropped rather than sanitized, so
// a hostile account name cannot smuggle a second header into every hook call.
async function identityHeaders(): Promise<Record<string, string>> {
	const headers: Record<string, string> = {}
	let info: ReturnType<typeof userInfo>
	try {
		info = userInfo()
	} catch (_) {
		// No identity is a supported outcome: the record is emitted
		// unattributed rather than wrongly attributed.
		return headers
	}
	// uid is -1 on Windows, where no POSIX uid exists. Reporting it would put
	// a value in user.id that belongs to neither identifier namespace.
	if (typeof info.uid === "number" && info.uid >= 0) {
		headers["X-DefenseClaw-User-Id"] = String(info.uid)
	}
	// Mirrors the account-name allowlist the POSIX hooks apply in their
	// shared hardening helper.
	if (typeof info.username === "string" && info.username.length > 0 &&
		info.username.length <= 256 && /^[A-Za-z0-9._-]+$/.test(info.username)) {
		headers["X-DefenseClaw-User-Name"] = info.username
	}
	const facts = await sessionFactsHeader()
	if (facts !== "") {
		headers["X-DefenseClaw-Session-Facts"] = facts
	}
	return headers
}

// The Kerberos principal of this login sits in a credential cache the plugin
// cannot read (a KCM cache is a socket protocol), so a DefenseClaw binary reads
// it: `hook session-facts` prints the whole X-DefenseClaw-Session-Facts value,
// the principal included, and keeps its own five-minute cache in
// ~/.defenseclaw. A managed install runs its administrator-owned hook binary
// (DC_FOREIGN_GUARD); a per-user install runs the gateway binary the installer
// puts in ~/.local/bin. No answer is a supported outcome: the SSH and logind
// variables alone follow.
const DC_SESSION_FACTS_TTL_MS = 300000
const DC_SESSION_FACTS_RETRY_MS = 30000
let sessionFactsCache = { key: "", value: "", until: 0 }

// The modification time of this login's FILE or DIR Kerberos credential
// cache is part of the session facts key: a new kinit into the same cache
// changes the principal while every session variable stays the same
// (GAP-1139). KCM, KEYRING and API caches have no file; the variables alone
// key them. The stat runs off the event loop and gets
// DC_CREDENTIAL_CACHE_STAT_MS; calls share one stat, and one still
// unanswered after that (a stalled network or FUSE mount) reads as null: the
// call sends the session variables alone.
const DC_CREDENTIAL_CACHE_STAT_MS = 250
let credentialCacheStat: { pending: Promise<string> | null; since: number } = { pending: null, since: 0 }

async function credentialCacheStamp(): Promise<string | null> {
	const name = String(process.env.KRB5CCNAME || "")
	let path = name
	if (name === "") path = typeof process.getuid === "function" ? "/tmp/krb5cc_" + process.getuid() : ""
	else if (name.startsWith("FILE:")) path = name.slice(5)
	else if (name.startsWith("DIR::")) path = name.slice(5)
	else if (name.startsWith("DIR:")) path = name.slice(4)
	if (!path.startsWith("/")) return ""
	const now = Date.now()
	if (credentialCacheStat.pending === null) {
		const pending = stat(path).then((info) => String(info.mtimeMs), () => "")
		credentialCacheStat = { pending, since: now }
		pending.then(() => {
			if (credentialCacheStat.pending === pending) credentialCacheStat = { pending: null, since: 0 }
		})
	}
	const left = credentialCacheStat.since + DC_CREDENTIAL_CACHE_STAT_MS - now
	if (left <= 0) return null
	let timer: ReturnType<typeof setTimeout> | undefined
	const overdue = new Promise<null>((resolve) => { timer = setTimeout(resolve, left, null) })
	try {
		return await Promise.race([credentialCacheStat.pending, overdue])
	} finally {
		clearTimeout(timer)
	}
}

async function fullSessionFacts(): Promise<string> {
	const env = process.env
	const stamp = await credentialCacheStamp()
	// The binary would wait on a stalled credential cache too.
	if (stamp === null) return ""
	const key = [env.KRB5CCNAME, env.XDG_SESSION_ID, env.SSH_CONNECTION, env.SSH_TTY, stamp]
		.map((v) => String(v || "")).join("|")
	const now = Date.now()
	if (sessionFactsCache.key === key && now < sessionFactsCache.until) return sessionFactsCache.value
	let value = ""
	try {
		const binary = DC_FOREIGN_GUARD || (DC_PER_USER_NATIVE_POST
			? perUserNativePostBinary()
			: join(homedir(), ".local", "bin", process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway"))
		const out = String(execFileSync(binary, ["hook", "session-facts"], {
			timeout: 3000, maxBuffer: 4096, windowsHide: true, stdio: ["ignore", "pipe", "ignore"],
		})).trim()
		if (out.startsWith("v1;") && out.length <= 1024 && /^[A-Za-z0-9._@\/:;=-]+$/.test(out)) value = out
	} catch (_) {
		// No binary or no answer: the caller falls back to the SSH variables.
	}
	sessionFactsCache = { key, value, until: now + (value ? DC_SESSION_FACTS_TTL_MS : DC_SESSION_FACTS_RETRY_MS) }
	return value
}

// sessionFactsHeader renders the claimed SSH and logind session facts as the
// X-DefenseClaw-Session-Facts value the hook runner also sends. Each value is
// dropped unless it matches the header's allowlisted charset.
async function sessionFactsHeader(): Promise<string> {
	const full = await fullSessionFacts()
	if (full !== "") return full
	const env = process.env
	const address = String(env.SSH_CONNECTION || "").trim().split(/\s+/)[0] || ""
	const tty = String(env.SSH_TTY || "").replace(/^\/dev\//, "")
	const session = String(env.XDG_SESSION_ID || "")
	const kind = address !== "" || tty !== "" ? "ssh" : (session !== "" ? "local" : "")
	const parts = ["v1"]
	for (const [key, value] of [["k", kind], ["tty", tty], ["ls", session], ["ca", address]]) {
		if (value.length > 0 && value.length <= 256 && /^[A-Za-z0-9._@\/:-]+$/.test(value)) {
			parts.push(key + "=" + value)
		}
	}
	return parts.length > 1 ? parts.join(";") : ""
}

type GatewayResponse = {
	action?: string
	raw_action?: string
	reason?: string
	additional_context?: string
	severity?: string
	// outage_notice is the warning of a per-user call that ran because this
	// account's gateway is down (perUserOutageOpen); never from the gateway.
	outage_notice?: string
}

type TurnState = {
	turnID: string
	message: string
}

type AgentFacts = {
	agent_name: string
	agent_type: string
	agent_definition_kind?: string
	agent_display_name?: string
	agent_mode?: string
	agent_metadata_provenance?: string
	model?: string
}

type BunFileRuntime = {
	file(path: string): { slice(start?: number, end?: number): { text(): Promise<string> } }
}

function stringID(value: unknown): string {
	return value === undefined || value === null ? "" : String(value)
}

function utf8Bytes(value: string): number {
	return new TextEncoder().encode(value).byteLength
}

function safeError(error: unknown): string {
	if (error instanceof Error && error.message) return error.message
	return String(error)
}

// gatewayJSON parses a gateway answer and refuses one that repeats a key in
// any object. JSON.parse keeps the last copy, so {"action":"block",
// "action":"allow"} would read as allow; the native and shell hooks refuse
// such an answer too (GAP-1007). The caller's catch closes the call.
function gatewayJSON(text: string): unknown {
	const value = JSON.parse(text)
	const objects: Array<Set<string> | null> = []
	let keyNext = false
	for (let i = 0; i < text.length; i++) {
		const c = text[i]
		if (c === '"') {
			let end = i + 1
			while (text[end] !== '"') end += text[end] === "\\" ? 2 : 1
			const keys = objects[objects.length - 1]
			if (keyNext && keys) {
				const key = JSON.parse(text.slice(i, end + 1)) as string
				if (keys.has(key)) throw new Error("ambiguous gateway answer (repeated key)")
				keys.add(key)
			}
			keyNext = false
			i = end
		} else if (c === "{" || c === "[") {
			objects.push(c === "{" ? new Set<string>() : null)
			keyNext = c === "{"
		} else if (c === "}" || c === "]") {
			objects.pop()
			keyNext = false
		} else if (c === ",") {
			keyNext = objects[objects.length - 1] instanceof Set
		}
	}
	return value
}

function trustedSocketOwner(uid: number): boolean {
	return uid === 0 || (DC_SERVICE_UID > 0 && uid === DC_SERVICE_UID)
}

// verifyHookSocket refuses a hook socket (or its directory, or the directory's
// parent) that root or the gateway service account does not own, or that
// another account could write. Only root or the service account can create a
// socket there, so a verified path cannot be an impostor listener.
async function verifyHookSocket(): Promise<void> {
	const dir = dirname(DC_HOOK_SOCKET)
	for (const path of [dirname(dir), dir]) {
		const info = await lstat(path)
		if (!info.isDirectory() || !trustedSocketOwner(info.uid) || (info.mode & 0o022) !== 0) {
			throw new Error("the DefenseClaw hook socket directory is not trusted")
		}
	}
	const socket = await lstat(DC_HOOK_SOCKET)
	if (!socket.isSocket() || !trustedSocketOwner(socket.uid)) {
		throw new Error("the DefenseClaw hook socket is not trusted")
	}
}

function peerError(reason: string): Error & { code: string } {
	return Object.assign(new Error(reason), { code: "DC_PEER_UNVERIFIED" })
}

// The proof and the hook request must use the same accepted socket. A new
// listener can take the port between two fetch calls, so never hand a bearer
// or event to a second socket even after a valid proof response.
async function provenTCPRequest(path: string, init: RequestInit, token: string): Promise<Response> {
	if (!DC_TOKEN_PATTERN.test(token || "")) throw new Error("invalid scoped hook credential")
	const http = await import("node:http")
	const endpoint = new URL(`http://${DC_API_ADDR}`)
	const agent = new http.Agent({ keepAlive: true, maxSockets: 1, maxFreeSockets: 1 })
	let provenSocket: import("node:net").Socket | undefined
	type TCPReply = { status: number; headers: Record<string, string | string[] | undefined>; body: string }
	const send = (
		requestPath: string, method: string, headers: Record<string, string>, body?: string,
		requiredSocket?: import("node:net").Socket,
	): Promise<TCPReply> => new Promise((resolve, reject) => {
		const req = http.request({
			hostname: endpoint.hostname.replace(/^\[|\]$/g, ""), port: endpoint.port,
			path: requestPath, method, headers, agent, signal: init.signal ?? undefined,
		}, (res) => {
			const chunks: Buffer[] = []
			let length = 0
			res.on("data", (chunk: Buffer) => {
				length += chunk.length
				if (length > 1048576) {
					req.destroy(new Error("oversized DefenseClaw gateway response"))
					return
				}
				chunks.push(chunk)
			})
			res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers,
				body: Buffer.concat(chunks).toString("utf8") }))
			res.on("error", reject)
		})
		req.on("error", reject)
		req.on("socket", (socket) => {
			if (requiredSocket && socket !== requiredSocket) {
				req.destroy(peerError("the DefenseClaw gateway listener changed after proving its identity"))
				return
			}
			if (!requiredSocket) provenSocket = socket
			req.end(body)
		})
	})
	const nonce = randomBytes(32).toString("hex")
	try {
		const challenge = await send("/api/v1/hook-listener-proof", "GET", {
			"X-DefenseClaw-Connector": "amp",
			"X-DefenseClaw-Listener-Key-Id": createHash("sha256").update(token).digest("hex"),
			"X-DefenseClaw-Listener-Nonce": nonce,
		})
		const proof = String(challenge.headers["x-defenseclaw-listener-proof"] || "")
		const want = createHmac("sha256", token)
			.update(`${DC_LISTENER_PROOF_DOMAIN}\u0000amp\u0000${nonce}`)
			.digest("hex")
		if (challenge.status !== 204 || !/^[0-9a-f]{64}$/.test(proof) ||
			!timingSafeEqual(Buffer.from(proof, "hex"), Buffer.from(want, "hex"))) {
			throw peerError("the DefenseClaw gateway listener did not prove its identity")
		}
		const response = await send(path, init.method || "POST", init.headers as Record<string, string>,
			String(init.body || ""), provenSocket)
		if (response.status >= 300 && response.status < 400) {
			throw peerError("the DefenseClaw gateway redirected a proven hook request")
		}
		return {
			ok: response.status >= 200 && response.status < 300, status: response.status,
			headers: { get: (name: string) => {
				const value = response.headers[name.toLowerCase()]
				return Array.isArray(value) ? value.join(", ") : value ?? null
			} },
			text: async () => response.body,
			json: async () => JSON.parse(response.body),
		} as Response
	} finally {
		agent.destroy()
	}
}

function perUserNativePostBinary(): string {
	const account = userInfo()
	const dataDir = dirname(dirname(DC_TOKEN_FILE))
	const dataHome = dirname(dataDir)
	// The token path is baked into this plugin at setup. A custom data
	// directory uses the OS account home. Neither path follows the agent's HOME.
	const homes = dataDir === join(dataHome, ".defenseclaw") ? [dataHome, account.homedir] : [account.homedir]
	let lastError: unknown = new Error("per-user gateway helper path is missing")
	for (const home of new Set(homes)) {
		const directory = join(home, ".local", "bin")
		const binary = join(directory, process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway")
		const paths = [home, join(home, ".local"), directory, binary]
		try {
			for (let index = 0; index < paths.length; index++) {
				const info = lstatSync(paths[index])
				if (info.isSymbolicLink() || (index === paths.length - 1 ? !info.isFile() : !info.isDirectory())) {
					throw new Error("per-user gateway helper path is untrusted")
				}
				if (process.platform !== "win32" && (info.uid !== account.uid || (info.mode & 0o022) !== 0)) {
					throw new Error("per-user gateway helper path is writable by another account")
				}
			}
			return binary
		} catch (error) {
			lastError = error
		}
	}
	throw lastError
}

// perUserHookPostBinary picks the small hook-post helper the POSIX installer
// puts beside the gateway, so a hook event does not start the full gateway
// CLI; both read the same JSON request and run the same connected-peer check.
// An install without it (Windows, or an older installer's roll-forward) keeps
// the verified gateway CLI. A present but untrusted helper is refused, never
// bypassed.
function perUserHookPostBinary(): string {
	const gateway = perUserNativePostBinary()
	const helper = join(homedir(), ".local", "bin", process.platform === "win32" ? "defenseclaw-hook-post.exe" : "defenseclaw-hook-post")
	let info: ReturnType<typeof lstatSync>
	try {
		info = lstatSync(helper)
	} catch (error) {
		if (error && (error as { code?: string }).code === "ENOENT") return gateway
		throw error
	}
	if (info.isSymbolicLink() || !info.isFile()) {
		throw new Error("per-user hook helper path is untrusted")
	}
	if (process.platform !== "win32" && (info.uid !== userInfo().uid || (info.mode & 0o022) !== 0)) {
		throw new Error("per-user hook helper path is writable by another account")
	}
	return helper
}

// gatewayFetch posts over the verified managed hook socket when one is
// configured (Bun's unix fetch option). A per-user post goes through the
// native helper, which verifies the same connected socket it sends on.
async function gatewayFetch(path: string, init: RequestInit, token: string): Promise<Response> {
	if (!DC_HOOK_SOCKET) {
		if (DC_PER_USER_NATIVE_POST) {
			const binary = perUserHookPostBinary()
			const output = execFileSync(binary, ["hook-post", "--api-addr", DC_API_ADDR], {
				input: JSON.stringify({ path, headers: init.headers || {}, body: String(init.body || "") }),
				timeout: DC_TIMEOUT_MS, maxBuffer: 2 * 1024 * 1024, windowsHide: true, encoding: "utf8",
			})
			const reply = JSON.parse(output) as { status: number; body: string; retry_after?: string }
			if (!Number.isInteger(reply.status) || reply.status < 100 || reply.status > 599 || typeof reply.body !== "string") {
				throw new Error("invalid native gateway response")
			}
			return {
				ok: reply.status >= 200 && reply.status < 300,
				status: reply.status,
				headers: { get: (name: string) => name.toLowerCase() === "retry-after" ? reply.retry_after || null : null },
				text: async () => reply.body,
			} as Response
		}
		if (DC_LISTENER_PROOF) return provenTCPRequest(path, init, token)
		throw peerError("the DefenseClaw gateway listener has no account proof")
	}
	await verifyHookSocket()
	if (!(globalThis as typeof globalThis & { Bun?: unknown }).Bun) {
		throw new Error("the DefenseClaw hook socket needs the Bun runtime")
	}
	return fetch(`http://localhost${path}`, { ...init, unix: DC_HOOK_SOCKET } as RequestInit)
}

// retryBusy sends the call again while the gateway answers 429: it is taking
// all the hook calls it can, or this account is over its budget, and has not
// evaluated the call. It waits the Retry-After the gateway asks for (1 to
// 3 s) at most 3 times; the caller's abort signal keeps the whole exchange
// inside the plugin timeout. The native hook runner does the same
// (GAP-0205); without it a short burst failed the tool call (GAP-0535).
async function retryBusy(send: () => Promise<Response>, signal: AbortSignal): Promise<Response> {
	let response = await send()
	for (let retry = 0; retry < 3 && response.status === 429; retry++) {
		const asked = Number.parseInt(response.headers.get("retry-after") || "", 10)
		const delay = Math.min(Math.max(Number.isFinite(asked) ? asked : 1, 1), 3) * 1000
		await new Promise<void>((resolve, reject) => {
			if (signal.aborted) return reject(new Error("DefenseClaw gateway busy"))
			const timer = setTimeout(resolve, delay)
			signal.addEventListener("abort", () => {
				clearTimeout(timer)
				reject(new Error("DefenseClaw gateway busy"))
			}, { once: true })
		})
		response = await send()
	}
	return response
}

async function scopedHookToken(): Promise<string> {
	const runtime = (globalThis as typeof globalThis & { Bun?: BunFileRuntime }).Bun
	if (!runtime) throw new Error("scoped hook credential reader unavailable")
	const raw = await runtime.file(DC_TOKEN_FILE).slice(0, DC_MAX_TOKEN_FILE_BYTES + 1).text()
	if (utf8Bytes(raw) > DC_MAX_TOKEN_FILE_BYTES) throw new Error("oversized scoped hook credential")
	const token = raw.trim()
	if (!DC_TOKEN_PATTERN.test(token)) throw new Error("invalid scoped hook credential")
	return token
}

// agent.end includes the user prompt plus the turn transcript. Project only
// assistant text blocks onto the response-inspection rail: thinking, tool-use,
// user, and info blocks are intentionally excluded.
function assistantResponse(messages: ThreadMessage[]): string {
	const parts: string[] = []
	for (const message of messages) {
		if (message.role !== "assistant") continue
		for (const block of message.content) {
			if (block.type === "text" && block.text) parts.push(block.text)
		}
	}
	return parts.join("\n")
}

// runForeignHookCheck asks the administrator-owned hook binary for the
// foreign-hook guard's decision and resolves to a block reason, or "" when
// no unapproved plugin or hook is present. A binary that cannot be run,
// times out, or answers anything but {"deny": false} blocks, unless the
// managed deployment was uninstalled (its install marker is gone): uninstall
// removes the hook binary too, and this plugin then stops failing closed as
// it does for the gateway call.
function runForeignHookCheck(event: string, cwd: string): Promise<string> {
	if (!DC_FOREIGN_GUARD) return Promise.resolve("")
	return new Promise(resolve => {
		const fail = (why: string) => {
			void deploymentRemoved().then(removed => resolve(removed
				? ""
				: foreignCheckFailure(event, why)))
		}
		try {
			const child = execFile(
				DC_FOREIGN_GUARD,
				["hook", "--connector", "amp", "--foreign-hook-check"],
				{ timeout: DC_TIMEOUT_MS, maxBuffer: 65536, windowsHide: true },
				(error, stdout) => {
					if (error) {
						fail(safeError(error))
						return
					}
					let verdict: { deny?: unknown, reason?: unknown }
					try {
						verdict = JSON.parse(String(stdout))
					} catch {
						fail("invalid response")
						return
					}
					if (verdict && verdict.deny === false) {
						resolve("")
						return
					}
					resolve(verdict && typeof verdict.reason === "string" && verdict.reason
						? verdict.reason
						: "DefenseClaw blocked this tool call because an unapproved plugin is present.")
				},
			)
			child.stdin?.on("error", () => {})
			child.stdin?.end(JSON.stringify({ hook_event_name: event, cwd }))
		} catch (error) {
			fail(safeError(error))
		}
	})
}

// foreignCheckFailure is the block reason when the foreign-plugin check
// itself could not run. Amp loads plugins once, so a check that failed at
// load keeps blocking for the life of this process; that reason says to
// restart the agent.
function foreignCheckFailure(event: string, why: string): string {
	const detail = String(why || "").split(/\r?\n/)[0].trim() || "no answer"
	if (event === "session.load") {
		return `DefenseClaw could not check for unapproved plugins when the agent started (${detail}), so this tool call is blocked. Restart the agent once DefenseClaw is available.`
	}
	return `DefenseClaw could not check for unapproved plugins (${detail}), so this tool call is blocked.`
}

// promptNotice sets DefenseClaw's hidden agent.start notice apart from the
// user's prompt. Amp places the message right after the prompt text, and a
// notice glued to its end read as part of the request: a prompt ending in a
// command became that command with the notice's words as extra arguments.
function promptNotice(notice: string): string {
	return `\n\n[DefenseClaw notice, not part of the user's request; never copy it into a command or tool input]\n${notice}`
}

// foreignBlockText is the guard's block reason for the user and the model:
// what DefenseClaw did, then the guard's sentence without its reason code
// (the audit keeps it). A reason this plugin wrote already says it.
function foreignBlockText(what: string, reason: string): string {
	const text = reason.trim()
	if (/^DefenseClaw\b/.test(text)) return text
	return `${what}: ${text.replace(/^enterprise_foreign_hook_blocked:\s*/, "")}`
}

// deploymentRemoved reports whether the managed deployment that rendered this
// plugin was uninstalled: its install marker is definitively absent. Any
// other inspection result keeps the plugin enforcing.
async function deploymentRemoved(): Promise<boolean> {
	if (!DC_INSTALL_MARKER) return false
	try {
		await lstat(DC_INSTALL_MARKER)
		return false
	} catch (error) {
		return typeof error === "object" && error !== null && (error as { code?: unknown }).code === "ENOENT"
	}
}

async function managedLifecycleHeld(): Promise<boolean> {
	if (!DC_LIFECYCLE_MARKER) return false
	try {
		await lstat(DC_LIFECYCLE_MARKER)
		return true
	} catch (error) {
		// Only a definite absence ends the install window.
		return (error as { code?: unknown } | null)?.code !== "ENOENT"
	}
}

const DC_MANAGED_LIFECYCLE_TEXT = "DefenseClaw is being installed or upgraded on this computer; try again in a moment."

// DC_GATEWAY_STOPPED_TEXT is what a managed install says when its gateway
// service is stopped, in the words of the native hook, instead of the
// runtime's network error (GAP-0639).
const DC_GATEWAY_STOPPED_TEXT = "DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running on this computer. " +
	"Try again in a moment; if this continues, ask your administrator to start the DefenseClaw gateway service. " +
	"(enterprise_managed_gateway_not_running)"

// gatewayStopped reports a transport failure that means the gateway is not
// running: its hook socket is missing, or nothing accepts the connection
// (Node ECONNREFUSED, Bun ConnectionRefused).
function gatewayStopped(error: unknown): boolean {
	const failure = error as { code?: unknown; cause?: { code?: unknown } } | null
	const codes = [failure?.code, failure?.cause?.code]
	return codes.some((code) => code === "ENOENT" || code === "ECONNREFUSED" || code === "ConnectionRefused")
}

async function perUserInstallInProgress(): Promise<boolean> {
	return false
}

async function failureResponse(reason: string): Promise<GatewayResponse> {
	if (DC_FAIL_MODE === "closed") {
		return { action: "block", reason: `DefenseClaw hook failed closed (${reason})` }
	}
	return { action: "allow" }
}

function withheldToolResult(reason: string): ToolResultResult {
	return {
		status: "error",
		error: reason || "DefenseClaw blocked this Amp tool result.",
		output: "[DefenseClaw withheld this tool result before model delivery.]",
	}
}

function sourceEventID(event: string, threadID: string, nativeID?: unknown): string {
	return [event, threadID, stringID(nativeID)].filter(Boolean).join(":")
}

export default function defenseclawAmpPlugin(amp: PluginAPI) {
	const turns = new Map<string, TurnState>()
	const agents = new Map<string, AgentFacts>()
	const processNonce = crypto.randomUUID()
	let sourceSequence = 0
	const workspaceRoot = amp.system.workspaceRoot
		? amp.helpers.filePathFromURI(amp.system.workspaceRoot)
		: ""
	const executorKind = amp.system.executor?.kind || ""
	// Amp loads plugins once at startup: a foreign plugin present now keeps
	// running for this process even if its file is deleted later, so a block
	// found at load holds for the whole process.
	const startupGuard = runForeignHookCheck("session.load", workspaceRoot)
	const foreignHookCheck = async (event: string): Promise<string> =>
		(await managedLifecycleHeld()) ? DC_MANAGED_LIFECYCLE_TEXT :
			(await startupGuard) || (await runForeignHookCheck(event, workspaceRoot))

	async function agentFacts(threadID: string, ctx: { thread: { agent(): Promise<Agent> } }): Promise<AgentFacts> {
		const cached = agents.get(threadID)
		if (cached) return cached

		try {
			const agent = await ctx.thread.agent()
			const definition = agent.definition
			let facts: AgentFacts
			// agent_type names the agent's traces (invoke_agent <type>), so it
			// stays "amp". A custom agent definition is its own agent and keeps
			// its name; a built-in mode (smart, rush, medium) is only a setting
			// of Amp, so the agent stays "amp" and the mode goes in agent_mode.
			// Naming the agent after the mode (gen_ai.agent.name=medium) hid
			// Amp from every view grouped by agent name.
			if (definition.kind === "agent-definition") {
				const display = definition.display?.label || ""
				facts = {
					agent_name: definition.name || display || "amp",
					agent_type: "amp",
					agent_definition_kind: definition.kind,
					...(display ? { agent_display_name: display } : {}),
					agent_metadata_provenance: "reported",
					model: definition.model,
				}
			} else {
				const mode = stringID(definition.mode)
				facts = {
					agent_name: "amp",
					agent_type: "amp",
					agent_definition_kind: definition.kind,
					...(mode ? { agent_mode: mode } : {}),
					agent_metadata_provenance: "reported",
				}
			}
			agents.set(threadID, facts)
			return facts
		} catch {
			// session.start can arrive before the thread's agent handle is
			// ready. Do not cache this fallback: a later callback may resolve
			// the first-class definition and enrich the rest of the session.
			return {
				agent_name: "amp",
				agent_type: "amp",
			}
		}
	}

	async function basePayload(
		event: string,
		threadID: string,
		ctx: { thread: { agent(): Promise<Agent> } },
		nativeID?: unknown,
		includeTurn = true,
	) {
		const turn = includeTurn ? turns.get(threadID) : undefined
		sourceSequence++
		const sequence = sourceSequence
		const agent = await agentFacts(threadID, ctx)
		return {
			hook_event_name: event,
			session_id: threadID,
			thread_id: threadID,
			turn_id: turn?.turnID || "",
			message_id: turn?.turnID || "",
			source_event_id: `${sourceEventID(event, threadID, nativeID)}:${processNonce}:${sequence}`,
			source_sequence: String(sequence),
			...agent,
			executor_kind: executorKind,
			workspace_id: amp.system.user?.workspace?.id || "",
			user_id: amp.system.user?.id || "",
			cwd: workspaceRoot,
		}
	}

	async function post(payload: Record<string, unknown>, actionable: boolean): Promise<GatewayResponse> {
		if (actionable && await managedLifecycleHeld()) return { action: "block", reason: DC_MANAGED_LIFECYCLE_TEXT }
		let body: string
		try {
			body = JSON.stringify(payload)
		} catch (error) {
			return failureResponse(`payload serialization: ${safeError(error)}`)
		}

		const originalBytes = utf8Bytes(body)
		if (originalBytes > DC_MAX_BODY_BYTES) {
			if (actionable) {
				return failureResponse(`payload exceeds ${DC_MAX_BODY_BYTES} bytes`)
			}
			const reduced = {
				hook_event_name: payload.hook_event_name || "",
				session_id: payload.session_id || "",
				thread_id: payload.thread_id || "",
				turn_id: payload.turn_id || "",
				message_id: payload.message_id || "",
				source_event_id: payload.source_event_id || "",
				source_sequence: payload.source_sequence || "",
				agent_name: payload.agent_name || "amp",
				agent_type: payload.agent_type || "amp",
				agent_definition_kind: payload.agent_definition_kind || "",
				agent_display_name: payload.agent_display_name || "",
				agent_mode: payload.agent_mode || "",
				agent_metadata_provenance: payload.agent_metadata_provenance || "",
				model: payload.model || "",
				executor_kind: payload.executor_kind || "",
				workspace_id: payload.workspace_id || "",
				user_id: payload.user_id || "",
				cwd: payload.cwd || "",
				tool_call_id: payload.tool_call_id || "",
				tool_name: payload.tool_name || "",
				status: payload.status || "",
				content_truncated: true,
				original_body_bytes: originalBytes,
				tool_response: "[DefenseClaw payload omitted: size limit exceeded]",
			}
			body = JSON.stringify(reduced)
		}

		let token: string
		try {
			token = DC_HOOK_SOCKET ? "" : await scopedHookToken()
		} catch {
			// Credential failures are categorically unsafe at the two Amp policy
			// boundaries, regardless of the operator's transport fail mode,
			// unless the managed deployment itself was uninstalled.
			if (await deploymentRemoved()) return { action: "allow" }
			if (actionable) {
				return { action: "block", reason: "DefenseClaw hook credential is unavailable." }
			}
			return { action: "allow" }
		}

		const controller = new AbortController()
		const timer = setTimeout(() => controller.abort(), DC_TIMEOUT_MS)
		const headers: Record<string, string> = {
			"Content-Type": "application/json",
			"X-DefenseClaw-Client": "amp-plugin/1.0",
			...(await identityHeaders()),
		}
		if (token) headers.Authorization = `Bearer ${token}`

		try {
			const response = await retryBusy(() => gatewayFetch("/api/v1/amp/hook", {
				method: "POST",
				headers,
				body,
				signal: controller.signal,
			}, token), controller.signal)
			if (!response.ok) {
				return failureResponse(`HTTP ${response.status}`)
			}

			const data = gatewayJSON(await response.text()) as GatewayResponse
			if (actionable && await managedLifecycleHeld()) return { action: "block", reason: DC_MANAGED_LIFECYCLE_TEXT }

			if (!data || !["allow", "block", "confirm", "alert"].includes(data.action || "")) {
				return failureResponse("invalid gateway verdict")
			}
			return data
		} catch (error) {
			if (error && typeof error === "object" && "code" in error && error.code === "DC_PEER_UNVERIFIED") {
				return { action: "block", reason: `DefenseClaw hook failed closed (${safeError(error)})` }
			}
			if (DC_PER_USER_NATIVE_POST) {
				return { action: "block", reason: "DefenseClaw hook failed closed (per-user gateway peer unverified)" }
			}
			if (await deploymentRemoved()) return { action: "allow" }
			if (DC_FAIL_MODE === "closed" && (DC_HOOK_SOCKET || DC_FOREIGN_GUARD) && gatewayStopped(error)) {
				return { action: "block", reason: DC_GATEWAY_STOPPED_TEXT }
			}
			return failureResponse(safeError(error))
		} finally {
			clearTimeout(timer)
		}
	}

	async function notifyIfForeground(threadID: string, message: string) {
		if (!message || amp.activeThread.current?.id !== threadID) return
		try {
			await amp.ui.notify(message)
		} catch {
			// Alert delivery is observe-only and must never change the verdict.
		}
	}

	amp.on("session.start", async (event, ctx) => {
		const threadID = stringID(event.thread.id)
		// SessionStartEvent reports only thread.id. Amp may emit it again when
		// switching to an existing thread, including while a turn is cached;
		// never misattribute that cached turn/message as source-reported here.
		await post(await basePayload("session.start", threadID, ctx, "start", false), false)
	})

	amp.on("agent.start", async (event, ctx) => {
		// Amp does not define tool.call handler order. A project plugin can
		// rewrite a call before this plugin sees it, so cancel the turn at
		// agent.start when the standalone guard finds an unapproved plugin.
		// Amp guarantees that cancel during this event prevents the turn from
		// starting; the guard applies the usual allowed_hooks digests.
		if (DC_FOREIGN_GUARD && DC_HOOK_SOCKET) {
			const blocked = await foreignHookCheck("agent.start")
			if (blocked) {
				await ctx.thread.cancel()
				const notice = foreignBlockText("DefenseClaw stopped this turn", blocked)
				try {
					await ctx.ui.notify(notice)
				} catch {
					// Cancellation is the policy action; notice is best effort.
				}
				// The notice fades after a few seconds; the message stays in
				// the thread with the prompt.
				return { message: { content: notice, display: true } }
			}
		}
		const threadID = stringID(event.thread.id)
		const turnID = stringID(event.id)
		turns.set(threadID, { turnID, message: event.message })
		// thread.agent() reports the agent currently selected for this turn.
		// Amp allows users to change built-in modes or custom-agent definitions
		// between turns on the same thread, so a session-lifetime cache would
		// attribute later Agent360/Galileo events to the previous mode/model.
		agents.delete(threadID)
		const verdict = await post({
			...await basePayload("agent.start", threadID, ctx, event.id),
			turn_id: turnID,
			message_id: turnID,
			prompt: event.message,
		}, false)
		if (verdict.additional_context) {
			return { message: { content: promptNotice(verdict.additional_context), display: false } }
		}
		return {}
	})

	amp.on("tool.call", async (event, ctx): Promise<ToolCallResult> => {
		const blocked = await foreignHookCheck("tool.call")
		if (blocked) return { action: "reject-and-continue", message: foreignBlockText("DefenseClaw blocked this tool call", blocked) }
		const threadID = stringID(event.thread.id)
		const toolUseID = stringID(event.toolUseID)
		const verdict = await post({
			...await basePayload("tool.call", threadID, ctx, event.toolUseID),
			tool_call_id: toolUseID,
			tool_name: event.tool,
			tool_input: event.input,
			delegation_boundary: /(?:^|[._:-])(oracle|task|subagent)(?:$|[._:-])/i.test(event.tool),
		}, true)

		switch (verdict.action) {
		case "block":
			return {
				action: "reject-and-continue",
				message: verdict.reason || "DefenseClaw blocked this Amp tool call.",
			}
		case "confirm": {
			const reason = verdict.reason || "DefenseClaw requires approval for this Amp tool call."
			if (amp.activeThread.current?.id !== event.thread.id) {
				return {
					action: "reject-and-continue",
					message: `${reason} Approval is unavailable for a background thread.`,
				}
			}
			try {
				const approved = await ctx.ui.confirm({
					title: `Allow ${event.tool}?`,
					message: reason,
					confirmButtonText: "Allow",
				})
				if (approved) return { action: "allow" }
				return { action: "reject-and-continue", message: "User denied the DefenseClaw approval request." }
			} catch (error) {
				const uiError = error instanceof Error ? error : new Error(safeError(error))
				const unavailable = amp.helpers.isPluginUINotAvailableError(uiError)
					? "Amp confirmation UI is unavailable."
					: `Amp confirmation failed: ${safeError(uiError)}`
				return { action: "reject-and-continue", message: `${reason} ${unavailable}` }
			}
		}
		case "alert":
			await notifyIfForeground(threadID, verdict.additional_context || verdict.reason || "DefenseClaw flagged this tool call.")
			return { action: "allow" }
		default:
			if (verdict.outage_notice) await notifyIfForeground(threadID, verdict.outage_notice)
			return { action: "allow" }
		}
	})

	amp.on("tool.result", async (event, ctx): Promise<ToolResultResult> => {
		const threadID = stringID(event.thread.id)
		const verdict = await post({
			...await basePayload("tool.result", threadID, ctx, event.toolUseID),
			tool_call_id: stringID(event.toolUseID),
			tool_name: event.tool,
			tool_input: event.input,
			tool_response: event.output,
			status: event.status,
			error: event.error || "",
		}, true)

		switch (verdict.action) {
		case "block":
			return withheldToolResult(verdict.reason || "DefenseClaw blocked this Amp tool result.")
		case "confirm": {
			const reason = verdict.reason || "DefenseClaw requires approval before this tool result reaches the model."
			if (amp.activeThread.current?.id !== event.thread.id) {
				return withheldToolResult(`${reason} Approval is unavailable for a background thread.`)
			}
			try {
				const approved = await ctx.ui.confirm({
					title: `Share ${event.tool} result with the model?`,
					message: reason,
					confirmButtonText: "Share result",
				})
				if (approved) return
				return withheldToolResult("User denied the DefenseClaw tool-result approval request.")
			} catch (error) {
				const uiError = error instanceof Error ? error : new Error(safeError(error))
				const unavailable = amp.helpers.isPluginUINotAvailableError(uiError)
					? "Amp confirmation UI is unavailable."
					: `Amp confirmation failed: ${safeError(uiError)}`
				return withheldToolResult(`${reason} ${unavailable}`)
			}
		}
		case "alert":
			await notifyIfForeground(
				threadID,
				verdict.additional_context || verdict.reason || "DefenseClaw flagged this tool result.",
			)
			return
		default:
			// A result kept because this account's gateway is down carries the
			// same one warning as the call. Returning void preserves Amp's
			// original status and output.
			if (verdict.outage_notice) await notifyIfForeground(threadID, verdict.outage_notice)
			return
		}
	})

	amp.on("agent.end", async (event, ctx) => {
		const threadID = stringID(event.thread.id)
		const turnID = stringID(event.id)
		const response = assistantResponse(event.messages)
		await post({
			...await basePayload("agent.end", threadID, ctx, event.id),
			turn_id: turnID,
			message_id: turnID,
			tool_name: "message",
			tool_response: response,
			response,
			status: event.status,
		}, false)
		turns.delete(threadID)
		agents.delete(threadID)
	})
}
