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
{{if .Sandbox}}// OpenShell sandbox variant: DefenseClaw's overlay image installs this file in
// the sandbox user's ~/.config/amp/plugins (Amp has no system plugin
// location, so this is the user tamper tier). The hook ingress address and
// the fail mode are baked at image build and the plugin always fails closed.
// The only runtime input is the per-sandbox binding token, an OpenShell
// provider placeholder read from the process environment for every request;
// the supervisor swaps in the real credential only on the ingress endpoint.
// Each request carries a fresh idempotency key and is retried once on a
// transport failure or relay 502/503/504.
{{else}}// The file is rendered at setup time with a stable scoped-token sidecar path.
// It loads and validates the credential for every request, so rotation never
// leaves a replacement credential in this longer-lived plugin. It deliberately
// does not read secrets or policy from process environment variables.
{{end}}
import type { Agent, PluginAPI, ThreadMessage, ToolCallResult, ToolResultResult } from '@ampcode/plugin'
import { execFile{{if not .Sandbox}}, execFileSync{{end}} } from 'node:child_process'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
{{if not .Sandbox}}import { lstatSync, readFileSync } from 'node:fs'
{{end}}
import { lstat{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}, mkdir, open{{end}}{{if not .Sandbox}}, stat{{end}} } from 'node:fs/promises'
import { {{if not .Sandbox}}homedir, {{end}}userInfo } from 'node:os'
import { dirname{{if not .Sandbox}}, isAbsolute, join{{end}} } from 'node:path'

const DC_API_ADDR = "{{.APIAddr}}"
{{if .Sandbox}}const DC_FAIL_MODE: string = "closed" // sandbox hooks always fail closed
const DC_TIMEOUT_MS = {{.SandboxMaxTime}}000
const DC_RETRY_TIMEOUT_MS = {{.SandboxRetryMaxTime}}000
// OpenShell placeholders (openshell:resolve:env:v<revision>_<KEY>) and the
// host token alphabet; anything else is never sent.
const DC_TOKEN_PATTERN = /^[A-Za-z0-9:._-]{1,512}$/
// The standalone managed-install hook socket, foreign-hook guard and install
// marker never apply in a sandbox: the plugin always posts to the ingress.
const DC_HOOK_SOCKET: string = ""
const DC_FOREIGN_GUARD: string = ""
const DC_INSTALL_MARKER: string = ""
{{else}}const DC_TOKEN_FILE = "{{.TokenFileJS}}"
const DC_FAIL_MODE: string = "{{if and .Managed .SecureClient}}{{.FailMode}}{{else}}closed{{end}}" // per-user and standalone hooks stay closed
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
const DC_PER_USER_NATIVE_POST: string = "{{if and (not .Managed) (not .SecureClient)}}1{{end}}"
// The Windows PowerShell that checks the helper's owner and DACL: setup
// resolves the system directory with GetSystemDirectoryW, so a Windows
// installed outside C:\Windows runs its own copy.
const DC_WINDOWS_POWERSHELL: string = "{{.WindowsPowerShellJS}}"
const DC_LISTENER_PROOF_DOMAIN = "defenseclaw.listener-proof.v1"
const DC_TIMEOUT_MS = 10000
const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/
const DC_MAX_TOKEN_FILE_BYTES = 4096
{{end}}// Gateway maxBodyMiddleware accepts 1 MiB. Leave headroom for UTF-8 encoding
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

{{if not .Sandbox}}// The Kerberos principal of this login sits in a credential cache the plugin
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

{{end}}// sessionFactsHeader renders the claimed SSH and logind session facts as the
// X-DefenseClaw-Session-Facts value the hook runner also sends. Each value is
// dropped unless it matches the header's allowlisted charset.
async function sessionFactsHeader(): Promise<string> {
{{if not .Sandbox}}	const full = await fullSessionFacts()
	if (full !== "") return full
{{end}}	const env = process.env
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

{{if not .Sandbox}}type BunFileRuntime = {
	file(path: string): { slice(start?: number, end?: number): { text(): Promise<string> } }
}
{{end}}
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

{{if .Sandbox}}async function scopedHookToken(): Promise<string> {
	const token = String(process.env.DEFENSECLAW_SANDBOX_TOKEN || "")
	if (!DC_TOKEN_PATTERN.test(token)) throw new Error("missing or malformed sandbox binding token")
	return token
}

// sandboxFetch POSTs to the baked ingress: one attempt, then exactly one
// retry with the same idempotency key after a transport failure (no
// connection, reset, timeout) or a relay 502/503/504. The ingress answers a
// retried key from its dedupe window instead of evaluating the event twice.
async function sandboxFetch(headers: Record<string, string>, body: string | Uint8Array): Promise<Response> {
	const key = crypto.randomUUID()
	let last: Response | Error | undefined
	for (let attempt = 0; attempt < 2; attempt++) {
		const controller = new AbortController()
		const timer = setTimeout(() => controller.abort(), attempt === 0 ? DC_TIMEOUT_MS : DC_RETRY_TIMEOUT_MS)
		try {
			const response = await fetch(`http://${DC_API_ADDR}/api/v1/amp/hook`, {
				method: "POST",
				headers: { ...headers, "X-DefenseClaw-Hook-Idempotency-Key": key },
				body,
				signal: controller.signal,
			})
			if (attempt === 0 && [502, 503, 504].includes(response.status)) {
				last = response
				continue
			}
			return response
		} catch (error) {
			last = error instanceof Error ? error : new Error(safeError(error))
		} finally {
			clearTimeout(timer)
		}
	}
	if (last instanceof Error || last === undefined) throw last ?? new Error("sandbox ingress unreachable")
	return last
}
{{else}}function trustedSocketOwner(uid: number): boolean {
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

{{if not .Sandbox}}function perUserNativePostBinary(): string {
	const account = userInfo()
	const hookDir = dirname(DC_TOKEN_FILE)
	const record = join(hookDir, ".gateway-helper")
	const recordInfo = lstatSync(record)
	if (!recordInfo.isFile() || recordInfo.isSymbolicLink() || recordInfo.size > 4096) throw new Error("per-user gateway helper record is untrusted")
	const content = readFileSync(record, "utf8")
	if (!content.endsWith("\n") || /[\r\n\0]/.test(content.slice(0, -1))) throw new Error("per-user gateway helper record is malformed")
	const binary = content.slice(0, -1)
	const home = dirname(dirname(dirname(binary)))
	if (!isAbsolute(binary) || binary !== join(home, ".local", "bin", process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway")) throw new Error("per-user gateway helper path is untrusted")
	const paths = [dirname(hookDir), hookDir, record, home, join(home, ".local"), join(home, ".local", "bin"), binary]
	for (let index = 0; index < paths.length; index++) {
		const info = lstatSync(paths[index])
		if (info.isSymbolicLink() || ([2, 6].includes(index) ? !info.isFile() : !info.isDirectory())) throw new Error("per-user gateway helper path is untrusted")
		if (process.platform !== "win32" && (info.uid !== account.uid || (info.mode & 0o022) !== 0)) throw new Error("per-user gateway helper path is writable by another account")
	}
	if (process.platform === "win32") {
		// A data directory nested deeper in the profile has its parents up to
		// the profile checked too.
		const root = home.toLowerCase() + "\\"
		for (let dir = dirname(dirname(hookDir)); dir.toLowerCase().startsWith(root); dir = dirname(dir)) paths.push(dir)
		checkWindowsHelperACL(paths)
	}
	return binary
}

function checkWindowsHelperACL(paths: string[]): void {
	// Windows stat mode bits do not represent the DACL. Check the owner and
	// write grants before the bearer-bearing native helper is launched: the
	// owner is this account, SYSTEM, Administrators (an elevated install) or
	// TrustedInstaller, and no other principal may write the path. An
	// inherit-only entry does not apply to the path itself; its children
	// carry it. execFileSync opens the helper by this path, so every folder
	// above a checked path, up to its volume root, must not let another
	// principal rename or replace what it holds (a custom data root's
	// parent, for one): a trusted owner and no delete-child, delete,
	// change-permissions or take-ownership grant to anyone else. A volume
	// root cannot be renamed, so delete is not checked there.
	const checked = new Set(paths.map((path) => path.toLowerCase()))
	const entries: [number, string][] = paths.map((p) => [0x500D0156, p])
	for (const path of paths) {
		for (let dir = dirname(path), top = false; !top; dir = dirname(dir)) {
			top = dirname(dir) === dir
			if (checked.has(dir.toLowerCase())) continue
			checked.add(dir.toLowerCase())
			entries.push([top ? 0x100C0040 : 0x100D0040, dir])
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
	].join("\n")
	const env: Record<string, string> = {}
	for (const [name, value] of Object.entries(process.env)) {
		if (value !== undefined && !/^(psmodulepath|psmoduleanalysiscachepath|cor_|complus_)/i.test(name)) env[name] = value
	}
	env.PSModulePath = join(dirname(DC_WINDOWS_POWERSHELL), "Modules")
	let output = ""
	try {
		output = execFileSync(DC_WINDOWS_POWERSHELL, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
			input: entries.map(([mask, path]) => mask + " " + Buffer.from(path, "utf8").toString("base64")).join("\n"),
			env, timeout: 5000, windowsHide: true, encoding: "utf8", stdio: ["pipe", "pipe", "ignore"],
		})
	} catch {
		output = ""
	}
	if (output.trim() !== "checked " + entries.length) throw new Error("per-user gateway helper path has an untrusted Windows owner or DACL")
}
{{end}}// gatewayFetch posts over the verified managed hook socket when one is
// configured (Bun's unix fetch option). A per-user post goes through the
// native helper, which verifies the same connected socket it sends on.
async function gatewayFetch(path: string, init: RequestInit, token: string): Promise<Response> {
	if (!DC_HOOK_SOCKET) {
		if (DC_PER_USER_NATIVE_POST) {
			const binary = perUserNativePostBinary()
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
{{end}}
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
	const failure = error as { code?: unknown; {{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}status?: unknown; {{end}}cause?: { code?: unknown } } | null
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}	// The per-user native helper exits 7 for a gateway that is not running.
	if (failure?.status === 7) return true
{{end}}	const codes = [failure?.code, failure?.cause?.code]
	return codes.some((code) => code === "ENOENT" || code === "ECONNREFUSED" || code === "ConnectionRefused")
}

{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}// The installer holds this data-directory lock while it replaces this
// account's stopped gateway. An open outage mode cannot bypass that upgrade.
const DC_INSTALL_WINDOW_TEXT = "DefenseClaw blocked this tool call: DefenseClaw is being installed or upgraded for this account, " +
	"and its gateway starts again when that is done. Try again in a moment; if the installer has stopped, run the installer again to finish or undo the interrupted install. `defenseclaw-gateway status` shows its state."

{{end}}{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}// perUserGatewayDownText is what a per-user install that fails closed says
// when its gateway gave no usable answer: why (an install or upgrade, a
// `defenseclaw-gateway stop`, a stopped, busy or failing gateway) and what
// brings it back, in the words of the native and shell hooks, instead of the
// runtime's network error alone (GAP-0850).
// defenseclaw-call-time-outage-v1: perUserOutageOpen reports a per-user call that may run unchecked: the
// native helper exited 7 (hookexec.PerUserPostOutageExit: this account's
// gateway refused or dropped the connection before any status), the outage
// mode in the config on disk is open and no install holds the data directory.
// An answer the gateway gave, an
// unverified listener and every other error keep the call blocked. Like the
// rest of this plugin it reads no environment, so strict availability does
// not apply (the strict policy tier closes it).
async function perUserOutageOpen(error: unknown): Promise<boolean> {
	if ((error as { status?: unknown } | null)?.status !== 7) return false
	return !(await installLockHeld()) && configOutageOpen()
}

// configOutageOpen asks the per-user helper (`hook-outage-mode`, which only
// reads the config.yaml of this plugin's data directory, never one the
// agent's DEFENSECLAW_CONFIG or DEFENSECLAW_HOME names) for Amp's outage mode
// now. A helper that cannot run or answers anything but "open" keeps it closed.
function configOutageOpen(installWindow = false): boolean {
	try {
		const args = ["hook-outage-mode", "--connector", "amp", "--hook-dir", dirname(DC_TOKEN_FILE)]
		if (installWindow) args.push("--install-window")
		const output = execFileSync(perUserNativePostBinary(), args, {
			timeout: 3000, maxBuffer: 4096, windowsHide: true, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
		})
		return String(output).trim() === "open"
	} catch {
		return false
	}
}

// perUserOutageNotice is the one warning of a call that ran because this
// account's gateway is down: the cause and the fix.
async function perUserOutageNotice(): Promise<string> {
	let stopped = false
	try {
		await lstat(join(dirname(dirname(DC_TOKEN_FILE)), "gateway.stopped"))
		stopped = true
	} catch {
		// No marker: the gateway is down for another reason.
	}
	const cause = stopped
		? "this account's gateway was stopped with `defenseclaw-gateway stop`"
		: "this account's gateway is not running"
	return `DefenseClaw is not checking this session: ${cause}, so tool calls run unchecked (fail mode open for an outage). ` +
		"Run `defenseclaw-gateway start` to resume protection. `defenseclaw-gateway status` shows its state. " +
		"If it does not start, run `defenseclaw doctor`."
}

// logFailOpen appends the hook-failures.jsonl row the shell and native hooks
// write for a call that ran unchecked, in this install's data directory, so
// the gateway reports it when it is back. Best effort: a row that cannot be
// written never changes the verdict.
async function logFailOpen(reason: string, payload: Record<string, unknown>): Promise<void> {
	try {
		const dir = join(dirname(dirname(DC_TOKEN_FILE)), "logs")
		await mkdir(dir, { recursive: true, mode: 0o700 })
		const file = await open(join(dir, "hook-failures.jsonl"), "a", 0o600)
		try {
			await file.appendFile(JSON.stringify({
				ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
				connector: "amp",
				hook: "amp-plugin",
				reason,
				category: "transport",
				fail_mode: "open",
				outcome: "fail_open",
				session_id: String(payload.session_id || "").slice(0, 256),
				call_id: String(payload.source_event_id || payload.tool_call_id || randomBytes(16).toString("hex")).slice(0, 256),
			}) + "\n")
		} finally {
			await file.close()
		}
	} catch {
		// A record of a failure never fails the call.
	}
}

async function perUserGatewayDownText(error: unknown, status: number): Promise<string> {
	const data = dirname(dirname(DC_TOKEN_FILE))
	const present = async (name: string) => {
		try {
			await lstat(join(data, name))
			return true
		} catch {
			return false
		}
	}
	const failure = error as { name?: unknown } | null
	let text: string
	if (await installLockHeld()) {
		text = "DefenseClaw is being installed or upgraded for this account, and its gateway starts again when that is done (fail mode closed). " +
			"Try again in a moment; if the installer has stopped, run the installer again to finish or undo the interrupted install."
	} else if (await present("gateway.stopped")) {
		text = "the DefenseClaw gateway was stopped with `defenseclaw-gateway stop` (fail mode closed). " +
			"Start it with `defenseclaw-gateway start`, then try again."
	} else if (status) {
		text = `this account's DefenseClaw gateway answered HTTP ${status} (fail mode closed); it may be starting or overloaded. ` +
			"Try again in a moment."
	} else if (gatewayStopped(error)) {
		text = "this account's DefenseClaw gateway is not running (fail mode closed). " +
			"Start it with `defenseclaw-gateway start`, then try again."
	} else if (failure?.name === "AbortError" || failure?.name === "TimeoutError") {
		text = "this account's DefenseClaw gateway did not answer in time (fail mode closed); it may be restarting or busy. " +
			"Try again in a moment."
	} else {
		text = "the DefenseClaw gateway is not running or not answering (fail mode closed). " +
			"Start it with `defenseclaw-gateway start`, then try again."
	}
	const detail = status ? `HTTP ${status}` : safeError(error)
	return `DefenseClaw blocked this tool call: ${text} \`defenseclaw-gateway status\` shows its state. (${detail})`
}

{{end}}{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}// installLockDirs are the folders an installer of this account locks: the
// gateway's data_dir (the folder that holds the hook credential) and the
// folder install.sh and install.ps1 lock, DEFENSECLAW_HOME or else
// ~/.defenseclaw, which differ when data_dir is set apart from it (GAP-1002);
// the shell hooks check the same two (GAP-0948).
function installLockDirs(): string[] {
	return [dirname(dirname(DC_TOKEN_FILE)), String(process.env.DEFENSECLAW_HOME || "") || join(homedir(), ".defenseclaw")]
}

// An interrupted install keeps its lock on purpose, next to one of these,
// until the installer runs again and finishes or undoes it
// (hookexec.InstallLockRecoveryRecords).
const DC_INSTALL_RECOVERY_RECORDS = ["previous.new", ".repair", ".rollback-hold", ".lifecycle-txn.json"]
// install.sh and install.ps1 write the lock's pid right after they make it,
// so a lock without a pid is an installer's for this long.
const DC_INSTALL_LOCK_NO_PID_MS = 10 * 60 * 1000
// A process that started more than this after the lock's pid was written
// has a reused pid (hookexec InstallLockStartSlack).
const DC_INSTALL_LOCK_START_SLACK_MS = 60 * 1000

// installLockNumber reads the lock's pid file: "absent" (missing, empty or
// not a positive number), "valid" (with when it was written), or
// "unreadable" (not a small regular file, or a read error but its absence).
async function installLockNumber(path: string): Promise<{ state: "absent" | "valid" | "unreadable"; value: number; writtenMs: number }> {
	try {
		const info = await lstat(path)
		if (!info.isFile() || info.size > 64) return { state: "unreadable", value: 0, writtenMs: 0 }
		const text = String(readFileSync(path, "utf8")).trim()
		return /^[1-9][0-9]{0,11}$/.test(text) ? { state: "valid", value: Number(text), writtenMs: info.mtimeMs } : { state: "absent", value: 0, writtenMs: 0 }
	} catch (error) {
		return { state: (error as { code?: unknown } | null)?.code === "ENOENT" ? "absent" : "unreadable", value: 0, writtenMs: 0 }
	}
}

// processStartMs is when process pid started (Unix ms), as the system names
// it: ps etime ([[dd-]hh:]mm:ss) on Linux and macOS, the process's start time
// on Windows; null when it does not say.
function processStartMs(pid: number): number | null {
	try {
		if (process.platform === "win32") {
			// Arguments apart: the helper ACL check is the plugin's one inline PowerShell call (its repair marker).
			const startArgs = ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
				"[DateTimeOffset]::new((Get-Process -Id " + pid + " -ErrorAction Stop).StartTime).ToUnixTimeMilliseconds()"]
			const text = String(execFileSync(DC_WINDOWS_POWERSHELL, startArgs,
				{ encoding: "utf8", timeout: 10000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] })).trim()
			return /^[1-9][0-9]{0,15}$/.test(text) ? Number(text) : null
		}
		for (const ps of ["/bin/ps", "/usr/bin/ps"]) {
			let text: string
			try {
				text = String(execFileSync(ps, ["-o", "etime=", "-p", String(pid)], { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] })).trim()
			} catch {
				continue
			}
			const age = /^(?:(?:(\d{1,6})-)?(\d{1,2}):)?(\d{1,2}):(\d{1,2})$/.exec(text)
			if (!age) return null
			return Date.now() - (((Number(age[1] || 0) * 24 + Number(age[2] || 0)) * 60 + Number(age[3])) * 60 + Number(age[4])) * 1000
		}
	} catch {
		// Fall through: the system does not say.
	}
	return null
}

// installLockState is the one install-lock rule of every per-user hook
// (hookexec installLockStale, the shell hooks, the OpenCode plugin) and of
// `defenseclaw doctor` (_install_lock_state): "none" when dir has no
// .install.lock and is a folder or absent; "stale" when the lock is a folder,
// no interrupted-install record sits beside it and its installer is proven
// gone: its pid names no process, or a process that started more than a
// minute after the pid was written (a reused pid), or it has had no pid for
// ten minutes; "held" for a live install (however long it runs) or an
// uncertain one, everything else. A stale lock is no lock; `defenseclaw doctor
// --fix` or the next installer run removes it.
async function installLockState(dir: string): Promise<"none" | "stale" | "held"> {
	const missing = (error: unknown) => (error as { code?: unknown } | null)?.code === "ENOENT"
	const lock = join(dir, ".install.lock")
	let info
	try {
		info = await lstat(lock)
	} catch (error) {
		if (!missing(error)) return "held"
		try {
			// A folder that is not one cannot be looked in (Windows reports
			// its child as absent).
			if (!(await lstat(dir)).isDirectory()) return "held"
		} catch (inner) {
			if (!missing(inner)) return "held"
		}
		return "none"
	}
	if (!info.isDirectory()) return "held"
	const now = Date.now()
	for (const name of DC_INSTALL_RECOVERY_RECORDS) {
		try {
			await lstat(join(dir, name))
			return "held"
		} catch (error) {
			if (!missing(error)) return "held"
		}
	}
	const owner = await installLockNumber(join(lock, "pid"))
	if (owner.state === "unreadable") return "held"
	if (owner.state === "absent" || owner.value > 2147483647) return now - info.mtimeMs > DC_INSTALL_LOCK_NO_PID_MS ? "stale" : "held"
	if (owner.value === process.pid) return "held"
	try {
		process.kill(owner.value, 0)
	} catch (error) {
		if ((error as { code?: unknown } | null)?.code === "ESRCH") return "stale"
	}
	const started = processStartMs(owner.value)
	return started !== null && started > owner.writtenMs + DC_INSTALL_LOCK_START_SLACK_MS ? "stale" : "held"
}

// installLocks reads the lock of every folder an installer of this account
// locks: whether one is held, and whether one is stale.
async function installLocks(): Promise<{ held: boolean; stale: boolean }> {
	const states: string[] = []
	for (const dir of installLockDirs()) states.push(await installLockState(dir))
	return { held: states.includes("held"), stale: states.includes("stale") }
}

// installLockHeld reports an install that may be running: a lock that is
// not stale. Every failure and every outage stays closed under it.
async function installLockHeld(): Promise<boolean> {
	return (await installLocks()).held
}

const DC_INSTALL_WINDOW_NOTICE = "DefenseClaw is being installed or upgraded for this account. Its gateway checked this tool call, " +
	"so it runs (the default and permissive policies let checked calls run during an install; any failure blocks). `defenseclaw-gateway status` shows its state."
const DC_STALE_INSTALL_LOCK_NOTICE = "DefenseClaw found an install lock whose installer is no longer running, so it ignores it and checks tool calls as usual. " +
	"Run `defenseclaw doctor --fix` (or the installer again) to remove it."
let staleLockNoticeShown = false

// installWindow is what an install does to a call the gateway answers:
// "closed" holds it back while an installer holds this account's data
// directory and the outage mode the config gives Amp for an install window
// is not open (the strict tier, a saved closed, any doubt: hook-outage-mode
// --install-window); "open" lets the answer through with a warning (the
// default and permissive tiers, or a saved open); "stale" when only a
// stale lock is there; "none" otherwise.
async function installWindow(): Promise<"none" | "open" | "closed" | "stale"> {
	const locks = await installLocks()
	if (locks.held) return configOutageOpen(true) ? "open" : "closed"
	return locks.stale ? "stale" : "none"
}

// withInstallWindowNotice adds to a verdict that lets the call run the
// warning of an install window, or the one warning of this process about a
// stale lock.
function withInstallWindowNotice(data: GatewayResponse, lockWindow: string): GatewayResponse {
	if (data.action === "block" || data.action === "confirm" || data.outage_notice) return data
	if (lockWindow === "open") return { ...data, outage_notice: DC_INSTALL_WINDOW_NOTICE }
	if (lockWindow !== "stale" || staleLockNoticeShown) return data
	staleLockNoticeShown = true
	return { ...data, outage_notice: DC_STALE_INSTALL_LOCK_NOTICE }
}

{{end}}async function perUserInstallInProgress(): Promise<boolean> {
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}	if (DC_FAIL_MODE !== "open") return false
	return await installLockHeld()
{{else}}	return false
{{end}}}

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
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}		if (actionable && await installWindow() === "closed") return { action: "block", reason: DC_INSTALL_WINDOW_TEXT }
{{end}}		let body: string
		try {
			body = JSON.stringify(payload)
		} catch (error) {
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}			if (actionable && await installLockHeld()) return { action: "block", reason: DC_INSTALL_WINDOW_TEXT }
{{end}}			return failureResponse(`payload serialization: ${safeError(error)}`)
		}

		const originalBytes = utf8Bytes(body)
		if (originalBytes > DC_MAX_BODY_BYTES) {
			if (actionable) {
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}				if (await installLockHeld()) return { action: "block", reason: DC_INSTALL_WINDOW_TEXT }
{{end}}				return failureResponse(`payload exceeds ${DC_MAX_BODY_BYTES} bytes`)
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
			const response = await {{if .Sandbox}}sandboxFetch(headers, body){{else}}retryBusy(() => gatewayFetch("/api/v1/amp/hook", {
				method: "POST",
				headers,
				body,
				signal: controller.signal,
			}, token), controller.signal){{end}}
			if (!response.ok) {
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}				if (actionable && await installLockHeld()) return { action: "block", reason: DC_INSTALL_WINDOW_TEXT }
{{end}}{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}				if (response.status >= 500 && (DC_FAIL_MODE === "closed" || await perUserInstallInProgress())) {
					return { action: "block", reason: await perUserGatewayDownText(null, response.status) }
				}
{{end}}				return failureResponse(`HTTP ${response.status}`)
			}

			const data = gatewayJSON(await response.text()) as GatewayResponse

			if (!data || !["allow", "block", "confirm", "alert"].includes(data.action || "")) {
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}				if (actionable && await installLockHeld()) return { action: "block", reason: DC_INSTALL_WINDOW_TEXT }
{{end}}				return failureResponse("invalid gateway verdict")
			}
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}			const lockWindow = actionable ? await installWindow() : "none"
			if (lockWindow === "closed") return { action: "block", reason: DC_INSTALL_WINDOW_TEXT }
			return withInstallWindowNotice(data, lockWindow)
{{else}}			return data
{{end}}		} catch (error) {
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}			if (error && typeof error === "object" && "code" in error && error.code === "DC_PEER_UNVERIFIED") {
				return { action: "block", reason: `DefenseClaw hook failed closed (${safeError(error)})` }
			}
			if (DC_PER_USER_NATIVE_POST) {
				if (await perUserOutageOpen(error)) {
					if (actionable) await logFailOpen("gateway unreachable", payload)
					return { action: "allow", outage_notice: actionable ? await perUserOutageNotice() : "" }
				}
				if ((error as { status?: unknown } | null)?.status === 7) {
					return { action: "block", reason: await perUserGatewayDownText(error, 0) }
				}
				return { action: "block", reason: "DefenseClaw hook failed closed (per-user gateway peer unverified)" }
			}
{{else if not .Sandbox}}			if (error && typeof error === "object" && "code" in error && error.code === "DC_PEER_UNVERIFIED") {
				return { action: "block", reason: `DefenseClaw hook failed closed (${safeError(error)})` }
			}
			if (DC_PER_USER_NATIVE_POST) {
				return { action: "block", reason: "DefenseClaw hook failed closed (per-user gateway peer unverified)" }
			}
{{end}}			if (await deploymentRemoved()) return { action: "allow" }
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}			if (actionable && await installLockHeld()) return { action: "block", reason: DC_INSTALL_WINDOW_TEXT }
{{end}}			if (DC_FAIL_MODE === "closed" && (DC_HOOK_SOCKET || DC_FOREIGN_GUARD) && gatewayStopped(error)) {
				return { action: "block", reason: DC_GATEWAY_STOPPED_TEXT }
			}
{{if and (not .Sandbox) (not .Managed) (not .SecureClient)}}			if (DC_FAIL_MODE === "closed" || await perUserInstallInProgress()) {
				return { action: "block", reason: await perUserGatewayDownText(error, 0) }
			}
{{end}}			return failureResponse(safeError(error))
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

	const warnedUncheckedThreads = new Set<string>()
	async function warnUncheckedThread(
		threadID: string,
		message: string,
		ctx: { ui: { notify(message: string): Promise<void> } },
	) {
		if (!message || warnedUncheckedThreads.has(threadID)) return
		warnedUncheckedThreads.add(threadID)
		if (warnedUncheckedThreads.size > 1024) warnedUncheckedThreads.delete(warnedUncheckedThreads.values().next().value as string)
		try {
			// UI notifications reach the user without becoming a model turn.
			await ctx.ui.notify(message)
		} catch {
			// Retry on the next call if the UI was temporarily unavailable.
			warnedUncheckedThreads.delete(threadID)
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
			if (verdict.outage_notice) await warnUncheckedThread(threadID, verdict.outage_notice, ctx)
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
			if (verdict.outage_notice) await warnUncheckedThread(threadID, verdict.outage_notice, ctx)
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
