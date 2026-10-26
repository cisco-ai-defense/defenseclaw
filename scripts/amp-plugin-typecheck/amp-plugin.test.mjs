import assert from "node:assert/strict"
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import test from "node:test"
import { fileURLToPath, pathToFileURL } from "node:url"

// The plugin ships as a setup-time template; render it the way setup does
// (per-user defaults unless a test overrides a value) and load the result.
// The template also holds the OpenShell sandbox variant behind Go template
// branches; testdata/bridge_host is its host variant with the placeholders
// kept (TestBridgeHostTemplatesGolden keeps it current), which is what tsc
// checks and this test renders.
const pluginTemplate = readFileSync(
	join(dirname(fileURLToPath(import.meta.url)), "../../internal/gateway/connector/testdata/bridge_host/amp-plugin.ts"),
	"utf8",
)

async function renderAmpPlugin(values = {}) {
	const rendered = pluginTemplate
		.replaceAll("{{.APIAddr}}", values.apiAddr ?? "127.0.0.1:18970")
		.replaceAll("{{.TokenFileJS}}", values.tokenFile ?? "/nonexistent/.hook-amp.token")
		.replaceAll("{{.HookSocketJS}}", values.hookSocket ?? "")
		.replaceAll("{{.ServiceUID}}", values.serviceUID ?? "0")
		.replaceAll("{{.ForeignHookGuardJS}}", values.foreignGuard ?? "")
		.replaceAll("{{.InstallMarkerJS}}", values.installMarker ?? "")
		.replaceAll("{{.LifecycleMarkerJS}}", values.lifecycleMarker ?? "")
		.replaceAll("{{.ListenerProofJS}}", values.listenerProof ?? "")
		// config.HookOutageFailMode: "open" for a per-user install in the
		// default policy tier.
		.replaceAll("{{.OutageFailMode}}", values.outageFailMode ?? "open")
	assert.ok(!rendered.includes("{{."), "rendered plugin retains a template placeholder")
	const path = join(mkdtempSync(join(tmpdir(), "dc-amp-plugin-")), "amp-plugin.ts")
	writeFileSync(path, rendered)
	return (await import(pathToFileURL(path).href)).default
}

const defenseclawAmpPlugin = await renderAmpPlugin()

const allowEverything = `() => ({ action: "allow" })`

// A per-user plugin posts through the native gateway helper in ~/.local/bin,
// never through fetch (DC_PER_USER_NATIVE_POST). withNativeGateway points HOME
// at a new account home whose defenseclaw-gateway is a Node stand-in: it
// records each `hook-post` request it reads and answers it with respond, the
// source of a function from the hook payload to the gateway's verdict.
async function withNativeGateway(respond, run) {
	const home = mkdtempSync(join(tmpdir(), "dc-amp-home-"))
	const bin = join(home, ".local", "bin")
	mkdirSync(bin, { recursive: true, mode: 0o700 })
	const log = join(home, "requests.jsonl")
	const responder = join(home, "respond.cjs")
	writeFileSync(responder, `module.exports = ${respond}\n`)
	const helper = join(bin, process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway")
	writeFileSync(helper, [
		`#!${process.execPath}`,
		`const { appendFileSync, readFileSync } = require("node:fs")`,
		`const request = JSON.parse(readFileSync(0, "utf8"))`,
		`appendFileSync(${JSON.stringify(log)}, JSON.stringify({ args: process.argv.slice(2), ...request }) + "\\n")`,
		`const verdict = require(${JSON.stringify(responder)})(JSON.parse(request.body))`,
		`process.stdout.write(JSON.stringify({ status: 200, body: JSON.stringify(verdict) }))`,
	].join("\n") + "\n")
	chmodSync(helper, 0o755)
	const requests = () => {
		let data = ""
		try {
			data = readFileSync(log, "utf8")
		} catch {
			return []
		}
		return data.split("\n").filter(Boolean).map(line => JSON.parse(line))
	}
	const originalHome = process.env.HOME
	process.env.HOME = home
	try {
		return await run(requests)
	} finally {
		if (originalHome === undefined) delete process.env.HOME
		else process.env.HOME = originalHome
	}
}

test("posts through the native gateway helper beside the account's gateway", { skip: process.platform === "win32" }, async () => {
	const { handlers, amp, ctx } = fakeAmp("T-native")
	const originalBun = globalThis.Bun
	globalThis.Bun = { file: () => ({ slice: () => ({ text: async () => `${"a".repeat(64)}\n` }) }) }
	try {
		await withNativeGateway(allowEverything, async requests => {
			defenseclawAmpPlugin(amp)
			const result = await handlers.get("tool.call")({ thread: { id: "T-native" }, toolUseID: "TU-n", tool: "Bash", input: {} }, ctx)
			assert.equal(result.action, "allow")
			const [request] = requests()
			assert.deepEqual(request.args, ["hook-post", "--api-addr", "127.0.0.1:18970"])
			assert.equal(request.path, "/api/v1/amp/hook")
			assert.equal(JSON.parse(request.body).tool_call_id, "TU-n")
		})
	} finally {
		if (originalBun === undefined) delete globalThis.Bun
		else globalThis.Bun = originalBun
	}
})

test("refreshes agent identity when a thread changes mode between turns", { skip: process.platform === "win32" }, async () => {
	const handlers = new Map()
	let definition = { kind: "builtin-agent", mode: "medium" }
	let agentLookups = 0

	const amp = {
		system: {
			workspaceRoot: undefined,
			executor: { kind: "local" },
			user: { id: "user-1", workspace: { id: "workspace-1" } },
		},
		helpers: {
			filePathFromURI: value => value,
			isPluginUINotAvailableError: () => false,
		},
		activeThread: { current: { id: "T-identity" } },
		ui: { notify: async () => {} },
		on: (event, handler) => {
			handlers.set(event, handler)
			return { unsubscribe() {} }
		},
	}
	const ctx = {
		thread: {
			agent: async () => {
				agentLookups++
				return { definition }
			},
		},
		ui: { confirm: async () => true },
	}

	const originalBun = globalThis.Bun
	globalThis.Bun = {
		file: () => ({ slice: () => ({ text: async () => `${"a".repeat(64)}\n` }) }),
	}
	const notice = "DefenseClaw observed a HIGH amp hook finding: marker"
	const respond = `payload => payload.hook_event_name === "agent.start" && payload.turn_id === "M-turn-1"
		? { action: "allow", additional_context: ${JSON.stringify(notice)} }
		: { action: "allow" }`

	try {
		await withNativeGateway(respond, async requests => {
			defenseclawAmpPlugin(amp)

			const firstResult = await handlers.get("agent.start")(
				{ thread: { id: "T-identity" }, id: "M-turn-1", message: "first" },
				ctx,
			)
			// The hidden notice follows the prompt in Amp; it must start on its own
			// lines, apart from the prompt, so it never reads as part of a command.
			assert.equal(firstResult.message.display, false)
			assert.ok(firstResult.message.content.startsWith("\n\n"), firstResult.message.content)
			assert.ok(firstResult.message.content.endsWith(`\n${notice}`), firstResult.message.content)
			await handlers.get("tool.call")(
				{
					thread: { id: "T-identity" },
					toolUseID: "TU-1",
					tool: "Bash",
					input: { command: "printf first" },
				},
				ctx,
			)
			await handlers.get("agent.end")(
				{
					thread: { id: "T-identity" },
					id: "M-turn-1",
					message: "first",
					status: "done",
					messages: [],
				},
				ctx,
			)

			definition = {
				kind: "agent-definition",
				name: "security-reviewer",
				model: "anthropic/claude-sonnet",
				display: { label: "Security Reviewer" },
			}
			await handlers.get("agent.start")(
				{ thread: { id: "T-identity" }, id: "M-turn-2", message: "second" },
				ctx,
			)
			await handlers.get("tool.call")(
				{
					thread: { id: "T-identity" },
					toolUseID: "TU-2",
					tool: "Bash",
					input: { command: "printf second" },
				},
				ctx,
			)

			const posts = requests().map(request => JSON.parse(request.body))
			const firstStart = posts.find(
				payload => payload.hook_event_name === "agent.start" && payload.turn_id === "M-turn-1",
			)
			const firstTool = posts.find(payload => payload.tool_call_id === "TU-1")
			const secondStart = posts.find(
				payload => payload.hook_event_name === "agent.start" && payload.turn_id === "M-turn-2",
			)
			const secondTool = posts.find(payload => payload.tool_call_id === "TU-2")

			assert.equal(firstStart.agent_mode, "medium")
			assert.equal(firstStart.agent_type, "amp", "traces are named after agent_type, which must stay amp")
			assert.equal(secondStart.agent_type, "amp")
			assert.equal(firstTool.agent_mode, "medium")
			assert.equal(secondStart.agent_name, "security-reviewer")
			assert.equal(secondStart.agent_display_name, "Security Reviewer")
			assert.equal(secondStart.model, "anthropic/claude-sonnet")
			assert.equal(secondTool.agent_name, "security-reviewer")
			assert.equal(secondTool.model, "anthropic/claude-sonnet")
			assert.equal(agentLookups, 2, "agent facts should refresh once per turn and remain cached within it")
		})
	} finally {
		if (originalBun === undefined) delete globalThis.Bun
		else globalThis.Bun = originalBun
	}
})

test("fails both actionable boundaries closed when the scoped credential cannot be loaded", { skip: process.platform === "win32" }, async () => {
	const handlers = new Map()
	const amp = {
		system: { workspaceRoot: undefined, executor: { kind: "local" }, user: {} },
		helpers: {
			filePathFromURI: value => value,
			isPluginUINotAvailableError: () => false,
		},
		activeThread: { current: { id: "T-auth" } },
		ui: { notify: async () => {} },
		on: (event, handler) => {
			handlers.set(event, handler)
			return { unsubscribe() {} }
		},
	}
	const ctx = {
		thread: { agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) },
		ui: { confirm: async () => true },
	}
	const originalBun = globalThis.Bun
	let credential = "malformed-token"
	globalThis.Bun = { file: () => ({ slice: () => ({ text: async () => credential }) }) }

	try {
		await withNativeGateway(allowEverything, async requests => {
			defenseclawAmpPlugin(amp)
			const callResult = await handlers.get("tool.call")(
				{ thread: { id: "T-auth" }, toolUseID: "TU-auth", tool: "Bash", input: {} },
				ctx,
			)
			assert.equal(callResult.action, "reject-and-continue")
			assert.match(callResult.message, /credential is unavailable/)

			const resultResult = await handlers.get("tool.result")(
				{
					thread: { id: "T-auth" },
					toolUseID: "TU-auth",
					tool: "Bash",
					input: {},
					output: "result",
					status: "success",
				},
				ctx,
			)
			assert.equal(resultResult.status, "error")
			assert.match(resultResult.error, /credential is unavailable/)

			credential = "x".repeat(4097)
			const oversizedResult = await handlers.get("tool.call")(
				{ thread: { id: "T-auth" }, toolUseID: "TU-oversized", tool: "Bash", input: {} },
				ctx,
			)
			assert.equal(oversizedResult.action, "reject-and-continue")
			assert.match(oversizedResult.message, /credential is unavailable/)
			assert.equal(requests().length, 0, "credential failures must not send an unauthenticated request")
		})
	} finally {
		if (originalBun === undefined) delete globalThis.Bun
		else globalThis.Bun = originalBun
	}
})

test("reloads the scoped credential for rotation and rollback in one plugin instance", { skip: process.platform === "win32" }, async () => {
	const handlers = new Map()
	const amp = {
		system: { workspaceRoot: undefined, executor: { kind: "local" }, user: {} },
		helpers: {
			filePathFromURI: value => value,
			isPluginUINotAvailableError: () => false,
		},
		activeThread: { current: { id: "T-rotate" } },
		ui: { notify: async () => {} },
		on: (event, handler) => {
			handlers.set(event, handler)
			return { unsubscribe() {} }
		},
	}
	const ctx = {
		thread: { agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) },
		ui: { confirm: async () => true },
	}
	const aToken = "a".repeat(64)
	const bToken = "b".repeat(64)
	let token = aToken
	const originalBun = globalThis.Bun
	globalThis.Bun = { file: () => ({ slice: () => ({ text: async () => `${token}\n` }) }) }

	try {
		await withNativeGateway(allowEverything, async requests => {
			defenseclawAmpPlugin(amp)
			for (const [index, next] of [aToken, bToken, aToken].entries()) {
				token = next
				const result = await handlers.get("tool.call")(
					{ thread: { id: "T-rotate" }, toolUseID: `TU-${index}`, tool: "Bash", input: {} },
					ctx,
				)
				assert.equal(result.action, "allow")
			}
			assert.deepEqual(requests().map(request => request.headers.Authorization), [
				`Bearer ${aToken}`,
				`Bearer ${bToken}`,
				`Bearer ${aToken}`,
			])
		})
	} finally {
		if (originalBun === undefined) delete globalThis.Bun
		else globalThis.Bun = originalBun
	}
})

function fakeAmp(threadID) {
	const handlers = new Map()
	return {
		handlers,
		amp: {
			system: { workspaceRoot: "file:///work/repo", executor: { kind: "local" }, user: {} },
			helpers: {
				filePathFromURI: value => value.replace("file://", ""),
				isPluginUINotAvailableError: () => false,
			},
			activeThread: { current: { id: threadID } },
			ui: { notify: async () => {} },
			on: (event, handler) => {
				handlers.set(event, handler)
				return { unsubscribe() {} }
			},
		},
		ctx: {
			thread: { agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) },
			ui: { confirm: async () => true },
		},
	}
}

// fakeGuard writes an executable standing in for the administrator-owned
// hook binary: it answers each `hook --foreign-hook-check` call with the
// next of answers (repeating the last) and records the request it read.
function fakeGuard(answers) {
	const dir = mkdtempSync(join(tmpdir(), "dc-amp-guard-"))
	const guard = join(dir, "defenseclaw-hook")
	const script = ["#!/bin/sh", `dir='${dir}'`, 'n=$(cat "$dir/count" 2>/dev/null || echo 0)', 'echo $((n + 1)) > "$dir/count"', 'cat > "$dir/request-$n"', 'echo "$*" > "$dir/args"']
	answers.forEach((answer, index) => {
		const test = index === answers.length - 1 ? "true" : `[ "$n" -eq ${index} ]`
		script.push(`if ${test}; then printf '%s' '${answer}'; exit 0; fi`)
	})
	writeFileSync(guard, script.join("\n") + "\n")
	chmodSync(guard, 0o755)
	return { guard, dir }
}

test("a foreign-hook guard denial at load blocks every tool call of the process", { skip: process.platform === "win32" }, async () => {
	// The load check denies; later checks would allow (the plugin was deleted),
	// but the block found at load holds for the process.
	const { guard, dir } = fakeGuard(['{"deny":true,"reason":"enterprise_foreign_hook_blocked: The project file /work/repo/.amp/plugins/x.ts adds a plugin"}', '{"deny":false}'])
	const plugin = await renderAmpPlugin({ foreignGuard: guard })
	const { handlers, amp, ctx } = fakeAmp("T-guard")
	const originalBun = globalThis.Bun
	globalThis.Bun = { file: () => ({ slice: () => ({ text: async () => `${"a".repeat(64)}\n` }) }) }
	try {
		await withNativeGateway(allowEverything, async requests => {
			plugin(amp)
			for (const id of ["TU-1", "TU-2"]) {
				const result = await handlers.get("tool.call")({ thread: { id: "T-guard" }, toolUseID: id, tool: "Bash", input: {} }, ctx)
				assert.equal(result.action, "reject-and-continue")
				assert.match(result.message, /\.amp\/plugins\/x\.ts/)
			}
			assert.equal(requests().length, 0, "a guard denial must not reach the gateway")
		})
		assert.match(readFileSync(join(dir, "args"), "utf8"), /hook --connector amp --foreign-hook-check/)
		const loadRequest = JSON.parse(readFileSync(join(dir, "request-0"), "utf8"))
		assert.equal(loadRequest.cwd, "/work/repo")
		assert.equal(loadRequest.hook_event_name, "session.load")
	} finally {
		if (originalBun === undefined) delete globalThis.Bun
		else globalThis.Bun = originalBun
	}
})

test("an allowing guard lets the call through and a missing guard fails closed", { skip: process.platform === "win32" }, async () => {
	const { guard } = fakeGuard(['{"deny":false}'])
	const originalBun = globalThis.Bun
	globalThis.Bun = { file: () => ({ slice: () => ({ text: async () => `${"a".repeat(64)}\n` }) }) }
	try {
		await withNativeGateway(allowEverything, async requests => {
			const allowed = fakeAmp("T-allow")
			;(await renderAmpPlugin({ foreignGuard: guard }))(allowed.amp)
			const pass = await allowed.handlers.get("tool.call")({ thread: { id: "T-allow" }, toolUseID: "TU-a", tool: "Bash", input: {} }, allowed.ctx)
			assert.equal(pass.action, "allow")
			assert.equal(requests().length, 1)

			const missing = fakeAmp("T-missing")
			;(await renderAmpPlugin({ foreignGuard: "/nonexistent/defenseclaw-hook" }))(missing.amp)
			const blocked = await missing.handlers.get("tool.call")({ thread: { id: "T-missing" }, toolUseID: "TU-m", tool: "Bash", input: {} }, missing.ctx)
			assert.equal(blocked.action, "reject-and-continue")
			assert.match(blocked.message, /could not check for unapproved plugins/)
			assert.equal(requests().length, 1)
		})
	} finally {
		if (originalBun === undefined) delete globalThis.Bun
		else globalThis.Bun = originalBun
	}
})
