import assert from "node:assert/strict"
import test from "node:test"

import defenseclawAmpPlugin from "../../internal/gateway/connector/hooks/amp-plugin.ts"

test("refreshes agent identity when a thread changes mode between turns", async () => {
	const handlers = new Map()
	const posts = []
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

	const originalFetch = globalThis.fetch
	globalThis.fetch = async (_url, init) => {
		posts.push(JSON.parse(init.body))
		return {
			ok: true,
			json: async () => ({ action: "allow" }),
		}
	}

	try {
		defenseclawAmpPlugin(amp)

		await handlers.get("agent.start")(
			{ thread: { id: "T-identity" }, id: "M-turn-1", message: "first" },
			ctx,
		)
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

		const firstStart = posts.find(
			payload => payload.hook_event_name === "agent.start" && payload.turn_id === "M-turn-1",
		)
		const firstTool = posts.find(payload => payload.tool_call_id === "TU-1")
		const secondStart = posts.find(
			payload => payload.hook_event_name === "agent.start" && payload.turn_id === "M-turn-2",
		)
		const secondTool = posts.find(payload => payload.tool_call_id === "TU-2")

		assert.equal(firstStart.agent_mode, "medium")
		assert.equal(firstTool.agent_mode, "medium")
		assert.equal(secondStart.agent_name, "security-reviewer")
		assert.equal(secondStart.agent_display_name, "Security Reviewer")
		assert.equal(secondStart.model, "anthropic/claude-sonnet")
		assert.equal(secondTool.agent_name, "security-reviewer")
		assert.equal(secondTool.model, "anthropic/claude-sonnet")
		assert.equal(agentLookups, 2, "agent facts should refresh once per turn and remain cached within it")
	} finally {
		globalThis.fetch = originalFetch
	}
})
