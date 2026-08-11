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

const DC_API_ADDR = "{{.APIAddr}}"
const DC_TOKEN_FILE = "{{.TokenFileJS}}"
const DC_FAIL_MODE: string = "{{.FailMode}}" // "open" or "closed"
const DC_TIMEOUT_MS = 10000
const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/
const DC_MAX_TOKEN_FILE_BYTES = 4096
// Gateway maxBodyMiddleware accepts 1 MiB. Leave headroom for UTF-8 encoding
// differences and future envelope fields.
const DC_MAX_BODY_BYTES = 900 * 1024

type GatewayResponse = {
	action?: string
	raw_action?: string
	reason?: string
	additional_context?: string
	severity?: string
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

function failureResponse(reason: string): GatewayResponse {
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

	async function agentFacts(threadID: string, ctx: { thread: { agent(): Promise<Agent> } }): Promise<AgentFacts> {
		const cached = agents.get(threadID)
		if (cached) return cached

		try {
			const agent = await ctx.thread.agent()
			const definition = agent.definition
			let facts: AgentFacts
			if (definition.kind === "agent-definition") {
				const display = definition.display?.label || ""
				facts = {
					agent_name: definition.name || display || "amp",
					agent_type: definition.kind,
					agent_definition_kind: definition.kind,
					...(display ? { agent_display_name: display } : {}),
					agent_metadata_provenance: "reported",
					model: definition.model,
				}
			} else {
				const mode = stringID(definition.mode)
				facts = {
					agent_name: mode || "amp",
					agent_type: mode || definition.kind,
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
		let body: string
		try {
			body = JSON.stringify(payload)
		} catch (error) {
			return failureResponse(`payload serialization: ${safeError(error)}`)
		}

		const originalBytes = utf8Bytes(body)
		if (originalBytes > DC_MAX_BODY_BYTES) {
			if (actionable) return failureResponse(`payload exceeds ${DC_MAX_BODY_BYTES} bytes`)
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
			token = await scopedHookToken()
		} catch {
			// Credential failures are categorically unsafe at the two Amp policy
			// boundaries, regardless of the operator's transport fail mode.
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
		}
		headers.Authorization = `Bearer ${token}`

		try {
			const response = await fetch(`http://${DC_API_ADDR}/api/v1/amp/hook`, {
				method: "POST",
				headers,
				body,
				signal: controller.signal,
			})
			if (!response.ok) return failureResponse(`HTTP ${response.status}`)

			const data = await response.json() as GatewayResponse
			if (!data || !["allow", "block", "confirm", "alert"].includes(data.action || "")) {
				return failureResponse("invalid gateway verdict")
			}
			return data
		} catch (error) {
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
			return { message: { content: verdict.additional_context, display: false } }
		}
		return {}
	})

	amp.on("tool.call", async (event, ctx): Promise<ToolCallResult> => {
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
			// Returning void preserves Amp's original status and output.
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
