// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// AID surface names used by HookContract.AIDSurfaces.
const (
	AIDSurfacePrompt       = "prompt"
	AIDSurfaceToolCall     = "tool_call"
	AIDSurfaceToolResult   = "tool_result"
	AIDSurfaceEventContent = "event_content"
)

// AIDWireVersionChatToolCalls names the encoding a hook surface is sent in:
// the flattened text as a user message, the same one sent before tool calls
// were carried, and for a tool invocation an assistant tool call whose
// arguments are a JSON string, placed ahead of that text so the text stays the
// last message. Changing the encoding takes a new version here, which the
// manifest parity test then requires.
const AIDWireVersionChatToolCalls = "chat-tool-calls-v1"

// aidPromptSurfaceEvents and aidToolResultSurfaceEvents are the canonical
// spellings each surface accepts, copied from the runtime classification in
// isPromptLikeEvent / isResultLikeEvent on this branch. Every spelling those
// switches accept is listed here and nothing else, which
// TestAIDSurfaceEventListsMatchRuntime checks against the runtime.
var aidPromptSurfaceEvents = map[string]bool{
	"userpromptsubmit": true, "userpromptsubmitted": true,
	"beforesubmitprompt": true, "preuserprompt": true, "subagentstart": true,
	"prellmcall": true, "beforeagent": true, "beforemodel": true, "agentstart": true,
	"preinvocation": true,
}

var aidToolResultSurfaceEvents = map[string]bool{
	"posttooluse": true, "posttoolusefailure": true, "permissiondenied": true,
	"aftertool": true, "posttoolcall": true, "postreadcode": true, "postwritecode": true,
	"postruncommand": true, "postmcptooluse": true, "aftershellexecution": true,
	"aftermcpexecution": true, "afterfileedit": true, "aftertabfileedit": true,
	"afteragentresponse": true, "afteragentthought": true, "afteragent": true,
	"aftermodel": true, "postllmcall": true, "postcascaderesponse": true,
	"postcascaderesponsewithtranscript": true, "toolexecuteafter": true,
	"toolresult": true, "agentend": true, "postinvocation": true,
}

// AIDSurfaceEventSpellings returns the canonical spellings the registry
// assigns to the prompt or tool_result surface, for the test that holds them
// to the runtime classification. Nil for any other surface.
func AIDSurfaceEventSpellings(surface string) []string {
	var set map[string]bool
	switch surface {
	case AIDSurfacePrompt:
		set = aidPromptSurfaceEvents
	case AIDSurfaceToolResult:
		set = aidToolResultSurfaceEvents
	default:
		return nil
	}
	out := make([]string, 0, len(set))
	for spelling := range set {
		out = append(out, spelling)
	}
	return out
}

// aidSurfaceEventsFor names the contract's own events per AID surface, taken
// from what the contract already declares: the tool-call lifecycle routing for
// tool_call, and the canonical spellings above for the others. A surface the
// contract does not list is absent. event_content stays kind-level: it has no
// event set of its own, it is whatever content a connector-specific decoder
// projects.
func aidSurfaceEventsFor(contract HookContract) map[string][]string {
	declared := make(map[string]bool, len(contract.AIDSurfaces))
	for _, surface := range contract.AIDSurfaces {
		declared[surface] = true
	}

	events := make(map[string][]string)
	if declared[AIDSurfaceToolCall] {
		if routed := intersectEvents(
			contract.Routing().StructuredActionEvents, contract.Events,
		); len(routed) > 0 {
			events[AIDSurfaceToolCall] = routed
		}
	}
	if declared[AIDSurfacePrompt] {
		if matched := filterEvents(contract.Events, aidPromptSurfaceEvents); len(matched) > 0 {
			events[AIDSurfacePrompt] = matched
		}
	}
	if declared[AIDSurfaceToolResult] {
		if matched := filterEvents(contract.Events, aidToolResultSurfaceEvents); len(matched) > 0 {
			events[AIDSurfaceToolResult] = matched
		}
	}
	if len(events) == 0 {
		return nil
	}
	return events
}

// Routing returns the contract's tool-event routing.
func (contract HookContract) Routing() ToolEventRouting {
	return contract.ToolCallLifecycle.Routing
}

func copyAIDSurfaceEvents(events map[string][]string) map[string][]string {
	if events == nil {
		return nil
	}
	out := make(map[string][]string, len(events))
	for surface, names := range events {
		out[surface] = append([]string(nil), names...)
	}
	return out
}

func filterEvents(events []string, canonical map[string]bool) []string {
	var out []string
	for _, event := range events {
		if canonical[canonicalHookEvent(event)] {
			out = append(out, event)
		}
	}
	return out
}

// intersectEvents keeps the routed order and drops anything the contract does
// not also declare as an event it receives.
func intersectEvents(routed, events []string) []string {
	known := make(map[string]bool, len(events))
	for _, event := range events {
		known[canonicalHookEvent(event)] = true
	}
	var out []string
	for _, event := range routed {
		if known[canonicalHookEvent(event)] {
			out = append(out, event)
		}
	}
	return out
}

// AIDToolCallShape declares how one of a contract's tools reaches AID as a tool
// call: the vendor's tool name as function.name, the canonical surface it acts
// on, and the argument key that holds the command for a shell tool. A cloud
// rule reads function.name and the arguments as the vendor sends them; this is
// the registry's record of those names, so a vendor renaming a tool or a
// command key fails the golden test instead of reaching AID unnoticed.
type AIDToolCallShape struct {
	Tool       string      `json:"tool"`
	Surface    ToolSurface `json:"surface"`
	CommandArg string      `json:"command_arg,omitempty"`
}

// aidToolCallShapesByContract lists, per contract, the tools the committed
// golden payloads (scripts/live-connector-e2e/golden) show reaching AID as a
// tool call. Every shell tool sends its command as "command" after decoding.
// antigravity-hooks-v2 has none: its golden's tool name does not survive the
// decoder, and a call without a name goes to AID as text alone.
var aidToolCallShapesByContract = map[string][]AIDToolCallShape{
	"claudecode-hooks-v1": {{Tool: "Bash", Surface: ToolSurfaceShell, CommandArg: "command"}},
	"codex-hooks-v4":      {{Tool: "shell", Surface: ToolSurfaceShell, CommandArg: "command"}},
	"cursor-hooks-v1":     {{Tool: "run_terminal_cmd", Surface: ToolSurfaceShell, CommandArg: "command"}},
	"amp-plugin-v1":       {{Tool: "shell", Surface: ToolSurfaceShell, CommandArg: "command"}},
	"hermes-hooks-v1":     {{Tool: "execute_command", Surface: ToolSurfaceShell, CommandArg: "command"}},
	"openhands-hooks-v1":  {{Tool: "terminal", Surface: ToolSurfaceShell, CommandArg: "command"}},
	"copilot-hooks-v1":    {{Tool: "shell", Surface: ToolSurfaceShell, CommandArg: "command"}},
	"geminicli-hooks-v1":  {{Tool: "RunShellCommand", Surface: ToolSurfaceShell, CommandArg: "command"}},
	"windsurf-hooks-v1":   {{Tool: "run_command", Surface: ToolSurfaceShell, CommandArg: "command"}},
}

// AIDToolCallShapeFor returns the declared shape of one of the contract's
// tools, matched on the exact vendor name.
func (contract HookContract) AIDToolCallShapeFor(tool string) (AIDToolCallShape, bool) {
	for _, shape := range contract.AIDToolCallShapes {
		if shape.Tool == tool {
			return shape, true
		}
	}
	return AIDToolCallShape{}, false
}

// fillAIDDeclaration derives a contract's AID events and wire version from what
// it already declares. A contract with no AID surface gets neither, so the
// send path treats it as undeclared.
func fillAIDDeclaration(contract *HookContract) {
	if contract.AIDSurfaceEvents == nil {
		contract.AIDSurfaceEvents = aidSurfaceEventsFor(*contract)
	}
	if contract.AIDWireVersion == "" && len(contract.AIDSurfaces) > 0 {
		contract.AIDWireVersion = AIDWireVersionChatToolCalls
	}
	if contract.AIDToolCallShapes == nil {
		contract.AIDToolCallShapes = append([]AIDToolCallShape(nil), aidToolCallShapesByContract[contract.ContractID]...)
	}
}

func init() {
	for _, contracts := range builtinHookContracts {
		for i := range contracts {
			fillAIDDeclaration(&contracts[i])
		}
	}
}
