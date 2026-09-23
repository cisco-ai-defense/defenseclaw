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
// the flattened text as a user message, and the invocation as an assistant
// tool call whose arguments are a JSON string. Changing the encoding takes a
// new version here, which the manifest parity test then requires.
const AIDWireVersionChatToolCalls = "chat-tool-calls-v1"

// aidPromptSurfaceEvents and aidToolResultSurfaceEvents are the canonical
// spellings each surface accepts, mirroring the runtime classification in
// isPromptLikeEvent / isResultLikeEvent. TestAgentHookAIDSurfaceEventsMatchRuntime
// fails if the two ever disagree.
var aidPromptSurfaceEvents = map[string]bool{
	"userpromptsubmit": true, "userpromptsubmitted": true, "userprompttransformed": true,
	"beforesubmitprompt": true, "preuserprompt": true, "subagentstart": true,
	"prellmcall": true, "beforeagent": true, "beforemodel": true, "agentstart": true,
}

var aidToolResultSurfaceEvents = map[string]bool{
	"posttooluse": true, "posttoolusefailure": true, "permissiondenied": true,
	"aftertool": true, "posttoolcall": true, "postreadcode": true, "postwritecode": true,
	"postruncommand": true, "postmcptooluse": true, "aftershellexecution": true,
	"aftermcpexecution": true, "afterfileedit": true, "aftertabfileedit": true,
	"afteragentresponse": true, "afteragentthought": true, "afteragent": true,
	"aftermodel": true, "postllmcall": true, "postcascaderesponse": true,
	"postcascaderesponsewithtranscript": true, "toolexecuteafter": true,
	"toolresult": true, "agentend": true,
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

func init() {
	for _, contracts := range builtinHookContracts {
		for i := range contracts {
			if contracts[i].AIDSurfaceEvents == nil {
				contracts[i].AIDSurfaceEvents = aidSurfaceEventsFor(contracts[i])
			}
			if contracts[i].AIDWireVersion == "" && len(contracts[i].AIDSurfaces) > 0 {
				contracts[i].AIDWireVersion = AIDWireVersionChatToolCalls
			}
		}
	}
}
