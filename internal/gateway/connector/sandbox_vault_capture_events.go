// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "strings"

// VaultCapturePoint says where in an agent's turn a sandbox hook event
// sits, for the sandbox vault's auto-capture: whether a secret the event
// carries has reached the model, and what the event can answer.
type VaultCapturePoint uint8

const (
	// VaultCaptureOther is an event capture gives no place (a session or
	// lifecycle event, a notification): a secret in it is stored exposed
	// and alerted, and the call is not stopped.
	VaultCaptureOther VaultCapturePoint = iota
	// VaultCapturePrompt is the person's prompt at an event that stops it
	// before the model reads it: the only point a captured secret is not
	// exposed.
	VaultCapturePrompt
	// VaultCapturePromptSeen is the person's prompt at an event that
	// cannot stop it, or is not known to: the model may read it.
	VaultCapturePromptSeen
	// VaultCaptureToolCall is a tool call's input, before the tool runs:
	// the model wrote it.
	VaultCaptureToolCall
	// VaultCaptureToolOutput is a tool's output, which the model reads.
	VaultCaptureToolOutput
	// VaultCaptureReply is the model's own output.
	VaultCaptureReply
)

// VaultCaptureEvent is how capture treats one hook event of a sandbox
// harness.
type VaultCaptureEvent struct {
	Point VaultCapturePoint
	// Stop: the call is answered block, the strongest answer the event
	// has (a prompt or tool call is stopped, a Claude Code or Codex
	// PostToolUse hands the model the reason, a prompt event that cannot
	// stop tells the agent not to carry it out). Otherwise it is answered
	// alert: the event cannot stop anything, or a block would restart the
	// agent's turn (Stop).
	Stop bool
}

// Exposed reports whether a secret captured at the event is marked
// exposed: every point but a prompt the hook stops.
func (e VaultCaptureEvent) Exposed() bool { return e.Point != VaultCapturePrompt }

// FromModel reports whether a secret at the event is one the agent's model
// wrote or read (a tool call, a tool's output, a reply, another event), not
// the person's prompt: a new entry counts toward the vault's model-side
// bound, so model-side values never use up the room prompts need.
func (e VaultCaptureEvent) FromModel() bool {
	return e.Point != VaultCapturePrompt && e.Point != VaultCapturePromptSeen
}

// Stores reports whether a secret the vault does not hold yet is stored at
// the event: a prompt, a tool call, or a tool's output (a key the agent
// assembled as a tool ran is first seen there). At a reply or another
// event the value is only removed from the body, and a value the vault
// already holds is marked exposed.
func (e VaultCaptureEvent) Stores() bool {
	switch e.Point {
	case VaultCapturePrompt, VaultCapturePromptSeen, VaultCaptureToolCall, VaultCaptureToolOutput:
		return true
	}
	return false
}

// Where names the point for a person: "prompt", "tool call", ...
func (e VaultCaptureEvent) Where() string {
	switch e.Point {
	case VaultCapturePrompt, VaultCapturePromptSeen:
		return "prompt"
	case VaultCaptureToolCall:
		return "tool call"
	case VaultCaptureToolOutput:
		return "tool output"
	case VaultCaptureReply:
		return "reply"
	}
	return "hook event"
}

var (
	vcPrompt     = VaultCaptureEvent{VaultCapturePrompt, true}
	vcPromptSeen = VaultCaptureEvent{VaultCapturePromptSeen, true}
	vcToolCall   = VaultCaptureEvent{VaultCaptureToolCall, true}
	vcOutputStop = VaultCaptureEvent{VaultCaptureToolOutput, true}
	vcOutput     = VaultCaptureEvent{VaultCaptureToolOutput, false}
	vcReply      = VaultCaptureEvent{VaultCaptureReply, false}
)

// sandboxVaultCaptureEvents maps each sandbox harness's hook events, as
// the gateway names them, to their capture point. A harness's other events
// are VaultCaptureOther: capture reads every event of a sandbox harness, so
// a secret in any hook body is kept out of what the gateway evaluates,
// records and relays. Only Claude Code and Codex prompts are marked
// stoppable: their prompt block is measured; Cursor's beforeSubmitPrompt
// and Devin's UserPromptSubmit are answered block but their secret is still
// stored exposed. Amp's agent.start carries the prompt, but its plugin can
// only add a note for the model there (exposed; the note tells the agent).
// Antigravity's PreInvocation carries no prompt and its documented
// PostToolUse input carries no tool output: PostToolUse is placed as tool
// output only so a secret in any field it does send is still kept exposed.
// OpenCode has no prompt hook. Cursor's stop and subagentStop are replies
// answered with no message: their only output (followup_message) starts a
// new turn. Cursor's subagentStart is a tool call (the subagent's task,
// which the model wrote) and is denied.
var sandboxVaultCaptureEvents = map[string]map[string]VaultCaptureEvent{
	"claudecode": {
		"UserPromptSubmit": vcPrompt, "UserPromptExpansion": vcPrompt,
		"PreToolUse": vcToolCall, "PermissionRequest": vcToolCall,
		"PostToolUse": vcOutputStop, "PostToolUseFailure": vcOutput, "PostToolBatch": vcOutput,
		"MessageDisplay": vcReply, "Stop": vcReply, "SubagentStop": vcReply,
	},
	"codex": {
		"UserPromptSubmit": vcPrompt,
		"PreToolUse":       vcToolCall, "PermissionRequest": vcToolCall,
		"PostToolUse": vcOutputStop,
		"Stop":        vcReply,
	},
	"copilot": {
		"userPromptSubmitted": vcPromptSeen, "userPromptTransformed": vcPromptSeen,
		"preToolUse": vcToolCall, "permissionRequest": vcToolCall,
		"postToolUse": vcOutput, "postToolUseFailure": vcOutput,
		"agentStop": vcReply, "subagentStop": vcReply,
	},
	"opencode": {
		"tool.execute.before": vcToolCall,
		"tool.execute.after":  vcOutput,
	},
	"hermes": {
		"pre_llm_call":   vcPromptSeen,
		"pre_tool_call":  vcToolCall,
		"post_tool_call": vcOutput, "transform_tool_result": vcOutput, "transform_terminal_output": vcOutput,
		"post_llm_call": vcReply, "transform_llm_output": vcReply,
	},
	"kiro": {
		"userPromptSubmit": vcPromptSeen,
		"preToolUse":       vcToolCall,
		"postToolUse":      vcOutput,
		"stop":             vcReply,
	},
	"antigravity": {
		"PreToolUse":  vcToolCall,
		"PostToolUse": vcOutput,
		"Stop":        vcReply, "PostInvocation": vcReply,
	},
	"amp": {
		"agent.start": vcPromptSeen,
		"tool.call":   vcToolCall,
		"tool.result": vcOutputStop,
	},
	"cursor": {
		"beforeSubmitPrompt": vcPromptSeen,
		"preToolUse":         vcToolCall, "beforeShellExecution": vcToolCall, "beforeMCPExecution": vcToolCall,
		"beforeReadFile": vcToolCall, "beforeTabFileRead": vcToolCall, "subagentStart": vcToolCall,
		"postToolUse": vcOutput, "postToolUseFailure": vcOutput, "afterShellExecution": vcOutput,
		"afterMCPExecution": vcOutput, "afterFileEdit": vcOutput, "afterTabFileEdit": vcOutput,
		"afterAgentResponse": vcReply, "afterAgentThought": vcReply, "stop": vcReply, "subagentStop": vcReply,
	},
	"devin": {
		"UserPromptSubmit": vcPromptSeen,
		"PreToolUse":       vcToolCall, "PermissionRequest": vcToolCall,
		"PostToolUse": vcOutput,
		"Stop":        vcReply,
	},
}

// SandboxVaultCaptureConnectors lists the connectors capture reads: every
// harness that runs in an OpenShell sandbox.
func SandboxVaultCaptureConnectors() []string {
	out := make([]string, 0, len(sandboxVaultCaptureEvents))
	for name := range sandboxVaultCaptureEvents {
		out = append(out, name)
	}
	return out
}

// SandboxVaultCaptureEventFor classifies a sandbox harness's hook event.
// ok is false for a connector capture does not read; an event the table
// does not name is VaultCaptureOther.
func SandboxVaultCaptureEventFor(connectorName, event string) (VaultCaptureEvent, bool) {
	events, ok := sandboxVaultCaptureEvents[connectorName]
	if !ok {
		return VaultCaptureEvent{}, false
	}
	return events[strings.TrimSpace(event)], true
}

// SandboxVaultCaptureEvents returns a copy of a connector's classified
// events (nil for a connector capture does not read).
func SandboxVaultCaptureEvents(connectorName string) map[string]VaultCaptureEvent {
	events, ok := sandboxVaultCaptureEvents[connectorName]
	if !ok {
		return nil
	}
	out := make(map[string]VaultCaptureEvent, len(events))
	for k, v := range events {
		out[k] = v
	}
	return out
}
