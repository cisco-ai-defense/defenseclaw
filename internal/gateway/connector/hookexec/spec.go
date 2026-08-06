// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"sort"
	"strings"
)

// decisionStyle selects how a connector shapes a 2xx gateway response into
// agent-native stdout + exit code. Each value corresponds to one of the
// distinct .sh hook tails under internal/gateway/connector/hooks.
type decisionStyle int

const (
	// styleClaudeCode: echo claude_code_output; on action=block, exit 0 if
	// output present (JSON carries the deny) else write reason to stderr +
	// exit 2. (claude-code-hook.sh)
	styleClaudeCode decisionStyle = iota
	// styleCodex: echo codex_output; on action=block, exit 0 if output
	// present else emit minimal {"decision":"block",...} on stdout + exit 0.
	// (codex-hook.sh)
	styleCodex
	// styleHookEcho: echo hook_output and exit 0 — the gateway already
	// encoded the decision in the agent-native hook_output. (cursor / copilot
	// / geminicli / hermes)
	styleHookEcho
	// styleHookEchoDecision: echo hook_output, then exit 2 if its
	// `decision` is deny/block. (openhands-hook.sh)
	styleHookEchoDecision
	// styleActionStderr: no stdout echo; on action=block write reason to
	// stderr + exit 2. (windsurf-hook.sh)
	styleActionStderr
)

// failResult is a fail-closed outcome: an optional connector-native JSON body
// printed to stdout and the exit code to return.
type failResult struct {
	body   string
	exit   int
	closed bool
}

// spec is the immutable per-connector contract mirrored from the .sh hooks.
type spec struct {
	connector   string // logical name + oversized stderr label ("claudecode")
	hookName    string // X-DefenseClaw-Client + log hook name ("claude-code-hook")
	errLabel    string // fail_response stderr label ("claude-code")
	subject     string // unreachable stderr subject ("claude-code tool")
	endpoint    string // gateway path ("/api/v1/claude-code/hook")
	outputField string // response field echoed to stdout ("claude_code_output")
	style       decisionStyle
	// failOpenOnly is set when the upstream host has no exit-status or
	// fail-closed hook contract. Runtime, authentication, transport, timeout,
	// and malformed-response failures must then remain an empty exit-0 allow;
	// only a valid connector-native response may request a block.
	failOpenOnly bool

	defaultBlockReason string // used when action=block but reason is empty

	openAllow         failResult // connector-native allow for empty/fail-open paths
	oversizedClosed   failResult // oversized payload + FAIL_MODE=closed
	unreachableStrict failResult // transport failure + STRICT_AVAILABILITY=1
	responseClosed    failResult // response-layer failure + FAIL_MODE=closed
}

const (
	tooLarge     = "DefenseClaw hook payload too large"
	failedClosed = "DefenseClaw hook failed closed"
)

// specs is the single source of truth for the Go hook contract. Every entry
// here is pinned by a golden test against the corresponding .sh hook.
var specs = map[string]spec{
	"amp": {
		connector: "amp", hookName: "amp-plugin", errLabel: "amp",
		subject: "amp tool", endpoint: "/api/v1/amp/hook",
		outputField: "", style: styleActionStderr,
		defaultBlockReason: "Blocked by DefenseClaw Amp policy.",
		oversizedClosed:    failResult{exit: blockExit},
		unreachableStrict:  failResult{exit: blockExit},
		responseClosed:     failResult{exit: blockExit},
	},
	"claudecode": {
		connector: "claudecode", hookName: "claude-code-hook", errLabel: "claude-code",
		subject: "claude-code tool", endpoint: "/api/v1/claude-code/hook",
		outputField: "claude_code_output", style: styleClaudeCode,
		defaultBlockReason: "Blocked by DefenseClaw Claude Code policy.",
		oversizedClosed:    failResult{body: `{"decision":"block","reason":"` + tooLarge + `"}`, exit: blockExit},
		unreachableStrict:  failResult{exit: blockExit},
		responseClosed:     failResult{exit: blockExit},
	},
	"codex": {
		connector: "codex", hookName: "codex-hook", errLabel: "codex",
		subject: "codex tool", endpoint: "/api/v1/codex/hook",
		outputField: "codex_output", style: styleCodex,
		defaultBlockReason: "Blocked by DefenseClaw Codex policy.",
		oversizedClosed:    failResult{body: `{"decision":"block","reason":"` + tooLarge + `"}`, exit: blockExit},
		unreachableStrict:  failResult{exit: blockExit},
		responseClosed:     failResult{exit: blockExit},
	},
	"cursor": {
		connector: "cursor", hookName: "cursor-hook", errLabel: "cursor",
		subject: "cursor tool", endpoint: "/api/v1/cursor/hook",
		outputField: "hook_output", style: styleHookEcho,
		defaultBlockReason: "Blocked by DefenseClaw Cursor policy.",
		// Cursor fallback bodies are rendered from Options.Event at emission
		// time. The body here is only the failure reason; no event accepts the
		// old generic continue+permission+message object.
		openAllow:         failResult{},
		oversizedClosed:   failResult{body: tooLarge, exit: blockExit, closed: true},
		unreachableStrict: failResult{body: failedClosed, exit: blockExit, closed: true},
		responseClosed:    failResult{body: failedClosed, closed: true},
	},
	"copilot": {
		connector: "copilot", hookName: "copilot-hook", errLabel: "copilot",
		subject: "copilot tool", endpoint: "/api/v1/copilot/hook",
		outputField: "hook_output", style: styleHookEcho, failOpenOnly: true,
	},
	"geminicli": {
		connector: "geminicli", hookName: "geminicli-hook", errLabel: "geminicli",
		subject: "geminicli tool", endpoint: "/api/v1/geminicli/hook",
		outputField: "hook_output", style: styleHookEcho,
		oversizedClosed:   failResult{exit: blockExit},
		unreachableStrict: failResult{exit: blockExit},
		responseClosed:    failResult{exit: blockExit},
	},
	// Antigravity consumes per-event JSON on stdout. PreToolUse decision=deny is
	// the only documented hard block; hookexec converts generic failure results
	// into exact event-native bodies and does not rely on process exit status.
	"antigravity": {
		connector: "antigravity", hookName: "antigravity-hook", errLabel: "antigravity",
		subject: "antigravity tool", endpoint: "/api/v1/antigravity/hook",
		outputField: "hook_output", style: styleHookEcho,
		oversizedClosed:   failResult{exit: blockExit},
		unreachableStrict: failResult{exit: blockExit},
		responseClosed:    failResult{exit: blockExit},
	},
	"hermes": {
		connector: "hermes", hookName: "hermes-hook", errLabel: "hermes",
		subject: "hermes tool", endpoint: "/api/v1/hermes/hook",
		outputField: "hook_output", style: styleHookEcho, failOpenOnly: true,
	},
	"windsurf": {
		connector: "windsurf", hookName: "windsurf-hook", errLabel: "windsurf",
		subject: "windsurf tool", endpoint: "/api/v1/windsurf/hook",
		outputField: "", style: styleActionStderr,
		defaultBlockReason: "DefenseClaw blocked this Cascade action.",
		oversizedClosed:    failResult{exit: blockExit},
		unreachableStrict:  failResult{exit: blockExit},
		responseClosed:     failResult{exit: blockExit},
	},
	"openhands": {
		connector: "openhands", hookName: "openhands-hook", errLabel: "openhands",
		subject: "openhands hook", endpoint: "/api/v1/openhands/hook",
		outputField: "hook_output", style: styleHookEchoDecision,
		oversizedClosed:   failResult{body: `{"decision":"deny","reason":"` + tooLarge + `"}`, exit: blockExit},
		unreachableStrict: failResult{body: `{"decision":"deny","reason":"` + failedClosed + `"}`, exit: blockExit},
		responseClosed:    failResult{body: `{"decision":"deny","reason":"` + failedClosed + `"}`, exit: blockExit},
	},
}

func cursorFallbackOutput(event string, closed bool, reason string) string {
	if closed {
		return cursorActionOutput(event, "block", reason)
	}
	return cursorActionOutput(event, "allow", reason)
}

func cursorActionOutput(event, action, reason string) string {
	event = strings.ToLower(strings.TrimSpace(event))
	if action != "block" {
		if action == "confirm" {
			switch event {
			case "beforeshellexecution", "beforemcpexecution":
				message := mustJSONString(reason)
				return `{"permission":"ask","user_message":` + message + `,"agent_message":` + message + `}`
			}
		}
		switch event {
		case "beforesubmitprompt":
			return `{"continue":true}`
		case "pretooluse", "subagentstart", "beforereadfile", "beforetabfileread",
			"beforeshellexecution", "beforemcpexecution":
			return `{"permission":"allow"}`
		default:
			return `{}`
		}
	}

	message := mustJSONString(reason)
	switch event {
	case "beforesubmitprompt":
		return `{"continue":false,"user_message":` + message + `}`
	case "pretooluse", "beforeshellexecution", "beforemcpexecution":
		return `{"permission":"deny","user_message":` + message + `,"agent_message":` + message + `}`
	case "subagentstart", "beforereadfile":
		return `{"permission":"deny","user_message":` + message + `}`
	case "beforetabfileread":
		return `{"permission":"deny"}`
	case "stop", "subagentstop":
		return `{"followup_message":` + message + `}`
	default:
		// Cursor documents no response fields for lifecycle and after-events.
		// If a strict local failure occurs before the event can be decoded,
		// exit 2 remains Cursor's documented generic block signal.
		return `{}`
	}
}

func specFor(connector string) (spec, bool) {
	s, ok := specs[connector]
	return s, ok
}

// SupportedConnectors returns the sorted list of connectors the native Go hook
// runner understands. Used by the CLI to validate --connector and by parity
// tests to keep this table in sync with the .sh hooks and the registry.
func SupportedConnectors() []string {
	names := make([]string, 0, len(specs))
	for name := range specs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
