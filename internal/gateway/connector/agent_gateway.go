// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The agent-gateway hook route (issue #1394) is for gateways that run agents
// through their own tool interface and call DefenseClaw for each step. It
// installs nothing into an agent and has no setup: the calling gateway posts
// a small, closed event contract (schemas/connectors/agent-gateway-hook.json)
// to the route. The gateway maps it onto the generic hook vocabulary and
// evaluates it on the same path every connector hook takes, so rules,
// chains, correlation and lineage behave as they do for any hook. The route
// is absent until connectors.agent_gateway.enabled is true.
const (
	// AgentGatewayConnectorName names the route's connector in audit and
	// telemetry.
	AgentGatewayConnectorName = "agent-gateway"
	// AgentGatewayHookPath is the route.
	AgentGatewayHookPath = "/api/v1/agent-gateway/hook"
	// AgentGatewayMaxIDBytes bounds session, tool use and root ids.
	AgentGatewayMaxIDBytes = 256
	// AgentGatewayMaxUserBytes bounds acting_for.user.
	AgentGatewayMaxUserBytes = 256
)

// Agent-gateway events (the contract's event values).
const (
	AgentGatewayEventSessionStart  = "session_start"
	AgentGatewayEventSessionEnd    = "session_end"
	AgentGatewayEventUserPrompt    = "user_prompt"
	AgentGatewayEventPreTool       = "pre_tool"
	AgentGatewayEventPostTool      = "post_tool"
	AgentGatewayEventSubagentStart = "subagent_start"
	AgentGatewayEventSubagentStop  = "subagent_stop"
)

// agentGatewayHookEvents maps each contract event to the generic hook event
// the evaluator already knows.
var agentGatewayHookEvents = map[string]string{
	AgentGatewayEventSessionStart:  "SessionStart",
	AgentGatewayEventSessionEnd:    "SessionEnd",
	AgentGatewayEventUserPrompt:    "UserPromptSubmit",
	AgentGatewayEventPreTool:       "PreToolUse",
	AgentGatewayEventPostTool:      "PostToolUse",
	AgentGatewayEventSubagentStart: "SubagentStart",
	AgentGatewayEventSubagentStop:  "SubagentStop",
}

// agentGatewayBlockEvents are the events whose answer the caller enforces.
var agentGatewayBlockEvents = []string{"PreToolUse", "UserPromptSubmit"}

// Tool kinds. A kind picks the generic tool the rules already use: shell
// commands get the shell rules, file writes the path rules, fetches the
// network rules. mcp and other keep the caller's tool name and get every
// content scan the generic path applies to a tool it does not know.
const (
	AgentGatewayToolShell     = "shell"
	AgentGatewayToolFileRead  = "file_read"
	AgentGatewayToolFileWrite = "file_write"
	AgentGatewayToolFetch     = "fetch"
	AgentGatewayToolMCP       = "mcp"
	AgentGatewayToolOther     = "other"
)

// agentGatewayKindTools is the generic tool name of each typed kind.
var agentGatewayKindTools = map[string]string{
	AgentGatewayToolShell:     "shell",
	AgentGatewayToolFileRead:  "read_file",
	AgentGatewayToolFileWrite: "write_file",
	AgentGatewayToolFetch:     "web_fetch",
}

// AgentGatewayEvent is one decoded request of the contract.
type AgentGatewayEvent struct {
	Event           string            `json:"event"`
	SessionID       string            `json:"session_id"`
	ToolUseID       string            `json:"tool_use_id,omitempty"`
	Traceparent     string            `json:"traceparent,omitempty"`
	ParentSessionID string            `json:"parent_session_id,omitempty"`
	CWD             string            `json:"cwd,omitempty"`
	Tool            *AgentGatewayTool `json:"tool,omitempty"`
	ToolResponse    json.RawMessage   `json:"tool_response,omitempty"`
	// Status is how the tool call ended (post_tool only): success, error,
	// denied or cancelled. Only a success completes a chain step; a
	// post_tool without it is recorded but proves nothing.
	Status        string              `json:"status,omitempty"`
	Prompt        *string             `json:"prompt,omitempty"`
	ActingFor     *AgentGatewayActing `json:"acting_for,omitempty"`
	RootSessionID string              `json:"root_session_id,omitempty"`
}

// AgentGatewayTool is the contract's tool object.
type AgentGatewayTool struct {
	Name  string          `json:"name"`
	Kind  string          `json:"kind"`
	Input json.RawMessage `json:"input,omitempty"`
}

// AgentGatewayActing is acting_for: the person a trusted connector acts for
// (issue #1392). It is honoured only for a trusted connector's service
// account on a managed device; from any other caller it is ignored and
// audited.
type AgentGatewayActing struct {
	User string `json:"user"`
}

// AgentGatewayContractError is a request the contract refuses; Reason is a
// short stable code for audit and the 400 answer.
type AgentGatewayContractError struct {
	Reason string
	Detail string
}

func (e *AgentGatewayContractError) Error() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

func agentGatewayContractError(reason, format string, args ...any) error {
	return &AgentGatewayContractError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// DecodeAgentGatewayEvent decodes and checks one request body. Unknown
// fields anywhere in the closed parts of the contract are refused, as are
// duplicate keys, trailing data and fields an event does not take.
func DecodeAgentGatewayEvent(body []byte) (AgentGatewayEvent, error) {
	var ev AgentGatewayEvent
	if len(bytes.TrimSpace(body)) == 0 {
		return ev, agentGatewayContractError("invalid_json", "empty body")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return ev, agentGatewayContractError("invalid_json", "%s", err.Error())
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			return ev, agentGatewayContractError("invalid_json", "malformed JSON")
		}
		return ev, agentGatewayContractError("unknown_field", "%s", boundedContractDetail(err.Error()))
	}
	if _, err := dec.Token(); err != io.EOF {
		return ev, agentGatewayContractError("invalid_json", "trailing data after the event")
	}
	if err := ev.validate(); err != nil {
		return ev, err
	}
	return ev, nil
}

func (ev *AgentGatewayEvent) validate() error {
	if _, ok := agentGatewayHookEvents[ev.Event]; !ok {
		return agentGatewayContractError("invalid_event", "event must be one of session_start, session_end, user_prompt, pre_tool, post_tool, subagent_start, subagent_stop")
	}
	if err := checkContractID("session_id", ev.SessionID, true); err != nil {
		return err
	}
	if err := checkContractID("root_session_id", ev.RootSessionID, false); err != nil {
		return err
	}
	if err := checkContractID("parent_session_id", ev.ParentSessionID, false); err != nil {
		return err
	}
	tool := ev.Event == AgentGatewayEventPreTool || ev.Event == AgentGatewayEventPostTool
	if err := checkContractID("tool_use_id", ev.ToolUseID, tool); err != nil {
		return err
	}
	if !tool && ev.ToolUseID != "" {
		return agentGatewayContractError("field_not_allowed", "tool_use_id is only for pre_tool and post_tool")
	}
	if ev.Traceparent != "" && !validTraceparent(ev.Traceparent) {
		return agentGatewayContractError("invalid_traceparent", "traceparent must be a W3C traceparent")
	}
	if ev.CWD != "" {
		if len(ev.CWD) > 4096 || !utf8.ValidString(ev.CWD) || strings.ContainsRune(ev.CWD, 0) || !agentGatewayAbsPath(ev.CWD) {
			return agentGatewayContractError("invalid_cwd", "cwd must be an absolute path")
		}
	}
	subagent := ev.Event == AgentGatewayEventSubagentStart || ev.Event == AgentGatewayEventSubagentStop
	if ev.ParentSessionID != "" && !subagent {
		return agentGatewayContractError("field_not_allowed", "parent_session_id is only for subagent_start and subagent_stop")
	}
	if subagent && ev.ParentSessionID == "" {
		return agentGatewayContractError("missing_field", "parent_session_id is required for %s", ev.Event)
	}
	switch {
	case tool && ev.Tool == nil:
		return agentGatewayContractError("missing_field", "tool is required for %s", ev.Event)
	case !tool && ev.Tool != nil:
		return agentGatewayContractError("field_not_allowed", "tool is only for pre_tool and post_tool")
	}
	if ev.Event == AgentGatewayEventPostTool && len(ev.ToolResponse) == 0 {
		return agentGatewayContractError("missing_field", "tool_response is required for post_tool")
	}
	if ev.Event != AgentGatewayEventPostTool && len(ev.ToolResponse) != 0 {
		return agentGatewayContractError("field_not_allowed", "tool_response is only for post_tool")
	}
	switch {
	case ev.Status != "" && ev.Event != AgentGatewayEventPostTool:
		return agentGatewayContractError("field_not_allowed", "status is only for post_tool")
	case ev.Status != "" && !agentGatewayStatuses[ev.Status]:
		return agentGatewayContractError("invalid_status", "status must be one of success, error, denied, cancelled")
	}
	if ev.Event == AgentGatewayEventUserPrompt && ev.Prompt == nil {
		return agentGatewayContractError("missing_field", "prompt is required for user_prompt")
	}
	if ev.Event != AgentGatewayEventUserPrompt && ev.Prompt != nil {
		return agentGatewayContractError("field_not_allowed", "prompt is only for user_prompt")
	}
	if ev.Tool != nil {
		if err := ev.Tool.validate(); err != nil {
			return err
		}
	}
	if ev.ActingFor != nil {
		user := ev.ActingFor.User
		if strings.TrimSpace(user) == "" || len(user) > AgentGatewayMaxUserBytes || !utf8.ValidString(user) || hasControl(user) {
			return agentGatewayContractError("invalid_acting_for", "acting_for.user must name one account")
		}
	}
	return nil
}

func (t *AgentGatewayTool) validate() error {
	if t.Kind == "" {
		return agentGatewayContractError("missing_field", "tool.kind is required")
	}
	switch t.Kind {
	case AgentGatewayToolShell, AgentGatewayToolFileRead, AgentGatewayToolFileWrite, AgentGatewayToolFetch,
		AgentGatewayToolMCP, AgentGatewayToolOther:
	default:
		return agentGatewayContractError("invalid_tool_kind", "tool.kind must be one of shell, file_read, file_write, fetch, mcp, other")
	}
	name := strings.TrimSpace(t.Name)
	if name == "" || len(name) > 256 || name != t.Name || !utf8.ValidString(name) || hasControl(name) || strings.ContainsRune(name, ' ') {
		return agentGatewayContractError("invalid_tool_name", "tool.name must be a non-empty name without spaces")
	}
	return nil
}

func checkContractID(field, value string, required bool) error {
	if value == "" {
		if required {
			return agentGatewayContractError("missing_field", "%s is required", field)
		}
		return nil
	}
	if len(value) > AgentGatewayMaxIDBytes || strings.TrimSpace(value) != value || !utf8.ValidString(value) || hasControl(value) {
		return agentGatewayContractError("invalid_id", "%s must be at most %d bytes of printable text", field, AgentGatewayMaxIDBytes)
	}
	return nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func validTraceparent(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 4 || len(parts[0]) != 2 || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return false
	}
	for _, part := range parts {
		for _, c := range part {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return parts[0] != "ff" && strings.Trim(parts[1], "0") != "" && strings.Trim(parts[2], "0") != ""
}

func agentGatewayAbsPath(path string) bool {
	if strings.HasPrefix(path, "/") {
		return true
	}
	// A Windows drive path (C:\work) or UNC path.
	return filepath.VolumeName(path) != "" || len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')
}

func boundedContractDetail(detail string) string {
	if len(detail) > 160 {
		return detail[:160]
	}
	return detail
}

// rejectDuplicateJSONKeys refuses an object that names one key twice, at any
// depth: encoding/json keeps the last one, which lets two readers of the
// same body disagree about the event.
func rejectDuplicateJSONKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nests too deeply")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := keyTok.(string)
				if seen[key] {
					return fmt.Errorf("duplicate key %q", boundedContractDetail(key))
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	return walk(0)
}

// AgentGatewayHookPayload maps a decoded event onto the generic hook
// vocabulary: hook_event_name, session_id, tool_call_id (the canonical
// correlation key of tool_use_id), tool_name,
// tool_input, tool_response, prompt, cwd, the W3C traceparent and, for a
// sub-agent event, parent_session_id. acting_for and root_session_id are
// never copied: the route decides about them before evaluation.
func AgentGatewayHookPayload(ev AgentGatewayEvent) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"hook_event_name": agentGatewayHookEvents[ev.Event],
		"session_id":      ev.SessionID,
	}
	if ev.CWD != "" {
		payload["cwd"] = ev.CWD
	}
	if ev.Traceparent != "" {
		payload["traceparent"] = ev.Traceparent
	}
	if ev.ParentSessionID != "" {
		payload["parent_session_id"] = ev.ParentSessionID
	}
	if ev.ToolUseID != "" {
		payload["tool_call_id"] = ev.ToolUseID
	}
	if ev.Prompt != nil {
		payload["prompt"] = *ev.Prompt
	}
	if ev.Tool != nil {
		name, input, err := agentGatewayToolCall(*ev.Tool)
		if err != nil {
			return nil, err
		}
		payload["tool_name"] = name
		payload["tool_input"] = input
	}
	if ev.Status != "" {
		payload["tool_status"] = ev.Status
	}
	if len(ev.ToolResponse) != 0 {
		var response interface{}
		if err := json.Unmarshal(ev.ToolResponse, &response); err != nil {
			return nil, agentGatewayContractError("invalid_json", "tool_response is not JSON")
		}
		payload["tool_response"] = response
	}
	return payload, nil
}

// agentGatewayToolCall is the generic tool name and input of a tool. The
// typed kinds take a fixed tool name, so a caller cannot pick a name the
// rules treat more leniently; mcp and other keep the caller's name.
func agentGatewayToolCall(tool AgentGatewayTool) (string, interface{}, error) {
	var input interface{} = map[string]interface{}{}
	if len(tool.Input) != 0 {
		if err := json.Unmarshal(tool.Input, &input); err != nil {
			return "", nil, agentGatewayContractError("invalid_json", "tool.input is not JSON")
		}
	}
	name, typed := agentGatewayKindTools[tool.Kind]
	if !typed {
		return tool.Name, input, nil
	}
	switch value := input.(type) {
	case string:
		switch tool.Kind {
		case AgentGatewayToolShell:
			return name, map[string]interface{}{"command": value}, nil
		case AgentGatewayToolFileRead:
			return name, map[string]interface{}{"path": value}, nil
		case AgentGatewayToolFetch:
			return name, map[string]interface{}{"url": value}, nil
		}
		return "", nil, agentGatewayContractError("invalid_tool_input", "tool.input for %s must be an object", tool.Kind)
	case map[string]interface{}:
		if tool.Kind == AgentGatewayToolShell {
			command, ok := value["command"].(string)
			if !ok {
				return "", nil, agentGatewayContractError("invalid_tool_input", "a shell tool.input object needs a command string")
			}
			for key := range value {
				if key != "command" {
					return "", nil, agentGatewayContractError("invalid_tool_input", "a shell tool.input object takes only command; send cwd at the top level")
				}
			}
			return name, map[string]interface{}{"command": command}, nil
		}
		return name, value, nil
	default:
		return "", nil, agentGatewayContractError("invalid_tool_input", "tool.input for %s must be a string or an object", tool.Kind)
	}
}

var agentGatewayStatuses = map[string]bool{"success": true, "error": true, "denied": true, "cancelled": true}

// AgentGatewayContractID names the reviewed event contract of the route.
const AgentGatewayContractID = "agent-gateway-hook-v1"

// agentGatewayToolCallLifecycle is the route's tool-call lifecycle: a
// pre_tool proposes, a post_tool with the same tool_use_id settles it by its
// status, a session_end ends the session's chain state. Sub-agent and
// prompt events are audit only.
func agentGatewayToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"PreToolUse"},
		AuthoritativeSuccessEvents:        []string{"PostToolUse"},
		AuthoritativeFailureEvents:        []string{"PostToolUse"},
		AuthoritativeDenialEvents:         []string{"PostToolUse"},
		AuthoritativePendingDiscardEvents: []string{},
		AuthoritativeTerminalEvents:       []string{"SessionEnd"},
		InvocationIDAuthority:             ToolInvocationIDPairedID,
		OutcomeAuthority:                  ToolOutcomeResultPayload,
		StatefulEnforcementLevel:          StatefulToolPairedOutcomes,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"PreToolUse"},
			ResultContentEvents:    []string{"PostToolUse"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"SessionStart", "UserPromptSubmit", "SubagentStart", "SubagentStop", "SessionEnd"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead, ToolSurfaceFileWrite, ToolSurfaceMCP,
		},
		OfficialSourceURLs: []string{"https://github.com/cisco-ai-defense/defenseclaw/blob/main/schemas/connectors/agent-gateway-hook.json"},
		Limitations: []string{
			"The calling gateway enforces the answer; DefenseClaw cannot enforce it inside a third-party process.",
			"A post_tool without status is recorded but never completes a chain step.",
		},
	}
}

// classifyAgentGatewayResult is the outcome a post_tool states in status.
func classifyAgentGatewayResult(payload map[string]interface{}) ToolLifecycleOutcome {
	return classifyStatusValue(payload["tool_status"])
}

// AgentGatewayHookProfile is the route's hook profile: a generic hook-only
// profile whose answer is the generic {action, reason, rule_ids} body.
func AgentGatewayHookProfile() HookProfile {
	events := make([]string, 0, len(agentGatewayHookEvents))
	for _, contract := range []string{
		AgentGatewayEventSessionStart, AgentGatewayEventSessionEnd, AgentGatewayEventUserPrompt,
		AgentGatewayEventPreTool, AgentGatewayEventPostTool, AgentGatewayEventSubagentStart, AgentGatewayEventSubagentStop,
	} {
		events = append(events, agentGatewayHookEvents[contract])
	}
	return HookProfile{
		Name: AgentGatewayConnectorName,
		Capabilities: HookCapability{
			CanBlock:           true,
			BlockEvents:        append([]string(nil), agentGatewayBlockEvents...),
			SupportsFailClosed: true,
			Scope:              "route",
		},
		SupportsTraceparent: true,
		SupportedEvents:     events,
		ContractID:          AgentGatewayContractID,
		CompatibilityStatus: HookCompatibilityUnversioned,
		ToolCallLifecycle:   agentGatewayToolCallLifecycle(),
		Correlation:         ExplicitCanonicalCorrelationSpec(AgentGatewayConnectorName),
		AIDSurfaces:         []string{"prompt", "tool_call", "tool_result"},
		Decode:              agentGatewayProfileDecode,
		MapVerdict:          hookOnlyProfileMapVerdict,
		Respond:             hookOnlyProfileRespond,
	}
}

func agentGatewayProfileDecode(payload map[string]interface{}) HookProfileRequest {
	event := hookFirstString(payload, "hook_event_name")
	req := HookProfileRequest{
		ConnectorName:    AgentGatewayConnectorName,
		HookEventName:    event,
		SessionID:        hookFirstString(payload, "session_id"),
		ParentSessionID:  hookFirstString(payload, "parent_session_id"),
		ToolInvocationID: hookFirstString(payload, "tool_call_id"),
		CWD:              hookFirstString(payload, "cwd"),
		ToolName:         hookFirstString(payload, "tool_name"),
		Payload:          payload,
	}
	if input, ok := payload["tool_input"]; ok {
		if encoded, err := json.Marshal(input); err == nil {
			req.ToolArgs = encoded
		}
	}
	switch canonicalHookEvent(event) {
	case "posttooluse":
		if response, ok := payload["tool_response"]; ok {
			if encoded, err := json.Marshal(response); err == nil {
				req.Content = string(encoded)
				req.Direction = "tool_result"
			}
		}
	case "userpromptsubmit":
		req.Content = hookFirstString(payload, "prompt")
		req.Direction = "prompt"
	}
	return req
}
