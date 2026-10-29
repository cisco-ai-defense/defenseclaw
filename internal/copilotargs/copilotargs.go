// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package copilotargs is the one projection of a GitHub Copilot hook body
// onto the tool name and arguments DefenseClaw judges. The gateway's Copilot
// profiles (the CLI dialect and the VS Code Local dialect) and the hook-side
// write-target resolver (hookpaths) both use it, so the operands the resolver
// describes are the operands the gateway judges.
package copilotargs

import (
	"bytes"
	"encoding/json"
	"strings"
)

// NativeSingleCall reads a CLI preToolUse toolCalls envelope of exactly one
// fully named call. Unknown fields leave it unread instead of silently
// dropping a write.
func NativeSingleCall(value any) (string, any, bool) {
	calls, ok := value.([]any)
	if !ok || len(calls) != 1 {
		return "", nil, false
	}
	return nativeCall(calls[0])
}

// MaxNativeCalls bounds the calls of one toolCalls envelope the gateway
// judges; a larger envelope stays unread.
const MaxNativeCalls = 64

// NativeCall is one call of a CLI preToolUse toolCalls envelope, with the
// arguments CLIToolArgs projects for it.
type NativeCall struct {
	Name string
	Args json.RawMessage
}

// NativeCalls reads every call of a CLI preToolUse toolCalls envelope: a
// model's parallel tool calls arrive in one hook, and the one decision covers
// them all, so each is judged (GAP-1016). Every entry must be a fully named
// call with exactly id, name and args whose arguments project; any other
// entry leaves the whole envelope unread, so no write is dropped.
func NativeCalls(value any) ([]NativeCall, bool) {
	calls, ok := value.([]any)
	if !ok || len(calls) == 0 || len(calls) > MaxNativeCalls {
		return nil, false
	}
	out := make([]NativeCall, 0, len(calls))
	for _, entry := range calls {
		name, args, ok := nativeCall(entry)
		if !ok {
			return nil, false
		}
		projected := CLIToolArgs(name, args)
		if len(projected) == 0 {
			return nil, false
		}
		out = append(out, NativeCall{Name: name, Args: projected})
	}
	return out, true
}

func nativeCall(value any) (string, any, bool) {
	call, ok := value.(map[string]any)
	if !ok || !onlyKeys(call, "id", "name", "args") || len(call) != 3 {
		return "", nil, false
	}
	id, idOK := call["id"].(string)
	name, nameOK := call["name"].(string)
	if !idOK || strings.TrimSpace(id) == "" || !nameOK || strings.TrimSpace(name) != name || name == "" {
		return "", nil, false
	}
	args, present := call["args"]
	return name, args, present
}

// CLIToolArgs returns the arguments the Copilot CLI dialect judges for the
// toolArgs value of a call to toolName: the object, or a JSON string of one
// (the official hook tutorial sends it so), or an apply_patch call's patch
// text as {"patch": text}. A VS Code Local tool name sent in a CLI-shaped
// body (the Local harness running the CLI hook file, GAP-1903) gets its
// Local projection. Any other value has no arguments (nil).
func CLIToolArgs(toolName string, value any) json.RawMessage {
	var args json.RawMessage
	switch value := value.(type) {
	case map[string]any:
		if raw, err := json.Marshal(value); err == nil {
			args = raw
		}
	case string:
		raw := bytes.TrimSpace([]byte(value))
		if len(raw) >= 2 && raw[0] == '{' && raw[len(raw)-1] == '}' && json.Valid(raw) {
			args = append(json.RawMessage(nil), raw...)
		} else if patch, ok := PatchText(toolName, raw); ok {
			// apply_patch is a freeform tool: its arguments are the patch
			// text itself, sent raw or as a JSON string (GAP-0668).
			args, _ = json.Marshal(map[string]string{"patch": patch})
		}
	}
	if LocalTool(toolName) && len(args) != 0 {
		var input any
		if json.Unmarshal(args, &input) == nil {
			args = LocalToolArgs(toolName, input)
		}
	}
	return args
}

// PatchText is the patch an apply_patch toolArgs string carries: the text
// itself or a JSON string of it, starting with "*** Begin Patch".
func PatchText(toolName string, raw []byte) (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(toolName), "apply_patch") {
		return "", false
	}
	text := string(raw)
	if len(raw) >= 2 && raw[0] == '"' {
		if json.Unmarshal(raw, &text) != nil {
			return "", false
		}
	}
	return text, strings.HasPrefix(text, "*** Begin Patch")
}

// localProjection maps one VS Code agent tool onto the canonical ActionFacts
// tool and argument names. keys is the closed set of argument names the tool
// is known to send; fields maps the ones DefenseClaw judges.
type localProjection struct {
	action string
	keys   []string
	fields map[string]string
}

// The Local harness publishes no list of built-in tool names ("tool names and
// arguments differ between harnesses"), so the projections cover the VS Code
// agent tools DefenseClaw can judge exactly and pass every other tool or
// argument shape through unchanged, which ActionFacts parses as partial.
var localProjections = map[string]localProjection{
	"run_in_terminal": {
		action: "shell",
		keys:   []string{"command", "explanation", "goal", "isBackground", "mode", "timeout"},
		fields: map[string]string{"command": "command"},
	},
	"read_file": {
		action: "read_file",
		keys:   []string{"filePath", "startLine", "endLine", "offset", "limit"},
		fields: map[string]string{"filePath": "path"},
	},
	"list_dir": {
		action: "list_directory",
		keys:   []string{"path"},
		fields: map[string]string{"path": "path"},
	},
	"create_file": {
		action: "create_file",
		keys:   []string{"filePath", "content"},
		fields: map[string]string{"filePath": "path", "content": "content"},
	},
	"replace_string_in_file": {
		action: "edit_file",
		keys:   []string{"filePath", "oldString", "newString", "explanation"},
		fields: map[string]string{"filePath": "path", "newString": "content"},
	},
	"insert_edit_into_file": {
		action: "edit_file",
		keys:   []string{"filePath", "code", "explanation"},
		fields: map[string]string{"filePath": "path", "code": "content"},
	},
}

// LocalTool reports a VS Code Local agent tool DefenseClaw projects. The
// Local harness also runs the per-user Copilot CLI hook file (~/.copilot/hooks)
// and then sends a CLI-shaped body (toolName, toolArgs) with these tool names,
// which the Copilot CLI never uses, so the CLI dialect projects them the same
// way (GAP-1903).
func LocalTool(toolName string) bool {
	toolName = strings.TrimSpace(toolName)
	_, ok := localProjections[toolName]
	return ok || toolName == "fetch_webpage"
}

// LocalActionTool is the ActionFacts tool name for a VS Code Local tool: its
// projection's canonical name, or the native name.
func LocalActionTool(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if toolName == "fetch_webpage" {
		return "web_fetch"
	}
	if p, ok := localProjections[toolName]; ok {
		return p.action
	}
	return toolName
}

// LocalCall is the tool name and arguments the VS Code Local dialect judges
// for a body's tool_name and tool_input: LocalToolArgs of the call, except
// for an apply_patch call. The Copilot CLI runs the PascalCase hooks of the
// Local hook file too and names its apply_patch tool Edit there, with the
// patch text itself as tool_input (Copilot CLI 1.0.91, GAP-2497). That call
// is the apply_patch call its own preToolUse names, so it is judged as one:
// {"patch": text}, like the CLI dialect's (CLIToolArgs). Any other string
// input keeps its native value and stays unread.
func LocalCall(toolName string, input any) (string, json.RawMessage) {
	if text, ok := input.(string); ok {
		switch strings.TrimSpace(toolName) {
		case "Edit", "apply_patch":
			if patch, ok := PatchText("apply_patch", []byte(text)); ok {
				args, err := marshal(map[string]string{"patch": patch})
				if err == nil {
					return "apply_patch", args
				}
			}
		}
	}
	return toolName, LocalToolArgs(toolName, input)
}

// LocalToolArgs projects a known tool's arguments onto canonical names. An
// unknown tool, an unknown argument name, or a non-string judged value keeps
// the native object, so ActionFacts sees the shape it cannot prove instead of
// a projection that drops part of the call.
func LocalToolArgs(toolName string, input any) json.RawMessage {
	native, err := marshal(input)
	if err != nil {
		return nil
	}
	args, ok := input.(map[string]any)
	if !ok {
		return native
	}
	toolName = strings.TrimSpace(toolName)
	if toolName == "fetch_webpage" {
		// One URL is one fetch; a list or a query-only call stays native.
		urls, ok := args["urls"].([]any)
		if !ok || len(urls) != 1 || !onlyKeys(args, "urls", "query") {
			return native
		}
		url, ok := urls[0].(string)
		if !ok || strings.TrimSpace(url) == "" {
			return native
		}
		out, _ := marshal(map[string]string{"url": url})
		return out
	}
	p, ok := localProjections[toolName]
	if !ok || !onlyKeys(args, p.keys...) {
		return native
	}
	out := make(map[string]string, len(p.fields))
	for from, to := range p.fields {
		value, present := args[from]
		if !present {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return native
		}
		out[to] = text
	}
	encoded, err := marshal(out)
	if err != nil {
		return native
	}
	return encoded
}

func onlyKeys(args map[string]any, keys ...string) bool {
	for key := range args {
		known := false
		for _, want := range keys {
			if key == want {
				known = true
				break
			}
		}
		if !known {
			return false
		}
	}
	return true
}

// marshal encodes v as compact JSON without HTML escaping, as the gateway's
// tool-argument encoder does (connector.MarshalToolArgs).
func marshal(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
