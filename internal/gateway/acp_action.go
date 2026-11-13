// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// ACP frames that perform an action (rel-1-0-10:GAP-0176).
//
// An ACP agent acts through the editor: terminal/create runs a command,
// fs/read_text_file and fs/write_text_file read and write a file, and
// session/request_permission asks before the agent runs one of its own
// tools. The agent also reports the tools it runs itself in session/update
// (tool_call, tool_call_update), and may send the editor methods of its own.
// Each of those is the action a hook connector reports as a tool call, so it
// is judged as that tool call, through the hook path's own code
// (inspectAgentHookToolCall): the command, path, protected-target and
// effects rules see it. Judged as prose, a frame that ran a command was
// checked by the content rules alone.

// acpToolCall is one tool call an ACP frame performs, in the hook shape.
type acpToolCall struct {
	tool string          // the hook tool the action is judged as
	args json.RawMessage // its arguments in that tool's shape
	cwd  string          // the working directory the frame names, or ""
	// unread marks an action whose arguments the frame does not carry in
	// the documented shape. It is refused as the hook path refuses a tool
	// call it cannot read (hookToolCallUnparsedRuleID): unknown, not clean.
	unread bool
}

// acpFrameAction is the action an ACP frame performs.
type acpFrameAction struct {
	calls []acpToolCall
	// enforceable: the guard can refuse the frame before the action runs. A
	// request the agent sends the editor is refused before the editor acts;
	// a report of a tool the agent runs itself only withholds the report.
	enforceable bool
	// prose is the frame's text that is not the action (a permission's
	// title and content blocks), still judged by the content rules.
	prose string
}

// acpMaxFrameToolCalls bounds the calls one frame may have judged (a
// permission naming many locations).
const acpMaxFrameToolCalls = 8

// acpFrameToolCalls is the action of one ACP frame. ok is false for a frame
// that performs none (a prompt, agent text, a terminal's lifecycle, a
// response), which the content rules judge as before. goos is the platform
// the editor runs the action on; the guard, the editor and this gateway run
// on one host.
func acpFrameToolCalls(req acp.Evaluation, goos string) (acpFrameAction, bool) {
	if req.Aggregate || req.Direction != acp.AgentToClient {
		return acpFrameAction{}, false
	}
	msg, err := acp.ParseMessageAllowingNullIDErrors(req.Payload)
	if err != nil || msg.Method == "" {
		return acpFrameAction{}, false
	}
	switch msg.Method {
	case "terminal/create":
		return acpFrameAction{calls: []acpToolCall{acpTerminalCreateCall(msg.Params, goos)}, enforceable: true}, true
	case "fs/read_text_file", "fs/write_text_file":
		return acpFrameAction{calls: []acpToolCall{acpFileCall(msg.Method, msg.Params)}, enforceable: true}, true
	case "session/request_permission":
		var params struct {
			ToolCall json.RawMessage `json:"toolCall"`
		}
		if json.Unmarshal(msg.Params, &params) != nil || !acpJSONObject(params.ToolCall) {
			return acpFrameAction{calls: []acpToolCall{{unread: true}}, enforceable: true}, true
		}
		calls, prose := acpToolCallUpdateCalls(params.ToolCall, goos, true)
		return acpFrameAction{calls: calls, enforceable: true, prose: prose}, true
	case "session/update":
		var params struct {
			Update json.RawMessage `json:"update"`
		}
		if json.Unmarshal(msg.Params, &params) != nil || !acpJSONObject(params.Update) {
			return acpFrameAction{}, false
		}
		var update struct {
			SessionUpdate string `json:"sessionUpdate"`
		}
		if json.Unmarshal(params.Update, &update) != nil ||
			(update.SessionUpdate != "tool_call" && update.SessionUpdate != "tool_call_update") {
			return acpFrameAction{}, false
		}
		calls, prose := acpToolCallUpdateCalls(params.Update, goos, false)
		if len(calls) == 0 {
			// A status or output report names no action: its text is agent
			// output, judged as before.
			return acpFrameAction{}, false
		}
		return acpFrameAction{calls: calls, prose: prose}, true
	}
	if acp.Classify(msg, req.Direction) != acp.SurfaceTool {
		return acpFrameAction{}, false
	}
	// A method of the agent's own: a tool call under the method's name,
	// judged by the non-shell tool lane, its text by the content rules.
	args := msg.Params
	if !acpJSONObject(args) {
		args = json.RawMessage(`{}`)
	}
	return acpFrameAction{
		calls:       []acpToolCall{{tool: msg.Method, args: args}},
		enforceable: msg.IsRequest(),
		prose:       acp.InspectableText(req.Payload),
	}, true
}

// acpTerminalCreateCall is terminal/create as a shell call: the command
// line the editor runs (Zed runs command and args through the user's
// shell), with the environment it sets, in the directory it names.
func acpTerminalCreateCall(raw json.RawMessage, goos string) acpToolCall {
	var params struct {
		Command *string  `json:"command"`
		Args    []string `json:"args"`
		Env     []struct {
			Name  *string `json:"name"`
			Value *string `json:"value"`
		} `json:"env"`
		CWD *string `json:"cwd"`
	}
	if json.Unmarshal(raw, &params) != nil || params.Command == nil || strings.TrimSpace(*params.Command) == "" {
		return acpToolCall{tool: "shell", unread: true}
	}
	var line strings.Builder
	for _, variable := range params.Env {
		if variable.Name == nil || variable.Value == nil || !acpEnvName.MatchString(*variable.Name) {
			return acpToolCall{tool: "shell", unread: true}
		}
		if goos == "windows" {
			line.WriteString("$env:" + *variable.Name + "=" + acpQuoteWord(*variable.Value, goos) + "; ")
		} else {
			line.WriteString(*variable.Name + "=" + acpQuoteWord(*variable.Value, goos) + " ")
		}
	}
	line.WriteString(*params.Command)
	for _, arg := range params.Args {
		line.WriteString(" " + acpQuoteWord(arg, goos))
	}
	call := acpToolCall{tool: "shell", args: acpCommandArgs(line.String())}
	if params.CWD != nil {
		call.cwd = strings.TrimSpace(*params.CWD)
	}
	return call
}

// acpFileCall is fs/read_text_file as Read and fs/write_text_file as Write
// of the path it names.
func acpFileCall(method string, raw json.RawMessage) acpToolCall {
	var params struct {
		Path    *string `json:"path"`
		Content *string `json:"content"`
	}
	tool := "Read"
	if method == "fs/write_text_file" {
		tool = "Write"
	}
	if json.Unmarshal(raw, &params) != nil || params.Path == nil || strings.TrimSpace(*params.Path) == "" ||
		(tool == "Write" && params.Content == nil) {
		return acpToolCall{tool: tool, unread: true}
	}
	args := map[string]string{"file_path": *params.Path}
	if tool == "Write" {
		args["content"] = *params.Content
	}
	return acpToolCall{tool: tool, args: acpMarshal(args)}
}

// acpToolCallUpdateCalls reads an ACP ToolCall or ToolCallUpdate (a
// permission's toolCall, a tool_call report) as the tool calls it performs:
// by its kind, from its rawInput and locations. prose is its other text
// (title, content blocks). A report that names no input gives no calls; a
// permission for an action it does not show is refused as unread.
func acpToolCallUpdateCalls(raw json.RawMessage, goos string, permission bool) ([]acpToolCall, string) {
	var call struct {
		Kind      string          `json:"kind"`
		Title     string          `json:"title"`
		RawInput  json.RawMessage `json:"rawInput"`
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
	}
	if json.Unmarshal(raw, &call) != nil {
		if permission {
			return []acpToolCall{{unread: true}}, ""
		}
		return nil, ""
	}
	prose := acpToolCallProse(raw)
	input := map[string]json.RawMessage{}
	hasInput := acpJSONObject(call.RawInput) && json.Unmarshal(call.RawInput, &input) == nil && len(input) > 0
	var paths []string
	if path := acpInputString(input, "file_path", "filePath", "path", "absolute_path", "abs_path", "target_file", "notebook_path"); path != "" {
		paths = append(paths, path)
	}
	for _, location := range call.Locations {
		if path := strings.TrimSpace(location.Path); path != "" && !slices.Contains(paths, path) {
			paths = append(paths, path)
		}
	}
	if !hasInput && len(paths) == 0 {
		if permission {
			// The editor is asked to allow an action the frame does not
			// show: it cannot be shown to be safe.
			return []acpToolCall{{unread: true}}, prose
		}
		return nil, prose
	}
	var calls []acpToolCall
	addPaths := func(tool string, args func(path string) map[string]string) {
		for _, path := range paths {
			if len(calls) == acpMaxFrameToolCalls {
				return
			}
			calls = append(calls, acpToolCall{tool: tool, args: acpMarshal(args(path))})
		}
	}
	switch call.Kind {
	case "execute":
		command, ok := acpInputCommand(input, goos)
		if !ok {
			// A shell call with no command the gateway can read: judged as
			// the hook path judges it (unverifiedShellCommandFinding).
			args := call.RawInput
			if !hasInput {
				args = json.RawMessage(`{}`)
			}
			return []acpToolCall{{tool: "shell", args: args}}, prose
		}
		return []acpToolCall{{tool: "shell", args: acpCommandArgs(command),
			cwd: acpInputString(input, "cwd", "workdir", "working_directory", "directory")}}, prose
	case "read":
		addPaths("Read", func(path string) map[string]string { return map[string]string{"file_path": path} })
	case "edit":
		content, hasContent := acpInputText(input, "content")
		oldText, hasOld := acpInputText(input, "old_string")
		newText, hasNew := acpInputText(input, "new_string")
		addPaths("Write", func(path string) map[string]string {
			switch {
			case hasOld && hasNew && path == paths[0]:
				return map[string]string{"file_path": path, "old_string": oldText, "new_string": newText}
			case hasContent && path == paths[0]:
				return map[string]string{"file_path": path, "content": content}
			}
			return map[string]string{"file_path": path}
		})
		if hasOld && hasNew && len(calls) > 0 {
			calls[0].tool = "Edit"
		}
	case "delete":
		addPaths("delete_file", func(path string) map[string]string { return map[string]string{"path": path} })
	case "fetch":
		if url := acpInputString(input, "url", "uri"); url != "" {
			calls = append(calls, acpToolCall{tool: "WebFetch", args: acpMarshal(map[string]string{"url": url})})
		}
	}
	if len(calls) > 0 {
		return calls, prose
	}
	// Any other kind (search, move, think, other) or a kind the input does
	// not fit: a tool call under the tool's name, read by the non-shell tool
	// lane, with each location judged as a read of that path.
	args := call.RawInput
	if !hasInput {
		args = json.RawMessage(`{}`)
	}
	calls = append(calls, acpToolCall{tool: acpToolName(call.Title, call.Kind), args: args})
	addPaths("Read", func(path string) map[string]string { return map[string]string{"file_path": path} })
	return calls, prose
}

// acpToolCallProse is the text of a ToolCall other than its rawInput and
// rawOutput (title, content blocks, locations), for the content rules.
func acpToolCallProse(raw json.RawMessage) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ""
	}
	delete(fields, "rawInput")
	delete(fields, "rawOutput")
	return acp.InspectableText(acpMarshal(fields))
}

// acpInputCommand is the command an execute tool's input names: a command
// line, or an argv joined as the shell would read it.
func acpInputCommand(input map[string]json.RawMessage, goos string) (string, bool) {
	for _, key := range []string{"command", "cmd"} {
		raw, ok := input[key]
		if !ok {
			continue
		}
		var line string
		if json.Unmarshal(raw, &line) == nil && strings.TrimSpace(line) != "" {
			return line, true
		}
		var argv []string
		if json.Unmarshal(raw, &argv) == nil && len(argv) > 0 && strings.TrimSpace(argv[0]) != "" {
			words := make([]string, len(argv))
			for i, word := range argv {
				words[i] = acpQuoteWord(word, goos)
			}
			return strings.Join(words, " "), true
		}
		return "", false
	}
	return "", false
}

func acpInputString(input map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		if value, ok := acpInputText(input, key); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func acpInputText(input map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := input[key]
	if !ok {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

// acpToolName is the name a tool call of another kind is judged under: its
// title when that is a tool identifier, else its kind.
func acpToolName(title, kind string) string {
	if title = strings.TrimSpace(title); acpToolIdentifier.MatchString(title) {
		return title
	}
	if acpToolIdentifier.MatchString(kind) {
		return "acp_" + kind
	}
	return "acp_tool"
}

var (
	acpEnvName        = lazyregexp.New(`^[A-Za-z_][A-Za-z0-9_]*$`)
	acpToolIdentifier = lazyregexp.New(`^[A-Za-z][A-Za-z0-9_.:/-]{0,63}$`)
	acpPlainWord      = lazyregexp.New(`^[A-Za-z0-9_@%+=:,./-]+$`)
)

// acpQuoteWord quotes one argument as the platform's shell reads it as one
// word: POSIX single quotes, or PowerShell's on Windows.
func acpQuoteWord(word, goos string) string {
	if acpPlainWord.MatchString(word) {
		return word
	}
	if goos == "windows" {
		return "'" + strings.ReplaceAll(word, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

func acpCommandArgs(command string) json.RawMessage {
	return acpMarshal(map[string]string{"command": command})
}

func acpMarshal(value any) json.RawMessage {
	out, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}

func acpJSONObject(raw json.RawMessage) bool {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	return len(raw) > 1 && raw[0] == '{'
}

// inspectACPFrameAction judges the tool calls of one ACP frame as the hook
// path judges them, with the frame's prose through the content rules, and
// returns the strongest verdict. enforceable is passed as the hook path
// passes a surface's block capability.
//
// A frame the guard cannot refuse before its action runs (a report of a tool
// the agent runs itself) is a surface that cannot block, as a hook event
// outside a connector's block events is: a block of its action is an alert
// that would have blocked (reportOnly), as mapHookActionForProfile answers
// such an event. The prose may still withhold the report, as before.
func (a *APIServer) inspectACPFrameAction(
	ctx context.Context, req acp.Evaluation, connectorName string, action acpFrameAction,
	content func(text string) *ToolInspectVerdict,
) (verdict *ToolInspectVerdict, reportOnly bool) {
	profile := a.hookProfileForRequest(ctx, connectorName)
	session := acpFrameSessionID(req, false)
	for _, call := range action.calls {
		var judged *ToolInspectVerdict
		if call.unread {
			judged = acpUnreadToolCallVerdict(connectorName)
		} else {
			judged = a.inspectAgentHookToolCall(ctx, agentHookRequest{
				ConnectorName: connectorName,
				HookEventName: req.Method,
				SessionID:     session,
				CWD:           call.cwd,
				ReportedCWD:   call.cwd,
				ToolName:      call.tool,
				ToolArgs:      call.args,
				Direction:     "tool_call",
			}, profile, action.enforceable)
		}
		verdict = strongerACPVerdict(verdict, judged)
	}
	if verdict != nil && !action.enforceable {
		if decided := normalizeCodexAction(verdict.Action); decided == "block" || decided == "confirm" {
			capped := *verdict
			capped.Action = "alert"
			verdict, reportOnly = &capped, true
		}
	}
	if action.prose != "" && content != nil {
		prose := content(action.prose)
		if prose != nil && (verdict == nil || acpVerdictRank(prose) > acpVerdictRank(verdict)) {
			reportOnly = false
		}
		verdict = strongerACPVerdict(verdict, prose)
	}
	if verdict == nil {
		verdict = &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}
	return verdict, reportOnly
}

// acpUnreadToolCallVerdict refuses an ACP action the frame does not carry
// in its documented shape, as the hook path refuses a tool call it cannot
// read (GAP-0337).
func acpUnreadToolCallVerdict(connectorName string) *ToolInspectVerdict {
	reason := "DefenseClaw could not read the action in this ACP frame, so it cannot show the action is safe and blocks it. " +
		"Update DefenseClaw and the agent if this repeats."
	if unparsedToolCallReasonConnector.MatchString(connectorName) {
		reason = "DefenseClaw could not read the action in this " + connectorName +
			" ACP frame, so it cannot show the action is safe and blocks it. Update DefenseClaw and the agent if this repeats."
	}
	return &ToolInspectVerdict{
		Action: "block", Severity: "HIGH", Confidence: 1.0,
		Reason:   reason,
		Findings: []string{hookToolCallUnparsedRuleID},
		DetailedFindings: []RuleFinding{{
			RuleID: hookToolCallUnparsedRuleID, Title: "tool call in the ACP frame could not be read",
			Severity: "HIGH", Confidence: 1.0, Tags: []string{"tool-arguments"},
		}},
	}
}

// strongerACPVerdict is the stronger of two verdicts of one frame, holding
// the findings of both.
func strongerACPVerdict(current, next *ToolInspectVerdict) *ToolInspectVerdict {
	if next == nil {
		return current
	}
	if current == nil {
		return next
	}
	winner, other := current, next
	if acpVerdictRank(next) > acpVerdictRank(current) {
		winner, other = next, current
	}
	out := *winner
	out.Findings = append(slices.Clone(winner.Findings), other.Findings...)
	out.DetailedFindings = append(slices.Clone(winner.DetailedFindings), other.DetailedFindings...)
	return &out
}

func acpVerdictRank(verdict *ToolInspectVerdict) int {
	rank := 0
	switch normalizeCodexAction(verdict.Action) {
	case "block":
		rank = 30
	case "confirm":
		rank = 20
	case "alert":
		rank = 10
	}
	return rank + severityRank[strings.ToUpper(strings.TrimSpace(verdict.Severity))]
}
