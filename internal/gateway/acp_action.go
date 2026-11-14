// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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
	// trunc holds the caps hit while reading the frame (more locations than
	// the bound, a field left out of the kept state for size, an action
	// whose shape is not known). What was read is judged as usual and the
	// verdict is then raised to the unknown tier of the pack
	// (internal/guardrail/bounded), never below.
	trunc bounded.CapSet
}

// acpMaxFrameToolCalls bounds the locations of one frame that are judged one
// by one (a permission naming many). A frame that names more has its first
// ones judged and is then judged at the unknown tier of the pack: alert in
// the default and permissive packs, which the editor shows as the permission
// it asks the user, and block in strict (rel-1-0-10:GAP-0296, GAP-0331).
const acpMaxFrameToolCalls = 64

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
		toolCall, merged := acpMergeToolCall(req.ToolCallState, params.ToolCall)
		calls, prose, read := acpToolCallUpdateCalls(toolCall, goos, true, merged)
		return acpFrameAction{calls: calls, enforceable: true, prose: prose, trunc: merged.Union(read)}, true
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
		update2 := params.Update
		var merged bounded.CapSet
		if acpUpdateNamesAnAction(update2) {
			// A report that carries the kind, input or locations of the call
			// is the call as the editor merges it onto the earlier reports;
			// a status or output update alone names no action.
			update2, merged = acpMergeToolCall(req.ToolCallState, update2)
		}
		calls, prose, read := acpToolCallUpdateCalls(update2, goos, false, merged)
		if len(calls) == 0 {
			// A status or output report names no action: its text is agent
			// output, judged as before.
			return acpFrameAction{}, false
		}
		return acpFrameAction{calls: calls, prose: prose, trunc: merged.Union(read)}, true
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
		// The value is always quoted: a bare word after = is a command in
		// PowerShell, and a value is data in both shells.
		if goos == "windows" {
			line.WriteString("$env:" + *variable.Name + "=" + acpQuoteAlways(*variable.Value, goos) + "; ")
		} else {
			line.WriteString(*variable.Name + "=" + acpQuoteAlways(*variable.Value, goos) + " ")
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
// permission for an action it does not show is refused as unread, unless
// carried says the guard's state of the call was cut or dropped: then the
// action is not known and the frame is judged at the unknown tier. trunc holds
// the caps hit: more locations than acpMaxFrameToolCalls (the first ones are
// judged), or an action whose shape could not be fixed.
//
// Only a read reads. Every other kind is an action on its locations and they
// are judged as writes: an edit, a delete, a move (a write of the destination
// and a delete of the source), and the kinds that name no file action of their
// own (search, other, think...), whose locations are not known to be only read
// (rel-1-0-10:GAP-0373). A call without a kind (the field is optional in an
// update, and the kind may have come only in the first report, which the guard
// merges in) is read by the shape of its input: a command is a shell call, text
// to write or a replacement is a Write or Edit of its location. A location or
// input that shows no action at all is unknown: judged as a read and raised to
// the unknown tier of the pack, never a write the input does not show
// (rel-1-0-10:GAP-0330, GAP-0375).
func acpToolCallUpdateCalls(raw json.RawMessage, goos string, permission bool, carried bounded.CapSet) (calls []acpToolCall, prose string, caps bounded.CapSet) {
	var call struct {
		Kind      string          `json:"kind"`
		Title     string          `json:"title"`
		RawInput  json.RawMessage `json:"rawInput"`
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
	}
	var trunc bounded.Truncated // one per reading, never copied
	if json.Unmarshal(raw, &call) != nil {
		if permission {
			return []acpToolCall{{unread: true}}, "", trunc.Set()
		}
		return nil, "", trunc.Set()
	}
	prose = acpToolCallProse(raw)
	input := map[string]json.RawMessage{}
	hasInput := acpJSONObject(call.RawInput) && json.Unmarshal(call.RawInput, &input) == nil && len(input) > 0
	var paths []string
	if path := acpInputString(input, "file_path", "filePath", "path", "absolute_path", "abs_path", "target_file", "notebook_path"); path != "" {
		paths = append(paths, path)
	}
	addPath := func(path string) bool {
		path = strings.TrimSpace(path)
		if path == "" || slices.Contains(paths, path) {
			return true
		}
		if len(paths) == acpMaxFrameToolCalls {
			trunc.Hit(bounded.Locations)
			return false
		}
		paths = append(paths, path)
		return true
	}
	for _, location := range call.Locations {
		if !addPath(location.Path) {
			break
		}
	}
	// A move names its two ends in its input as often as in its locations.
	sources := acpInputPaths(input, "source", "src", "from", "old_path", "oldPath", "source_path", "sourcePath", "old_file_path")
	destinations := acpInputPaths(input, "destination", "dest", "dst", "to", "new_path", "newPath", "destination_path", "destinationPath", "target", "new_file_path")
	if call.Kind == "move" {
		for _, path := range append(slices.Clone(sources), destinations...) {
			if !addPath(path) {
				break
			}
		}
	}
	if !hasInput && len(paths) == 0 {
		if permission {
			if carried.Any() {
				// The guard cut or dropped what it kept of this call, so the
				// permission that names only its id shows no action: not known,
				// judged by the unknown tier, not a refusal as unreadable.
				// The judge, where one is configured, is shown what the agent did
				// show of the call: its id and title.
				return []acpToolCall{{tool: "acp_tool", args: raw}}, prose, trunc.Set()
			}
			// The editor is asked to allow an action the frame does not
			// show: it cannot be shown to be safe.
			return []acpToolCall{{unread: true}}, prose, trunc.Set()
		}
		return nil, prose, trunc.Set()
	}
	// The text an edit writes, under the names ACP agents use. Kiro's own
	// fs_write and str_replace inputs say file_text, old_str and new_str
	// (connector.KiroTrustedWriteArgs); read only as "content", the text
	// never reached the content rules.
	content, hasContent := acpInputTextOf(input, "content", "file_text", "fileText", "text")
	oldText, hasOld := acpInputTextOf(input, "old_string", "old_str", "oldStr", "oldString")
	newText, hasNew := acpInputTextOf(input, "new_string", "new_str", "newStr", "newString")
	kind := call.Kind
	if kind == "" {
		_, hasCommand := acpInputCommandKey(input)
		switch {
		case hasCommand:
			kind = "execute"
		case len(paths) > 0 && (hasContent || hasOld && hasNew):
			kind = "edit"
		case len(paths) > 0:
			// A path and no text to write: the action it asks for is not
			// shown. Read as a read, at the unknown tier.
			kind = "read"
			trunc.Hit(bounded.Items)
		default:
			// An input that names no command and no location: the action it
			// performs is not known.
			trunc.Hit(bounded.Items)
		}
	}
	added := 0
	addPaths := func(tool string, args func(path string) map[string]string) {
		for _, path := range paths {
			if added == acpMaxFrameToolCalls {
				trunc.Hit(bounded.Locations)
				return
			}
			added++
			calls = append(calls, acpToolCall{tool: tool, args: acpMarshal(args(path))})
		}
	}
	write := func(path string) map[string]string { return map[string]string{"file_path": path} }
	switch kind {
	case "execute":
		command, ok := acpInputCommand(input, goos)
		if !ok {
			// A shell call with no command the gateway can read: judged as
			// the hook path judges it (unverifiedShellCommandFinding).
			args := call.RawInput
			if !hasInput {
				args = json.RawMessage(`{}`)
			}
			return []acpToolCall{{tool: "shell", args: args}}, prose, trunc.Set()
		}
		return []acpToolCall{{tool: "shell", args: acpCommandArgs(command),
			cwd: acpInputString(input, "cwd", "workdir", "working_directory", "directory")}}, prose, trunc.Set()
	case "read":
		addPaths("Read", write)
	case "edit":
		addPaths("Write", func(path string) map[string]string {
			switch {
			case hasOld && hasNew && path == paths[0]:
				return map[string]string{"file_path": path, "old_string": oldText, "new_string": newText}
			case hasContent && path == paths[0]:
				return map[string]string{"file_path": path, "content": content}
			}
			return write(path)
		})
		if hasOld && hasNew && len(calls) > 0 {
			calls[0].tool = "Edit"
		}
	case "delete":
		addPaths("delete_file", func(path string) map[string]string { return map[string]string{"path": path} })
	case "move":
		// The source goes (a delete), the destination is written. An end the
		// input does not name as one is both.
		for _, path := range paths {
			if added >= acpMaxFrameToolCalls {
				trunc.Hit(bounded.Locations)
				break
			}
			added++
			isSource, isDestination := slices.Contains(sources, path), slices.Contains(destinations, path)
			if isSource || !isDestination {
				calls = append(calls, acpToolCall{tool: "delete_file", args: acpMarshal(map[string]string{"path": path})})
			}
			if isDestination || !isSource {
				calls = append(calls, acpToolCall{tool: "Write", args: acpMarshal(write(path))})
			}
		}
	case "fetch":
		if url := acpInputString(input, "url", "uri"); url != "" {
			calls = append(calls, acpToolCall{tool: "WebFetch", args: acpMarshal(map[string]string{"url": url})})
		}
	}
	if len(calls) > 0 {
		return calls, prose, trunc.Set()
	}
	// Any other kind (search, other, think, ...) or a kind the input does not
	// fit: a tool call under the tool's name, read by the non-shell tool lane,
	// with each location judged as a write of that path: a tool of that kind
	// is not shown to only read it.
	args := call.RawInput
	if !hasInput {
		args = json.RawMessage(`{}`)
	}
	calls = append(calls, acpToolCall{tool: acpToolName(call.Title, kind), args: args})
	addPaths("Write", write)
	return calls, prose, trunc.Set()
}

// acpInputPaths are the paths the input names under keys (a string or a list
// of strings).
func acpInputPaths(input map[string]json.RawMessage, keys ...string) []string {
	var out []string
	for _, key := range keys {
		raw, ok := input[key]
		if !ok {
			continue
		}
		var one string
		var many []string
		switch {
		case json.Unmarshal(raw, &one) == nil:
			many = []string{one}
		case json.Unmarshal(raw, &many) != nil:
			continue
		}
		for _, path := range many {
			if path = strings.TrimSpace(path); path != "" && !slices.Contains(out, path) {
				out = append(out, path)
			}
		}
	}
	return out
}

// acpUpdateNamesAnAction reports that a tool_call report carries the kind,
// the input or the locations of its call.
func acpUpdateNamesAnAction(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, name := range []string{"kind", "rawInput", "locations"} {
		if value, ok := fields[name]; ok && strings.TrimSpace(string(value)) != "null" {
			return true
		}
	}
	return false
}

// acpMergeToolCall applies a ToolCallUpdate (own) onto the fields the guard
// kept of the call it names (state, Evaluation.ToolCallState), as the editor
// does: a field own holds replaces the kept one. A field the guard cut or left
// out of the state for size, or a state it dropped to make room, is a cap hit.
func acpMergeToolCall(state, own json.RawMessage) (json.RawMessage, bounded.CapSet) {
	var trunc bounded.Truncated
	if len(state) == 0 {
		return own, trunc.Set()
	}
	var kept struct {
		Kind      json.RawMessage `json:"kind"`
		Title     json.RawMessage `json:"title"`
		RawInput  json.RawMessage `json:"rawInput"`
		Locations json.RawMessage `json:"locations"`
		Truncated bool            `json:"truncated"`
		Dropped   bool            `json:"dropped"`
	}
	var fields map[string]json.RawMessage
	if len(state) > acp.MaxFrameBytes || json.Unmarshal(state, &kept) != nil || json.Unmarshal(own, &fields) != nil || fields == nil {
		return own, trunc.Set()
	}
	if kept.Truncated {
		trunc.Hit(bounded.Bytes)
	}
	if kept.Dropped {
		trunc.Hit(bounded.Items)
	}
	for name, value := range map[string]json.RawMessage{"kind": kept.Kind, "title": kept.Title, "rawInput": kept.RawInput, "locations": kept.Locations} {
		if len(value) == 0 {
			continue
		}
		if present, ok := fields[name]; !ok || strings.TrimSpace(string(present)) == "null" {
			fields[name] = value
		}
	}
	return acpMarshal(fields), trunc.Set()
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

// acpInputCommandKey reports that input names a command (command or cmd), in
// whatever shape.
func acpInputCommandKey(input map[string]json.RawMessage) (string, bool) {
	for _, key := range []string{"command", "cmd"} {
		if _, ok := input[key]; ok {
			return key, true
		}
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

// acpInputTextOf is the text under the first of keys that holds a string.
func acpInputTextOf(input map[string]json.RawMessage, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := acpInputText(input, key); ok {
			return value, true
		}
	}
	return "", false
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

// acpQuoteAlways quotes a value even when it is a plain word.
func acpQuoteAlways(word, goos string) string {
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
	tier := a.boundedTier(ctx, connectorName)
	var trunc bounded.Truncated
	trunc.Merge(action.trunc)
	for _, call := range action.calls {
		var judged *ToolInspectVerdict
		cwd := acpCallDirectory(req.SessionCWD, call.cwd)
		if call.unread {
			judged = acpUnreadToolCallVerdict(connectorName)
		} else {
			if acpCallNeedsDirectory(call) && !acpAbsolute(cwd) {
				// A command runs in the directory the frame names, else in
				// the session's; a file named relative to one. With none
				// known, the rules read what the call names relative to
				// nothing: judged as given, then raised to the unknown tier
				// of the pack, never clean (rel-1-0-10:GAP-0297, GAP-0331).
				trunc.Hit(bounded.Paths)
			}
			// Judged as the hook path judges a tool call that can be
			// refused. The report of a tool the agent already ran is then
			// capped below: an alert that would have blocked, as for a hook
			// event outside a connector's block events.
			// A frame cut at a bound is judged in full: the judge's
			// proven-read skip reads only what was kept.
			callCtx := ctx
			if trunc.Any() {
				callCtx = withJudgeInputCut(ctx)
			}
			judged = a.inspectAgentHookToolCall(callCtx, agentHookRequest{
				ConnectorName: connectorName,
				HookEventName: req.Method,
				SessionID:     session,
				// The working directory is read as a hook event's is: kept
				// as reported, and placed by the same rule (Windows cleaning,
				// the account's own folders) for the rules that need a place.
				CWD:         hookCWDForContext(ctx, cwd),
				ReportedCWD: cwd,
				ToolName:    call.tool,
				ToolArgs:    call.args,
				Direction:   "tool_call",
			}, profile, true)
		}
		verdict = strongerACPVerdict(verdict, judged)
	}
	// What was read before a cap decides on its own; a frame cut short or
	// read relative to nothing is at least the unknown tier of the pack: alert
	// in the default and permissive packs (the editor still asks the user a
	// permission), block in strict.
	verdict.floorBoundedTruncated(trunc.Set(), tier)
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

// acpCallNeedsDirectory reports a call whose verdict depends on the
// directory it runs in: a shell command, and a file call that names its path
// relative.
func acpCallNeedsDirectory(call acpToolCall) bool {
	if call.tool == "shell" {
		return true
	}
	switch call.tool {
	case "Read", "Write", "Edit", "delete_file":
		var args struct {
			FilePath string `json:"file_path"`
			Path     string `json:"path"`
		}
		if json.Unmarshal(call.args, &args) != nil {
			return false
		}
		path := strings.TrimSpace(args.FilePath + args.Path)
		return path != "" && !acpAbsolute(path)
	}
	return false
}

// acpAbsolute reports a path or directory that names its place by itself, in
// either platform's spelling: a rooted POSIX path, a drive or UNC path of
// Windows, or one under the home (~). A Windows spelling is absolute here
// whatever platform the gateway runs on, as the rules read it.
func acpAbsolute(path string) bool {
	path = strings.TrimSpace(path)
	switch {
	case path == "":
		return false
	case filepath.IsAbs(path), strings.HasPrefix(path, "/"), strings.HasPrefix(path, `\\`), strings.HasPrefix(path, "~"):
		return true
	case len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') &&
		(path[0]|0x20) >= 'a' && (path[0]|0x20) <= 'z':
		return true
	}
	return false
}

// acpCallDirectory is the directory an ACP action runs in: the one the frame
// names (joined to the session's when relative), else the session's, else "".
func acpCallDirectory(sessionCWD, callCWD string) string {
	sessionCWD, callCWD = strings.TrimSpace(sessionCWD), strings.TrimSpace(callCWD)
	if callCWD == "" {
		return sessionCWD
	}
	if filepath.IsAbs(callCWD) || sessionCWD == "" {
		return callCWD
	}
	return hookpaths.JoinDirectoryText(sessionCWD, callCWD)
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
