// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/flow"
)

// The Secret flow tracking result adapter (S7, rel-1-0-10 GAP-0125, GAP-0126).
//
// The value lane compares what a call sends with the secret values the session
// saw in the results of credential reads. Every connector reports a finished
// tool call in its own event, under its own field, in its own shape. This file
// is the one place that turns any of them into the text of the result and the
// call that produced it:
//
//   - which events carry a tool's output (secretFlowResultEvent);
//   - where the output sits in the payload and how to read it
//     (secretFlowResultText: strings, objects, arrays, JSON in a string);
//   - the call that produced it, projected the way the pre-call path projects
//     it, with the shell dialect the session's call ran under
//     (secretFlowResultCall).
//
// A connector whose post-tool event is not listed here, or whose output is under
// a field this adapter does not read, indexes nothing: the value lane then does
// not run on it. The per-connector table test pins every supported shape.

// secretFlowResultEvent reports a post-tool event that carries the output of a
// tool call. Model and agent responses, failures and denials are not tool
// output a credential read can leave a value in.
func secretFlowResultEvent(event string) bool {
	switch canonicalEvent(event) {
	case "posttooluse", "aftertool", "posttoolcall", "postreadcode", "postruncommand",
		"postmcptooluse", "aftershellexecution", "aftermcpexecution",
		"toolexecuteafter", "toolresult":
		return true
	}
	return false
}

// secretFlowResultKeys are the payload fields connectors put a tool's output
// under (Claude Code tool_response, Copilot toolResult, Cursor tool_output /
// output / result_json, Amp and generic result, Devin mcp_result).
var secretFlowResultKeys = []string{
	"tool_response", "toolResponse", "tool_result", "toolResult", "result",
	"tool_output", "toolOutput", "output", "result_json", "mcp_result",
}

// secretFlowResultNestedKeys are result fields one object down (Hermes puts
// them in extra, other payloads in tool_info).
var secretFlowResultNestedKeys = map[string][]string{
	"extra":     {"result", "output"},
	"tool_info": {"mcp_result", "response", "output"},
}

// secretFlowMetaKeys are fields of a result object that name the call, not its
// output.
var secretFlowMetaKeys = map[string]bool{
	"filePath": true, "file_path": true, "path": true, "cwd": true, "type": true,
	"status": true, "opencode_v2_status": true, "tool_use_id": true, "id": true,
	"mimeType": true, "resultType": true,
}

const (
	secretFlowResultMaxBytes = 1 << 20
	secretFlowResultMaxNodes = 4096
	secretFlowResultMaxDepth = 8
)

// secretFlowResultText returns the text of a tool result: every string in the
// result fields of the payload, in order, one per line. A result that is an
// object or array is walked (Claude Code's {"stdout": ...} and {"file":
// {"content": ...}}, Codex's content list, OpenCode's nested output); a string
// that holds JSON is parsed and walked (Cursor's result_json). content, the
// request's own content field, is used when the payload has none of the keys.
func secretFlowResultText(payload map[string]interface{}, content string) string {
	var sb strings.Builder
	nodes := 0
	seen := map[string]bool{}
	var walk func(v interface{}, key string, depth int)
	walk = func(v interface{}, key string, depth int) {
		if depth > secretFlowResultMaxDepth || nodes > secretFlowResultMaxNodes || sb.Len() >= secretFlowResultMaxBytes {
			return
		}
		nodes++
		switch t := v.(type) {
		case string:
			if secretFlowMetaKeys[key] || t == "" || seen[t] {
				return
			}
			trim := strings.TrimSpace(t)
			if len(trim) > 1 && (trim[0] == '{' || trim[0] == '[') {
				var inner interface{}
				if json.Unmarshal([]byte(trim), &inner) == nil {
					switch inner.(type) {
					case map[string]interface{}, []interface{}:
						walk(inner, key, depth+1)
						return
					}
				}
			}
			seen[t] = true
			sb.WriteString(t)
			sb.WriteByte('\n')
		case map[string]interface{}:
			for k, c := range t {
				walk(c, k, depth+1)
			}
		case []interface{}:
			for _, c := range t {
				walk(c, key, depth+1)
			}
		}
	}
	for _, k := range secretFlowResultKeys {
		if v, ok := payload[k]; ok && v != nil {
			walk(v, k, 0)
		}
	}
	for parent, keys := range secretFlowResultNestedKeys {
		obj, ok := payload[parent].(map[string]interface{})
		if !ok {
			continue
		}
		for _, k := range keys {
			if v, ok := obj[k]; ok && v != nil {
				walk(v, k, 0)
			}
		}
	}
	if sb.Len() == 0 && strings.TrimSpace(content) != "" {
		walk(content, "content", 0)
	}
	return sb.String()
}

// secretFlowHostOptions places a call in the Windows path namespace when the
// hook runs on a Windows host and the call's own paths are Windows paths. A
// hook runs on the same machine as its agent, so a Claude Code Bash call under
// Git Bash, or a Read tool call, there carries a C:\... working directory or
// path whatever the shell. On a POSIX flavor that cwd is unplaceable
// (dynamic_cwd) and no read is ever labeled; on the Windows flavor, with the
// POSIX grammar of Git Bash for a bare shell command, it is placed. A call with
// a POSIX-shaped cwd (a sandbox guest, a test) keeps the POSIX flavor, where
// absolute POSIX paths such as /tmp stay placeable.
func secretFlowHostOptions(call effects.Call, opts effects.Options) effects.Options {
	return secretFlowHostOptionsFor(runtime.GOOS, call, opts)
}

func secretFlowHostOptionsFor(goos string, call effects.Call, opts effects.Options) effects.Options {
	if goos != "windows" || opts.Flavor == effects.FlavorWindows {
		return opts
	}
	cwd := strings.TrimSpace(opts.CWD)
	if cwd == "" {
		cwd = strings.TrimSpace(call.Workdir)
	}
	switch {
	case windowsShapedPath(cwd):
	case cwd == "" && call.Surface != effects.SurfaceShell && call.Surface != effects.SurfaceArgv:
	default:
		return opts
	}
	opts.Flavor = effects.FlavorWindows
	if (opts.Dialect == effects.DialectNone || opts.Dialect == "") && call.Surface == effects.SurfaceShell {
		opts.Dialect = effects.DialectPOSIX
	}
	return opts
}

// windowsShapedPath reports a drive-letter or UNC path.
func windowsShapedPath(p string) bool {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
		(p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z') {
		return true
	}
	return strings.HasPrefix(p, `\\`)
}

// secretFlowCaseInsensitive reports a path namespace that folds case: Windows
// paths always, and a macOS host. It is derived from the call's flavor and the
// gateway's own OS, as the effect lane's callers do.
func secretFlowCaseInsensitive(flavor effects.Flavor) bool {
	return secretFlowCaseInsensitiveFor(runtime.GOOS, flavor)
}

func secretFlowCaseInsensitiveFor(goos string, flavor effects.Flavor) bool {
	return flavor == effects.FlavorWindows || goos == "darwin"
}

// secretFlowResultDialect picks the shell dialect to read a result's call
// under: a PowerShell tool is PowerShell; otherwise the dialect the session's
// last shell call reported; otherwise, on a Windows host, the one the call's
// own command selects. It is empty (POSIX) elsewhere.
func secretFlowResultDialect(sid string, req agentHookRequest, tool string, args json.RawMessage) actionfacts.Dialect {
	if trustedPowerShellExecutionTool(req.ToolName) {
		return actionfacts.DialectPowerShell
	}
	if d := secretFlowSessions.dialectOf(sid); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		return agentHookWindowsShellDialect(actionfacts.Input{Tool: tool, Args: args})
	}
	return ""
}

// secretFlowResultCall rebuilds the effect-extractor call for the tool call a
// result belongs to, the way the pre-call path projects it.
func secretFlowResultCall(req agentHookRequest, home string) (effects.Call, effects.Options, bool) {
	tool := agentHookTrustedActionTool(req.ConnectorName, req.ToolName, runtime.GOOS)
	args, cwd := agentHookTrustedActionArgs(req.ConnectorName, req.ToolName, req.ToolArgs)
	if strings.EqualFold(req.ConnectorName, "cursor") && canonicalEvent(req.HookEventName) == "aftershellexecution" {
		// afterShellExecution names no tool: its payload is the command.
		if command := payloadString(req.Payload, "command"); command != "" {
			if b, err := json.Marshal(map[string]string{"command": command}); err == nil {
				tool, args = "shell", b
			}
		}
	}
	// Cowork's VM shell is Claude Code's Bash, read as POSIX on every host.
	var forced actionfacts.Dialect
	if strings.EqualFold(req.ConnectorName, "claudecode") {
		if cw, ok := claudeCodeCoworkInspectionFor(req.ToolName, req.ToolArgs, req.Payload); ok && cw.actionTool == "Bash" {
			tool, args, forced = cw.actionTool, cw.args, cw.dialect
		}
	}
	if cwd == "" {
		cwd = req.CWD
	}
	input := actionfacts.Input{Tool: tool, Args: args, CWD: cwd, ActiveHome: home}
	if forced != "" {
		input.DialectHint = forced
	} else {
		input.DialectHint = secretFlowResultDialect(req.SessionID, req, tool, args)
	}
	call, opts, has := effectCall(req.ConnectorName, input)
	if !has {
		return effects.Call{}, effects.Options{}, false
	}
	opts = secretFlowHostOptions(call, opts)
	opts.CaseInsensitive = secretFlowCaseInsensitive(opts.Flavor)
	return call, opts, true
}

// addSecretFlowResultValues feeds the secret-shaped values of a successful
// sensitive-read tool result into the session so a later outbound call that
// sends the value (even re-encoded) is caught by the value lane. It stores
// only keyed digests, never the raw value, and is a no-op when the lane is off,
// the event is not a tool result, or the call read nothing the label set labels.
func addSecretFlowResultValues(ctx context.Context, req agentHookRequest) {
	defer func() {
		if r := recover(); r != nil {
			secretFlowPanics.Add(1)
		}
	}()
	if req.SessionID == "" || !secretFlowResultEvent(req.HookEventName) {
		return
	}
	g := currentGeneration()
	if g == nil || g.Config == nil || secretFlowLaneMode(g.Config.Guardrail) == flowLaneOff {
		return
	}
	result := secretFlowResultText(req.Payload, req.Content)
	if strings.TrimSpace(result) == "" {
		return
	}
	// Index the result only when the flow label set labels the read target
	// (one classifier, same as the file labeler). Indexing every tool output
	// would waste the digest budget.
	sf := g.Config.Guardrail.SecretFlow
	home := hookActiveHome(ctx)
	call, opts, ok := secretFlowResultCall(req, home)
	if !ok {
		return
	}
	fcfg := flow.Config{
		Credentials:         sf.CredentialsEnabled(),
		ExtraPathGlobs:      sf.LabelSets.ExtraPathGlobs,
		ExtraSecretPatterns: sf.LabelSets.ExtraSecretPatterns,
		Reencodings:         sf.Reencodings,
		MaxValueDigests:     sf.Memory.MaxValueDigests,
		Home:                home,
		Flavor:              opts.Flavor,
	}
	res := effects.Extract(call, opts)
	labeled := false
	for i := range res.Effects {
		e := &res.Effects[i]
		if e.Kind != effects.KindRead {
			continue
		}
		if _, _, ok := fcfg.LabelForTarget(e.Target); ok {
			labeled = true
			break
		}
	}
	if !labeled {
		return
	}
	st, ok := secretFlowSessions.lookup(req.SessionID)
	if !ok {
		st = secretFlowSessions.session(req.SessionID, flow.Config{
			MaxLabeledPaths: sf.Memory.MaxLabeledPaths,
			MaxValueDigests: sf.Memory.MaxValueDigests,
		})
	}
	st.AddResultValues([]byte(result), "tool_result", fcfg)
}
