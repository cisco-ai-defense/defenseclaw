// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
)

// extractFileTool models a native file-write / edit / read tool call. The tool
// name decides the kind; the target is a path argument. Content is Data, never
// a path.
func extractFileTool(call Call, o Options) Result {
	res := Result{Surface: SurfaceFileTool, Flavor: o.flavor(), Dialect: DialectNone}
	m := decodeArgs(call.Args)
	kind := fileToolKind(call.Tool)
	// Every path key is read: when several name different paths the tool's
	// own key precedence decides which it writes, so each is a target whose
	// role is unknown (S3-PRE security review, DET111 R1).
	pathVals := distinctStrings(m, "file_path", "path", "filePath", "filename", "file", "target", "notebook_path")
	mk := func() Effect {
		return Effect{Kind: kind, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
			Target: Target{Type: TargetPath, Flavor: o.flavor(), Link: LinkNotChecked},
			Origin: Origin{Surface: SurfaceFileTool, Command: 1, Program: call.Tool}}
	}
	if len(pathVals) == 0 {
		e := mk()
		e.Kind = KindOpaque
		e.addReason(ReasonUnknownTool, ScopeTarget)
		res.Effects = append(res.Effects, e)
		return res
	}
	// Schema accounting (review R5-1): an argument key the file-tool schema does
	// not expect means the call is not fully understood -> not fully known.
	unknownKey := false
	for k := range m {
		if !fileToolArgKey(k) {
			unknownKey = true
			break
		}
	}
	content := ""
	if kind == KindWrite {
		content = firstString(m, "content", "new_string", "newString", "contents", "text", "file_text")
	}
	for _, pathVal := range pathVals {
		e := mk()
		e.Target.Spelling = cap4k(pathVal)
		if abs, ok, reason := placePath(pathVal, o); ok {
			e.Target.Path = abs
		} else {
			e.addReason(reason, ScopeTarget)
		}
		if kind == KindWrite {
			e.Data = &Data{Kind: DataLiteral, Bytes: len(content), Text: cap8k(content)}
		}
		if unknownKey || len(pathVals) > 1 {
			e.addReason(ReasonUnknownTool, ScopeRole)
		}
		res.Effects = append(res.Effects, e)
	}
	return res
}

// wholeAbsPath reports a string that is one absolute path and nothing else:
// /x or ~/x on POSIX, C:\x or \\host\x on Windows, no blank or newline.
func wholeAbsPath(v string, o Options) bool {
	if len(v) < 2 || len(v) > maxSpellingBytes || strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~/") {
		return !strings.HasPrefix(v, "//")
	}
	if o.flavor() == FlavorWindows {
		return len(v) > 2 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') || strings.HasPrefix(v, `\\`)
	}
	return false
}

// distinctStrings is every non-empty string value of keys, in key order, each
// once.
func distinctStrings(m map[string]any, keys ...string) []string {
	var out []string
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// fileToolArgKey reports whether a file-tool argument key is in the expected
// schema (path, content, edit, and the common benign metadata connectors add).
func fileToolArgKey(k string) bool {
	switch k {
	case "file_path", "path", "filePath", "filename", "file", "target", "notebook_path",
		"content", "contents", "text", "file_text", "new_string", "newString", "new_str",
		"old_string", "oldString", "old_str", "replace_all", "replaceAll", "cell_id", "cell_number",
		"edits", "changes", "line", "lineNumber", "range", "offset", "limit", "encoding",
		"description", "explanation", "instructions", "language", "mode", "create", "overwrite",
		"display_description", "blocking", "empty_file":
		return true
	}
	return false
}

func fileToolKind(tool string) Kind {
	switch strings.ToLower(tool) {
	case "read", "view", "cat", "notebookread", "read_file", "fs_read", "open_file", "readfile":
		return KindRead
	case "write", "edit", "multiedit", "create", "create_file", "write_file", "writefile",
		"str_replace", "str_replace_editor", "notebookedit", "apply_diff", "edit_file", "fs_write":
		return KindWrite
	}
	return KindWrite
}

// extractPatch parses an apply_patch envelope. This is the GAP-0004-safe path:
// the patch text is Data; only the envelope header names a target, and a
// heredoc/arg whose body merely contains "*** Begin Patch" is data unless the
// tool is apply_patch (which this surface is).
func extractPatch(call Call, o Options) Result {
	res := Result{Surface: SurfacePatch, Flavor: o.flavor(), Dialect: DialectNone}
	text := call.Command
	if text == "" {
		m := decodeArgs(call.Args)
		text = firstString(m, "input", "patch", "command", "content")
	}
	targets, ok := parsePatchEnvelope(text)
	if !ok {
		e := Effect{Kind: KindWrite, TargetState: TargetStateUnknown, RoleState: RoleStateKnown,
			Target: Target{Type: TargetPath, Flavor: o.flavor(), Link: LinkNotChecked},
			Origin: Origin{Surface: SurfacePatch, Command: 1, Program: "apply_patch"},
			Data:   &Data{Kind: DataPatchText}}
		e.addReason(ReasonInvalidSyntax, ScopeTarget)
		res.Effects = append(res.Effects, e)
		return res
	}
	for _, pt := range targets {
		e := Effect{Kind: pt.kind, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
			Target: Target{Type: TargetPath, Spelling: cap4k(pt.path), Flavor: o.flavor(), Link: LinkNotChecked},
			Origin: Origin{Surface: SurfacePatch, Command: 1, Program: "apply_patch"},
			Data:   &Data{Kind: DataPatchText}}
		// A $ or % in a header path is not expanded by the patch tool, but a
		// runner that does would write elsewhere: the target is unknown, and
		// its spelling stays on the effect so the protected-set grade still
		// reads the name (a \\host\c$ share to a credential file is the same
		// name as the file tool's write of it).
		if strings.ContainsAny(pt.path, "$%") {
			e.addReason(ReasonDynamicExpansion, ScopeTarget)
		} else if abs, ok, reason := placePath(pt.path, o); ok {
			e.Target.Path = abs
		} else {
			e.addReason(reason, ScopeTarget)
		}
		res.Effects = append(res.Effects, e)
	}
	return res
}

type patchTarget struct {
	path string
	kind Kind
	// moved marks the targets of an Update File + Move to pair.
	moved bool
}

func parsePatchEnvelope(text string) ([]patchTarget, bool) {
	if !strings.Contains(text, "*** Begin Patch") {
		return nil, false
	}
	var out []patchTarget
	sawEnd := false
	inUpdate := false // inside an Update File chunk body
	for _, line := range strings.Split(text, "\n") {
		// A "*** Delete File:" sitting in an Update File chunk body (a context
		// line, leading blank) is attacker text, not a header (review SF-5).
		// Anywhere else a header the applier trims is one: apply_patch reads a
		// hunk header with its leading blanks trimmed (S3-PRE security review,
		// DET111 R1), so an indented header is read there too.
		l := strings.TrimRight(line, "\r")
		if !strings.HasPrefix(l, "*** ") {
			t := strings.TrimLeft(l, " \t")
			if inUpdate || !strings.HasPrefix(t, "*** ") {
				continue
			}
			l = t
		}
		switch {
		case strings.HasPrefix(l, "*** Add File:"):
			inUpdate = false
			out = append(out, patchTarget{path: strings.TrimSpace(l[len("*** Add File:"):]), kind: KindWrite})
		case strings.HasPrefix(l, "*** Update File:"):
			inUpdate = true
			out = append(out, patchTarget{path: strings.TrimSpace(l[len("*** Update File:"):]), kind: KindWrite})
		case strings.HasPrefix(l, "*** Delete File:"):
			inUpdate = false
			out = append(out, patchTarget{path: strings.TrimSpace(l[len("*** Delete File:"):]), kind: KindDelete})
		case strings.HasPrefix(l, "*** Move to:"):
			// A move after an Update File writes the new name and removes the old
			// one (GAP-1057).
			if n := len(out); n > 0 && out[n-1].kind == KindWrite && !out[n-1].moved {
				out[n-1].moved = true
				out = append(out, patchTarget{path: out[n-1].path, kind: KindDelete, moved: true})
			}
			out = append(out, patchTarget{path: strings.TrimSpace(l[len("*** Move to:"):]), kind: KindWrite, moved: true})
		case strings.HasPrefix(l, "*** End Patch"):
			sawEnd = true
		}
	}
	if !sawEnd || len(out) == 0 {
		return nil, false // an unterminated or empty envelope: unknown targets
	}
	for _, pt := range out {
		if pt.path == "" {
			return nil, false
		}
	}
	return out, true
}

// extractMCP walks a JSON argument object for path- and URL-shaped values. The
// target is known; the effect kind is only guessed from the tool and key names,
// so RoleState is guessed with reason mcp_semantics (review R1).
func extractMCP(call Call, o Options) Result {
	res := Result{Surface: SurfaceMCP, Flavor: o.flavor(), Dialect: DialectNone}
	var root any
	if err := json.Unmarshal(call.Args, &root); err != nil {
		e := Effect{Kind: KindOpaque, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown,
			Origin: Origin{Surface: SurfaceMCP, Command: 1, Program: call.Tool}}
		e.addReason(ReasonUnknownTool, ScopeStructure)
		res.Effects = append(res.Effects, e)
		return res
	}
	kindGuess := mcpKindFromTool(call.Tool)
	nodes := 0
	truncated := false
	var walk func(key string, v any, depth int)
	walk = func(key string, v any, depth int) {
		if depth > maxMCPDepth || nodes > maxMCPNodes || len(res.Effects) >= o.maxEffects() {
			truncated = true // a path/url arg below the cap would be dropped (review SF-6)
			return
		}
		nodes++
		switch t := v.(type) {
		case map[string]any:
			// Sort keys so the effect order is deterministic (review SF-7).
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(k, t[k], depth+1)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv, depth+1)
			}
		case string:
			if scheme, host, _ := parseURL(t); host != "" {
				e := Effect{Kind: mcpURLKind(call.Tool), RoleState: RoleStateGuessed, TargetState: TargetStateKnown,
					Target: Target{Type: TargetURL, URL: cap4k(t), Scheme: scheme, Host: host, Flavor: o.flavor(), Link: LinkNotChecked},
					Origin: Origin{Surface: SurfaceMCP, Command: 1, Program: call.Tool}}
				e.addReason(ReasonMCPSemantics, ScopeRole)
				res.Effects = append(res.Effects, e)
				return
			}
			if looksPathKey(key) && looksAbsOrRel(t) {
				e := Effect{Kind: kindGuess, RoleState: RoleStateGuessed, TargetState: TargetStateKnown,
					Target: Target{Type: TargetPath, Spelling: cap4k(t), Flavor: o.flavor(), Link: LinkNotChecked},
					Origin: Origin{Surface: SurfaceMCP, Command: 1, Program: call.Tool}}
				if abs, ok, reason := placePath(t, o); ok {
					e.Target.Path = abs
				} else {
					e.addReason(reason, ScopeTarget)
				}
				e.addReason(ReasonMCPSemantics, ScopeRole)
				res.Effects = append(res.Effects, e)
				return
			}
			// A whole absolute path under a key that does not name one (query,
			// arg, value) may still be what the server opens: a target of
			// unknown role, never dropped (S3-PRE security review, DET111 R1).
			if wholeAbsPath(t, o) {
				e := Effect{Kind: kindGuess, RoleState: RoleStateUnknown, TargetState: TargetStateKnown,
					Target: Target{Type: TargetPath, Spelling: cap4k(t), Flavor: o.flavor(), Link: LinkNotChecked},
					Origin: Origin{Surface: SurfaceMCP, Command: 1, Program: call.Tool}}
				if abs, ok, reason := placePath(t, o); ok {
					e.Target.Path = abs
				} else {
					e.addReason(reason, ScopeTarget)
				}
				e.addReason(ReasonMCPSemantics, ScopeRole)
				res.Effects = append(res.Effects, e)
			}
		}
	}
	walk("", root, 0)
	if truncated {
		res.addUnknown(ReasonLimit)
	}
	// A tool whose name means "send" (post_message, send_email, create_issue,
	// upload, webhook, ...) exfiltrates even when no URL appears in its arguments
	// (the endpoint is the server's, configured out of band). Emit a network_send
	// with the role only guessed; the host is a guess from a small server table,
	// else unknown (s7-flow). Skip when a URL argument already produced a send.
	if mcpIsSender(call.Tool) {
		hasSend := false
		for _, e := range res.Effects {
			if e.Kind == KindNetworkSend {
				hasSend = true
				break
			}
		}
		if !hasSend && len(res.Effects) < o.maxEffects() {
			e := Effect{Kind: KindNetworkSend, RoleState: RoleStateGuessed, TargetState: TargetStateUnknown,
				Target: Target{Type: TargetHost, Flavor: o.flavor(), Link: LinkNotChecked},
				Origin: Origin{Surface: SurfaceMCP, Command: 1, Program: call.Tool}}
			// The host from the server table is only a guess, so the target stays
			// unknown (review 6 #5): fill it as a hint but never mark it known.
			if host := mcpSendHost(call.Tool); host != "" {
				e.Target.Host = host
				e.addReason(ReasonMCPSemantics, ScopeTarget)
			} else {
				e.addReason(ReasonDynamicExpansion, ScopeTarget)
			}
			e.addReason(ReasonMCPSemantics, ScopeRole)
			res.Effects = append(res.Effects, e)
		}
	}
	if len(res.Effects) == 0 {
		e := Effect{Kind: KindOpaque, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown,
			Origin: Origin{Surface: SurfaceMCP, Command: 1, Program: call.Tool}}
		e.addReason(ReasonMCPSemantics, ScopeStructure)
		res.Effects = append(res.Effects, e)
	}
	return res
}

func mcpKindFromTool(tool string) Kind {
	l := strings.ToLower(tool)
	switch {
	case strings.Contains(l, "delete"), strings.Contains(l, "remove"), strings.Contains(l, "unlink"):
		return KindDelete
	case strings.Contains(l, "write"), strings.Contains(l, "create"), strings.Contains(l, "put"),
		strings.Contains(l, "save"), strings.Contains(l, "edit"), strings.Contains(l, "update"):
		return KindWrite
	case strings.Contains(l, "read"), strings.Contains(l, "get"), strings.Contains(l, "list"),
		strings.Contains(l, "cat"), strings.Contains(l, "view"), strings.Contains(l, "search"):
		return KindRead
	}
	return KindRead
}

// mcpIsSender reports an MCP tool whose name means it transmits data to an
// external service (s7-flow). The match is on the tool name only, so the role is
// always guessed, never known.
func mcpIsSender(tool string) bool {
	l := strings.ToLower(tool)
	for _, s := range []string{"send", "email", "upload", "post", "webhook", "notify",
		"publish", "message", "tweet", "dispatch", "sms", "pager", "create_issue",
		"create_pull", "create_pr", "comment", "http_request"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// mcpSendHost guesses the destination host of a sender MCP tool from a small
// table of common servers. It is a guess (the effect's role stays guessed); an
// empty result leaves the host unknown.
func mcpSendHost(tool string) string {
	l := strings.ToLower(tool)
	switch {
	case strings.Contains(l, "slack"):
		return "slack.com"
	case strings.Contains(l, "github"):
		return "api.github.com"
	case strings.Contains(l, "gitlab"):
		return "gitlab.com"
	case strings.Contains(l, "discord"):
		return "discord.com"
	case strings.Contains(l, "telegram"):
		return "api.telegram.org"
	case strings.Contains(l, "twilio"), strings.Contains(l, "sms"):
		return "api.twilio.com"
	case strings.Contains(l, "pagerduty"):
		return "events.pagerduty.com"
	case strings.Contains(l, "notion"):
		return "api.notion.com"
	case strings.Contains(l, "jira"):
		return "atlassian.net"
	}
	return ""
}

func mcpURLKind(tool string) Kind {
	l := strings.ToLower(tool)
	if strings.Contains(l, "send") || strings.Contains(l, "upload") || strings.Contains(l, "post") || strings.Contains(l, "email") {
		return KindNetworkSend
	}
	return KindNetworkFetch
}

func looksPathKey(k string) bool {
	l := strings.ToLower(k)
	for _, s := range []string{"path", "file", "dir", "dest", "source", "src", "target", "filename", "location"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func looksAbsOrRel(s string) bool {
	if s == "" || len(s) > maxSpellingBytes {
		return false
	}
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") || (len(s) >= 2 && isDriveLetter(s[0]) && s[1] == ':') ||
		strings.ContainsAny(s, `/\`)
}

func decodeArgs(raw json.RawMessage) map[string]any {
	m := map[string]any{}
	if len(raw) == 0 {
		return m
	}
	_ = json.Unmarshal(raw, &m)
	return m
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
