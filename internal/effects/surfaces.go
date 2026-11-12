// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"encoding/json"
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
	pathVal := firstString(m, "file_path", "path", "filePath", "filename", "file", "target", "notebook_path")
	e := Effect{Kind: kind, RoleState: RoleStateKnown, TargetState: TargetStateKnown,
		Target: Target{Type: TargetPath, Flavor: o.flavor(), Link: LinkNotChecked},
		Origin: Origin{Surface: SurfaceFileTool, Command: 1, Program: call.Tool}}
	if pathVal == "" {
		e.Kind = KindOpaque
		e.addReason(ReasonUnknownTool, ScopeTarget)
		res.Effects = append(res.Effects, e)
		return res
	}
	e.Target.Spelling = cap4k(pathVal)
	if abs, ok, reason := placePath(pathVal, o); ok {
		e.Target.Path = abs
	} else {
		e.addReason(reason, ScopeTarget)
	}
	if kind == KindWrite {
		content := firstString(m, "content", "new_string", "newString", "contents", "text", "file_text")
		e.Data = &Data{Kind: DataLiteral, Bytes: len(content), Text: cap8k(content)}
	}
	res.Effects = append(res.Effects, e)
	return res
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
		if abs, ok, reason := placePath(pt.path, o); ok {
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
}

func parsePatchEnvelope(text string) ([]patchTarget, bool) {
	if !strings.Contains(text, "*** Begin Patch") {
		return nil, false
	}
	var out []patchTarget
	sawEnd := false
	for _, line := range strings.Split(text, "\n") {
		// Match headers only at column 0: a "*** Delete File:" sitting in the
		// diff body (a context/'+' line) is attacker text, not a real header
		// (review SF-5).
		l := strings.TrimRight(line, "\r")
		if !strings.HasPrefix(l, "*** ") {
			continue
		}
		switch {
		case strings.HasPrefix(l, "*** Add File:"):
			out = append(out, patchTarget{path: strings.TrimSpace(l[len("*** Add File:"):]), kind: KindWrite})
		case strings.HasPrefix(l, "*** Update File:"):
			out = append(out, patchTarget{path: strings.TrimSpace(l[len("*** Update File:"):]), kind: KindWrite})
		case strings.HasPrefix(l, "*** Delete File:"):
			out = append(out, patchTarget{path: strings.TrimSpace(l[len("*** Delete File:"):]), kind: KindDelete})
		case strings.HasPrefix(l, "*** Move to:"):
			out = append(out, patchTarget{path: strings.TrimSpace(l[len("*** Move to:"):]), kind: KindWrite})
		case strings.HasPrefix(l, "*** End Patch"):
			sawEnd = true
		}
	}
	if !sawEnd || len(out) == 0 {
		return nil, false // an unterminated or empty envelope: unknown targets
	}
	for _, pt := range out {
		if pt.path == "" || strings.ContainsAny(pt.path, "$%") {
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
			}
		}
	}
	walk("", root, 0)
	if truncated {
		res.addUnknown(ReasonLimit)
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
