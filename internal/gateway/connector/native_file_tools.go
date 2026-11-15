// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"strings"
)

// nativeFileRole is what one argument of a native file tool means.
type nativeFileRole uint8

const (
	nativeFilePath nativeFileRole = iota + 1
	nativeFileContent
	nativeFileOld
	nativeFileNew
	nativeFileReplaceAll
	// nativeFileEmpty is a boolean that, when true, writes an empty file.
	nativeFileEmpty
	// The others change neither the target nor the bytes written: model
	// labels (a string), line windows (a number), a range (a list).
	nativeFileLabel
	nativeFileNumber
	nativeFileList
)

// nativeFileShape is one native file tool: the Claude Code tool it performs
// (Write, Edit or Read) and the meaning of each argument it may carry.
type nativeFileShape struct {
	tool string
	args map[string]nativeFileRole
}

var antigravityLabels = map[string]nativeFileRole{
	"toolAction": nativeFileLabel, "toolSummary": nativeFileLabel,
}

func withLabels(base map[string]nativeFileRole, labels map[string]nativeFileRole) map[string]nativeFileRole {
	out := make(map[string]nativeFileRole, len(base)+len(labels))
	for key, role := range labels {
		out[key] = role
	}
	for key, role := range base {
		out[key] = role
	}
	return out
}

// nativeFileShapes are the native file write, edit and read tools whose
// argument names differ from the reviewed shapes ActionFacts and CodeGuard
// read (Claude Code Write {file_path, content}, Edit {file_path, old_string,
// new_string}, Read {file_path}). Judged under their own names they named no
// target: antigravity's tools took the MCP-argument path (alert only where
// Claude Code blocks a protected path, rel-1-0-10:GAP-0779), Amp's edit_file
// had no protected-path rules (GAP-0778) and Copilot's view read as an MCP
// argument (GAP-0781). Each shape is exact: any other argument, a mistyped
// one or a missing target leaves the call as it was.
var nativeFileShapes = map[string]nativeFileShape{
	// Antigravity (agy) write_to_file {TargetFile, CodeContent, EmptyFile}.
	"write_to_file": {tool: "Write", args: withLabels(map[string]nativeFileRole{
		"TargetFile": nativeFilePath, "CodeContent": nativeFileContent, "EmptyFile": nativeFileEmpty,
	}, antigravityLabels)},
	// agy replace_file_content {TargetFile, TargetContent, ReplacementContent, AllowMultiple}.
	"replace_file_content": {tool: "Edit", args: withLabels(map[string]nativeFileRole{
		"TargetFile": nativeFilePath, "TargetContent": nativeFileOld, "ReplacementContent": nativeFileNew,
		"AllowMultiple": nativeFileReplaceAll, "Instruction": nativeFileLabel,
	}, antigravityLabels)},
	// agy view_file {AbsolutePath, StartLine, EndLine}.
	"view_file": {tool: "Read", args: withLabels(map[string]nativeFileRole{
		"AbsolutePath": nativeFilePath, "StartLine": nativeFileNumber, "EndLine": nativeFileNumber,
	}, antigravityLabels)},
	// Amp edit_file {path, old_str, new_str, replace_all}.
	"edit_file": {tool: "Edit", args: map[string]nativeFileRole{
		"path": nativeFilePath, "old_str": nativeFileOld, "new_str": nativeFileNew, "replace_all": nativeFileReplaceAll,
	}},
	// Copilot CLI view {path, view_range}: a file or directory read.
	"view": {tool: "Read", args: map[string]nativeFileRole{
		"path": nativeFilePath, "view_range": nativeFileList,
	}},
}

// NativeFileToolView maps a native file write, edit or read tool call onto
// the Claude Code tool it performs and that tool's reviewed arguments, so
// the call gets the same file-write or read facts, protected-path rules and
// content scan as Claude Code's Write, Edit or Read (one normalization point
// for every connector and route, rel-1-0-10:GAP-0778, GAP-0779, GAP-0781).
// ok is false, and the call is left alone, for any other tool or argument
// set. A write with EmptyFile true writes no content.
func NativeFileToolView(toolName string, args json.RawMessage) (tool string, projected json.RawMessage, ok bool) {
	shape, known := nativeFileShapes[strings.TrimSpace(toolName)]
	if !known || antigravityValidateUniqueJSON(args) != nil {
		return toolName, args, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return toolName, args, false
	}
	var path, content, oldText, newText string
	var hasPath, hasContent, hasOld, hasNew, replaceAll, empty bool
	text := func(raw json.RawMessage) (string, bool) {
		var value string
		return value, json.Unmarshal(raw, &value) == nil && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
	}
	for key, raw := range fields {
		role, known := shape.args[key]
		if !known {
			return toolName, args, false
		}
		switch role {
		case nativeFilePath:
			value, ok := text(raw)
			if !ok || strings.TrimSpace(value) == "" {
				return toolName, args, false
			}
			path, hasPath = value, true
		case nativeFileContent, nativeFileOld, nativeFileNew:
			value, ok := text(raw)
			if !ok {
				return toolName, args, false
			}
			switch role {
			case nativeFileContent:
				content, hasContent = value, true
			case nativeFileOld:
				oldText, hasOld = value, true
			default:
				newText, hasNew = value, true
			}
		case nativeFileReplaceAll, nativeFileEmpty:
			var flag bool
			if json.Unmarshal(raw, &flag) != nil {
				return toolName, args, false
			}
			if role == nativeFileEmpty {
				empty = flag
			} else {
				replaceAll = flag
			}
		case nativeFileLabel:
			if _, ok := text(raw); !ok {
				return toolName, args, false
			}
		case nativeFileNumber:
			var number float64
			if json.Unmarshal(raw, &number) != nil {
				return toolName, args, false
			}
		case nativeFileList:
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) != nil {
				return toolName, args, false
			}
		}
	}
	if !hasPath {
		return toolName, args, false
	}
	out := map[string]any{"file_path": path}
	switch shape.tool {
	case "Write":
		if empty {
			content, hasContent = "", true
		}
		if !hasContent {
			return toolName, args, false
		}
		out["content"] = content
	case "Edit":
		if !hasOld || !hasNew {
			return toolName, args, false
		}
		out["old_string"], out["new_string"] = oldText, newText
		if replaceAll {
			out["replace_all"] = true
		}
	}
	encoded, err := MarshalToolArgs(out)
	if err != nil {
		return toolName, args, false
	}
	return shape.tool, encoded, true
}

// CursorTrustedReadArgs projects Cursor's beforeReadFile payload ({file_path,
// content, and the session fields every Cursor hook carries}) onto Claude
// Code's Read {file_path}. The event names no tool, so the whole payload was
// judged as an unknown tool's arguments: a read of an SSH private key took
// the MCP-argument path and alerted where Cursor's own preToolUse Read and
// Claude Code block (rel-1-0-10:GAP-0781). Refused (ok false) for any other
// event or a payload without a non-blank string file_path.
func CursorTrustedReadArgs(event string, payload json.RawMessage) (projected json.RawMessage, ok bool) {
	if canonicalHookEvent(event) != "beforereadfile" || antigravityValidateUniqueJSON(payload) != nil {
		return payload, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || fields == nil {
		return payload, false
	}
	var path string
	if raw, present := fields["file_path"]; !present || json.Unmarshal(raw, &path) != nil || strings.TrimSpace(path) == "" {
		return payload, false
	}
	out, err := MarshalToolArgs(map[string]string{"file_path": path})
	if err != nil {
		return payload, false
	}
	return out, true
}
