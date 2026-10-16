// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"strings"
)

// KiroUnverifiedWriteArgs is the projection of a Kiro write-class tool call
// that fits none of the reviewed shapes below: it is judged as a patch whose
// write targets are unknown (the protected files may be among them), so a
// fail-closed hook gives the conservative block instead of a silent allow.
var KiroUnverifiedWriteArgs = json.RawMessage(`{}`)

// KiroTrustedWriteArgs projects a Kiro native file-write call onto the
// reviewed write contracts the trusted-action parser judges (write_file
// {path, content} and edit {file_path, old_string, new_string}), carrying
// the text the call writes as content, so its target reaches the same
// file-write rules as Claude Code's Write and Edit and content rules fire
// too. The native tool names and argument shapes differ across Kiro surfaces.
//
// The shapes (keys outside them make the call unreviewed):
//
//   - kiro-cli write, fs_write and fsWrite: command create|append|insert|
//     str_replace|strReplace, path, and the command's text and line fields.
//     Create accepts content, file_text, fileText or new_str/newStr; append
//     and insert accept content or new_str/newStr. Insert may specify
//     insert_line/insertLine; replacement accepts old_str/oldStr and
//     new_str/newStr, with an optional boolean replaceAll.
//   - Kiro IDE fs_write/fsWrite and fs_append/fsAppend {path, text}:
//     text is the content written.
//   - str_replace/strReplace {path, oldStr, newStr} or the snake_case
//     spellings: an edit.
//
// Every shape may carry Kiro's __tool_use_purpose note and a summary.
// fs_write {path, content} is already a reviewed write shape and is left
// alone (ok false); with a note it is projected as write_file too. Every
// other unreviewed write call is projected onto apply_patch with unknown
// targets, so the fail-closed hook blocks it.
func KiroTrustedWriteArgs(toolName string, args json.RawMessage) (tool string, projected json.RawMessage, ok bool) {
	name := strings.TrimSpace(toolName)
	switch name {
	case "write", "fs_write", "fsWrite", "fs_append", "fsAppend", "str_replace", "strReplace":
	default:
		return "", args, false
	}
	fields, valid := hermesWriteFields(args)
	if valid && name == "fs_write" && len(fields) == 2 {
		path, pathOK := hermesString(fields, "path")
		_, contentOK := hermesString(fields, "content")
		if pathOK && strings.TrimSpace(path) != "" && contentOK {
			return "", args, false
		}
	}
	if valid {
		if tool, out, ok := kiroWriteView(name, fields); ok {
			return tool, out, true
		}
	}
	return "apply_patch", KiroUnverifiedWriteArgs, true
}

// kiroLabelKeys are notes Kiro adds to a tool call; they write nothing.
var kiroLabelKeys = []string{"__tool_use_purpose", "summary"}

func kiroWriteView(name string, fields map[string]json.RawMessage) (string, json.RawMessage, bool) {
	path, ok := hermesString(fields, "path")
	if !ok || strings.TrimSpace(path) == "" {
		return "", nil, false
	}
	for _, key := range kiroLabelKeys {
		if _, ok := kiroOptionalString(fields, key); !ok {
			return "", nil, false
		}
	}
	if _, cli := fields["command"]; cli && (name == "write" || name == "fs_write" || name == "fsWrite") {
		command, ok := hermesString(fields, "command")
		if !ok {
			return "", nil, false
		}
		switch command {
		case "create":
			if !kiroOnlyKeys(fields, "command", "path", "content", "file_text", "fileText", "new_str", "newStr") {
				return "", nil, false
			}
			if raw, present := fields["file_text"]; present && hermesJSONNull(raw) {
				// The CLI uses new_str when its optional file_text is null.
				if !kiroOnlyKeys(fields, "command", "path", "file_text", "new_str", "newStr") {
					return "", nil, false
				}
				return kiroRequiredWriteFileView(fields, path, "new_str", "newStr")
			}
			return kiroRequiredWriteFileView(fields, path, "content", "file_text", "fileText", "new_str", "newStr")
		case "append":
			if !kiroOnlyKeys(fields, "command", "path", "content", "new_str", "newStr") {
				return "", nil, false
			}
			return kiroRequiredWriteFileView(fields, path, "content", "new_str", "newStr")
		case "insert":
			if !kiroOnlyKeys(fields, "command", "path", "insert_line", "insertLine", "content", "new_str", "newStr") ||
				!kiroAliasedLine(fields, "insert_line", "insertLine") {
				return "", nil, false
			}
			return kiroRequiredWriteFileView(fields, path, "content", "new_str", "newStr")
		case "str_replace", "strReplace":
			if !kiroOnlyKeys(fields, "command", "path", "old_str", "oldStr", "new_str", "newStr", "replaceAll") {
				return "", nil, false
			}
			if raw, present := fields["replaceAll"]; present {
				var replaceAll bool
				if hermesJSONNull(raw) || json.Unmarshal(raw, &replaceAll) != nil {
					return "", nil, false
				}
			}
			return kiroAliasedEditView(fields, path)
		default:
			return "", nil, false
		}
	}
	switch name {
	case "fs_write", "fsWrite", "fs_append", "fsAppend":
		if kiroOnlyKeys(fields, "path", "text") {
			return kiroRequiredWriteFileView(fields, path, "text")
		}
		if (name == "fs_write" || name == "fsWrite") && kiroOnlyKeys(fields, "path", "content") {
			return kiroRequiredWriteFileView(fields, path, "content")
		}
	case "write":
		if kiroOnlyKeys(fields, "path", "content") {
			return kiroRequiredWriteFileView(fields, path, "content")
		}
	case "str_replace", "strReplace":
		if kiroOnlyKeys(fields, "path", "oldStr", "newStr", "old_str", "new_str") {
			return kiroAliasedEditView(fields, path)
		}
	}
	return "", nil, false
}

func kiroRequiredWriteFileView(fields map[string]json.RawMessage, path string, keys ...string) (string, json.RawMessage, bool) {
	text, ok := kiroAliasedString(fields, keys...)
	if !ok {
		return "", nil, false
	}
	return kiroWriteFileView(path, text)
}

func kiroWriteFileView(path, content string) (string, json.RawMessage, bool) {
	out, err := json.Marshal(map[string]string{"path": path, "content": content})
	if err != nil {
		return "", nil, false
	}
	return "write_file", out, true
}

func kiroAliasedEditView(fields map[string]json.RawMessage, path string) (string, json.RawMessage, bool) {
	_, snakeOld := fields["old_str"]
	_, snakeNew := fields["new_str"]
	_, camelOld := fields["oldStr"]
	_, camelNew := fields["newStr"]
	if (snakeOld || snakeNew) && (camelOld || camelNew) &&
		(!snakeOld || !snakeNew || !camelOld || !camelNew) {
		return "", nil, false
	}
	oldText, oldOK := kiroAliasedString(fields, "old_str", "oldStr")
	newText, newOK := kiroAliasedString(fields, "new_str", "newStr")
	if !oldOK || !newOK {
		return "", nil, false
	}
	out, err := json.Marshal(map[string]string{"file_path": path, "old_string": oldText, "new_string": newText})
	if err != nil {
		return "", nil, false
	}
	return "edit", out, true
}

// kiroAliasedString accepts equivalent spellings only when their values agree.
func kiroAliasedString(fields map[string]json.RawMessage, keys ...string) (string, bool) {
	var text string
	seen := false
	for _, key := range keys {
		raw, present := fields[key]
		if !present {
			continue
		}
		if hermesJSONNull(raw) {
			return "", false
		}
		value, ok := hermesString(fields, key)
		if !ok || (seen && text != value) {
			return "", false
		}
		text, seen = value, true
	}
	return text, seen
}

func kiroAliasedLine(fields map[string]json.RawMessage, keys ...string) bool {
	var line uint64
	seen := false
	for _, key := range keys {
		raw, present := fields[key]
		if !present {
			continue
		}
		var value uint64
		if hermesJSONNull(raw) || json.Unmarshal(raw, &value) != nil || (seen && line != value) {
			return false
		}
		line, seen = value, true
	}
	return true
}

// kiroOnlyKeys reports whether every key of fields is one of keys or a Kiro
// label key. The views check that their required keys are present.
func kiroOnlyKeys(fields map[string]json.RawMessage, keys ...string) bool {
	for key := range fields {
		if !kiroListed(key, keys) && !kiroListed(key, kiroLabelKeys) {
			return false
		}
	}
	return true
}

func kiroListed(key string, keys []string) bool {
	for _, listed := range keys {
		if key == listed {
			return true
		}
	}
	return false
}

// kiroOptionalString reads an optional string argument: absent or JSON null
// is "", true; any other non-string value is not one.
func kiroOptionalString(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, present := fields[key]
	if !present || hermesJSONNull(raw) {
		return "", true
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return "", false
	}
	return text, true
}
