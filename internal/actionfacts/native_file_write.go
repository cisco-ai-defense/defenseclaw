// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
)

// nativeFileWrite is one file a native file-tool call changes and the text it
// gives that file. replaced is the text an edit tool removes; it is empty for
// a whole-file write.
type nativeFileWrite struct {
	target, added, replaced string
}

// The argument names the reviewed whole-file write tools use for the target and
// the written text (Claude Code Write, the write_file aliases, OpenCode and the
// Copilot CLI create tool), and for a patch envelope.
var (
	nativeFilePathKeys    = []string{"file_path", "filePath", "path"}
	nativeFileContentKeys = []string{"content", "file_text"}
	nativePatchTextKeys   = []string{"command", "patch", "patchText", "patch_text", "input"}
)

// nativeFileWrites reads the files a native file-tool call writes, edits or
// patches, and the text each receives, from the closed argument shapes of the
// reviewed tools. A call whose arguments are not one of those shapes, or whose
// tool is not a file-writing tool, yields nothing, so a proof built on it
// never covers an unreviewed call.
func nativeFileWrites(tool string, args json.RawMessage) []nativeFileWrite {
	if tool == "" || strings.TrimSpace(tool) != tool {
		return nil
	}
	patchTool := isApplyPatchTool(tool)
	if !patchTool {
		semantics, known := lookupToolArgumentSemantics(tool)
		if !known || !semantics.acceptsContent || !semantics.acceptsPaths {
			return nil
		}
	}
	object, problem := exactJSONObject(args)
	if problem.status != "" {
		return nil
	}
	if patchTool {
		return nativePatchWrites(object)
	}
	if _, ok := object["edits"]; ok {
		return nativeMultiEditWrites(object)
	}
	edit := codingAgentEditDialect(object)
	if _, ok := object[edit.old]; ok {
		return nativeEditWrites(object, edit)
	}
	return nativeWholeFileWrites(object)
}

func nativeWholeFileWrites(object map[string]any) []nativeFileWrite {
	if len(object) != 2 {
		return nil
	}
	target, targetOK := nativeStringField(object, nativeFilePathKeys)
	content, contentOK := nativeStringField(object, nativeFileContentKeys)
	if !targetOK || !contentOK {
		return nil
	}
	return []nativeFileWrite{{target: target, added: content}}
}

func nativeEditWrites(object map[string]any, edit codingAgentEditKeys) []nativeFileWrite {
	allowed := map[string]bool{edit.path: true, edit.old: true, edit.new: true}
	if edit.all != "" {
		allowed[edit.all] = true
	}
	for key := range object {
		if !allowed[key] {
			return nil
		}
	}
	target, targetOK := object[edit.path].(string)
	oldText, oldOK := object[edit.old].(string)
	newText, newOK := object[edit.new].(string)
	if !targetOK || !oldOK || !newOK {
		return nil
	}
	return []nativeFileWrite{{target: target, added: newText, replaced: oldText}}
}

func nativeMultiEditWrites(object map[string]any) []nativeFileWrite {
	edit := codingAgentEditDialect(object)
	if len(object) != 2 {
		return nil
	}
	target, targetOK := object[edit.path].(string)
	edits, editsOK := object["edits"].([]any)
	if !targetOK || !editsOK || len(edits) == 0 || len(edits) > 64 {
		return nil
	}
	var added, replaced []string
	for _, value := range edits {
		item, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		oldText, oldOK := item[edit.old].(string)
		newText, newOK := item[edit.new].(string)
		if !oldOK || !newOK {
			return nil
		}
		added, replaced = append(added, newText), append(replaced, oldText)
	}
	return []nativeFileWrite{{
		target: target, added: strings.Join(added, "\n"), replaced: strings.Join(replaced, "\n"),
	}}
}

// nativePatchWrites reads the added and removed lines of each file of one
// apply_patch envelope. A moved file's new path receives the same hunks.
func nativePatchWrites(object map[string]any) []nativeFileWrite {
	if len(object) != 1 {
		return nil
	}
	text, ok := nativeStringField(object, nativePatchTextKeys)
	if !ok || parsePatchEnvelope(text).status != StatusComplete {
		return nil
	}
	var writes []nativeFileWrite
	var current []int
	for _, line := range strings.Split(
		strings.TrimSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), "\n",
	) {
		switch {
		case strings.HasPrefix(line, "*** Add File: "), strings.HasPrefix(line, "*** Update File: "):
			writes = append(writes, nativeFileWrite{target: line[strings.Index(line, ": ")+2:]})
			current = []int{len(writes) - 1}
		case strings.HasPrefix(line, "*** Move to: "):
			writes = append(writes, nativeFileWrite{target: strings.TrimPrefix(line, "*** Move to: ")})
			current = append(current, len(writes)-1)
		case strings.HasPrefix(line, "*** Delete File: "):
			current = nil
		case strings.HasPrefix(line, "+"):
			for _, index := range current {
				writes[index].added += line[1:] + "\n"
			}
		case strings.HasPrefix(line, "-"):
			for _, index := range current {
				writes[index].replaced += line[1:] + "\n"
			}
		}
	}
	return writes
}

// nativeStringField returns the string value of the one key of keys that the
// object carries; two of them at once is not a reviewed shape.
func nativeStringField(object map[string]any, keys []string) (string, bool) {
	found, value := 0, ""
	for _, key := range keys {
		if raw, ok := object[key]; ok {
			text, isString := raw.(string)
			if !isString {
				return "", false
			}
			found, value = found+1, text
		}
	}
	return value, found == 1
}
