// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
)

// nativeFileWrite is one file a native file-tool call changes and the text it
// gives that file. replaced is the text an edit tool removes; it is empty for
// a whole-file write. whole is set when added is the complete new content of
// the file (a whole-file write or a patch that adds the file), so a proof that
// needs the final document may rely on it and not on a fragment. after lists,
// for a multi-step edit or a patch, the text each replacement or hunk leaves in
// place (a replacement's new text; a hunk's context and added lines), in
// order, for a proof that judges the text an edit leaves and must not read
// pieces from different places of the file as one text; added and replaced are
// the added and removed pieces joined.
type nativeFileWrite struct {
	target, added, replaced string
	whole                   bool
	after                   []string
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
	writes := readNativeFileWrites(tool, args)
	for index := range writes {
		writes[index].added = boundedNativeText(writes[index].added)
		writes[index].replaced = boundedNativeText(writes[index].replaced)
		for piece := range writes[index].after {
			writes[index].after[piece] = boundedNativeText(writes[index].after[piece])
		}
	}
	return writes
}

// boundedNativeText is text padded with white space past maxCommandBytes in
// the form the file reads the same in: without the white space around it. A
// proof's size bound then applies to the content, so padding a patch hunk
// does not carry protected text past the proof, as it does not for a write
// (OverLimitWriteBoundedTwin). Text without such padding is returned as it is.
func boundedNativeText(text string) string {
	if len(text) <= maxCommandBytes {
		return text
	}
	if trimmed := strings.TrimSpace(text); len(trimmed) <= maxCommandBytes {
		return trimmed
	}
	return text
}

// nativeCallWrites reads the files one call writes and the facts that describe
// them. A native file-tool call gives them in its arguments, and its facts are
// the facts of the call. A shell command gives them only in the literal
// envelope of an apply_patch command with a quoted here-document, the form in
// which Codex sends its patch tool (exec_command), and the proofs then read the
// path facts of those commands only: a path another command of the same text
// reads or writes is judged by the rules for that command, and is no operand of
// the patch. Any other shell text, and any call with an argument vector, writes
// no file a content proof reads.
func nativeCallWrites(input Input, facts Facts) ([]nativeFileWrite, Facts) {
	if len(input.Argv) != 0 {
		return nil, facts
	}
	if PathTool(input.Tool) {
		if input.Command != "" {
			return nil, facts
		}
		return nativeFileWrites(input.Tool, input.Args), facts
	}
	view := facts
	view.Paths = nil
	var writes []nativeFileWrite
	patchCommands := map[int64]bool{}
	for _, command := range facts.Commands {
		if command.Dialect != DialectPOSIX || command.Executable != "apply_patch" ||
			!command.ArgvComplete || len(command.Argv) != 1 ||
			!command.LiteralStdinComplete || command.LiteralStdinAmbiguous ||
			parsePatchEnvelope(command.LiteralStdin).status != StatusComplete {
			continue
		}
		patchCommands[command.ID] = true
		for _, write := range nativePatchEnvelopeWrites(command.LiteralStdin) {
			write.added = boundedNativeText(write.added)
			write.replaced = boundedNativeText(write.replaced)
			writes = append(writes, write)
		}
	}
	for _, candidate := range facts.Paths {
		if patchCommands[candidate.CommandID] {
			view.Paths = append(view.Paths, candidate)
		}
	}
	return writes, view
}

func readNativeFileWrites(tool string, args json.RawMessage) []nativeFileWrite {
	if tool == "" || strings.TrimSpace(tool) != tool {
		return nil
	}
	patchTool := isApplyPatchTool(tool)
	appendTool := false
	if !patchTool {
		semantics, known := lookupToolArgumentSemantics(tool)
		if !known || !semantics.acceptsContent || !semantics.acceptsPaths {
			return nil
		}
		appendTool = semantics.pathAccess == PathAccessAppend
	}
	// A patch envelope is a string the generic analysis reads up to the
	// whole-argument bound, so it is read to that bound here too.
	stringLimit := maxCommandBytes
	if patchTool {
		stringLimit = maxArgsJSONBytes
	}
	object, problem := exactJSONObjectWithStringLimit(args, stringLimit)
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
	writes := nativeWholeFileWrites(object)
	for index := range writes {
		// An append tool adds to the file: its text is never the whole file.
		writes[index].whole = !appendTool
	}
	return writes
}

// NativeFileWriteTargets lists, as written, the files a native file-tool call
// writes, edits or patches (nativeFileWrites). A gateway that resolves the
// links of a per-user home itself asks it which names to resolve.
func NativeFileWriteTargets(input Input) []string {
	if input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	writes := nativeFileWrites(input.Tool, input.Args)
	targets := make([]string, 0, len(writes))
	for _, write := range writes {
		if write.target != "" {
			targets = append(targets, write.target)
		}
	}
	return targets
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
	return []nativeFileWrite{{target: target, added: content, whole: true}}
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
	// A replace-all flag that is not a boolean is a call the tool refuses.
	if value, present := object[edit.all]; edit.all != "" && present {
		if _, isBool := value.(bool); !isBool {
			return nil
		}
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
	var after []string
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
		after = append(after, newText)
	}
	return []nativeFileWrite{{
		target: target, added: strings.Join(added, "\n"), replaced: strings.Join(replaced, "\n"),
		after: after,
	}}
}

// nativePatchWrites reads the added and removed lines of each file of one
// apply_patch envelope given to the native tool, joined, and the text each hunk
// leaves in place (an @@ line starts the next hunk). A moved file's new path
// receives the same hunks.
func nativePatchWrites(object map[string]any) []nativeFileWrite {
	if len(object) != 1 {
		return nil
	}
	text, ok := nativeStringField(object, nativePatchTextKeys)
	if !ok || parsePatchEnvelope(text).status != StatusComplete {
		return nil
	}
	return nativePatchEnvelopeWrites(text)
}

// nativePatchEnvelopeWrites reads the files and the added and removed lines of
// an apply_patch envelope that parsePatchEnvelope read complete.
func nativePatchEnvelopeWrites(text string) []nativeFileWrite {
	var writes []nativeFileWrite
	var current []int
	for _, line := range strings.Split(
		strings.TrimSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), "\n",
	) {
		switch {
		case strings.HasPrefix(line, "*** Add File: "), strings.HasPrefix(line, "*** Update File: "):
			writes = append(writes, nativeFileWrite{
				target: line[strings.Index(line, ": ")+2:],
				whole:  strings.HasPrefix(line, "*** Add File: "),
			})
			current = []int{len(writes) - 1}
		case strings.HasPrefix(line, "*** Move to: "):
			writes = append(writes, nativeFileWrite{target: strings.TrimPrefix(line, "*** Move to: ")})
			current = append(current, len(writes)-1)
		case strings.HasPrefix(line, "*** Delete File: "):
			current = nil
		case strings.HasPrefix(line, "@@"):
			for _, index := range current {
				if after := writes[index].after; len(after) > 0 && after[len(after)-1] != "" {
					writes[index].after = append(after, "")
				}
			}
		case strings.HasPrefix(line, "+"):
			for _, index := range current {
				writes[index].added += line[1:] + "\n"
				*writes[index].lastHunk() += line[1:] + "\n"
			}
		case strings.HasPrefix(line, "-"):
			for _, index := range current {
				writes[index].replaced += line[1:] + "\n"
			}
		case strings.HasPrefix(line, " "), line == "":
			for _, index := range current {
				*writes[index].lastHunk() += strings.TrimPrefix(line, " ") + "\n"
			}
		}
	}
	return writes
}

// lastHunk is the text of the hunk the next context or added line belongs to,
// started when the write has none.
func (write *nativeFileWrite) lastHunk() *string {
	if len(write.after) == 0 {
		write.after = append(write.after, "")
	}
	return &write.after[len(write.after)-1]
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
