// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
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
// the added and removed pieces joined. before is, for an edit, the text each
// step replaces, parallel to after, and all whether the step replaces every
// occurrence; edit is set for an Edit or a MultiEdit, whose steps the tool
// applies to the file in order.
type nativeFileWrite struct {
	target, added, replaced string
	whole, edit             bool
	after, before           []string
	all                     []bool
}

// NativeEditContentLimit is the largest file text a proof reads for an Edit
// or MultiEdit (ClientNativeFileContents): a larger file is not read.
const NativeEditContentLimit = maxCommandBytes

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
		for piece := range writes[index].before {
			writes[index].before[piece] = boundedNativeText(writes[index].before[piece])
		}
	}
	return writes
}

// editResult says what applying the steps of an edit to the text of a file
// gave.
type editResult int

const (
	// editUnread: the steps are not applied to the file. The call is not an
	// edit, or the file holds no text and the steps do not apply to nothing (the
	// gateway cannot tell an empty file from one it does not see). The text the
	// call carries is then read without the file.
	editUnread editResult = iota
	// editApplied: every step applied, and the document is the text they leave.
	editApplied
	// editRefused: the file holds text (white space included) and a step cannot
	// apply to it (its text is absent, found more than once without
	// replace-all, or empty over a file with text). The tool refuses such a call
	// and writes nothing, so the call adds nothing to the file.
	editRefused
	// editUncomputable: a step would grow the text past nativeEditWorkLimit, so
	// the document the steps leave is not computed. It is never read as
	// harmless: no fragment of the call can stand for a document that was not
	// built.
	editUncomputable
)

// nativeEditWorkLimit bounds the text a step of an edit may build while the
// steps are applied. It is not the bound of a document the proof reads: a step
// may take the text past that bound and a later step bring it back, as the
// tool does, and only the document the steps leave is held to the bound. A step
// that passes this limit leaves a document the proof cannot compute
// (editUncomputable).
const nativeEditWorkLimit = 4 << 20

// applyEdits applies the steps of an Edit or a MultiEdit, in order, to the text
// of the file, as the tool does: a step replaces its text where the file holds
// it once, or every occurrence when the step asks for it; an empty replaced
// text over a file with no text gives the new text. A file with any text,
// white space included, is a file with text.
func (write nativeFileWrite) applyEdits(content string) (string, editResult) {
	if !write.edit || len(write.before) == 0 ||
		len(write.before) != len(write.after) || len(write.before) != len(write.all) {
		return "", editUnread
	}
	failed := editUnread
	if content != "" {
		failed = editRefused
	}
	for step, replaced := range write.before {
		replacement := write.after[step]
		if replaced == "" {
			if content != "" {
				return "", failed
			}
			content = replacement
			continue
		}
		count := strings.Count(content, replaced)
		if count == 0 || count > 1 && !write.all[step] {
			return "", failed
		}
		if len(content)+count*(len(replacement)-len(replaced)) > nativeEditWorkLimit {
			return "", editUncomputable
		}
		content = strings.ReplaceAll(content, replaced, replacement)
	}
	return content, editApplied
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
	all, _ := object[edit.all].(bool)
	return []nativeFileWrite{{
		target: target, added: newText, replaced: oldText, edit: true,
		after: []string{newText}, before: []string{oldText}, all: []bool{all},
	}}
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
	var after, before []string
	var all []bool
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
		after, before = append(after, newText), append(before, oldText)
		replaceAll, _ := item[edit.all].(bool)
		all = append(all, replaceAll)
	}
	return []nativeFileWrite{{
		target: target, added: strings.Join(added, "\n"), replaced: strings.Join(replaced, "\n"),
		edit: true, after: after, before: before, all: all,
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

// editPieces are the texts a proof reads for what a multi-step edit or a patch
// leaves in place, whatever the file held: each piece (after), the pieces
// joined in order with and without a line break between them (a name or a list
// that one piece opens and the next finishes), and the text the steps of a
// multi-step edit make where they meet (nativeEditResults), alone and joined
// the same way. An edit that gives no pieces is its added text.
func (write nativeFileWrite) editPieces() []string {
	if len(write.after) == 0 {
		return []string{write.added}
	}
	pieces := slices.Clone(write.after)
	if len(write.after) == 1 {
		return pieces
	}
	pieces = append(pieces, strings.Join(write.after, "\n"), strings.Join(write.after, ""))
	if results := write.nativeEditResults(); !slices.Equal(results, write.after) {
		pieces = append(pieces, results...)
		if len(results) > 1 {
			pieces = append(pieces, strings.Join(results, "\n"), strings.Join(results, ""))
		}
	}
	return pieces
}

// nativeEditResults is the text the steps of a multi-step edit leave where
// they land, assembled the way the tool applies them to a file it does not
// show: a step whose replaced text lies inside text an earlier step left (or
// continues, at an end, a text that step left unfinished) rewrites that text;
// any other step leaves a text of its own. Text one step opens and a later one finishes (a list one step
// empties and another fills, a name one step starts and another ends) is then
// read as the text it makes, not as two pieces. Nothing is credited: the
// pieces themselves are judged as well (after), and a rewrite that would grow
// past the proof bound is not made.
func (write nativeFileWrite) nativeEditResults() []string {
	if len(write.before) != len(write.after) {
		return nil
	}
	var segments []string
	for step, replaced := range write.before {
		segments = nativeApplyEditStep(segments, replaced, write.after[step])
	}
	return segments
}

func nativeApplyEditStep(segments []string, replaced, replacement string) []string {
	if replaced == "" {
		return append(segments, replacement)
	}
	for index, segment := range segments {
		count := strings.Count(segment, replaced)
		if count == 0 {
			continue
		}
		if len(segment)+count*(len(replacement)-len(replaced)) <= maxCommandBytes {
			segments[index] = strings.ReplaceAll(segment, replaced, replacement)
			return segments
		}
	}
	for index, segment := range segments {
		if nativeTextUnfinished(segment) {
			if overlap := nativeLongestOverlap(segment, replaced); overlap > 0 {
				segments[index] = segment[:len(segment)-overlap] + replacement
				return segments
			}
		}
		if nativeTextUnfinished(replacement) {
			if overlap := nativeLongestOverlap(replaced, segment); overlap > 0 {
				segments[index] = replacement + segment[overlap:]
				return segments
			}
		}
	}
	return append(segments, replacement)
}

// nativeTextUnfinished reports whether text, read from its start as a piece of
// a JSON document, cannot stand where it ends: it stops inside a string, leaves
// a list or an object open, stops after a name, or ends in a string that is
// not the value of a name (a name waiting for its colon). Only such a text is
// read as continued by a later step whose replaced text starts inside it. A
// text that is complete gives no evidence that a step meeting its last
// characters edits the same place: the same closing characters occur at many
// places of a file, and only the file tells them apart.
func nativeTextUnfinished(text string) bool {
	inString, escaped, depth := false, false, 0
	last, beforeString := byte(0), byte(0)
	for index := 0; index < len(text); index++ {
		char := text[index]
		switch {
		case escaped:
			escaped = false
		case inString && char == '\\':
			escaped = true
		case inString:
			if char == '"' {
				inString, last = false, '"'
			}
		case char == '"':
			inString, beforeString = true, last
		case char == ' ' || char == '\t' || char == '\r' || char == '\n':
		default:
			last = char
			switch char {
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			}
		}
	}
	return inString || depth > 0 || last == ':' || last == '"' && beforeString != ':'
}

// nativeLongestOverlap is the length of the longest suffix of left that is
// also a prefix of right, shorter than both.
func nativeLongestOverlap(left, right string) int {
	for length := min(len(left), len(right)) - 1; length > 0; length-- {
		if strings.HasSuffix(left, right[:length]) {
			return length
		}
	}
	return 0
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

// NativeCallWriteTargets lists, as written, the files one call writes through
// a patch or file tool it runs itself: the files of a native file-tool call
// (NativeFileWriteTargets) and the files of the literal apply_patch envelope
// of a shell here-document, the form in which Codex sends its patch tool
// (nativeCallWrites). Such a call runs no command that could open a closed
// directory before it writes, so the permissions it meets at the hook are the
// ones the write meets.
func NativeCallWriteTargets(input Input, facts Facts) []string {
	writes, _ := nativeCallWrites(input, facts)
	targets := make([]string, 0, len(writes))
	for _, write := range writes {
		if write.target != "" {
			targets = append(targets, write.target)
		}
	}
	return targets
}
