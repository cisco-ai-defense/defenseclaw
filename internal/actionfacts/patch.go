// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	pathpkg "path"
	"strings"
	"unicode/utf8"
)

const maxPatchDirectives = 256

type patchPathChange struct {
	path   string
	access PathAccess
}

type patchEnvelopeResult struct {
	changes []patchPathChange
	hasMove bool
	status  ParseStatus
	issue   IssueCode
}

func isApplyPatchTool(tool string) bool {
	if tool == "" || strings.TrimSpace(tool) != tool {
		return false
	}
	switch strings.ToLower(tool) {
	case "apply_patch", "applypatch", "apply-patch":
		return true
	default:
		return false
	}
}

func isPatchInputField(field string) bool {
	switch field {
	case "command", "patch", "patchText", "patch_text":
		return true
	default:
		return false
	}
}

// isPatchEnvelopeField reports the "input" key of a patch tool whose value
// is a patch envelope. Codex and the Copilot CLI send the freeform patch as
// {"input": "*** Begin Patch ..."}; that text is the patch, not a nested
// command line whose "***" words are globs (GAP-2180). Any other "input"
// value keeps the nested reading.
func isPatchEnvelopeField(field string, value any) bool {
	text, ok := value.(string)
	return ok && field == "input" && strings.HasPrefix(text, "*** Begin Patch")
}

// isAcceptedPatchPath reports a patch target with one stable meaning: a path
// relative to the working directory, an absolute POSIX or drive path, or a
// root-relative path (/x or \x), which a Windows working directory roots on
// its own drive as it does any other root-relative path. Codex and the
// Copilot CLI apply such a target as given, so it is a write fact like a
// relative one and every path rule judges it (rel-1-0-6:GAP-0361,
// GAP-0398). Home forms (~) stay unread because the tool does not expand
// them, and so do UNC shares (\\host) and drive-relative paths (C:x), which
// name another host or the current directory of another drive.
func isAcceptedPatchPath(value string) bool {
	if value == "" || value == "~" || strings.HasPrefix(value, "~/") ||
		strings.HasPrefix(value, `~\`) || strings.HasPrefix(value, `\\`) {
		return false
	}
	if len(value) >= 2 && isASCIILetter(value[0]) && value[1] == ':' {
		return len(value) >= 3 && (value[2] == '/' || value[2] == '\\')
	}
	return true
}

func appendExtractedPatch(out *extractedInput, text string) {
	if out.patchSet {
		out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		return
	}
	out.patchSet = true
	parsed := parsePatchEnvelope(text)
	if parsed.status != StatusComplete {
		out.mergeProblem(parsed.status, parsed.issue)
		return
	}
	out.patchChanges = parsed.changes
	out.patchMove = parsed.hasMove
	out.markApplicable()
}

func parsePatchEnvelope(text string) patchEnvelopeResult {
	fail := func(status ParseStatus, issue IssueCode) patchEnvelopeResult {
		return patchEnvelopeResult{status: status, issue: issue}
	}
	if len(text) == 0 || strings.IndexByte(text, 0) >= 0 || !utf8.ValidString(text) {
		return fail(StatusInvalid, IssueInvalidSyntax)
	}
	if len(text) > maxArgsJSONBytes {
		return fail(StatusLimitExceeded, IssueInputLimit)
	}

	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		return fail(StatusInvalid, IssueInvalidSyntax)
	}
	normalized = strings.TrimSuffix(normalized, "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) < 3 || lines[0] != "*** Begin Patch" ||
		lines[len(lines)-1] != "*** End Patch" {
		return fail(StatusInvalid, IssueInvalidSyntax)
	}

	changes := make([]patchPathChange, 0, 8)
	seenPaths := make(map[string]struct{})
	directives := 0
	pendingUpdate := -1
	activeDirective := ""
	contentAfterDirective := false
	updateHunk := false
	updateContent := false
	hasMove := false
	for _, line := range lines[1 : len(lines)-1] {
		if line == "*** End of File" {
			if activeDirective != "update" || !updateHunk || !updateContent {
				return fail(StatusInvalid, IssueInvalidSyntax)
			}
			pendingUpdate = -1
			activeDirective = "eof"
			contentAfterDirective = false
			updateHunk = false
			updateContent = false
			continue
		}
		switch activeDirective {
		case "add":
			if strings.HasPrefix(line, "+") {
				contentAfterDirective = true
				continue
			}
		case "update":
			if strings.HasPrefix(line, "@@") {
				updateHunk = true
				contentAfterDirective = true
				continue
			}
			if updateHunk && (strings.HasPrefix(line, "+") ||
				strings.HasPrefix(line, "-") || strings.HasPrefix(line, " ")) {
				contentAfterDirective = true
				updateContent = true
				continue
			}
		}
		if line == "" || strings.HasPrefix(line, "+") ||
			strings.HasPrefix(line, "-") || strings.HasPrefix(line, " ") ||
			strings.HasPrefix(line, "@@") {
			return fail(StatusInvalid, IssueInvalidSyntax)
		}
		if line == "*** Begin Patch" || line == "*** End Patch" {
			return fail(StatusInvalid, IssueInvalidSyntax)
		}

		kind := ""
		pathValue := ""
		for _, directive := range []struct {
			prefix string
			kind   string
		}{
			{prefix: "*** Add File: ", kind: "add"},
			{prefix: "*** Update File: ", kind: "update"},
			{prefix: "*** Delete File: ", kind: "delete"},
			{prefix: "*** Move to: ", kind: "move"},
		} {
			if strings.HasPrefix(line, directive.prefix) {
				kind = directive.kind
				pathValue = strings.TrimPrefix(line, directive.prefix)
				break
			}
		}
		if kind == "" || pathValue == "" ||
			strings.TrimSpace(pathValue) != pathValue ||
			len(pathValue) > maxScalarBytes ||
			strings.IndexByte(pathValue, 0) >= 0 ||
			!isAcceptedPatchPath(pathValue) {
			status := StatusInvalid
			issue := IssueInvalidSyntax
			if len(pathValue) > maxScalarBytes {
				status = StatusLimitExceeded
				issue = IssueInputLimit
			}
			return fail(status, issue)
		}
		if kind != "move" && activeDirective == "update" && !updateContent {
			return fail(StatusInvalid, IssueInvalidSyntax)
		}
		directives++
		if directives > maxPatchDirectives {
			return fail(StatusLimitExceeded, IssueFactLimit)
		}
		// The envelope can spell the same effective target through dot
		// segments or either separator style. Key duplicate detection by that
		// conservative lexical identity so conflicting access facts cannot regain
		// authority after path normalization.
		pathKey := pathpkg.Clean(strings.ReplaceAll(pathValue, `\`, "/"))
		if _, duplicate := seenPaths[pathKey]; duplicate {
			return fail(StatusAmbiguous, IssueConflictingSources)
		}

		switch kind {
		case "add", "update":
			seenPaths[pathKey] = struct{}{}
			changes = append(changes, patchPathChange{
				path: pathValue, access: PathAccessWrite,
			})
			pendingUpdate = -1
			if kind == "update" {
				pendingUpdate = len(changes) - 1
			}
			activeDirective = kind
			contentAfterDirective = false
			updateHunk = false
			updateContent = false
		case "delete":
			seenPaths[pathKey] = struct{}{}
			changes = append(changes, patchPathChange{
				path: pathValue, access: PathAccessDelete,
			})
			pendingUpdate = -1
			activeDirective = kind
			contentAfterDirective = false
			updateHunk = false
			updateContent = false
		case "move":
			if pendingUpdate < 0 || activeDirective != "update" ||
				contentAfterDirective {
				return fail(StatusInvalid, IssueInvalidSyntax)
			}
			seenPaths[pathKey] = struct{}{}
			changes[pendingUpdate].access = PathAccessDelete
			changes = append(changes, patchPathChange{
				path: pathValue, access: PathAccessWrite,
			})
			pendingUpdate = -1
			activeDirective = "update"
			contentAfterDirective = false
			updateHunk = false
			updateContent = false
			hasMove = true
		}
	}
	if directives == 0 || len(changes) == 0 {
		return fail(StatusInvalid, IssueInvalidSyntax)
	}
	if activeDirective == "update" && !updateContent {
		return fail(StatusInvalid, IssueInvalidSyntax)
	}
	return patchEnvelopeResult{
		changes: changes,
		hasMove: hasMove,
		status:  StatusComplete,
	}
}

// applyPatchStdinText is the envelope text of a POSIX apply_patch command
// fed by a here-document, in every delimiter spelling: the document itself
// when no shell expansion touches it, and for a document the shell expands,
// the text it shows (LiteralStdinView) when no file directive of it holds an
// expansion or a backslash. The expansions are then unknown content of the
// lines that hold them; the files the patch names are as the text names them.
// A document that is not read yields no text.
func applyPatchStdinText(command CommandFact) (string, bool) {
	if command.Dialect != DialectPOSIX || command.Executable != "apply_patch" ||
		!command.ArgvComplete || len(command.Argv) != 1 {
		return "", false
	}
	if command.LiteralStdinComplete && !command.LiteralStdinAmbiguous {
		return command.LiteralStdin, true
	}
	if command.LiteralStdinComplete || command.LiteralStdinView == "" {
		return "", false
	}
	for _, line := range strings.Split(command.LiteralStdinView, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "*** ") && strings.ContainsAny(line, "$\\") {
			return "", false
		}
	}
	return command.LiteralStdinView, true
}

// classifyPOSIXApplyPatchStdin gives a shell-fed, literal patch the same
// path operations as the native apply_patch tool. A here-document keeps the
// envelope bytes (applyPatchStdinText); other stdin forms have no
// authoritative patch text.
func classifyPOSIXApplyPatchStdin(out *parseOutput, command *CommandFact) {
	text, ok := applyPatchStdinText(*command)
	if !ok {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	patch := parsePatchEnvelope(text)
	if patch.status != StatusComplete {
		if patch.status == StatusLimitExceeded {
			out.markLimit(patch.issue)
		} else {
			out.markPartial(patch.issue)
		}
		return
	}
	for _, change := range patch.changes {
		switch change.access {
		case PathAccessWrite:
			addOperation(command, OperationWrite)
		case PathAccessDelete:
			addOperation(command, OperationDelete)
		}
		appendCommandPath(out, command, change.access, change.path)
	}
	if patch.hasMove {
		addOperation(command, OperationMove)
	}
}
