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
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxPatchDirectives = 256

type patchPathChange struct {
	path   string
	access PathAccess
}

type patchEnvelopeResult struct {
	// canonical is the envelope as the patch tool reads it: without the white
	// space around the patch and around a file header, and with LF line ends.
	// The content proofs read the files text from it, so they judge what the
	// tool applies.
	canonical string
	changes   []patchPathChange
	hasMove   bool
	status    ParseStatus
	issue     IssueCode
	// unplaced says the envelope is well formed but a header names its file
	// by a spelling no reader places (isAcceptedPatchPath). The tool writes
	// that file, so the call is judged at the unknown tier
	// (PatchNamesUnplacedTarget for the tool, CommandPatchNamesUnplacedTarget
	// for a here-document), never read as an envelope the tool rejects.
	// The changes of the other headers are kept and judged as they are in an
	// envelope of their own (rel-1-0-10:GAP-1055); when no header is placed,
	// the status is invalid, since the envelope names nothing a rule reads.
	unplaced bool
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
	return ok && field == "input" && strings.HasPrefix(strings.TrimSpace(text), patchBeginLine)
}

const (
	patchBeginLine = "*** Begin Patch"
	patchEndLine   = "*** End Patch"
)

// patchFileHeaderPrefixes start the header line of a file of a patch.
var patchFileHeaderPrefixes = []string{"*** Add File: ", "*** Update File: ", "*** Delete File: "}

func isPatchFileHeader(line string) bool {
	for _, prefix := range patchFileHeaderPrefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// isAcceptedPatchPath reports a patch target with one stable meaning: a path
// relative to the working directory, an absolute POSIX or drive path, or a
// root-relative path (/x or \x), which a Windows working directory roots on
// its own drive as it does any other root-relative path. Codex and the
// Copilot CLI apply such a target as given, so it is a write fact like a
// relative one and every path rule judges it (rel-1-0-6:GAP-0361,
// GAP-0398). So is a spelling that begins with two backslashes and names a
// file below a root the path rules read (isWindowsRootedPatchTarget): a
// Claude Code Write or Edit of that name is a path fact as written, and the
// patch of the same file must be judged as that write is
// (rel-1-0-10:GAP-1052, GAP-0947). Home forms (~) are not, because the tool
// does not expand them, nor are drive-relative paths (C:x) on their own: C:x
// names a file of the current folder of drive C, which only the working
// folder of the call tells (patchDriveRelativePlaced places it there when
// that folder is on C:, rel-1-0-10:GAP-1078). Another drive's current folder
// is not known: the tool writes a file no rule can name, and the call is
// judged at the unknown tier (unplaced).
//
// The drive and backslash forms are read so only where the patch tool runs on
// Windows (patchTargetsAreWindowsNames). On Linux and macOS a backslash is a
// character of a file name and a colon after a letter means nothing, so a
// drive-relative, device or share spelling is a relative name of the working
// folder that the path rules place, as rel read it (rel-1-0-10:GAP-1056). The
// home forms stay unplaced on every host.
func isAcceptedPatchPath(value string) bool {
	if value == "" || value == "~" || strings.HasPrefix(value, "~/") ||
		strings.HasPrefix(value, `~\`) {
		return false
	}
	if !patchTargetsAreWindowsNames {
		return true
	}
	if strings.HasPrefix(value, `\\`) {
		return isWindowsRootedPatchTarget(value)
	}
	if len(value) >= 2 && isASCIILetter(value[0]) && value[1] == ':' {
		return len(value) >= 3 && (value[2] == '/' || value[2] == '\\')
	}
	return true
}

// patchTargetsAreWindowsNames says the patch tool, which runs on the host of
// this gateway, reads its targets as Windows names. A variable so a test can
// read either host's names.
var patchTargetsAreWindowsNames = runtime.GOOS == "windows"

// isWindowsRootedPatchTarget reports a patch target that begins with two
// backslashes and names a file below a root the path rules read
// (windowsOpenedPath): a drive path behind the extended-length or device
// prefix (\\?\C:\x, \\.\C:\x), or a file of a share of any host
// (\\server\share\x, the admin shares \\host\C$\x included, also below
// \\?\UNC\). The share of this machine opens the file of its drive path,
// and the share of another host keeps its server and share, as the path of
// a Claude Code Write of the same name does (rel-1-0-6:GAP-1004,
// rel-1-0-10:GAP-1052). Any other device or namespace (\\.\pipe\x,
// \\?\Volume{...}\x), a share without a file, and a drive without a path
// name nothing the rules read, and stay unplaced.
func isWindowsRootedPatchTarget(value string) bool {
	text := strings.TrimPrefix(strings.ReplaceAll(value, "/", `\`), `\\`)
	if strings.HasPrefix(text, `?\`) || strings.HasPrefix(text, `.\`) {
		text = text[2:]
		if len(text) >= 3 && isASCIILetter(text[0]) && text[1] == ':' && text[2] == '\\' {
			return true
		}
		if len(text) < 4 || !strings.EqualFold(text[:4], `unc\`) {
			return false
		}
		text = text[4:]
	}
	parts := strings.SplitN(text, `\`, 3)
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

// patchDirectives are the directive lines of an apply_patch envelope that name
// a file, with the operation each one gives.
var patchDirectives = []struct {
	prefix string
	kind   string
}{
	{prefix: "*** Add File: ", kind: "add"},
	{prefix: "*** Update File: ", kind: "update"},
	{prefix: "*** Delete File: ", kind: "delete"},
	{prefix: "*** Move to: ", kind: "move"},
}

// isPatchDirectiveLine reports a line that names a file of the envelope.
func isPatchDirectiveLine(line string) bool {
	for _, directive := range patchDirectives {
		if strings.HasPrefix(line, directive.prefix) {
			return true
		}
	}
	return false
}

// PatchTargetName is the name an apply_patch tool opens for the text a
// directive line gives after its prefix. The tools take that text without any
// tab or carriage return, wherever it stands, and without the white space that
// ends it; a Windows name then also drops trailing dots. A spelling with such
// characters therefore names the plain file, so every reader of an envelope
// judges this name and none reads the spelling or treats it as an unreadable
// envelope. White space that begins the name is part of the file name.
func PatchTargetName(text string) string {
	if strings.ContainsAny(text, "\t\r") {
		text = strings.Map(func(r rune) rune {
			if r == '\t' || r == '\r' {
				return -1
			}
			return r
		}, text)
	}
	return strings.TrimRightFunc(text, unicode.IsSpace)
}

// patchDirectivePath is the name a directive line gives its file.
func patchDirectivePath(line, prefix string) string {
	return PatchTargetName(strings.TrimPrefix(line, prefix))
}

func appendExtractedPatch(out *extractedInput, text, cwd string) {
	if out.patchSet {
		out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		return
	}
	out.patchSet = true
	parsed := readPatchEnvelope(text, patchView{cwd: cwd})
	if parsed.status != StatusComplete {
		out.mergeProblem(parsed.status, parsed.issue)
		return
	}
	out.patchChanges = parsed.changes
	out.patchMove = parsed.hasMove
	out.markApplicable()
}

// patchView is how a reader reads the header names of an envelope: in the
// text a shell shows of a here-document it expands (shellView), and with the
// working folder of the call (cwd) that a drive-relative name is placed
// against (patchDriveRelativePlaced). An empty cwd places no drive-relative
// name.
type patchView struct {
	shellView bool
	cwd       string
}

// patchCallCWD is the working folder of an apply_patch tool call on a host
// whose patch tool reads Windows names: the hook's working folder, or the
// call's own working-folder argument when the hook gives none (the folder
// Analyze reads the call in). Elsewhere it is empty: no drive-relative names.
func patchCallCWD(input Input) string {
	if !patchTargetsAreWindowsNames || !isApplyPatchTool(input.Tool) {
		return ""
	}
	if input.CWD != "" {
		return input.CWD
	}
	return extractArgsForTool(input.Args, input.Tool).cwd
}

// patchDriveRelativePlaced places a drive-relative header name (C:name, no
// separator after the colon) against cwd when cwd is a drive path on the
// same drive: Win32 opens C:name in the current folder of drive C, which is
// the working folder when that folder is on C: (rel-1-0-10:GAP-1078). The
// rule hookpaths cmdMklinkDriveRelative applies to the target of cmd mklink.
// A name on another drive, a bare C:, or no drive working folder is not placed.
func patchDriveRelativePlaced(name, cwd string) (string, bool) {
	if !patchTargetsAreWindowsNames || len(name) < 3 || !isASCIILetter(name[0]) || name[1] != ':' ||
		name[2] == '/' || name[2] == '\\' {
		return "", false
	}
	if len(cwd) < 3 || !isASCIILetter(cwd[0]) || cwd[1] != ':' || cwd[2] != '/' && cwd[2] != '\\' ||
		!strings.EqualFold(cwd[:1], name[:1]) {
		return "", false
	}
	return strings.TrimRight(cwd, `/\`) + `\` + name[2:], true
}

// patchNamePlaced reports a header name a reader places: one
// isAcceptedPatchPath accepts and, in the text a shell shows of a
// here-document it expands (shellView), one the shell does not change (no
// expansion, no escape: posixHeredocLiteralEscapes). A name the shell expands
// is a file the tool writes whose name no rule reads, as one no reader places
// (rel-1-0-10:GAP-1077).
func patchNamePlaced(name string, view patchView) bool {
	return isAcceptedPatchPath(name) && (!view.shellView || !posixHeredocLiteralEscapes(name))
}

// patchHomeMarker stands for a plain $HOME or ${HOME} in the text a shell
// shows of a here-document it expands (posixHeredocText). Its bytes are no
// shell syntax, and no body that holds its first byte gets one.
const patchHomeMarker = "\x01HOME\x01"

// patchHeaderTarget is the name a reader places for a header name, and false
// for one no reader places (patchNamePlaced). In the text a shell shows of a
// here-document it expands (shellView), a name whose only expansion is a
// leading $HOME or ${HOME} before a relative name is the file under the
// active home, "~/<name>", which the path facts resolve as they resolve a
// shell operand $HOME (rel-1-0-10:GAP-1094). The envelope stays unplaced as
// a whole (GAP-1093): this only adds the file the header names.
// A drive-relative name on the drive of the working folder is the file of
// that folder (patchDriveRelativePlaced).
func patchHeaderTarget(name string, view patchView) (string, bool) {
	if view.shellView {
		if rest, ok := strings.CutPrefix(name, patchHomeMarker+"/"); ok {
			if rest == "" || strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "~") ||
				strings.IndexByte(rest, patchHomeMarker[0]) >= 0 || posixHeredocLiteralEscapes(rest) ||
				!isAcceptedPatchPath(rest) {
				return "", false
			}
			return "~/" + rest, true
		}
	}
	if placed, ok := patchDriveRelativePlaced(name, view.cwd); ok && !view.shellView {
		return placed, true
	}
	return name, patchNamePlaced(name, view)
}

// readPatchEnvelope reads an apply_patch envelope as the tool reads it: the
// text of the envelope, or the text a shell shows of a here-document it
// expands (shellView), whose header names may change when the shell expands
// them (patchNamePlaced).
func readPatchEnvelope(text string, view patchView) patchEnvelopeResult {
	fail := func(status ParseStatus, issue IssueCode) patchEnvelopeResult {
		return patchEnvelopeResult{status: status, issue: issue}
	}
	if len(text) == 0 || strings.IndexByte(text, 0) >= 0 || !utf8.ValidString(text) {
		return fail(StatusInvalid, IssueInvalidSyntax)
	}
	if len(text) > maxArgsJSONBytes {
		return fail(StatusLimitExceeded, IssueInputLimit)
	}

	// The patch tool trims the white space around the patch text, and around
	// its first and last line, before it checks the Begin and End markers, and
	// reads CRLF as LF. The white space it trims is every Unicode space (the
	// ASCII ones, a lone carriage return, U+0085, U+00A0, U+1680, U+2000 to
	// U+200A, U+2028, U+2029, U+202F, U+205F and U+3000), the set that
	// strings.TrimSpace takes, so the envelope is judged in that form: the same
	// text with any padding or line end style is the same patch. A carriage
	// return that does not end a line and lies between the markers is not
	// padding: one beside a directive keeps the envelope unread.
	normalized := strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
	lines := strings.Split(normalized, "\n")
	if len(lines) < 3 {
		return fail(StatusInvalid, IssueInvalidSyntax)
	}
	lines[0] = strings.TrimSpace(lines[0])
	lines[len(lines)-1] = strings.TrimSpace(lines[len(lines)-1])
	if lines[0] != patchBeginLine || lines[len(lines)-1] != patchEndLine {
		return fail(StatusInvalid, IssueInvalidSyntax)
	}
	canonical := make([]string, 0, len(lines))
	canonical = append(canonical, lines[0])

	changes := make([]patchPathChange, 0, 8)
	directives := 0
	pendingUpdate := -1
	activeDirective := ""
	contentAfterDirective := false
	updateHunk := false
	updateContent := false
	hasMove := false
	unplaced := false
	// unplacedChange marks the changes of changes whose file no reader places.
	var unplacedChange []bool
	for _, line := range lines[1 : len(lines)-1] {
		// A carriage return that does not end a line is read only in a
		// directive name, which the tools take without it.
		if strings.ContainsRune(line, '\r') && !isPatchDirectiveLine(line) {
			return fail(StatusInvalid, IssueInvalidSyntax)
		}
		canonical = append(canonical, line)
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
			// The tool reads an empty line of an update as an empty line of
			// its text.
			if updateHunk && line == "" {
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
		// The tool reads the header of a file without the white space around
		// it. A line that starts with a space inside an update is a line of
		// its text, not a header.
		if header := strings.TrimSpace(line); header != line &&
			isPatchFileHeader(header) && (activeDirective != "update" || line[0] != ' ') {
			line = header
			canonical[len(canonical)-1] = header
		}
		if line == "" || strings.HasPrefix(line, "+") ||
			strings.HasPrefix(line, "-") || strings.HasPrefix(line, " ") ||
			strings.HasPrefix(line, "@@") {
			return fail(StatusInvalid, IssueInvalidSyntax)
		}
		if line == patchBeginLine || line == patchEndLine {
			return fail(StatusInvalid, IssueInvalidSyntax)
		}

		kind := ""
		pathValue := ""
		headerUnplaced := false
		for _, directive := range patchDirectives {
			if strings.HasPrefix(line, directive.prefix) {
				kind = directive.kind
				pathValue = patchDirectivePath(line, directive.prefix)
				break
			}
		}
		target, placed := patchHeaderTarget(pathValue, view)
		if kind != "" && pathValue != "" && len(pathValue) <= maxScalarBytes &&
			strings.IndexByte(pathValue, 0) < 0 &&
			strings.TrimLeftFunc(pathValue, unicode.IsSpace) == pathValue &&
			!placed {
			// The tool writes this file, but no reader places its name:
			// the rest of the envelope is still read, and a well formed
			// one is unplaced, not invalid.
			unplaced = true
			headerUnplaced = true
		} else if kind == "" || pathValue == "" ||
			strings.TrimLeftFunc(pathValue, unicode.IsSpace) != pathValue ||
			len(pathValue) > maxScalarBytes ||
			strings.IndexByte(pathValue, 0) >= 0 {
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
		// A file the envelope names in more than one block is changed by each
		// block in order, so every block is a change of its own: each is judged
		// by the path rules, and nativePatchEnvelopeWrites by the content rules.
		switch kind {
		case "add", "update":
			changes = append(changes, patchPathChange{
				path: target, access: PathAccessWrite,
			})
			unplacedChange = append(unplacedChange, headerUnplaced)
			pendingUpdate = -1
			if kind == "update" {
				pendingUpdate = len(changes) - 1
			}
			activeDirective = kind
			contentAfterDirective = false
			updateHunk = false
			updateContent = false
		case "delete":
			changes = append(changes, patchPathChange{
				path: target, access: PathAccessDelete,
			})
			unplacedChange = append(unplacedChange, headerUnplaced)
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
			changes[pendingUpdate].access = PathAccessDelete
			changes = append(changes, patchPathChange{
				path: target, access: PathAccessWrite,
			})
			unplacedChange = append(unplacedChange, headerUnplaced)
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
	if unplaced {
		// A header no reader places hides none of the others: each placed
		// change is judged as its single-header patch is, and the caller adds
		// the unknown-tier finding for the rest (rel-1-0-10:GAP-1055).
		placed := make([]patchPathChange, 0, len(changes))
		for index, change := range changes {
			if !unplacedChange[index] {
				placed = append(placed, change)
			}
		}
		if len(placed) == 0 {
			result := fail(StatusInvalid, IssueInvalidSyntax)
			result.unplaced = true
			return result
		}
		changes = placed
	}
	return patchEnvelopeResult{
		canonical: strings.Join(append(canonical, patchEndLine), "\n"),
		changes:   changes,
		hasMove:   hasMove,
		status:    StatusComplete,
		unplaced:  unplaced,
	}
}

// applyPatchStdinText is the envelope text of a POSIX apply_patch command
// fed by a here-document, in every delimiter spelling: the document itself
// when no shell expansion touches it (shellView false), and for a document
// the shell expands, the text it shows (LiteralStdinView, shellView true).
// The expansions are then unknown content of the lines that hold them, and a
// header whose name the shell may change names a file no reader places
// (readPatchEnvelope): the other headers are read as the text names them, so
// that header hides none of them (rel-1-0-10:GAP-1077). A document that is
// not read yields no text.
func applyPatchStdinText(command CommandFact) (text string, shellView, ok bool) {
	if command.Dialect != DialectPOSIX || command.Executable != "apply_patch" ||
		!command.ArgvComplete || len(command.Argv) != 1 {
		return "", false, false
	}
	if command.LiteralStdinComplete && !command.LiteralStdinAmbiguous {
		return command.LiteralStdin, false, true
	}
	if command.LiteralStdinComplete || command.LiteralStdinView == "" {
		return "", false, false
	}
	return command.LiteralStdinView, true, true
}

// CommandPatchEnvelopes is the envelope text of each apply_patch command of
// facts fed by a here-document (applyPatchStdinText), in the order the
// commands are read: the patch the tool reads, the form in which Codex sends
// its patch tool (exec_command `apply_patch <<PATCH`). The content checks of
// the native apply_patch tool read it as they read the tool's own envelope,
// as nativeCallWrites gives its files to the path proofs (rel-1-0-10:GAP-1635).
// shellView is true when one of them is the text of a document the shell
// expands, whose expansions are content no reader knows.
func CommandPatchEnvelopes(facts Facts) (envelopes []string, shellView bool) {
	for _, command := range facts.Commands {
		text, view, ok := applyPatchStdinText(command)
		if !ok {
			continue
		}
		envelopes = append(envelopes, text)
		shellView = shellView || view
	}
	return envelopes, shellView
}

// classifyPOSIXApplyPatchStdin gives a shell-fed, literal patch the same
// path operations as the native apply_patch tool. A here-document keeps the
// envelope bytes (applyPatchStdinText); other stdin forms have no
// authoritative patch text.
func classifyPOSIXApplyPatchStdin(out *parseOutput, command *CommandFact) {
	text, shellView, ok := applyPatchStdinText(*command)
	if !ok {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	patch := readPatchEnvelope(text, patchView{shellView: shellView})
	// A header no reader places is a file the tool writes and no path rule
	// can name: the command carries the mark, and the gateway judges it at
	// the unknown tier at least (CommandPatchNamesUnplacedTarget), as it
	// judges the same envelope given to the native tool. The placed headers
	// stay complete facts, so a block they prove stays a block
	// (rel-1-0-10:GAP-1077). A body the shell expands (shellView) carries the
	// mark too: an expansion in any line, a content line included, may hold
	// newlines and add a header no reader sees, so the header set of the
	// envelope is not known (rel-1-0-10:GAP-1093).
	command.PatchUnplacedTarget = patch.unplaced || shellView
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

// UnplacedPatchTargetReason is the audit reason of a patch call judged at the
// unknown tier because a header names its file by a spelling no reader places.
const UnplacedPatchTargetReason = "patch_target_unplaced"

// PatchNamesUnplacedTarget reports an apply_patch tool call whose patch text,
// in any field the patch reader reads (isPatchInputField,
// isPatchEnvelopeField), is a well formed envelope with a header that names
// its file by a spelling no reader places: a home form the tool does not
// expand, a drive-relative path, a device or namespace path, a share without
// a file. The tool writes that file and no path rule can name it, so the
// caller judges the call at the unknown tier of the pack, never as a clean
// allow (rel-1-0-10:GAP-1052, GAP-0947). An envelope the tool rejects for its
// syntax writes nothing and is not reported.
func PatchNamesUnplacedTarget(input Input) bool {
	tool, args := input.Tool, input.Args
	if !isApplyPatchTool(tool) || len(args) == 0 || len(args) > maxArgsJSONBytes {
		return false
	}
	view := patchView{cwd: patchCallCWD(input)}
	var object map[string]any
	if json.Unmarshal(args, &object) != nil {
		return false
	}
	for key, value := range object {
		text, ok := value.(string)
		if ok && (isPatchInputField(key) || isPatchEnvelopeField(key, value)) && readPatchEnvelope(text, view).unplaced {
			return true
		}
	}
	return false
}

// PatchPathIsUnplacedWindowsName reports a patch target the patch tool reads
// as a Windows name that no reader places (isAcceptedPatchPath): a
// drive-relative path (C:x), a device or namespace path, a share without a
// file. False where the patch tool does not read Windows names
// (patchTargetsAreWindowsNames) and for the home forms, which a tool that
// expands them (Hermes) places. Hermes' V4A patch tool writes such a file as
// apply_patch does, so the gateway judges that call at the unknown tier too
// (rel-1-0-10:GAP-1057).
func PatchPathIsUnplacedWindowsName(value string) bool {
	if !patchTargetsAreWindowsNames || value == "" || value == "~" ||
		strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		return false
	}
	return !isAcceptedPatchPath(value)
}

// CommandPatchNamesUnplacedTarget reports a shell command of facts that feeds
// apply_patch an envelope, by a here-document (applyPatchStdinText), with a
// header no reader places, or with a body the shell expands, whose headers
// are not all known (rel-1-0-10:GAP-1093): the shell route of
// PatchNamesUnplacedTarget. The caller judges the call at the unknown tier of
// the pack at least, and the placed headers of the same envelope are path
// facts the rules judge (rel-1-0-10:GAP-1077).
func CommandPatchNamesUnplacedTarget(facts Facts) bool {
	return slices.ContainsFunc(facts.Commands, func(command CommandFact) bool {
		return command.PatchUnplacedTarget
	})
}
