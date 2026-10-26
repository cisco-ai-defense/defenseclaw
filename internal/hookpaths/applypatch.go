// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"mvdan.cc/sh/v3/syntax"
)

const (
	patchBeginMarker = "*** Begin Patch"
	patchEndMarker   = "*** End Patch"
)

// patchTargetDirectives name the files an apply_patch envelope writes.
// Delete File and the source of a move remove a file, which also changes the
// protected file, so they count as write targets too.
var patchTargetDirectives = []string{
	"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:",
}

// ApplyPatchWriteTargets lists the files that the apply_patch edits in one
// tool call write, as absolute, cleaned paths. Codex sends apply_patch as its
// own tool (the envelope in tool_input.command, or a path field), or as a
// shell command that carries the envelope in a heredoc, a here-string, a
// quoted argument, a bash -c / sh -c script or a PowerShell @' '@ string.
// The envelope lines appear verbatim in each of those texts, so the text is
// scanned for envelopes and not parsed as one shell dialect.
//
// ok is false when the call carries an apply_patch edit whose targets are
// unknown: an envelope without "*** End Patch", an unknown "***" header, an
// empty path, a path with an unexpanded variable, a relative path without an
// absolute cwd, or an apply_patch tool call with no envelope and no path. The
// caller must then treat the protected file as a possible target. There is
// no bound on the number of targets.
func ApplyPatchWriteTargets(tool string, args json.RawMessage, command, cwd, home string) (targets []string, ok bool) {
	return applyPatchTargets(tool, args, command, cwd, home, true)
}

// ApplyPatchLexicalTargets lists the same targets as ApplyPatchWriteTargets
// for an apply_patch tool call, placed in cwd and home but not resolved on
// this host's filesystem. A managed gateway that cannot traverse a user's
// private home binds these names to the user-side hook's resolved evidence.
// Absolute, home-form and relative directives are all listed.
func ApplyPatchLexicalTargets(tool string, args json.RawMessage, cwd, home string) ([]string, bool) {
	if !isApplyPatchToolName(tool) {
		return nil, false
	}
	return applyPatchTargets(tool, args, "", cwd, home, false)
}

// ApplyPatchNamesProtectedTarget is the protected-target check of an
// apply_patch call whose payload could not be proven (GAP-1461). It reads
// every directive line without the envelope parse, places each path lexically
// in cwd and home, and reports one that is a protected authorized-keys file of
// home, by name or through the target the user-side hook resolved for it
// (resolved, keyed like the hook evidence). It only adds a finding to an
// unparsed call and never proves a call ordinary.
func ApplyPatchNamesProtectedTarget(tool string, args json.RawMessage, cwd, home string, resolved map[string]string) bool {
	if !isApplyPatchToolName(tool) || len(args) == 0 {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(args, &fields) != nil {
		fields = map[string]json.RawMessage{"patch": args}
	}
	protectedPaths := ProtectedAuthorizedKeysPaths(home)
	protected := func(path string) bool {
		for _, candidate := range protectedPaths {
			if path != "" && samePathName(filepath.Clean(path), candidate) {
				return true
			}
		}
		return false
	}
	names := func(path string) bool {
		paths, _ := patchTargetPaths(path, cwd, home, false)
		for _, target := range paths {
			if protected(target) || protected(resolved[OperandPath(target, cwd)]) {
				return true
			}
		}
		return false
	}
	for _, key := range []string{"command", "cmd", "patch", "patchText", "patch_text", "input"} {
		for _, line := range strings.Split(patchTextField(fields[key]), "\n") {
			line = strings.TrimSpace(line)
			for _, directive := range patchTargetDirectives {
				if strings.HasPrefix(line, directive) && names(strings.TrimSpace(line[len(directive):])) {
					return true
				}
			}
		}
	}
	for _, key := range []string{"path", "file_path", "filePath"} {
		var path string
		if json.Unmarshal(fields[key], &path) == nil && names(path) {
			return true
		}
	}
	return false
}

// ApplyPatchLexicalCommandTargets lists the directive targets of the
// envelopes an apply_patch tool call or a shell command supplies, placed in
// cwd and home but not resolved on this host. A managed gateway that cannot
// traverse the user's home binds them to the user-side hook's evidence
// (GAP-1106).
func ApplyPatchLexicalCommandTargets(tool string, args json.RawMessage, command, cwd, home string) ([]string, bool) {
	return applyPatchTargets(tool, args, command, cwd, home, false)
}

// PatchCallNamesProtectedTarget is the protected-target check of a call that
// may run apply_patch with targets that could not be read. It reports a call
// whose text names the SSH directory or an authorized-keys file anywhere, or
// whose directive lines name a protected file directly or through the
// target the user-side hook resolved (resolved, keyed like the hook
// evidence). A call with no protected-named word is never the SSH rule
// (TGT-0194).
func PatchCallNamesProtectedTarget(tool string, args json.RawMessage, command, cwd, home string, resolved map[string]string) bool {
	if ApplyPatchNamesProtectedTarget("apply_patch", args, cwd, home, resolved) ||
		command != "" && ApplyPatchNamesProtectedTarget("apply_patch", jsonStringRaw(command), cwd, home, resolved) {
		return true
	}
	texts := []string{command, string(args)}
	for _, text := range texts {
		if patchTextNamesSSH.MatchString(text) {
			return true
		}
	}
	return false
}

// patchShellCommandBody returns the script of a command that is exactly one
// static shell -c call (bash -lc '...'), with no redirect or assignment.
func patchShellCommandBody(command string) (string, bool) {
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 1 {
		return "", false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || stmt.Background || stmt.Negated || len(call.Args) < 3 {
		return "", false
	}
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		value, known := StaticWord(arg, "")
		if !known {
			return "", false
		}
		words[i] = value
	}
	switch programBase(words[0]) {
	case "bash", "sh", "zsh", "dash", "ksh":
	default:
		return "", false
	}
	index, ok := shellCommandBodyIndex(words)
	if !ok || index != len(words)-1 {
		return "", false
	}
	return words[index], true
}

// ApplyPatchToolWithoutText reports an apply_patch tool call whose arguments
// carry no patch text and no path.
func ApplyPatchToolWithoutText(tool string, args json.RawMessage) bool {
	if !isApplyPatchToolName(tool) {
		return false
	}
	var fields map[string]json.RawMessage
	if len(args) != 0 && json.Unmarshal(args, &fields) != nil {
		return false
	}
	for _, key := range []string{"command", "cmd", "patch", "patchText", "patch_text", "input", "path", "file_path", "filePath"} {
		if patchTextField(fields[key]) != "" {
			return false
		}
	}
	return true
}

// patchTextNamesSSH matches an authorized-keys name or a .ssh path component
// in raw call text (JSON escapes included).
var patchTextNamesSSH = regexp.MustCompile(`(?i)authorized_keys|(?:^|[^A-Za-z0-9_.-])\.ssh(?:$|[^A-Za-z0-9_.-])`)

func jsonStringRaw(value string) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

func applyPatchTargets(tool string, args json.RawMessage, command, cwd, home string, resolve bool) (targets []string, ok bool) {
	var fields map[string]json.RawMessage
	if len(args) != 0 {
		_ = json.Unmarshal(args, &fields)
	}
	patchTool := isApplyPatchToolName(tool)
	texts := []string{command}
	keys := []string{"command", "cmd"}
	if patchTool {
		keys = append(keys, "patch", "patchText", "patch_text", "input")
	}
	for _, key := range keys {
		texts = append(texts, patchTextField(fields[key]))
	}
	found := false
	for _, text := range texts {
		if text == "" {
			continue
		}
		if !patchTool {
			known, calls, _ := patchShellInvocationsKnown(text)
			if !known {
				// bash -lc '<script>': the envelope is in the script the
				// child shell runs (GAP-0781).
				if body, ok := patchShellCommandBody(text); ok {
					text = body
					known, calls, _ = patchShellInvocationsKnown(text)
				}
			}
			if !known {
				return nil, false
			}
			if calls == 0 {
				// An envelope stored as command data is not an edit.
				continue
			}
		}
		paths, envelopes, parsed := patchEnvelopePaths(text)
		if !parsed {
			return nil, false
		}
		found = found || envelopes > 0
		for _, path := range paths {
			resolved, known := patchTargetPaths(path, cwd, home, resolve)
			if !known {
				return nil, false
			}
			targets = append(targets, resolved...)
		}
	}
	if patchTool {
		for _, key := range []string{"path", "file_path", "filePath"} {
			var path string
			if json.Unmarshal(fields[key], &path) != nil || path == "" {
				continue
			}
			resolved, known := patchTargetPaths(path, cwd, home, resolve)
			if !known {
				return nil, false
			}
			targets = append(targets, resolved...)
			found = true
		}
		if !found {
			return nil, false
		}
	}
	return targets, true
}

func isApplyPatchToolName(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "apply_patch", "applypatch", "apply-patch":
		return true
	}
	return false
}

// patchTextField reads a string field, or an argv array (["apply_patch",
// "<envelope>"], ["bash", "-lc", "<script>"]) joined by newlines.
func patchTextField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var argv []string
	if json.Unmarshal(raw, &argv) == nil {
		return strings.Join(argv, "\n")
	}
	return ""
}

// patchEnvelopePaths returns the directive paths of every envelope in text.
// An envelope starts on a line that ends with "*** Begin Patch" (any prefix:
// "apply_patch '", "@'", a quote) and ends on a line that starts with
// "*** End Patch". Added and removed lines (+, -) are content. Any other
// "***" line inside an envelope must be a known directive or "*** End of
// File". A Begin marker followed by a directive on the same line is an
// envelope with escaped newlines (printf, echo -e, $'...'), which is unknown.
func patchEnvelopePaths(text string) (paths []string, envelopes int, ok bool) {
	inside := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if !inside {
			index := strings.Index(line, patchBeginMarker)
			if index < 0 {
				continue
			}
			rest := line[index+len(patchBeginMarker):]
			if rest == "" {
				inside = true
				envelopes++
				continue
			}
			for _, directive := range patchTargetDirectives {
				if strings.Contains(rest, directive) {
					return nil, envelopes, false
				}
			}
			continue
		}
		if strings.HasPrefix(line, patchEndMarker) {
			inside = false
			continue
		}
		raw = strings.TrimLeft(raw, "\t")
		if strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") || !strings.HasPrefix(line, "***") {
			continue
		}
		if line == "*** End of File" {
			continue
		}
		known := false
		for _, directive := range patchTargetDirectives {
			if strings.HasPrefix(line, directive) {
				path := strings.TrimSpace(line[len(directive):])
				if path == "" {
					return nil, envelopes, false
				}
				paths = append(paths, path)
				known = true
				break
			}
		}
		if !known {
			return nil, envelopes, false
		}
	}
	if inside {
		return nil, envelopes, false
	}
	return paths, envelopes, true
}

// A patch envelope only explains a shell invocation when it is actually
// supplied to that invocation. In particular, a quoted envelope printed by
// another command cannot explain a later file-fed apply_patch.
var (
	patchProgramWord  = regexp.MustCompile(`(?i)\b(?:apply_patch|applypatch|apply-patch)\b`)
	patchDirectInput  = regexp.MustCompile(`\b(?:apply_patch|applypatch|apply-patch)\s*(?:<<<\s*|<<\s*|@)?['"]`)
	patchHeredocInput = regexp.MustCompile(`\b(?:apply_patch|applypatch|apply-patch)\s*<<-?\s*[A-Za-z_][A-Za-z0-9_]*\s*$`)
	patchPipedHeredoc = regexp.MustCompile(`\bcat\s+<<[^\n|]*\|\s*(?:apply_patch|applypatch|apply-patch)\b`)
	patchPipeCall     = regexp.MustCompile(`^\s*['"]?@?\s*\|\s*(?:apply_patch|applypatch|apply-patch)\b`)
	patchPrinter      = regexp.MustCompile(`(?i)\b(?:echo|printf|write-output)\b|@['"]`)
	heredocOperator   = regexp.MustCompile(`<<(-?)\s*(?:'([^'\s]+)'|"([^"\s]+)"|([A-Za-z_][A-Za-z0-9_]*))(?:[\s|;&)>]|$)`)
)

// patchShellInvocationsKnown reports whether every apply_patch that a shell
// text may run reads an envelope in that text, and how many calls are bound.
// fedBody marks the body lines of the envelopes bound to a call.
// Lines of an envelope body are
// patch data, not shell, while the quote or here-document that feeds the
// envelope is still open. That state is tracked from the top of the text: it
// is known only while every line before the envelope's opener is plain shell
// and every earlier envelope closed its feed on its End line (or the line
// after it). A body line that may close or expand the feed, a body line that
// is not a patch line, or any doubt about the state makes the rest of the
// text shell, so an apply_patch in it counts as a call of its own, and the
// envelope binds no call.
func patchShellInvocationsKnown(text string) (known bool, calls int, fedBody []bool) {
	lines := strings.Split(text, "\n")
	bound := make([]int, len(lines))
	body := make([]bool, len(lines))
	fedBody = make([]bool, len(lines))
	inert := make([]bool, len(lines))
	known = true
	cursor := 0
	for start := 0; start < len(lines); start++ {
		begin := strings.Index(lines[start], patchBeginMarker)
		if begin < 0 || strings.TrimSpace(lines[start][begin+len(patchBeginMarker):]) != "" {
			continue
		}
		end := start + 1
		for end < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[end]), patchEndMarker) {
			end++
		}
		if end == len(lines) {
			continue // patchEnvelopePaths already rejects an open envelope
		}
		inputLine, opener := start, lines[start][:begin]
		if strings.TrimSpace(opener) == "" && start > 0 {
			inputLine, opener = start-1, lines[start-1]
		}
		for j := cursor; j < inputLine; j++ {
			known = known && plainShellText(lines[j])
		}
		feed, fed := patchOpenerFeed(opener, inputLine < start)
		fed = fed && known && inputLine >= cursor
		for i := start + 1; i < end; i++ {
			body[i] = true
			line := strings.TrimRight(strings.TrimLeft(lines[i], "\t"), "\r")
			fed = fed && patchBodyShape(line) && !feed.ends(line) && !feed.expands(line)
			inert[i] = fed
		}
		cursor, known = feed.closeAfter(lines, end)
		known = known && fed
		if !fed {
			// An expanding or malformed feed may hand apply_patch other
			// directives than the text shows, so it binds no call: the
			// apply_patch that reads it stays unknown (GAP-1506).
			start = end
			continue
		}
		close := strings.TrimSpace(lines[end])
		if index := strings.Index(close, patchEndMarker); index >= 0 {
			close = close[index+len(patchEndMarker):]
		}
		direct := patchDirectInput.FindStringIndex(opener)
		if direct == nil {
			direct = patchHeredocInput.FindStringIndex(opener)
		}
		if direct == nil {
			direct = patchPipedHeredoc.FindStringIndex(opener)
		}
		fed = false
		if direct != nil && !strings.Contains(opener[direct[1]:], "<") && !strings.Contains(close, "<") {
			bound[inputLine]++
			fed = true
		} else if patchPrinter.MatchString(opener) {
			pipeLine := end
			if patchPipeCall.MatchString(close) && !strings.Contains(close, "<") {
				bound[pipeLine]++
				fed = true
			} else if end+1 < len(lines) {
				// A pipe on the next line must continue the quoted printer.
				next := strings.TrimSpace(lines[end+1])
				if strings.HasPrefix(next, "'") || strings.HasPrefix(next, "\"") {
					if patchPipeCall.MatchString(next) {
						bound[end+1]++
						fed = true
					}
				}
			}
		}
		for i := start + 1; fed && i < end; i++ {
			fedBody[i] = true
		}
		start = end
	}
	for i, line := range lines {
		if inert[i] ||
			!body[i] && !invokesApplyPatch(line) && bound[i] == 0 && !strings.ContainsAny(line, ";|&") {
			continue
		}
		count := len(patchProgramWord.FindAllString(line, -1))
		calls += count
		if count > bound[i] {
			return false, calls, nil
		}
	}
	return true, calls, fedBody
}

// patchFedLines marks the lines inside every envelope in a shell text that
// an apply_patch call reads: the "***" headers and the added, removed and
// context lines. apply_patch writes only the files its headers name, so a
// path in the other lines is file content (GAP-0781). It is nil when any
// apply_patch in the text has an unknown input.
func patchFedLines(text string) []bool {
	known, calls, fedBody := patchShellInvocationsKnown(text)
	if !known || calls == 0 {
		return nil
	}
	if _, _, parsed := patchEnvelopePaths(text); !parsed {
		return nil
	}
	return fedBody
}

// patchFeed is the quote, here-document or PowerShell here-string that carries
// an envelope to the command that reads it.
type patchFeed struct {
	quote      byte   // ' or " of a quoted argument or here-string
	delim      string // here-document delimiter, or '@ / "@
	powershell bool
	expand     bool // the feed can expand variables or command substitutions
}

// patchOpenerFeed reads the feed that an envelope's opener leaves open: the
// text before "*** Begin Patch" on its line, or the line before it (ownLine).
// It fails for an opener whose quoting is unclear (escapes, several or nested
// quotes and here-documents, PowerShell block comments).
func patchOpenerFeed(opener string, ownLine bool) (patchFeed, bool) {
	if ownLine {
		trimmed := strings.TrimSpace(opener)
		for _, open := range []string{"@'", `@"`} {
			if head, found := strings.CutSuffix(trimmed, open); found {
				feed := patchFeed{delim: open[1:] + "@", powershell: true, expand: open[1] == '"'}
				return feed, plainShellText(head)
			}
		}
		if strings.Count(opener, "<<") == 1 && !strings.Contains(opener, "<<<") {
			match := heredocOperator.FindStringSubmatchIndex(opener)
			if match == nil {
				return patchFeed{}, false
			}
			feed := patchFeed{expand: match[8] >= 0}
			for group := 2; group <= 4; group++ {
				if match[2*group] >= 0 {
					feed.delim = opener[match[2*group]:match[2*group+1]]
					tail := match[2*group+1]
					if group < 4 {
						tail++ // the closing quote of a quoted delimiter
					}
					return feed, plainShellText(opener[:match[0]]) && plainShellText(opener[tail:])
				}
			}
		}
	}
	head := strings.ReplaceAll(opener, "<<<", "")
	if shellNesting(head) {
		return patchFeed{}, false
	}
	quote := openQuote(head)
	return patchFeed{quote: quote, expand: quote == '"'}, quote != 0
}

// ends reports a body line that may close the feed.
func (f patchFeed) ends(line string) bool {
	if f.quote != 0 {
		return strings.IndexByte(line, f.quote) >= 0
	}
	line = strings.TrimSpace(line)
	if f.powershell {
		return strings.HasPrefix(line, f.delim)
	}
	return line == f.delim
}

// expands reports a body line that the shell may expand or join with the next.
func (f patchFeed) expands(line string) bool {
	if !f.expand {
		return false
	}
	if strings.ContainsAny(line, "$`") {
		return true
	}
	if f.powershell {
		return false // Backslash is literal in a PowerShell here-string.
	}
	for i := 0; i < len(line); i++ {
		if line[i] != '\\' {
			continue
		}
		// Bash removes these escapes, or joins a line ending in backslash
		// with the next one. A backslash before an ordinary letter stays.
		if i+1 == len(line) || strings.ContainsRune("$`\\", rune(line[i+1])) {
			return true
		}
	}
	return false
}

// closeAfter checks that the feed closes right after the envelope, on its End
// line or the next line, and that the shell text after the close is plain. It
// returns the first line after the close.
func (f patchFeed) closeAfter(lines []string, end int) (int, bool) {
	rest := strings.TrimSpace(strings.TrimSpace(lines[end])[len(patchEndMarker):])
	if f.quote != 0 && rest != "" {
		return end + 1, rest[0] == f.quote && plainShellText(rest[1:])
	}
	if rest != "" || end+1 >= len(lines) {
		return end + 1, false
	}
	next := strings.TrimSpace(lines[end+1])
	switch {
	case f.quote != 0:
		return end + 2, next != "" && next[0] == f.quote && plainShellText(next[1:])
	case f.powershell:
		tail, found := strings.CutPrefix(next, f.delim)
		return end + 2, found && plainShellText(tail)
	default:
		return end + 2, f.delim != "" && next == f.delim
	}
}

// patchBodyShape reports a line that apply_patch reads as patch text: an
// added, removed or context line, a hunk or a "***" header, or an empty line.
func patchBodyShape(line string) bool {
	return line == "" || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") ||
		strings.HasPrefix(line, " ") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "***")
}

// plainShellText reports shell text that leaves no quote open and has no
// construct that nests quoting or reads later lines.
func plainShellText(text string) bool {
	return !shellNesting(text) && openQuote(text) == 0
}

// shellNesting reports an escape, a line continuation, a here-document or
// here-string, a command or parameter substitution, an ANSI-C $'...' quote,
// a PowerShell block comment or a stop-parsing token, in sh or PowerShell.
// Quotes inside or after those do not follow the plain quote rules of
// openQuote. Text in single quotes is literal in both shells, so it is not
// read: printf 'a\n' before an apply_patch heredoc is plain (GAP-0781).
func shellNesting(text string) bool {
	text = withoutSingleQuoted(text)
	if strings.ContainsAny(text, "\\`") {
		return true
	}
	for _, token := range []string{"<<", "<#", "@'", `@"`, "$(", "${", "$'", "--%"} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

// withoutSingleQuoted drops the text between single quotes that are not
// inside double quotes, keeping the quotes. A double-quoted part stays,
// since the shell expands it.
func withoutSingleQuoted(text string) string {
	var out strings.Builder
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote == '\'':
			if c != '\'' {
				continue
			}
			quote = 0
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		}
		out.WriteByte(c)
	}
	return out.String()
}

// openQuote returns the quote character still open at the end of text, which
// has no escapes, or 0.
func openQuote(text string) byte {
	var quote byte
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		}
	}
	return quote
}

// invokesApplyPatch reports a shell text that may run apply_patch as a
// command, also behind a wrapper (env, sudo, nice, nohup, time, exec,
// command) or in a sh -c script. Its patch then comes from a file or a pipe
// the hook cannot read. Each line is also read on its own, so a script fed
// to a shell on stdin (a here-document body) counts too.
func invokesApplyPatch(text string) bool {
	names := []string{"apply_patch", "applypatch", "apply-patch"}
	if tactics.RunsProgram(text, names...) {
		return true
	}
	for _, line := range strings.Split(text, "\n") {
		if tactics.RunsProgram(line, names...) {
			return true
		}
	}
	return false
}

// patchTargetPaths makes a directive path absolute. apply_patch does not
// expand ~ or variables, but a shell or PowerShell wrapper may, so a home
// form yields both the home path and the literal path under cwd.
func patchTargetPaths(path, cwd, home string, resolve bool) ([]string, bool) {
	if len(path) >= 2 && (path[0] == '"' || path[0] == '\'') && path[len(path)-1] == path[0] {
		path = path[1 : len(path)-1]
	}
	if path == "" || len(path) > MaxWriteTargetPathBytes {
		return nil, false
	}
	var paths []string
	literal := path
	if rest, homeForm := trimHomePrefix(path); homeForm {
		if !filepath.IsAbs(home) {
			return nil, false
		}
		paths = append(paths, filepath.Clean(filepath.Join(home, rest)))
	} else if strings.ContainsAny(path, "$`") {
		return nil, false
	}
	if !filepath.IsAbs(literal) {
		if !filepath.IsAbs(cwd) || runtime.GOOS == "windows" && filepath.VolumeName(literal) != "" {
			return nil, false
		}
		if runtime.GOOS == "windows" && (strings.HasPrefix(literal, "/") || strings.HasPrefix(literal, "\\")) {
			// A rooted path uses the current drive or UNC share on Windows.
			literal = filepath.VolumeName(cwd) + literal
		} else {
			literal = filepath.Join(cwd, literal)
		}
	}
	paths = append(paths, filepath.Clean(literal))
	if resolve {
		for _, candidate := range paths {
			if _, known := ResolvePatchWriteTarget(candidate); !known {
				return nil, false
			}
		}
	}
	return paths, true
}

// trimHomePrefix strips a leading home form: ~, $HOME, ${HOME}, $env:HOME,
// $env:USERPROFILE or %USERPROFILE%, alone or followed by a separator.
func trimHomePrefix(path string) (string, bool) {
	lower := strings.ToLower(path)
	for _, prefix := range []string{"~", "${home}", "$home", "$env:userprofile", "$env:home", "%userprofile%"} {
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		rest := path[len(prefix):]
		if rest == "" {
			return "", true
		}
		if rest[0] == '/' || rest[0] == '\\' {
			return strings.TrimLeft(rest, `/\`), true
		}
	}
	return "", false
}
