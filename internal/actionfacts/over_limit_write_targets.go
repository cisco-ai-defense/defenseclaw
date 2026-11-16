// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A native file-write tool call whose arguments go over maxArgsJSONBytes, or
// whose written text goes over maxCommandBytes, is limit-exceeded: its write
// target never becomes a path fact, so no file-write rule judges it
// (GAP-0674). The target keys of these schemas are small; only the text is
// large. OverLimitWriteTargetReduction reads such arguments once more with a
// bounded token scan that keeps every key and every small value, replaces
// only a large value of a reviewed text key with a one-byte stand-in, and
// analyzes that reduced call. A patch envelope keeps every file header and,
// per file, its hunk text without the white space that pads it
// (reducePatchEnvelope); only a file whose own text is still too large for
// the content proofs loses it. The reduced call's facts name the same tool
// and the same targets. The text it leaves out is never in Facts anyway:
// Facts keep only whether a payload is empty. What it leaves out is reported
// (overLimitReduction), so no size alone takes a call out of the content
// proofs: a call that cannot be bounded takes the conservative finding for
// the file whose text was left out (OverLimitWriteElidedContentTarget).

// maxOverLimitWriteArgsBytes bounds the second scan: the gateway's API
// request ceiling, so every hook body the gateway accepts can be read.
const maxOverLimitWriteArgsBytes = 1 << 20

// overLimitTextStandIn replaces a large text value. It is not empty, as the
// value it stands for is not.
const overLimitTextStandIn = "x"

// overLimitTextKeys are the reviewed write-tool argument keys whose value is
// only the text written or replaced (Claude Code, OpenCode, Copilot CLI and
// the Hermes projections). A large value of any other key is kept as it is,
// so a large target or an unknown key leaves the reduced call
// limit-exceeded or partial and the call has no reduction.
var overLimitTextKeys = map[string]struct{}{
	"content":    {},
	"old_string": {},
	"new_string": {},
	"oldString":  {},
	"newString":  {},
	"old_str":    {},
	"new_str":    {},
	"file_text":  {},
	"new_source": {},
}

// StructuredWriteTool reports whether tool names a reviewed native file
// mutation schema: a write, edit, append, create, patch, copy, move or delete
// tool.
func StructuredWriteTool(tool string) bool {
	semantics, known := lookupToolArgumentSemantics(tool)
	if !known {
		return false
	}
	switch semantics.pathShape {
	case toolPathOutput, toolPathPatch, toolPathCopy, toolPathMove:
		return true
	case toolPathTarget:
		return semantics.pathAccess == PathAccessDelete
	default:
		return false
	}
}

// ApplyPatchTool reports whether tool names the apply_patch envelope tool.
func ApplyPatchTool(tool string) bool { return isApplyPatchTool(tool) }

// LimitExceededWriteTool reports whether facts are the limit-exceeded
// analysis of a structured write tool call: one whose write targets the
// ordinary analysis could not read.
func LimitExceededWriteTool(input Input, facts Facts) bool {
	return facts.Parse.Status == StatusLimitExceeded &&
		StructuredWriteTool(input.Tool) &&
		input.Command == "" && len(input.Argv) == 0 &&
		len(bytes.TrimSpace(input.Args)) != 0
}

// OverLimitWriteTargetReduction returns the complete analysis of a
// limit-exceeded structured write tool call with its large text values
// replaced, and those reduced arguments. It reports false when the call is
// not one, when the arguments are malformed or over
// maxOverLimitWriteArgsBytes, or when the reduced call does not analyze
// complete with a write, append or delete target. The view proves only
// what the call writes: callers count a rule match on it and never a
// non-match.
func OverLimitWriteTargetReduction(input Input, facts Facts) (Facts, json.RawMessage, bool) {
	if !LimitExceededWriteTool(input, facts) ||
		len(input.Args) > maxOverLimitWriteArgsBytes || !utf8.Valid(input.Args) {
		return Facts{}, nil, false
	}
	view, reduction, ok := overLimitWriteReduction(input, false)
	return view, reduction.args, ok
}

// OverLimitWriteBoundedTwin returns the arguments of a limit-exceeded
// structured write tool call with each large text in its bounded form
// (boundedOverLimitText) when every large text has one: the same call,
// within the limits, whose content rules read the text as the file gets it
// (GAP-0687). Callers judge it as a twin of the call; false when the call
// is not one or a large text has no bounded form.
func OverLimitWriteBoundedTwin(input Input, facts Facts) (json.RawMessage, bool) {
	if !LimitExceededWriteTool(input, facts) ||
		len(input.Args) > maxOverLimitWriteArgsBytes || !utf8.Valid(input.Args) {
		return nil, false
	}
	_, reduction, ok := overLimitWriteReduction(input, true)
	if !ok || reduction.elidedText {
		return nil, false
	}
	return reduction.args, true
}

func overLimitWriteReduction(input Input, bounded bool) (Facts, overLimitReduction, bool) {
	reduction, ok := reduceOverLimitWriteArgs(input.Args, isApplyPatchTool(input.Tool), bounded)
	if ok && bounded && len(reduction.args) > maxArgsJSONBytes {
		// Escaping can grow a bounded form past the limit; the compact form
		// of the same call is the smaller reading of it.
		reduction, ok = reduceOverLimitWriteArgs(input.Args, isApplyPatchTool(input.Tool), false)
	}
	if !ok || len(reduction.args) > maxArgsJSONBytes {
		return Facts{}, overLimitReduction{}, false
	}
	reducedInput := input
	reducedInput.Args = reduction.args
	view := Analyze(reducedInput)
	if !view.Authoritative() || !factsMutateAPath(view) {
		return Facts{}, overLimitReduction{}, false
	}
	return view, reduction, true
}

// OverLimitWriteElidedContentTarget reports a limit-exceeded structured
// write whose reduced call still stands in for a written text and writes a
// file a content rule judges by its text (contentRuleWriteTarget), and that
// file's class. No content rule can read the text left out, so callers take
// the conservative block where the call is enforcement-capable (GAP-0687).
// An ordinary file is never such a target, however large the write. For a
// patch envelope only a file whose own text was left out counts. A patch
// envelope within maxArgsJSONBytes is not limit-exceeded; it counts the same
// when a file text is still over maxCommandBytes without its white space
// padding (unreadPatchContentTarget). resolved maps an operand to the file it
// reaches through links (nil when unknown).
func OverLimitWriteElidedContentTarget(input Input, facts Facts, resolved map[string]string) (string, bool) {
	if !LimitExceededWriteTool(input, facts) {
		return unreadPatchContentTarget(input, facts, resolved, false)
	}
	if len(input.Args) > maxOverLimitWriteArgsBytes || !utf8.Valid(input.Args) {
		return "", false
	}
	var view Facts
	var reduction overLimitReduction
	ok := false
	for _, bounded := range []bool{true, false} {
		if view, reduction, ok = overLimitWriteReduction(input, bounded); ok {
			break
		}
	}
	if !ok || (!reduction.elidedText && len(reduction.elidedPatchTargets) == 0) {
		return "", false
	}
	for _, path := range view.Paths {
		if path.Access != PathAccessWrite && path.Access != PathAccessAppend {
			continue
		}
		// A patch envelope leaves text out per file: only a file whose own
		// text was left out has an unproven content rule.
		if _, left := reduction.elidedPatchTargets[path.Value]; !reduction.elidedText && !left {
			continue
		}
		if class := pathContentRuleClass(path, view.CWD, input.CWD, resolved); class != "" {
			return class, true
		}
	}
	return "", false
}

// pathContentRuleClass is the class (contentRuleWriteTarget) of the file a
// write path reaches, "" for a file no content rule decides on. resolved is
// the file each operand reaches through the links on its way, as the hook
// client placed it: a link to a protected file is that file. The client keys
// an operand as OperandPath places it, so a relative operand is looked up by
// its placed spelling too.
func pathContentRuleClass(path PathFact, viewCWD, inputCWD string, resolved map[string]string) string {
	cwd := viewCWD
	if cwd == "" {
		cwd = inputCWD
	}
	for _, value := range []string{
		path.Normalized, path.Resolved, resolved[path.Value],
		resolved[OperandPath(path.Value, cwd)], resolved[path.Normalized],
	} {
		if class := contentRuleWriteTarget(value); class != "" {
			return class
		}
	}
	return ""
}

// unreadPatchContentTarget reports an apply_patch envelope that the analysis
// read in full (it is within maxArgsJSONBytes) and that still holds, for a
// file a content rule decides on, a text over maxCommandBytes after its white
// space padding is removed (boundedNativeText): the content proofs read no
// text that long, so no rule has judged it. It is the file the elided text of
// an envelope past maxArgsJSONBytes is (OverLimitWriteElidedContentTarget):
// the callers take the same conservative finding, and no size leaves a band in
// which neither reading applies. An ordinary file is never such a target.
// With combined it reads the write the blocks of one file make together
// (OverLimitCombinedPatchContentTarget) instead of the blocks themselves.
func unreadPatchContentTarget(input Input, facts Facts, resolved map[string]string, combined bool) (string, bool) {
	if !isApplyPatchTool(input.Tool) || !facts.Authoritative() ||
		input.Command != "" || len(input.Argv) != 0 {
		return "", false
	}
	unread := map[string]struct{}{}
	for _, write := range nativeFileWrites(input.Tool, input.Args) {
		if write.target != "" && write.combined == combined && write.textOverProofBound() {
			unread[write.target] = struct{}{}
		}
	}
	if len(unread) == 0 {
		return "", false
	}
	for _, path := range facts.Paths {
		if path.Access != PathAccessWrite && path.Access != PathAccessAppend {
			continue
		}
		if _, left := unread[path.Value]; !left {
			continue
		}
		if class := pathContentRuleClass(path, facts.CWD, input.CWD, resolved); class != "" {
			return class, true
		}
	}
	return "", false
}

// OverLimitCombinedPatchContentTarget is unreadPatchContentTarget for the
// blocks of one file taken together: every block alone is within the proof
// bound (and so read), but the text they make together is not, so no rule has
// judged a document that one block opens and a later block finishes. Only the
// strict tier and a managed install act on it: in the default and permissive
// tiers of a per-user install such blocks stay allowed, as a file written by
// separate calls does.
func OverLimitCombinedPatchContentTarget(input Input, facts Facts, resolved map[string]string) (string, bool) {
	return unreadPatchContentTarget(input, facts, resolved, true)
}

// textOverProofBound reports a text of the write, or a piece of it, that is
// over what the content proofs read: the added text, the removed text (the PAM
// and preload proofs read both the text a patch removes and the text it
// adds), the text each hunk or step leaves in place, and the text each edit
// step replaces.
func (write nativeFileWrite) textOverProofBound() bool {
	if len(write.added) > maxCommandBytes || len(write.replaced) > maxCommandBytes {
		return true
	}
	for _, pieces := range [][]string{write.after, write.before} {
		for _, piece := range pieces {
			if len(piece) > maxCommandBytes {
				return true
			}
		}
	}
	return false
}

// contentRuleWriteTarget is the class of a system file whose structured-write
// content rules decide on the written text: Docker's daemon configuration,
// sudoers, the account database, the global preload list and profile
// fragments, and PAM configuration. "" for any other path.
func contentRuleWriteTarget(value string) string {
	switch {
	case EtcSpelling(value) == dockerDaemonConfigPath:
		return "docker-daemon-config"
	case exactSudoersWriteTarget(value):
		return "sudoers"
	case EtcSpelling(value) == posixPasswdPath:
		return "account-database"
	case EtcSpelling(value) == "/etc/ld.so.preload" || ExactGlobalLDPreloadProfilePath(value):
		return "global-preload"
	case exactProtectedPAMPath(value):
		return "pam"
	}
	return ""
}

func factsMutateAPath(facts Facts) bool {
	for _, path := range facts.Paths {
		switch path.Access {
		case PathAccessWrite, PathAccessAppend, PathAccessDelete:
			return true
		}
	}
	return false
}

// overLimitReduction is the reduced arguments of a limit-exceeded write and
// what the reduction left out: elidedText is set when the text of a text key
// was replaced by the stand-in; elidedPatchTargets holds the header path of
// each patch file whose hunk text was left out.
type overLimitReduction struct {
	args               json.RawMessage
	elidedText         bool
	elidedPatchTargets map[string]struct{}
	// boundedCommand is set when a command text lost its white space padding
	// (OverLimitCommandBoundedTwin).
	boundedCommand bool
}

// overLimitArgsReducer copies one JSON object token by token. It holds the
// limits of validateJSONWithStringLimit (depth, members, key size, unique
// keys) and keeps no value it replaces.
type overLimitArgsReducer struct {
	decoder   *json.Decoder
	out       bytes.Buffer
	members   int
	patchTool bool
	// bounded keeps a large text in its bounded form when it has one.
	bounded bool
	// patchBudget is what the bounded patch files may still add.
	patchBudget int
	// commandTwin reduces only a string over maxCommandBytes, to its form
	// without padding white space, and nothing else.
	commandTwin bool
	overLimitReduction
}

func reduceOverLimitWriteArgs(raw json.RawMessage, patchTool, bounded bool) (overLimitReduction, bool) {
	return runOverLimitReducer(raw, &overLimitArgsReducer{
		patchTool: patchTool, bounded: bounded, patchBudget: maxBoundedPatchBytes,
	})
}

// runOverLimitReducer copies the object raw through reducer.
func runOverLimitReducer(raw json.RawMessage, reducer *overLimitArgsReducer) (overLimitReduction, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return overLimitReduction{}, false
	}
	reducer.decoder = json.NewDecoder(bytes.NewReader(trimmed))
	reducer.decoder.UseNumber()
	if !reducer.value(0, "") {
		return overLimitReduction{}, false
	}
	if _, err := reducer.decoder.Token(); !errors.Is(err, io.EOF) {
		return overLimitReduction{}, false
	}
	reducer.args = json.RawMessage(reducer.out.Bytes())
	return reducer.overLimitReduction, true
}

// value copies the next JSON value; key is the object key it belongs to
// ("" for an array element).
func (r *overLimitArgsReducer) value(depth int, key string) bool {
	if depth > maxJSONDepth {
		return false
	}
	token, err := r.decoder.Token()
	if err != nil {
		return false
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			return r.object(depth)
		case '[':
			return r.array(depth)
		default:
			return false
		}
	case string:
		text, ok := r.reduceString(key, token)
		return ok && r.writeString(text)
	case json.Number:
		r.out.WriteString(token.String())
	case bool:
		if token {
			r.out.WriteString("true")
		} else {
			r.out.WriteString("false")
		}
	case nil:
		r.out.WriteString("null")
	default:
		return false
	}
	return true
}

func (r *overLimitArgsReducer) object(depth int) bool {
	r.out.WriteByte('{')
	seen := make(map[string]struct{})
	for r.decoder.More() {
		token, err := r.decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || len(key) > maxScalarBytes {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		r.members++
		if r.members > maxJSONMembers {
			return false
		}
		if len(seen) > 1 {
			r.out.WriteByte(',')
		}
		if !r.writeString(key) {
			return false
		}
		r.out.WriteByte(':')
		if !r.value(depth+1, key) {
			return false
		}
	}
	end, err := r.decoder.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	r.out.WriteByte('}')
	return true
}

func (r *overLimitArgsReducer) array(depth int) bool {
	r.out.WriteByte('[')
	for index := 0; r.decoder.More(); index++ {
		r.members++
		if r.members > maxJSONMembers {
			return false
		}
		if index > 0 {
			r.out.WriteByte(',')
		}
		if !r.value(depth+1, "") {
			return false
		}
	}
	end, err := r.decoder.Token()
	if err != nil || end != json.Delim(']') {
		return false
	}
	r.out.WriteByte(']')
	return true
}

func (r *overLimitArgsReducer) writeString(text string) bool {
	encoded, err := json.Marshal(text)
	if err != nil {
		return false
	}
	r.out.Write(encoded)
	return true
}

// reduceString keeps a small value, reduces the envelope of a patch tool's
// patch key (reducePatchEnvelope) and stands in for the large value of a text key. Any other
// large value is kept, so the reduced call stays limit-exceeded.
func (r *overLimitArgsReducer) reduceString(key, text string) (string, bool) {
	if r.commandTwin {
		if len(text) > maxCommandBytes {
			if bounded, ok := boundedCommandText(text); ok {
				r.boundedCommand = true
				return bounded, true
			}
		}
		return text, true
	}
	if len(text) <= maxScalarBytes {
		return text, true
	}
	if r.patchTool && (isPatchInputField(key) || isPatchEnvelopeField(key, text)) {
		return r.reducePatch(text)
	}
	if _, ok := overLimitTextKeys[key]; ok {
		if bounded, ok := boundedOverLimitText(text); ok && r.bounded {
			return bounded, true
		}
		r.elidedText = true
		return overLimitTextStandIn, true
	}
	return text, true
}

// boundedOverLimitText is a large written text in a form its content reads
// the same in, when that form fits maxCommandBytes: without the white space
// around it, and, for a JSON document, compacted. White space padding no
// longer puts a short document past the content rules (GAP-0687).
func boundedOverLimitText(text string) (string, bool) {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) > maxCommandBytes && (trimmed[0] == '{' || trimmed[0] == '[') {
		var compact bytes.Buffer
		if json.Compact(&compact, []byte(trimmed)) == nil {
			trimmed = compact.String()
		}
	}
	return trimmed, trimmed != "" && len(trimmed) <= maxCommandBytes
}

// maxBoundedPatchSectionBytes bounds the hunk text one patch file keeps in
// the bounded form: the string limit the content proofs read a file's text
// at. maxBoundedPatchBytes bounds all files together, so that the escaped
// arguments stay within maxArgsJSONBytes.
const (
	maxBoundedPatchSectionBytes = maxCommandBytes
	maxBoundedPatchBytes        = 96 << 10
	// A run of white space longer than this is one space in the bounded
	// form: the text reads the same in any proof that splits on white space,
	// and padding no longer carries protected text past the limits.
	maxKeptWhiteSpaceRun = 64
)

// reducePatch reduces the envelope text of a patch tool (reducePatchEnvelope)
// and records which files' hunk text it left out.
func (r *overLimitArgsReducer) reducePatch(text string) (string, bool) {
	reduced, elided, unscoped, ok := reducePatchEnvelope(text, r.bounded, &r.patchBudget)
	if !ok {
		return "", false
	}
	r.elidedText = r.elidedText || unscoped
	for _, target := range elided {
		if r.elidedPatchTargets == nil {
			r.elidedPatchTargets = make(map[string]struct{})
		}
		r.elidedPatchTargets[target] = struct{}{}
	}
	return reduced, true
}

// patchHunkMarker is the line class of a patch hunk line: "@@", "+", "-" or
// " ". "" for any other line.
func patchHunkMarker(line string) string {
	switch {
	case strings.HasPrefix(line, "@@"):
		return "@@"
	case strings.HasPrefix(line, "+"), strings.HasPrefix(line, "-"), strings.HasPrefix(line, " "):
		return line[:1]
	}
	return ""
}

// boundedPatchHunkLine is a hunk line without the white space that pads it:
// none at its end, and a long run inside it as one space.
func boundedPatchHunkLine(line, marker string) string {
	return marker + boundedWhiteSpaceLine(line[len(marker):])
}

// boundedWhiteSpaceLine is a line of text without the white space that pads
// it: none at its end, and a run longer than maxKeptWhiteSpaceRun inside it
// as one space.
func boundedWhiteSpaceLine(line string) string {
	body := strings.TrimRightFunc(line, unicode.IsSpace)
	if len(body) <= maxKeptWhiteSpaceRun {
		return body
	}
	var out strings.Builder
	runStart := -1
	endRun := func(end int) {
		if run := body[runStart:end]; len(run) > maxKeptWhiteSpaceRun {
			out.WriteByte(' ')
		} else {
			out.WriteString(run)
		}
		runStart = -1
	}
	for index, char := range body {
		if unicode.IsSpace(char) {
			if runStart < 0 {
				runStart = index
			}
			continue
		}
		if runStart >= 0 {
			endRun(index)
		}
		out.WriteRune(char)
	}
	if runStart >= 0 {
		endRun(len(body))
	}
	return out.String()
}

// boundedWhiteSpaceText is a text without the white space that pads it:
// each line as boundedWhiteSpaceLine reads it, and a run of blank lines as
// one blank line. It reads the same in any proof that splits on white space
// and on lines, as the bounded form of a patch file does
// (reducePatchEnvelope).
func boundedWhiteSpaceText(text string) string {
	lines := strings.Split(text, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = boundedWhiteSpaceLine(line)
		if line == "" && len(kept) > 0 && kept[len(kept)-1] == "" {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// patchEnvelopeSection is one file of a patch envelope: its lines in order,
// with each hunk line in its bounded form, the paths it names and the size
// of its hunk lines.
type patchEnvelopeSection struct {
	lines     []string
	targets   []string
	hunkBytes int
}

// compactPatchSectionLines keeps one marker of each run of consecutive hunk
// lines of one class and every other line. dropped reports that a hunk line
// lost text or was left out.
func compactPatchSectionLines(lines []string) (kept []string, dropped bool) {
	kept = make([]string, 0, 16)
	previous := ""
	for _, line := range lines {
		marker := patchHunkMarker(line)
		if marker == "" {
			kept = append(kept, line)
			previous = ""
			continue
		}
		if len(line) > len(marker) || marker == previous {
			dropped = true
		}
		if marker == previous {
			continue
		}
		kept = append(kept, marker)
		previous = marker
	}
	return kept, dropped
}

// reducePatchEnvelope reduces a patch envelope that is over the limits to an
// envelope that parses to the same directives, paths and accesses (or fails
// the same way), and reports the files whose hunk text it left out.
//
// The bounded form keeps every line of a file, each hunk line without the
// white space that pads it, so the content proofs read the text the file
// gets: padding past the limits no longer takes a file out of them. A file
// whose bounded text is itself over maxBoundedPatchSectionBytes (or over what
// is left of the budget), and every file when bounded is false, is compacted:
// of consecutive "+", "-", " " or "@@" lines one marker is kept, which
// parsePatchEnvelope reads the same, since it reads each line only by that
// class. The header paths of the files so compacted are returned as
// elided; unscoped is set when a hunk line outside any file was dropped.
// Files that were not compacted lose nothing.
func reducePatchEnvelope(text string, bounded bool, budget *int) (reduced string, elided []string, unscoped, ok bool) {
	// The padding around the patch is dropped, as the tool drops it; the line
	// end that closes the patch is kept.
	closingLineEnd := ""
	if strings.HasSuffix(strings.TrimRight(text, " \t\r"), "\n") {
		closingLineEnd = "\n"
	}
	normalized := strings.ReplaceAll(strings.TrimSpace(text), "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		return "", nil, false, false
	}
	var out []string
	inUpdate := false
	section := &patchEnvelopeSection{}
	flush := func() {
		lines, dropped := section.lines, false
		if !bounded || section.hunkBytes > maxBoundedPatchSectionBytes || section.hunkBytes > *budget {
			lines, dropped = compactPatchSectionLines(lines)
		} else {
			*budget -= section.hunkBytes
		}
		out = append(out, lines...)
		if dropped {
			if len(section.targets) == 0 {
				unscoped = true
			}
			elided = append(elided, section.targets...)
		}
	}
	previous := ""
	for _, line := range strings.Split(normalized, "\n") {
		// The tool reads a file header without the white space around it
		// (parsePatchEnvelope), so the header is kept in that form.
		if header := strings.TrimSpace(line); header != line &&
			isPatchFileHeader(header) && (!inUpdate || line[0] != ' ') {
			line = header
		}
		if isPatchFileHeader(line) {
			inUpdate = strings.HasPrefix(line, "*** Update File: ")
		}
		switch {
		case strings.HasPrefix(line, "*** Add File: "), strings.HasPrefix(line, "*** Update File: "),
			strings.HasPrefix(line, "*** Delete File: "):
			flush()
			section = &patchEnvelopeSection{}
			previous = ""
			section.targets = append(section.targets, patchDirectivePath(line, line[:strings.Index(line, ": ")+2]))
		case strings.HasPrefix(line, "*** Move to: "):
			section.targets = append(section.targets, patchDirectivePath(line, "*** Move to: "))
		}
		marker := patchHunkMarker(line)
		if marker == "" {
			section.lines = append(section.lines, line)
			previous = ""
			continue
		}
		line = boundedPatchHunkLine(line, marker)
		if line == marker && line == previous {
			// Blank repeats read the same as one blank line of that class.
			continue
		}
		previous = line
		section.lines = append(section.lines, line)
		section.hunkBytes += len(line) + 1
	}
	flush()
	return strings.Join(out, "\n") + closingLineEnd, elided, unscoped, true
}
