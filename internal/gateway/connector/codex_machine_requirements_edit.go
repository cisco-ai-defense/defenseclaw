// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// The Windows Codex machine requirements document is usually authored by an
// administrator (Intune, GPO, configuration-management templates). DefenseClaw
// therefore never re-marshals it. Install and repair insert only the missing
// DefenseClaw-owned keys and hook groups, and surgical uninstall deletes only
// those entries; every other byte, including comments, ordering, and
// formatting, is preserved. (Uninstall is surgical only when the file no longer
// equals the recorded postimage; otherwise RemoveWindowsCodexMachineRequirements
// restores the stored install-time preimage.) The additions are:
//
//   - root keys, inserted at the top of the document and tagged with
//     windowsCodexRequirementsLineMarker (a TOML root key can only precede the
//     first table header);
//   - single keys added to an administrator-defined [features] or [hooks]
//     table, inserted directly below that header with the same tag;
//   - new tables and [[hooks.<event>]] groups, written inside one delimited
//     region at the end of the document.
//
// The TOML parser is used only to locate expressions. Each edited document is
// re-parsed and must be semantically identical to the model produced by the
// map-based merge/removal logic, so an unexpected layout fails closed with an
// error instead of rewriting or corrupting the administrator's policy.
const (
	windowsCodexRequirementsLineMarker  = "# managed by DefenseClaw"
	windowsCodexRequirementsRegionBegin = "# BEGIN DefenseClaw managed hooks (generated; do not edit inside this block)"
	windowsCodexRequirementsRegionEnd   = "# END DefenseClaw managed hooks"
)

type codexTOMLTableForm int

const (
	codexTOMLTableAbsent codexTOMLTableForm = iota
	// codexTOMLTableImplicit tables exist only through sub-table headers such
	// as [[hooks.Stop]]; TOML allows defining the super-table afterwards.
	codexTOMLTableImplicit
	codexTOMLTableHeader
	codexTOMLTableDottedRoot
	codexTOMLTableInline
)

type codexTOMLExpr struct {
	kind       unstable.Kind
	path       []string
	inRoot     bool
	keyOffset  int
	lineStart  int
	valueKind  unstable.Kind
	valueStart int
	valueEnd   int
}

type codexTOMLDocument struct {
	raw     []byte
	newline string
	exprs   []codexTOMLExpr
}

type codexTOMLEdit struct {
	start int
	end   int
	text  string
}

type codexTOMLRegion struct {
	beginLineStart int
	endLineStart   int
	endLineEnd     int
}

func parseCodexTOMLDocument(raw []byte) (*codexTOMLDocument, error) {
	doc := &codexTOMLDocument{raw: raw, newline: "\n"}
	if bytes.Contains(raw, []byte("\r\n")) {
		doc.newline = "\r\n"
	}
	var parser unstable.Parser
	parser.Reset(raw)
	var table []string
	for parser.NextExpression() {
		node := parser.Expression()
		if node.Kind != unstable.Table && node.Kind != unstable.ArrayTable &&
			node.Kind != unstable.KeyValue {
			continue
		}
		keys := make([]string, 0, 4)
		keyOffset := -1
		iterator := node.Key()
		for iterator.Next() {
			key := iterator.Node()
			if keyOffset < 0 {
				keyOffset = int(key.Raw.Offset)
			}
			keys = append(keys, string(key.Data))
		}
		if keyOffset < 0 || keyOffset > len(raw) {
			return nil, errors.New("TOML expression has no key position")
		}
		expr := codexTOMLExpr{
			kind:       node.Kind,
			keyOffset:  keyOffset,
			lineStart:  bytes.LastIndexByte(raw[:keyOffset], '\n') + 1,
			valueStart: -1,
			valueEnd:   -1,
		}
		// Every TOML expression starts on its own line; only indentation and
		// header brackets may precede its first key.
		for _, char := range raw[expr.lineStart:keyOffset] {
			if char != ' ' && char != '\t' && char != '[' {
				return nil, errors.New("TOML expression does not start on its own line")
			}
		}
		switch node.Kind {
		case unstable.Table, unstable.ArrayTable:
			expr.path = keys
			table = keys
		case unstable.KeyValue:
			expr.inRoot = table == nil
			expr.path = append(append(make([]string, 0, len(table)+len(keys)), table...), keys...)
			value := node.Value()
			expr.valueKind = value.Kind
			if value.Kind == unstable.String && value.Raw.Length > 0 {
				expr.valueStart = int(value.Raw.Offset)
				expr.valueEnd = int(value.Raw.Offset + value.Raw.Length)
			}
		}
		doc.exprs = append(doc.exprs, expr)
	}
	if err := parser.Error(); err != nil {
		return nil, err
	}
	return doc, nil
}

func codexTOMLPathEqual(path []string, want ...string) bool {
	if len(path) != len(want) {
		return false
	}
	for index := range path {
		if path[index] != want[index] {
			return false
		}
	}
	return true
}

func codexTOMLPathHasPrefix(path []string, prefix []string) bool {
	return len(path) >= len(prefix) && codexTOMLPathEqual(path[:len(prefix)], prefix...)
}

// lineEnd returns the offset just past the newline terminating the line that
// contains offset, or the document length for an unterminated last line.
func (d *codexTOMLDocument) lineEnd(offset int) int {
	if offset >= len(d.raw) {
		return len(d.raw)
	}
	if index := bytes.IndexByte(d.raw[offset:], '\n'); index >= 0 {
		return offset + index + 1
	}
	return len(d.raw)
}

func (d *codexTOMLDocument) header(name string) *codexTOMLExpr {
	for index := range d.exprs {
		if d.exprs[index].kind == unstable.Table && codexTOMLPathEqual(d.exprs[index].path, name) {
			return &d.exprs[index]
		}
	}
	return nil
}

func (d *codexTOMLDocument) keyValue(path ...string) *codexTOMLExpr {
	for index := range d.exprs {
		if d.exprs[index].kind == unstable.KeyValue && codexTOMLPathEqual(d.exprs[index].path, path...) {
			return &d.exprs[index]
		}
	}
	return nil
}

func (d *codexTOMLDocument) tableForm(name string) codexTOMLTableForm {
	if d.keyValue(name) != nil {
		return codexTOMLTableInline
	}
	if d.header(name) != nil {
		return codexTOMLTableHeader
	}
	form := codexTOMLTableAbsent
	for _, expr := range d.exprs {
		if len(expr.path) < 2 || expr.path[0] != name {
			continue
		}
		if expr.kind == unstable.KeyValue && expr.inRoot {
			return codexTOMLTableDottedRoot
		}
		form = codexTOMLTableImplicit
	}
	return form
}

// headerKeyValues returns the key/value expressions defined directly under
// the first [name] header, before the next table header.
func (d *codexTOMLDocument) headerKeyValues(name string) []*codexTOMLExpr {
	var values []*codexTOMLExpr
	inside, seen := false, false
	for index := range d.exprs {
		expr := &d.exprs[index]
		switch expr.kind {
		case unstable.Table, unstable.ArrayTable:
			inside = !seen && expr.kind == unstable.Table && codexTOMLPathEqual(expr.path, name)
			seen = seen || inside
		case unstable.KeyValue:
			if inside {
				values = append(values, expr)
			}
		}
	}
	return values
}

// insideRegion reports whether offset lies between the markers of a
// DefenseClaw region.
func (d *codexTOMLDocument) insideRegion(offset int) bool {
	for _, region := range codexTOMLRegions(d.raw) {
		if offset > region.beginLineStart && offset < region.endLineStart {
			return true
		}
	}
	return false
}

// keyValueLineRange covers the complete lines of a scalar key/value
// expression, including a trailing comment and the terminating newline.
func (d *codexTOMLDocument) keyValueLineRange(expr *codexTOMLExpr) (int, int) {
	last := expr.keyOffset
	if expr.valueEnd > 0 {
		last = expr.valueEnd - 1
	}
	return expr.lineStart, d.lineEnd(last)
}

// arrayTableElements returns the byte range of each [[path]] element in
// document order. An element extends to the next header that is not one of its
// sub-tables; trailing blank and comment-only lines stay with what follows.
func (d *codexTOMLDocument) arrayTableElements(path ...string) [][2]int {
	var elements [][2]int
	for index, expr := range d.exprs {
		if expr.kind != unstable.ArrayTable || !codexTOMLPathEqual(expr.path, path...) {
			continue
		}
		end := len(d.raw)
		for _, next := range d.exprs[index+1:] {
			if next.kind != unstable.Table && next.kind != unstable.ArrayTable {
				continue
			}
			if len(next.path) > len(path) && codexTOMLPathHasPrefix(next.path, path) {
				continue
			}
			end = next.lineStart
			break
		}
		elements = append(elements, [2]int{expr.lineStart, trimCodexTOMLTrailingTrivia(d.raw, expr.lineStart, end)})
	}
	return elements
}

func codexTOMLTrivialLine(line []byte) bool {
	trimmed := bytes.TrimLeft(line, " \t")
	trimmed = bytes.TrimRight(trimmed, " \t\r\n")
	return len(trimmed) == 0 || trimmed[0] == '#'
}

func trimCodexTOMLTrailingTrivia(raw []byte, start, end int) int {
	for end > start {
		lineStart := start + bytes.LastIndexByte(raw[start:end-1], '\n') + 1
		if !codexTOMLTrivialLine(raw[lineStart:end]) {
			break
		}
		end = lineStart
	}
	return end
}

func codexTOMLMarkerLine(line []byte) string {
	return string(bytes.Trim(line, " \t\r\n"))
}

// codexTOMLLines splits raw into lines that keep their terminators.
func codexTOMLLines(raw []byte) [][2]int {
	var lines [][2]int
	for start := 0; start < len(raw); {
		end := len(raw)
		if index := bytes.IndexByte(raw[start:], '\n'); index >= 0 {
			end = start + index + 1
		}
		lines = append(lines, [2]int{start, end})
		start = end
	}
	return lines
}

func codexTOMLRegions(raw []byte) []codexTOMLRegion {
	var regions []codexTOMLRegion
	begin := -1
	for _, line := range codexTOMLLines(raw) {
		switch codexTOMLMarkerLine(raw[line[0]:line[1]]) {
		case windowsCodexRequirementsRegionBegin:
			begin = line[0]
		case windowsCodexRequirementsRegionEnd:
			if begin >= 0 {
				regions = append(regions, codexTOMLRegion{
					beginLineStart: begin,
					endLineStart:   line[0],
					endLineEnd:     line[1],
				})
			}
			begin = -1
		}
	}
	return regions
}

func applyCodexTOMLEdits(raw []byte, edits []codexTOMLEdit) ([]byte, error) {
	sort.SliceStable(edits, func(left, right int) bool {
		return edits[left].start < edits[right].start
	})
	var out bytes.Buffer
	out.Grow(len(raw))
	cursor := 0
	for _, edit := range edits {
		if edit.start < cursor || edit.end < edit.start || edit.end > len(raw) {
			return nil, errors.New("overlapping Codex requirements edits")
		}
		out.Write(raw[cursor:edit.start])
		out.WriteString(edit.text)
		cursor = edit.end
	}
	out.Write(raw[cursor:])
	return out.Bytes(), nil
}

func codexTOMLEndsWithNewline(raw []byte) bool {
	return len(raw) > 0 && raw[len(raw)-1] == '\n'
}

func codexTOMLKey(key string) string {
	if key == "" {
		return `""`
	}
	for _, char := range key {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' || char == '_' || char == '-') {
			return codexTOMLString(key)
		}
	}
	return key
}

// codexTOMLString renders a single-line TOML string, preferring a literal
// string so Windows paths keep their backslashes verbatim.
func codexTOMLString(value string) string {
	literal := utf8.ValidString(value)
	for _, char := range value {
		if char == '\'' || char == 0x7f || char < 0x20 && char != '\t' {
			literal = false
			break
		}
	}
	if literal {
		return "'" + value + "'"
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, char := range value {
		switch char {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if char < 0x20 || char == 0x7f {
				out.WriteString(fmt.Sprintf(`\u%04X`, char))
			} else {
				out.WriteRune(char)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

func renderWindowsCodexRequirementsGroup(group codexHookGroup, hookBinary, newline string) string {
	command := codexTOMLString(windowsCodexManagedHookCommand(hookBinary))
	event := codexTOMLKey(group.eventType)
	lines := []string{"[[hooks." + event + "]]"}
	if group.matcher != "" {
		lines = append(lines, "matcher = "+codexTOMLString(group.matcher))
	}
	lines = append(lines,
		"[[hooks."+event+".hooks]]",
		"type = 'command'",
		"command = "+command,
		"command_windows = "+command,
		"timeout = "+strconv.Itoa(group.timeout),
	)
	return strings.Join(lines, newline)
}

// windowsCodexRequirementsMergePlan lists the DefenseClaw-owned entries the
// map-based merge added or normalized.
type windowsCodexRequirementsMergePlan struct {
	addManagedHooksOnly bool
	addFeatureHooks     bool
	addManagedDir       bool
	replaceManagedDir   bool
	missingGroups       []codexHookGroup
}

func (p windowsCodexRequirementsMergePlan) empty() bool {
	return !p.addManagedHooksOnly && !p.addFeatureHooks && !p.addManagedDir &&
		!p.replaceManagedDir && len(p.missingGroups) == 0
}

func windowsCodexRequirementsUneditableError(what string) error {
	return fmt.Errorf(
		"%s is defined in a form DefenseClaw cannot edit without rewriting administrator content; "+
			"convert it to a standard TOML table or add the DefenseClaw managed entries manually",
		what,
	)
}

// renderWindowsCodexRequirementsMerge inserts the plan's additions into raw
// without touching any existing byte (apart from a canonical managed
// directory value the merge normalizes).
func renderWindowsCodexRequirementsMerge(
	raw []byte,
	plan windowsCodexRequirementsMergePlan,
	opts WindowsCodexMachineRequirementsOptions,
) ([]byte, error) {
	if plan.empty() {
		return append([]byte(nil), raw...), nil
	}
	doc, err := parseCodexTOMLDocument(raw)
	if err != nil {
		return nil, err
	}
	newline := doc.newline
	var edits []codexTOMLEdit
	var rootLines []string
	var tailBlocks []string
	insertAfterHeader := func(name, line string) {
		offset := doc.lineEnd(doc.header(name).keyOffset)
		text := line + " " + windowsCodexRequirementsLineMarker + newline
		if offset == len(raw) && !codexTOMLEndsWithNewline(raw) {
			text = newline + text
		}
		edits = append(edits, codexTOMLEdit{start: offset, end: offset, text: text})
	}

	if plan.addManagedHooksOnly {
		rootLines = append(rootLines, "allow_managed_hooks_only = true")
	}
	if plan.addFeatureHooks {
		switch doc.tableForm("features") {
		case codexTOMLTableHeader:
			insertAfterHeader("features", "hooks = true")
		case codexTOMLTableDottedRoot:
			rootLines = append(rootLines, "features.hooks = true")
		case codexTOMLTableInline:
			return nil, windowsCodexRequirementsUneditableError("features")
		default:
			tailBlocks = append(tailBlocks, "[features]"+newline+"hooks = true")
		}
	}
	managedDir := codexTOMLString(opts.ManagedDir)
	if plan.addManagedDir {
		switch doc.tableForm("hooks") {
		case codexTOMLTableHeader:
			insertAfterHeader("hooks", "windows_managed_dir = "+managedDir)
		case codexTOMLTableDottedRoot:
			rootLines = append(rootLines, "hooks.windows_managed_dir = "+managedDir)
		case codexTOMLTableInline:
			return nil, windowsCodexRequirementsUneditableError("hooks")
		default:
			tailBlocks = append(tailBlocks, "[hooks]"+newline+"windows_managed_dir = "+managedDir)
		}
	} else if plan.replaceManagedDir {
		expr := doc.keyValue("hooks", "windows_managed_dir")
		if expr == nil || expr.valueKind != unstable.String || expr.valueStart < 0 {
			return nil, windowsCodexRequirementsUneditableError("hooks.windows_managed_dir")
		}
		edits = append(edits, codexTOMLEdit{start: expr.valueStart, end: expr.valueEnd, text: managedDir})
	}
	if len(plan.missingGroups) > 0 && doc.tableForm("hooks") == codexTOMLTableInline {
		return nil, windowsCodexRequirementsUneditableError("hooks")
	}
	for _, group := range plan.missingGroups {
		if doc.keyValue("hooks", group.eventType) != nil {
			return nil, windowsCodexRequirementsUneditableError("hooks." + group.eventType)
		}
		tailBlocks = append(tailBlocks, renderWindowsCodexRequirementsGroup(group, opts.HookBinary, newline))
	}
	if len(rootLines) > 0 {
		var text strings.Builder
		for _, line := range rootLines {
			text.WriteString(line + " " + windowsCodexRequirementsLineMarker + newline)
		}
		edits = append(edits, codexTOMLEdit{start: 0, end: 0, text: text.String()})
	}
	rendered, err := applyCodexTOMLEdits(raw, edits)
	if err != nil {
		return nil, err
	}
	if len(tailBlocks) == 0 {
		return rendered, nil
	}
	return appendWindowsCodexRequirementsRegion(rendered, strings.Join(tailBlocks, newline+newline), newline)
}

// appendWindowsCodexRequirementsRegion adds content to the final DefenseClaw
// region when nothing but comments follows it, otherwise to a new region at
// the end of the document. content always starts with a table header, so the
// administrator's last table cannot absorb it.
func appendWindowsCodexRequirementsRegion(raw []byte, content, newline string) ([]byte, error) {
	doc, err := parseCodexTOMLDocument(raw)
	if err != nil {
		return nil, err
	}
	if regions := codexTOMLRegions(raw); len(regions) > 0 {
		region := regions[len(regions)-1]
		trailingExpression := false
		for _, expr := range doc.exprs {
			if expr.lineStart >= region.endLineStart {
				trailingExpression = true
				break
			}
		}
		if !trailingExpression {
			text := newline + content + newline
			previousStart := bytes.LastIndexByte(raw[:max(region.endLineStart-1, 0)], '\n') + 1
			previous := raw[previousStart:region.endLineStart]
			if previousStart == region.beginLineStart || codexTOMLMarkerLine(previous) == "" {
				text = content + newline
			}
			return applyCodexTOMLEdits(raw, []codexTOMLEdit{{
				start: region.endLineStart,
				end:   region.endLineStart,
				text:  text,
			}})
		}
	}
	var text strings.Builder
	if len(raw) > 0 {
		if !codexTOMLEndsWithNewline(raw) {
			text.WriteString(newline)
		}
		text.WriteString(newline)
	}
	text.WriteString(windowsCodexRequirementsRegionBegin + newline)
	text.WriteString(content + newline)
	text.WriteString(windowsCodexRequirementsRegionEnd + newline)
	return append(append([]byte(nil), raw...), text.String()...), nil
}

// windowsCodexRequirementsRemovalPlan lists the entries the map-based
// surgical removal deleted. Group indices refer to the current document.
type windowsCodexRequirementsRemovalPlan struct {
	removedGroups          map[string][]int
	groupCounts            map[string]int
	removeManagedDir       bool
	removeHooksTable       bool
	removeManagedHooksOnly bool
	removeFeatureHooks     bool
	removeFeaturesTable    bool
}

// renderWindowsCodexRequirementsRemoval deletes exactly the expressions the
// plan names and nothing else. The result must reproduce want, the policy
// computed by the map-based removal. Leftover blank lines inside DefenseClaw
// regions are tidied and emptied regions are dropped; if tidying would change
// the policy (for example a multi-line string inside a region), the untidied
// edit is used.
func renderWindowsCodexRequirementsRemoval(
	raw []byte,
	plan windowsCodexRequirementsRemovalPlan,
	want map[string]interface{},
) ([]byte, error) {
	doc, err := parseCodexTOMLDocument(raw)
	if err != nil {
		return nil, err
	}
	var edits []codexTOMLEdit
	removeKeyValue := func(path ...string) error {
		expr := doc.keyValue(path...)
		if expr == nil {
			return windowsCodexRequirementsUneditableError(strings.Join(path, "."))
		}
		start, end := doc.keyValueLineRange(expr)
		edits = append(edits, codexTOMLEdit{start: start, end: end})
		return nil
	}
	removeTable := func(name string) {
		if header := doc.header(name); header != nil {
			edits = append(edits, codexTOMLEdit{start: header.lineStart, end: doc.lineEnd(header.keyOffset)})
		} else if expr := doc.keyValue(name); expr != nil {
			start, end := doc.keyValueLineRange(expr)
			edits = append(edits, codexTOMLEdit{start: start, end: end})
		}
	}

	events := make([]string, 0, len(plan.removedGroups))
	for event := range plan.removedGroups {
		events = append(events, event)
	}
	sort.Strings(events)
	for _, event := range events {
		elements := doc.arrayTableElements("hooks", event)
		if len(elements) != plan.groupCounts[event] {
			return nil, windowsCodexRequirementsUneditableError("hooks." + event)
		}
		for _, index := range plan.removedGroups[event] {
			edits = append(edits, codexTOMLEdit{start: elements[index][0], end: elements[index][1]})
		}
	}
	if plan.removeManagedDir {
		if err := removeKeyValue("hooks", "windows_managed_dir"); err != nil {
			return nil, err
		}
	}
	if plan.removeHooksTable {
		removeTable("hooks")
	}
	if plan.removeManagedHooksOnly {
		if err := removeKeyValue("allow_managed_hooks_only"); err != nil {
			return nil, err
		}
	}
	if plan.removeFeatureHooks {
		if err := removeKeyValue("features", "hooks"); err != nil {
			return nil, err
		}
	}
	if plan.removeFeaturesTable {
		removeTable("features")
	}

	// When the baseline defined a table only through sub-tables (for example
	// [features.sub]), install wrote its own [features] or [hooks] header
	// inside the DefenseClaw region. That header is DefenseClaw's once its only
	// key is removed, and dropping it keeps the policy because the sub-tables
	// still define the table. The edit is tried first and skipped if the
	// policy would change.
	var headerEdits []codexTOMLEdit
	removeRegionHeader := func(name, key string) {
		header := doc.header(name)
		if header == nil || !doc.insideRegion(header.lineStart) {
			return
		}
		for _, expr := range doc.headerKeyValues(name) {
			if !codexTOMLPathEqual(expr.path, name, key) {
				return
			}
		}
		headerEdits = append(headerEdits, codexTOMLEdit{start: header.lineStart, end: doc.lineEnd(header.keyOffset)})
	}
	if plan.removeFeatureHooks && !plan.removeFeaturesTable {
		removeRegionHeader("features", "hooks")
	}
	if plan.removeManagedDir && !plan.removeHooksTable {
		removeRegionHeader("hooks", "windows_managed_dir")
	}
	candidates := [][]codexTOMLEdit{edits}
	if len(headerEdits) > 0 {
		candidates = [][]codexTOMLEdit{append(append([]codexTOMLEdit(nil), edits...), headerEdits...), edits}
	}
	var mismatch error
	for _, candidate := range candidates {
		cleaned, err := applyCodexTOMLEdits(raw, candidate)
		if err != nil {
			return nil, err
		}
		tidied, err := tidyWindowsCodexRequirementsRegions(cleaned, doc.newline)
		if err != nil {
			return nil, err
		}
		if requireWindowsCodexRequirementsModel(tidied, want) == nil {
			return tidied, nil
		}
		if mismatch = requireWindowsCodexRequirementsModel(cleaned, want); mismatch == nil {
			return cleaned, nil
		}
	}
	return nil, mismatch
}

// tidyWindowsCodexRequirementsRegions drops blank lines at the edges of each
// DefenseClaw region and collapses blank runs inside it. A region left with
// no content is deleted together with the blank separator line written before
// it, restoring the administrator's original trailing bytes.
func tidyWindowsCodexRequirementsRegions(raw []byte, newline string) ([]byte, error) {
	var edits []codexTOMLEdit
	for _, region := range codexTOMLRegions(raw) {
		innerStart := region.beginLineStart
		if index := bytes.IndexByte(raw[innerStart:], '\n'); index >= 0 {
			innerStart += index + 1
		} else {
			continue
		}
		inner := raw[innerStart:region.endLineStart]
		var kept bytes.Buffer
		pendingBlank := false
		for _, line := range codexTOMLLines(inner) {
			text := inner[line[0]:line[1]]
			if codexTOMLMarkerLine(text) == "" {
				pendingBlank = kept.Len() > 0
				continue
			}
			if pendingBlank {
				kept.WriteString(newline)
				pendingBlank = false
			}
			kept.Write(text)
		}
		if kept.Len() > 0 {
			if !bytes.Equal(kept.Bytes(), inner) {
				edits = append(edits, codexTOMLEdit{start: innerStart, end: region.endLineStart, text: kept.String()})
			}
			continue
		}
		start := region.beginLineStart
		if start > 0 {
			previousStart := bytes.LastIndexByte(raw[:start-1], '\n') + 1
			if codexTOMLMarkerLine(raw[previousStart:start]) == "" {
				start = previousStart
			}
		}
		edits = append(edits, codexTOMLEdit{start: start, end: region.endLineEnd})
	}
	if len(edits) == 0 {
		return raw, nil
	}
	return applyCodexTOMLEdits(raw, edits)
}

// requireWindowsCodexRequirementsModel proves a structure-preserving edit
// produced exactly the policy the map-based merge or removal computed.
func requireWindowsCodexRequirementsModel(rendered []byte, want map[string]interface{}) error {
	got, err := parseWindowsCodexRequirements(rendered)
	if err != nil {
		return fmt.Errorf("edited Codex requirements are not valid TOML: %w", err)
	}
	gotCanonical, err := toml.Marshal(got)
	if err != nil {
		return err
	}
	wantCanonical, err := toml.Marshal(want)
	if err != nil {
		return err
	}
	if !bytes.Equal(gotCanonical, wantCanonical) {
		return errors.New(
			"structure-preserving Codex requirements edit does not match the expected policy; " +
				"refusing to rewrite administrator content",
		)
	}
	return nil
}
