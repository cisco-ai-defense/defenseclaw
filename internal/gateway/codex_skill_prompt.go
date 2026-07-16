// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	codexPromptSkillSurface       = "user_prompt_submit"
	codexMaxPromptSkillSelections = 256
)

// codexSkillSelection is the only prompt material retained by the skill
// policy path. Raw is always the bounded label token (for example, "$review")
// so audit output cannot expose an arbitrary linked destination. LinkedPath is
// retained internally for trusted exact-path resolution and must not be copied
// into asset-policy telemetry. The rest of the prompt is never retained.
type codexSkillSelection struct {
	Name       string
	Raw        string
	LinkedPath string
}

// lexCodexSkillSelections recognizes the explicit skill-selection syntax that
// reaches Codex 0.144.0's UserPromptSubmit hook. Codex itself accepts a broader
// dollar-reference grammar. Candidate tokenization follows Codex's
// is_mention_name_char set exactly (ASCII letters, digits, underscore, hyphen,
// and colon); exact runtime/policy identity lookup then distinguishes a real
// skill from currency, shell syntax, or ordinary dollar words. The hook still
// ignores escaped dollars, code, path-shaped values, and substrings. Ambiguous
// bare tokens such as $home or $5 are candidates because Codex permits those
// canonical names; they are ignored unless exact known identity lookup proves
// the client could select them.
//
// This function only identifies syntactically valid candidates. The caller
// performs an exact lookup against connector-scoped runtime state or configured
// policy identities before treating a candidate as a skill selection.
func lexCodexSkillSelections(prompt string) []codexSkillSelection {
	lines := codexPromptLinesOutsideFencedCode(prompt)
	lines = codexMaskMatchedInlineCodeSpans(lines)
	visiblePrompt := codexPromptTextOutsideCode(lines)

	var selections []codexSkillSelection
	seen := make(map[string]struct{})
	for _, selection := range lexCodexSkillSelectionsInlineText(visiblePrompt) {
		key := selection.Raw + "\x00" + selection.LinkedPath
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		selections = append(selections, selection)
	}
	return selections
}

type codexPromptLine struct {
	text      string
	blockCode bool
}

type codexMarkdownContainer struct {
	kind               byte
	continuationIndent int
}

type codexFenceState struct {
	char       byte
	width      int
	containers []codexMarkdownContainer
}

const (
	codexBlockQuoteContainer byte = '>'
	codexListContainer       byte = '-'
)

// codexPromptLinesOutsideFencedCode recognizes fences after CommonMark block
// quote and list container markers. Container membership is retained while a
// fence is open so an unterminated fence in one item cannot hide a real
// selection after that quote or list item ends.
func codexPromptLinesOutsideFencedCode(prompt string) []codexPromptLine {
	rawLines := strings.Split(prompt, "\n")
	lines := make([]codexPromptLine, 0, len(rawLines))
	var fence codexFenceState
	for _, rawLine := range rawLines {
		line := strings.TrimSuffix(rawLine, "\r")
		if fence.char != 0 {
			content, belongs := codexMarkdownContainerContinuation(line, fence.containers)
			if belongs {
				lines = append(lines, codexPromptLine{text: line, blockCode: true})
				if codexFenceClose(content, fence.char, fence.width) {
					fence = codexFenceState{}
				}
				continue
			}
			// The containing quote/list ended before its fence was closed. In
			// CommonMark the fenced block ends with the container, so process
			// this line normally instead of suppressing the rest of the prompt.
			fence = codexFenceState{}
		}

		content, containers := codexMarkdownContainerOpening(line)
		if char, width, opened := codexFenceOpen(content); opened {
			lines = append(lines, codexPromptLine{text: line, blockCode: true})
			fence = codexFenceState{char: char, width: width, containers: containers}
			continue
		}
		_, rawIndented := codexMarkdownIndent(line)
		_, containerIndented := codexMarkdownIndent(content)
		lines = append(lines, codexPromptLine{
			text:      line,
			blockCode: rawIndented || len(containers) > 0 && containerIndented,
		})
	}
	return lines
}

func codexPromptTextOutsideCode(lines []codexPromptLine) string {
	var visible strings.Builder
	for index, line := range lines {
		if index > 0 {
			visible.WriteByte('\n')
		}
		if !line.blockCode {
			visible.WriteString(line.text)
			continue
		}
		// A non-whitespace mask both removes selections inside block code
		// and prevents linked syntax from spanning across a block boundary.
		visible.WriteString(strings.Repeat("!", len(line.text)))
	}
	return visible.String()
}

func codexFenceOpen(line string) (byte, int, bool) {
	start, indented := codexMarkdownIndent(line)
	if indented || start >= len(line) || line[start] != '`' && line[start] != '~' {
		return 0, 0, false
	}
	width := byteRunLength(line, start, line[start])
	if width < 3 {
		return 0, 0, false
	}
	if line[start] == '`' && strings.ContainsRune(line[start+width:], '`') {
		return 0, 0, false
	}
	return line[start], width, true
}

func codexFenceClose(line string, char byte, width int) bool {
	start, indented := codexMarkdownIndent(line)
	if indented || start >= len(line) || line[start] != char {
		return false
	}
	run := byteRunLength(line, start, char)
	if run < width {
		return false
	}
	return strings.TrimSpace(line[start+run:]) == ""
}

func codexMarkdownIndent(line string) (int, bool) {
	spaces := 0
	for spaces < len(line) && line[spaces] == ' ' {
		spaces++
	}
	return spaces, spaces >= 4 || spaces < len(line) && line[spaces] == '\t'
}

// codexMarkdownContainerOpening removes only leading CommonMark quote/list
// markers. The returned continuation contract is later used to ensure a fence
// cannot escape its container.
func codexMarkdownContainerOpening(line string) (string, []codexMarkdownContainer) {
	pos := 0
	var containers []codexMarkdownContainer
	for pos < len(line) {
		indent := byteRunLength(line, pos, ' ')
		if indent > 3 {
			break
		}
		marker := pos + indent
		if marker < len(line) && line[marker] == '>' {
			pos = marker + 1
			if pos < len(line) && (line[pos] == ' ' || line[pos] == '\t') {
				pos++
			}
			containers = append(containers, codexMarkdownContainer{kind: codexBlockQuoteContainer})
			continue
		}
		markerWidth, padding, ok := codexListMarker(line, marker)
		if !ok {
			break
		}
		containers = append(containers, codexMarkdownContainer{
			kind:               codexListContainer,
			continuationIndent: indent + markerWidth + padding,
		})
		pos = marker + markerWidth + padding
	}
	return line[pos:], containers
}

func codexMarkdownContainerContinuation(line string, containers []codexMarkdownContainer) (string, bool) {
	if len(containers) == 0 {
		return line, true
	}
	pos := 0
	for _, container := range containers {
		switch container.kind {
		case codexBlockQuoteContainer:
			indent := byteRunLength(line, pos, ' ')
			if indent > 3 || pos+indent >= len(line) || line[pos+indent] != '>' {
				return "", false
			}
			pos += indent + 1
			if pos < len(line) && (line[pos] == ' ' || line[pos] == '\t') {
				pos++
			}
		case codexListContainer:
			if strings.TrimSpace(line[pos:]) == "" {
				return "", true
			}
			if len(line)-pos < container.continuationIndent {
				return "", false
			}
			for consumed := 0; consumed < container.continuationIndent; consumed++ {
				if line[pos+consumed] != ' ' {
					return "", false
				}
			}
			pos += container.continuationIndent
		default:
			return "", false
		}
	}
	return line[pos:], true
}

func codexListMarker(line string, start int) (int, int, bool) {
	if start >= len(line) {
		return 0, 0, false
	}
	markerEnd := start
	if line[start] == '-' || line[start] == '+' || line[start] == '*' {
		markerEnd++
	} else {
		for markerEnd < len(line) && markerEnd-start < 9 && isASCIIDigit(line[markerEnd]) {
			markerEnd++
		}
		if markerEnd == start || markerEnd >= len(line) || line[markerEnd] != '.' && line[markerEnd] != ')' {
			return 0, 0, false
		}
		markerEnd++
	}
	if markerEnd >= len(line) || line[markerEnd] != ' ' && line[markerEnd] != '\t' {
		return 0, 0, false
	}
	paddingEnd := markerEnd
	for paddingEnd < len(line) && line[paddingEnd] == ' ' {
		paddingEnd++
	}
	padding := paddingEnd - markerEnd
	if padding == 0 { // Treat a tab as one column for the container boundary.
		padding = 1
	} else if padding > 4 {
		// CommonMark treats five or more spaces after the marker as one
		// padding space plus indented item content.
		padding = 1
	}
	return markerEnd - start, padding, true
}

// codexMaskMatchedInlineCodeSpans masks matched backtick spans before token
// recognition. Looking ahead for the matching delimiter is intentional: an
// unmatched run remains literal text and therefore cannot suppress a genuine
// selection later in the prompt. Blank lines, block code, and container exits
// bound the CommonMark inline context.
func codexMaskMatchedInlineCodeSpans(lines []codexPromptLine) []codexPromptLine {
	maskedRanges := make([][]codexByteRange, len(lines))
	maskedPrefixEnd := make([]int, len(lines))
	for i := range lines {
		if lines[i].blockCode || strings.TrimSpace(lines[i].text) == "" {
			continue
		}
		for column := maskedPrefixEnd[i]; column < len(lines[i].text); {
			if lines[i].text[column] != '`' {
				column++
				continue
			}
			run := byteRunLength(lines[i].text, column, '`')
			if codexBacktickRunIsEscaped(lines[i].text, column) {
				column += run
				continue
			}
			powerShellDollarEscape := run == 1 && column+run < len(lines[i].text) && lines[i].text[column+run] == '$'
			closeLine, closeColumn, found := codexFindInlineCodeClose(lines, i, column+run, run)
			if found {
				if powerShellDollarEscape && closeLine > i {
					// When the first delimiter on the closing line also begins a
					// locally paired span, consume through that local pair. This
					// preserves the established escaped-dollar interpretation while
					// still giving every bounded multiline match precedence over the
					// PowerShell fallback.
					if localClose, localFound := codexFindInlineCodeCloseOnLine(
						lines[closeLine].text,
						closeColumn+run,
						run,
					); localFound {
						closeColumn = localClose
					}
				}
				codexRecordInlineCodeRange(
					lines,
					maskedRanges,
					maskedPrefixEnd,
					i,
					column,
					closeLine,
					closeColumn+run,
				)
				if closeLine == i {
					column = closeColumn + run
				} else {
					column = len(lines[i].text)
				}
				continue
			}
			if powerShellDollarEscape {
				// With no valid CommonMark close inside the established inline
				// bounds, retain PowerShell's single-backtick dollar escape.
				column += run
				continue
			}
			column += run
		}
	}
	return codexApplyInlineCodeMasks(lines, maskedRanges)
}

type codexByteRange struct {
	start int
	end   int
}

func codexRecordInlineCodeRange(
	lines []codexPromptLine,
	ranges [][]codexByteRange,
	maskedPrefixEnd []int,
	startLine int,
	startColumn int,
	endLine int,
	endColumn int,
) {
	for lineIndex := startLine; lineIndex <= endLine; lineIndex++ {
		start := 0
		end := len(lines[lineIndex].text)
		if lineIndex == startLine {
			start = startColumn
		}
		if lineIndex == endLine {
			end = endColumn
		}
		ranges[lineIndex] = append(ranges[lineIndex], codexByteRange{start: start, end: end})
		if start == 0 && end > maskedPrefixEnd[lineIndex] {
			maskedPrefixEnd[lineIndex] = end
		}
	}
}

func codexApplyInlineCodeMasks(lines []codexPromptLine, ranges [][]codexByteRange) []codexPromptLine {
	masked := make([]codexPromptLine, len(lines))
	copy(masked, lines)
	for lineIndex, lineRanges := range ranges {
		if len(lineRanges) == 0 {
			continue
		}
		line := []byte(masked[lineIndex].text)
		for _, byteRange := range lineRanges {
			// Keep a non-whitespace boundary so removing inline code cannot
			// accidentally join the two halves of linked mention syntax.
			for column := byteRange.start; column < byteRange.end; column++ {
				line[column] = '!'
			}
		}
		masked[lineIndex].text = string(line)
	}
	return masked
}

func codexFindInlineCodeCloseOnLine(line string, start, want int) (int, bool) {
	for column := start; column < len(line); {
		if line[column] != '`' {
			column++
			continue
		}
		run := byteRunLength(line, column, '`')
		if codexBacktickRunIsEscaped(line, column) {
			column += run
			continue
		}
		if run == want {
			return column, true
		}
		column += run
	}
	return 0, false
}

func codexFindInlineCodeClose(lines []codexPromptLine, openLine, start, want int) (int, int, bool) {
	_, openingContainers := codexMarkdownContainerOpening(lines[openLine].text)
	for lineIndex := openLine; lineIndex < len(lines); lineIndex++ {
		if lineIndex != openLine {
			if lines[lineIndex].blockCode || strings.TrimSpace(lines[lineIndex].text) == "" {
				return 0, 0, false
			}
			if len(openingContainers) > 0 {
				if _, belongs := codexMarkdownContainerContinuation(lines[lineIndex].text, openingContainers); !belongs {
					return 0, 0, false
				}
			} else if _, containers := codexMarkdownContainerOpening(lines[lineIndex].text); len(containers) > 0 {
				return 0, 0, false
			}
			start = 0
		}
		line := lines[lineIndex].text
		for column := start; column < len(line); {
			if line[column] != '`' {
				column++
				continue
			}
			run := byteRunLength(line, column, '`')
			if codexBacktickRunIsEscaped(line, column) {
				column += run
				continue
			}
			if run == want {
				return lineIndex, column, true
			}
			column += run
		}
	}
	return 0, 0, false
}

func lexCodexSkillSelectionsInlineText(line string) []codexSkillSelection {
	var selections []codexSkillSelection
	nextCloseParen := codexNextByteIndex(line, ')')
	for i := 0; i < len(line); {
		if line[i] == '`' {
			run := byteRunLength(line, i, '`')
			// Matched spans were masked by the prompt-level CommonMark pass.
			// Skip any remaining literal delimiter; codexDollarIsEscaped still
			// rejects PowerShell's immediately following escaped dollar.
			i += run
			continue
		}
		if line[i] != '$' || codexDollarIsEscaped(line, i) || !codexDollarHasBoundary(line, i) {
			i++
			continue
		}

		selection, end, ok := parseCodexSkillSelection(line, i)
		if !ok {
			i++
			continue
		}
		if linked, linkedEnd, ok := parseCodexLinkedSkillSelection(
			line,
			nextCloseParen,
			i,
			selection,
			end,
		); ok {
			selection = linked
			end = linkedEnd
		}
		selections = append(selections, selection)
		i = end
	}
	return selections
}

// parseCodexLinkedSkillSelection mirrors Codex 0.144.0's linked mention shape:
// [$name] followed by optional ASCII whitespace and a non-empty parenthesized
// destination ending at the first ')'. The label is not an authoritative skill
// identity; Codex resolves the trimmed destination by exact installed path.
func parseCodexLinkedSkillSelection(
	line string,
	nextCloseParen []int,
	dollar int,
	selection codexSkillSelection,
	nameEnd int,
) (codexSkillSelection, int, bool) {
	if dollar == 0 || line[dollar-1] != '[' || nameEnd >= len(line) || line[nameEnd] != ']' {
		return codexSkillSelection{}, nameEnd, false
	}
	pathOpen := nameEnd + 1
	for pathOpen < len(line) && isASCIIWhitespace(line[pathOpen]) {
		pathOpen++
	}
	if pathOpen >= len(line) || line[pathOpen] != '(' {
		return codexSkillSelection{}, nameEnd, false
	}
	pathStart := pathOpen + 1
	if pathStart >= len(nextCloseParen) {
		return codexSkillSelection{}, nameEnd, false
	}
	pathEnd := nextCloseParen[pathStart]
	if pathEnd < 0 {
		return codexSkillSelection{}, nameEnd, false
	}
	linkedPath := strings.TrimSpace(line[pathStart:pathEnd])
	if linkedPath == "" {
		return codexSkillSelection{}, nameEnd, false
	}
	selection.LinkedPath = linkedPath
	return selection, pathEnd + 1, true
}

func codexNextByteIndex(text string, want byte) []int {
	nextIndexes := make([]int, len(text)+1)
	next := -1
	nextIndexes[len(text)] = next
	for index := len(text) - 1; index >= 0; index-- {
		if text[index] == want {
			next = index
		}
		nextIndexes[index] = next
	}
	return nextIndexes
}

func parseCodexSkillSelection(line string, dollar int) (codexSkillSelection, int, bool) {
	start := dollar + 1
	if start >= len(line) || !isCodexMentionNameChar(line[start]) {
		return codexSkillSelection{}, dollar, false
	}

	i := start
	for i < len(line) && isCodexMentionNameChar(line[i]) {
		i++
	}

	name := line[start:i]
	if name == "" || len(name) > 128 {
		return codexSkillSelection{}, dollar, false
	}
	if !codexSkillSelectionHasEndBoundary(line, i) {
		return codexSkillSelection{}, dollar, false
	}
	raw := line[dollar:i]
	return codexSkillSelection{Name: name, Raw: raw}, i, true
}

func codexDollarIsEscaped(line string, dollar int) bool {
	if dollar > 0 && line[dollar-1] == '`' { // PowerShell escape character.
		return true
	}
	backslashes := 0
	for i := dollar - 1; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func codexDollarHasBoundary(line string, dollar int) bool {
	if dollar == 0 {
		return true
	}
	prev, _ := utf8.DecodeLastRuneInString(line[:dollar])
	return !unicode.IsLetter(prev) && !unicode.IsNumber(prev) && prev != '_' && prev != '$'
}

func codexSkillSelectionHasEndBoundary(line string, end int) bool {
	if end >= len(line) {
		return true
	}
	if line[end] == '/' || line[end] == '\\' || line[end] == '$' {
		return false
	}
	if line[end] == '.' && end+1 < len(line) {
		next, _ := utf8.DecodeRuneInString(line[end+1:])
		if unicode.IsLetter(next) || unicode.IsNumber(next) {
			return false
		}
	}
	if line[end] == ':' && end+1 < len(line) && line[end+1] != ' ' && line[end+1] != '\t' {
		return false
	}
	r, _ := utf8.DecodeRuneInString(line[end:])
	return !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.IsMark(r) && r != '_'
}

func isASCIIAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isASCIIWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isCodexMentionNameChar(c byte) bool {
	return isASCIIAlpha(c) || isASCIIDigit(c) || c == '_' || c == '-' || c == ':'
}

func byteRunLength(s string, start int, want byte) int {
	i := start
	for i < len(s) && s[i] == want {
		i++
	}
	return i - start
}

func codexBacktickRunIsEscaped(line string, start int) bool {
	backslashes := 0
	for i := start - 1; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 1
}

// codexPromptSkillAssetDecisions evaluates only exact, canonical identities.
// Unknown dollar words never inherit default-deny policy because Codex provides
// no structured proof that an arbitrary dollar word is a selected skill.
func (a *APIServer) codexPromptSkillAssetDecisions(ctx context.Context, prompt string) []runtimeAssetDecision {
	parsedSelections := lexCodexSkillSelections(prompt)
	selections := make([]codexSkillSelection, 0, len(parsedSelections))
	for _, selection := range parsedSelections {
		if selection.LinkedPath != "" && codexLinkedPathIsNonSkillResource(selection.LinkedPath) {
			continue
		}
		selections = append(selections, selection)
	}
	var decisions []runtimeAssetDecision
	var linkedIndex codexLinkedSkillIndex
	linkedIndexBuilt := false
	knownSelections := 0
	for _, selection := range selections {
		identityKnown := false
		probe := skillRuntimeProbe{
			TargetType: "skill",
			SkillName:  selection.Name,
			ToolName:   selection.Raw,
			RawName:    selection.Raw,
			Surface:    codexPromptSkillSurface,
			Matched:    true,
		}
		if selection.LinkedPath != "" {
			// Codex resolves linked mentions by exact path and never falls back
			// to the display label. App/MCP/plugin links are not skill mentions.
			if !linkedIndexBuilt {
				linkedIndex = a.buildCodexLinkedSkillIndex()
				linkedIndexBuilt = true
			}
			name, trustedSource, known, err := linkedIndex.resolve(selection.LinkedPath)
			if err != nil {
				probe.SkillName = "linked-skill"
				decision := runtimeAssetDisableBlockDecision(
					"skill",
					probe.SkillName,
					"codex",
					codexPromptSkillSurface,
					"linked skill identity check failed - failing closed",
					"runtime-disable-error",
				)
				a.emitRuntimeSkillAssetPolicyDecision(ctx, decision, "codex", "UserPromptSubmit", probe)
				decisions = append(decisions, runtimeAssetDecision{targetType: "skill", decision: decision})
				continue
			}
			if !known {
				continue
			}
			selection.Name = name
			probe.SkillName = name
			probe.SourcePath = trustedSource
			identityKnown = true
		}

		// Runtime-disable state is itself a known identity. Check it first so
		// enforcement does not depend on asset-policy scanner enablement.
		runtimeDecision, disabled := a.runtimeAssetDisableDecision(
			"skill", selection.Name, "codex", codexPromptSkillSurface,
		)
		identityKnown = identityKnown || disabled
		if !identityKnown && !a.codexPromptSkillPolicyIdentityKnown(selection.Name) {
			continue
		}
		knownSelections++
		if knownSelections > codexMaxPromptSkillSelections {
			overflowProbe := skillRuntimeProbe{
				TargetType: "skill",
				SkillName:  "skill-selection-overflow",
				ToolName:   "$selection-overflow",
				Surface:    codexPromptSkillSurface,
				Matched:    true,
			}
			overflowDecision := runtimeAssetDisableBlockDecision(
				"skill",
				overflowProbe.SkillName,
				"codex",
				codexPromptSkillSurface,
				"prompt contains too many known skill selections - failing closed",
				"runtime-disable-error",
			)
			a.emitRuntimeSkillAssetPolicyDecision(
				ctx, overflowDecision, "codex", "UserPromptSubmit", overflowProbe,
			)
			return append(decisions, runtimeAssetDecision{
				targetType: "skill",
				decision:   overflowDecision,
			})
		}
		if disabled {
			decision := runtimeDecision
			a.emitRuntimeSkillAssetPolicyDecision(ctx, decision, "codex", "UserPromptSubmit", probe)
			decisions = append(decisions, runtimeAssetDecision{targetType: "skill", decision: decision})
			continue
		}
		if decision, matched := a.evaluateRuntimeSkillAssetPolicy(ctx, "codex", "UserPromptSubmit", probe); matched {
			decisions = append(decisions, runtimeAssetDecision{targetType: "skill", decision: decision})
		}
	}
	return decisions
}

func (a *APIServer) codexPromptSkillPolicyIdentityKnown(name string) bool {
	if a == nil || a.scannerCfg == nil {
		return false
	}
	policy, ok := a.scannerCfg.EffectiveAssetTypePolicy("codex", "skill")
	if !ok {
		return false
	}
	for _, rules := range [][]config.AssetPolicyRule{policy.Registry, policy.Allowed, policy.Denied} {
		for _, rule := range rules {
			if strings.TrimSpace(rule.Name) != name {
				continue
			}
			connectorName := strings.ToLower(strings.TrimSpace(rule.Connector))
			if connectorName == "" || connectorName == "codex" {
				return true
			}
		}
	}
	return false
}

// codexSkillAssetMergeEvent maps the observable prompt-selection boundary to
// the existing enforceable prompt-expansion capability. The response and audit
// event remain UserPromptSubmit. In Codex 0.144.0 skill content is discovered
// before this hook runs, so this gate prevents model use but cannot honestly
// claim discovery/load prevention; managed isolation provides that guarantee.
func codexSkillAssetMergeEvent(hookEvent string, asset runtimeAssetDecision) string {
	if hookEvent == "UserPromptSubmit" && asset.targetType == "skill" && asset.decision.RuntimeSurface == codexPromptSkillSurface {
		return "UserPromptExpansion"
	}
	return hookEvent
}
