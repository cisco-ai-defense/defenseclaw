// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The Windows parsers deliberately recognize a small literal subset. They
// recover positive facts from syntax outside that subset, but any uncertainty
// makes the result non-authoritative.
type windowsDialect uint8

const (
	windowsPowerShell windowsDialect = iota + 1
	windowsCMD
)

type windowsLexemeKind uint8

const (
	windowsWordLexeme windowsLexemeKind = iota + 1
	windowsSeparatorLexeme
	windowsPipeLexeme
	windowsRedirectLexeme
	windowsCallLexeme
)

type windowsWord struct {
	value      string
	quote      QuoteKind
	expands    bool
	wildcard   bool
	quotedOnly bool
}

type windowsLexeme struct {
	kind     windowsLexemeKind
	word     windowsWord
	operator string
}

type windowsRedirect struct {
	fd     int64
	access PathAccess
	target windowsWord
}

type windowsParsedCommand struct {
	words        []windowsWord
	redirects    []windowsRedirect
	callOperator bool
}

type windowsPipelineEdge struct {
	from int
	to   int
}

type windowsWrapper struct {
	executable string
	argv       []string
	body       string
	keepOpen   bool
}

func parsePowerShell(source string, startID int64, wrapperDepth int) parseOutput {
	return parseWindows(source, startID, wrapperDepth, windowsPowerShell)
}

func parseCMD(source string, startID int64, wrapperDepth int) parseOutput {
	return parseWindows(source, startID, wrapperDepth, windowsCMD)
}

func parseWindows(source string, startID int64, wrapperDepth int, dialect windowsDialect) parseOutput {
	out := newParseOutput(windowsOutputDialect(dialect), startID)
	if len(source) > maxCommandBytes ||
		len(source)*(wrapperDepth+1) > maxNestedCommandBytes {
		out.markLimit(IssueInputLimit)
		return out
	}
	if !utf8.ValidString(source) {
		out.markInvalid(IssueInvalidUTF8)
		return out
	}
	if strings.TrimSpace(source) == "" {
		out.markInvalid(IssueInvalidSyntax)
		return out
	}
	if wrapperDepth > maxWrapperDepth {
		out.markLimit(IssueWrapperLimit)
		return out
	}

	if wrapper, ok := windowsExactWrapper(source, dialect); ok {
		if wrapperDepth == maxWrapperDepth {
			out.markLimit(IssueWrapperLimit)
			return out
		}
		var inner parseOutput
		if dialect == windowsPowerShell {
			inner = parsePowerShell(wrapper.body, startID, wrapperDepth+1)
		} else {
			inner = parseCMD(wrapper.body, startID, wrapperDepth+1)
		}
		for i := range inner.commands {
			inner.commands[i].Wrappers = append(
				[]WrapperFact{{Executable: wrapper.executable, Argv: cloneSlice(wrapper.argv)}},
				inner.commands[i].Wrappers...,
			)
		}
		if wrapperDepth > 0 || wrapper.keepOpen {
			inner.markPartial(IssueUnsupportedConstruct)
		}
		return inner
	}

	lexemes, ok := windowsLex(source, dialect, &out)
	if !ok {
		return out
	}
	commands, edges, ok := windowsBuildCommands(lexemes, &out)
	if !ok && len(commands) == 0 {
		return out
	}
	windowsProjectCommands(commands, edges, dialect, &out)
	windowsValidatePipelineAuthority(commands, edges, dialect, &out)
	return out
}

func windowsOutputDialect(dialect windowsDialect) Dialect {
	if dialect == windowsCMD {
		return DialectCMD
	}
	return DialectPowerShell
}

func windowsValidatePipelineAuthority(
	commands []windowsParsedCommand,
	edges []windowsPipelineEdge,
	dialect windowsDialect,
	out *parseOutput,
) {
	if len(edges) == 0 {
		return
	}
	if dialect == windowsPowerShell &&
		(windowsDirectWebExpressionPipeline(commands, edges) ||
			windowsDirectProcessStopPipeline(commands, edges)) {
		return
	}
	out.markPartial(IssueUnsupportedConstruct)
}

func windowsDirectWebExpressionPipeline(
	commands []windowsParsedCommand,
	edges []windowsPipelineEdge,
) bool {
	if len(commands) != 2 || len(edges) != 1 ||
		edges[0].from != 0 || edges[0].to != 1 ||
		len(commands[0].words) < 2 || len(commands[1].words) != 1 ||
		len(commands[0].redirects) != 0 || len(commands[1].redirects) != 0 ||
		commands[0].callOperator || commands[1].callOperator {
		return false
	}
	for _, command := range commands {
		for _, word := range command.words {
			if word.expands {
				return false
			}
		}
	}
	source := commandProgramForDialect(
		commands[0].words[0].value,
		DialectPowerShell,
	)
	sink := commandProgramForDialect(
		commands[1].words[0].value,
		DialectPowerShell,
	)
	switch source {
	case "invoke-webrequest", "iwr", "invoke-restmethod", "irm":
	default:
		return false
	}
	for _, word := range commands[0].words[1:] {
		if word.quote != QuoteNone {
			continue
		}
		switch strings.ToLower(word.value) {
		case "-outfile", "-o", "--output":
			return false
		}
	}
	return sink == "invoke-expression" || sink == "iex"
}

func windowsDirectProcessStopPipeline(
	commands []windowsParsedCommand,
	edges []windowsPipelineEdge,
) bool {
	if len(commands) != 2 || len(edges) != 1 ||
		edges[0].from != 0 || edges[0].to != 1 ||
		len(commands[0].words) != 1 || len(commands[1].words) < 2 ||
		len(commands[0].redirects) != 0 || len(commands[1].redirects) != 0 ||
		commands[0].callOperator || commands[1].callOperator {
		return false
	}
	for _, command := range commands {
		for _, word := range command.words {
			if word.expands || word.wildcard {
				return false
			}
		}
	}
	source := commandProgramForDialect(
		commands[0].words[0].value,
		DialectPowerShell,
	)
	sink := commandProgramForDialect(
		commands[1].words[0].value,
		DialectPowerShell,
	)
	if source != "get-process" || sink != "stop-process" {
		return false
	}
	forceSeen := false
	previewSeen := false
	for _, word := range commands[1].words[1:] {
		if word.quote != QuoteNone {
			return false
		}
		lower := strings.ToLower(word.value)
		switch {
		case lower == "-force" && !forceSeen:
			forceSeen = true
		case windowsExactPipelineWhatIf(lower) && !previewSeen:
			previewSeen = true
		default:
			return false
		}
	}
	return forceSeen
}

func windowsExactPipelineWhatIf(value string) bool {
	switch value {
	case "-whatif", "-whatif:$true", "-whatif:$false":
		return true
	default:
		return false
	}
}

// windowsExactWrapper unwraps only an exact, statically tokenized launcher.
// Reconstructing a command from multiple argv elements can change quoting and
// operator meaning, so those forms remain visible as unsupported commands.
func windowsExactWrapper(source string, dialect windowsDialect) (windowsWrapper, bool) {
	probe := newParseOutput(windowsOutputDialect(dialect), 1)
	lexemes, ok := windowsLex(source, dialect, &probe)
	if !ok || probe.status != StatusComplete {
		return windowsWrapper{}, false
	}
	commands, edges, ok := windowsBuildCommands(lexemes, &probe)
	if !ok || len(commands) != 1 || len(edges) != 0 || len(commands[0].redirects) != 0 {
		return windowsWrapper{}, false
	}
	words := commands[0].words
	if len(words) < 3 || words[0].expands {
		return windowsWrapper{}, false
	}
	executable := windowsExecutable(words[0].value)
	name := commandProgramForDialect(
		words[0].value,
		windowsOutputDialect(dialect),
	)
	if name == "" {
		return windowsWrapper{}, false
	}
	switch dialect {
	case windowsPowerShell:
		if name != "powershell" && name != "pwsh" {
			return windowsWrapper{}, false
		}
		for _, word := range words[1:] {
			switch strings.ToLower(word.value) {
			case "-encodedcommand", "-enc", "-e", "-file":
				return windowsWrapper{}, false
			}
		}
		commandIndex := -1
		// Profiles are ambient commands outside the statically supplied body.
		noProfileSeen := false
		for i := 1; i < len(words); i++ {
			lower := strings.ToLower(words[i].value)
			if lower == "-command" || lower == "-c" {
				if !noProfileSeen {
					return windowsWrapper{}, false
				}
				commandIndex = i
				break
			}
			switch lower {
			case "-noprofile":
				if noProfileSeen {
					return windowsWrapper{}, false
				}
				noProfileSeen = true
			case "-noninteractive", "-nologo":
			case "-executionpolicy":
				i++
				if i >= len(words) || words[i].expands {
					return windowsWrapper{}, false
				}
			default:
				return windowsWrapper{}, false
			}
		}
		if commandIndex < 0 || commandIndex+2 != len(words) || words[commandIndex+1].expands {
			return windowsWrapper{}, false
		}
		return windowsWrapper{
			executable: executable,
			argv:       windowsWordValues(words[:commandIndex+1]),
			body:       words[commandIndex+1].value,
		}, true

	case windowsCMD:
		if name != "cmd" {
			return windowsWrapper{}, false
		}
		commandIndex := -1
		keepOpen := false
		// /d disables Command Processor AutoRun entries before /c executes.
		disableAutoRunSeen := false
		for i := 1; i < len(words); i++ {
			lower := strings.ToLower(words[i].value)
			if lower == "/c" || lower == "/k" {
				if !disableAutoRunSeen {
					return windowsWrapper{}, false
				}
				commandIndex = i
				keepOpen = lower == "/k"
				break
			}
			switch lower {
			case "/d":
				if disableAutoRunSeen {
					return windowsWrapper{}, false
				}
				disableAutoRunSeen = true
			case "/q", "/s":
			default:
				return windowsWrapper{}, false
			}
		}
		if commandIndex < 0 || commandIndex+2 != len(words) || words[commandIndex+1].expands {
			return windowsWrapper{}, false
		}
		return windowsWrapper{
			executable: executable,
			argv:       windowsWordValues(words[:commandIndex+1]),
			body:       words[commandIndex+1].value,
			keepOpen:   keepOpen,
		}, true
	}
	return windowsWrapper{}, false
}

func windowsLex(source string, dialect windowsDialect, out *parseOutput) ([]windowsLexeme, bool) {
	lexemes := make([]windowsLexeme, 0, min(len(source)/4+1, maxWindowsTokens))
	var value strings.Builder
	var quote rune
	quoteKind := QuoteNone
	wordActive := false
	wordExpands := false
	wordWildcard := false
	wordQuotedOnly := false
	tokenBytes := 0

	markQuote := func(next QuoteKind) {
		if quoteKind == QuoteNone {
			quoteKind = next
			return
		}
		if quoteKind != next {
			quoteKind = QuoteMixed
		}
	}
	writeRune := func(r rune) bool {
		size := utf8.RuneLen(r)
		if size < 0 {
			size = 1
		}
		tokenBytes += size
		if tokenBytes > maxWindowsTokenBytes {
			out.markLimit(IssueInputLimit)
			return false
		}
		if quote == 0 {
			wordQuotedOnly = false
		}
		value.WriteRune(r)
		wordActive = true
		return true
	}
	appendLexeme := func(lexeme windowsLexeme) bool {
		if len(lexemes) >= maxWindowsTokens {
			out.markLimit(IssueNodeLimit)
			return false
		}
		lexemes = append(lexemes, lexeme)
		return true
	}
	flush := func() bool {
		if !wordActive {
			return true
		}
		if quoteKind == "" {
			quoteKind = QuoteNone
		}
		ok := appendLexeme(windowsLexeme{
			kind: windowsWordLexeme,
			word: windowsWord{
				value:      value.String(),
				quote:      quoteKind,
				expands:    wordExpands,
				wildcard:   wordWildcard,
				quotedOnly: wordQuotedOnly,
			},
		})
		value.Reset()
		quoteKind = QuoteNone
		wordActive = false
		wordExpands = false
		wordWildcard = false
		wordQuotedOnly = false
		tokenBytes = 0
		return ok
	}
	appendOperator := func(kind windowsLexemeKind, operator string) bool {
		if !flush() {
			return false
		}
		return appendLexeme(windowsLexeme{kind: kind, operator: operator})
	}

	runes := []rune(source)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if quote != 0 {
			if dialect == windowsPowerShell && quote == '\'' && r == '\'' &&
				i+1 < len(runes) && runes[i+1] == '\'' {
				if !writeRune('\'') {
					return lexemes, false
				}
				i++
				continue
			}
			if r == quote {
				quote = 0
				continue
			}
			if dialect == windowsPowerShell && quote != '\'' && r == '`' {
				out.markPartial(IssueDynamicWord)
				if i+1 >= len(runes) {
					out.markInvalid(IssueInvalidSyntax)
					return lexemes, false
				}
				i++
				if !writeRune(runes[i]) {
					return lexemes, false
				}
				continue
			}
			if dialect == windowsPowerShell && quote == '"' && r == '$' {
				wordExpands = true
				out.markPartial(IssueDynamicWord)
			}
			if dialect == windowsCMD && (r == '%' || r == '!') {
				wordExpands = true
				out.markPartial(IssueDynamicWord)
			}
			if (r == '*' || r == '?') &&
				!windowsLooksLikeURLQuery(value.String(), r) &&
				!windowsExtendedPathPrefixQuestion(value.String(), r, runes, i) &&
				!(dialect == windowsCMD && r == '?' && value.String() == "/") {
				wordWildcard = true
			}
			if dialect == windowsPowerShell &&
				(r == '[' || r == ']' || r == '~' && value.Len() == 0) {
				wordExpands = true
				out.markPartial(IssueDynamicWord)
			}
			if !writeRune(r) {
				return lexemes, false
			}
			continue
		}

		if dialect == windowsPowerShell && r == '-' && !wordActive &&
			i+2 < len(runes) && runes[i+1] == '-' && runes[i+2] == '%' &&
			(i+3 == len(runes) || unicode.IsSpace(runes[i+3])) {
			// PowerShell's stop-parsing token makes the rest of the native
			// invocation opaque. Do not interpret later metacharacters as new
			// commands or destinations.
			out.markPartial(IssueUnsupportedConstruct)
			wordExpands = true
			for _, literal := range "--%" {
				if !writeRune(literal) {
					return lexemes, false
				}
			}
			i = len(runes)
			break
		}
		if dialect == windowsPowerShell &&
			(r == '@' && i+1 < len(runes) && (runes[i+1] == '\'' || runes[i+1] == '"') ||
				(r == '$' || r == '@') && i+1 < len(runes) &&
					(runes[i+1] == '(' || runes[i+1] == '{')) {
			// Here-strings, subexpressions, arrays, and hashtables require a
			// full PowerShell AST. Preserve the surrounding positive command
			// only, and keep the remainder opaque.
			out.markPartial(IssueUnsupportedConstruct)
			wordExpands = true
			if !writeRune(r) {
				return lexemes, false
			}
			if !writeRune(runes[i+1]) {
				return lexemes, false
			}
			i = len(runes)
			break
		}

		if dialect == windowsPowerShell && r == '#' && !wordActive {
			if !flush() {
				return lexemes, false
			}
			for i < len(runes) && runes[i] != '\n' && runes[i] != '\r' {
				i++
			}
			i--
			continue
		}

		if r == '\'' && dialect == windowsPowerShell {
			if !wordActive {
				wordQuotedOnly = true
			}
			wordActive = true
			markQuote(QuoteSingle)
			quote = r
			continue
		}
		if r == '"' {
			if !wordActive {
				wordQuotedOnly = true
			}
			wordActive = true
			markQuote(QuoteDouble)
			quote = r
			continue
		}
		if dialect == windowsPowerShell && r == '`' ||
			dialect == windowsCMD && r == '^' {
			out.markPartial(IssueDynamicWord)
			if i+1 >= len(runes) {
				out.markInvalid(IssueInvalidSyntax)
				return lexemes, false
			}
			i++
			if !writeRune(runes[i]) {
				return lexemes, false
			}
			continue
		}
		if unicode.IsSpace(r) {
			if !flush() {
				return lexemes, false
			}
			if (r == '\n' || r == '\r') && len(lexemes) > 0 &&
				lexemes[len(lexemes)-1].kind != windowsSeparatorLexeme {
				out.markPartial(IssueUnsupportedConstruct)
				if !appendLexeme(windowsLexeme{kind: windowsSeparatorLexeme, operator: "newline"}) {
					return lexemes, false
				}
			}
			continue
		}

		if dialect == windowsPowerShell && r == '$' {
			if literal, end, ok := powerShellStaticSwitchBoolean(
				runes,
				i,
				value.String(),
			); ok {
				for _, literalRune := range literal {
					if !writeRune(literalRune) {
						return lexemes, false
					}
				}
				i = end
				continue
			}
			wordExpands = true
			out.markPartial(IssueDynamicWord)
		}
		if dialect == windowsPowerShell && r == '~' && !wordActive {
			wordExpands = true
			out.markPartial(IssueDynamicWord)
		}
		if dialect == windowsCMD && (r == '%' || r == '!') {
			wordExpands = true
			out.markPartial(IssueDynamicWord)
		}
		if (r == '*' || r == '?') &&
			!windowsLooksLikeURLQuery(value.String(), r) &&
			!windowsExtendedPathPrefixQuestion(value.String(), r, runes, i) &&
			!(dialect == windowsCMD && r == '?' && value.String() == "/") {
			wordWildcard = true
		}
		if dialect == windowsPowerShell && r == '@' && i+1 < len(runes) &&
			(runes[i+1] == '{' || runes[i+1] == '(' || unicode.IsLetter(runes[i+1])) {
			wordExpands = true
			out.markPartial(IssueDynamicWord)
		}

		if r == '>' || r == '<' {
			if dialect == windowsPowerShell && r == '<' {
				// PowerShell does not implement the cmd-style input
				// redirection operator. Reject it before projecting any facts
				// from a command whose syntax PowerShell itself rejects.
				out.markInvalid(IssueInvalidSyntax)
				return lexemes, false
			}
			if duplicationEnd, ok := windowsFDDuplicationEnd(runes, i); ok {
				// Descriptor duplication has no file target. Retain the
				// surrounding command as a non-authoritative positive fact,
				// but consume the whole construct so "&1" cannot become a
				// separator followed by a phantom command.
				if wordActive && quoteKind == QuoteNone && windowsAllDigits(value.String()) {
					value.Reset()
					quoteKind = QuoteNone
					wordActive = false
					wordExpands = false
					wordWildcard = false
					wordQuotedOnly = false
					tokenBytes = 0
				} else if !flush() {
					return lexemes, false
				}
				out.markPartial(IssueUnsupportedConstruct)
				i = duplicationEnd
				continue
			}
			operator := string(r)
			if r == '>' && i+1 < len(runes) && runes[i+1] == '>' {
				operator = ">>"
				i++
			}
			if wordActive && quoteKind == QuoteNone && windowsAllDigits(value.String()) {
				operator = value.String() + operator
				value.Reset()
				wordActive = false
				wordExpands = false
				wordWildcard = false
				tokenBytes = 0
			}
			if !appendOperator(windowsRedirectLexeme, operator) {
				return lexemes, false
			}
			continue
		}

		switch dialect {
		case windowsPowerShell:
			switch r {
			case '|':
				if i+1 < len(runes) && runes[i+1] == '|' {
					i++
					out.markPartial(IssueUnsupportedConstruct)
					if !appendOperator(windowsSeparatorLexeme, "||") {
						return lexemes, false
					}
				} else {
					if !appendOperator(windowsPipeLexeme, "|") {
						return lexemes, false
					}
				}
				continue
			case ';', '&':
				if r == '&' && (i+1 >= len(runes) || runes[i+1] != '&') &&
					!wordActive && windowsPowerShellCallPosition(lexemes) {
					if !windowsPowerShellQuotedCallTarget(runes, i+1) {
						// Dynamic expressions and script blocks can contain
						// arbitrary nested syntax. Retain only an opaque,
						// non-authoritative invocation rather than interpreting
						// their contents as commands or operands.
						out.markPartial(IssueUnsupportedConstruct)
						if !appendLexeme(windowsLexeme{
							kind: windowsWordLexeme,
							word: windowsWord{
								value:   "&",
								expands: true,
							},
						}) {
							return lexemes, false
						}
						i = len(runes)
						continue
					}
					if !appendOperator(windowsCallLexeme, "&") {
						return lexemes, false
					}
					continue
				}
				operator := string(r)
				if i+1 < len(runes) && runes[i+1] == r {
					operator += string(r)
					i++
				}
				out.markPartial(IssueUnsupportedConstruct)
				if !appendOperator(windowsSeparatorLexeme, operator) {
					return lexemes, false
				}
				continue
			case '(', ')', '{', '}':
				out.markPartial(IssueUnsupportedConstruct)
			case ',':
				out.markPartial(IssueUnsupportedConstruct)
			case '[', ']':
				wordExpands = true
				out.markPartial(IssueDynamicWord)
			}

		case windowsCMD:
			switch r {
			case '|', '&':
				operator := string(r)
				kind := windowsSeparatorLexeme
				if r == '|' {
					kind = windowsPipeLexeme
				}
				if i+1 < len(runes) && runes[i+1] == r {
					operator += string(r)
					i++
					kind = windowsSeparatorLexeme
				}
				if kind != windowsPipeLexeme {
					out.markPartial(IssueUnsupportedConstruct)
				}
				if !appendOperator(kind, operator) {
					return lexemes, false
				}
				continue
			case '(', ')':
				out.markPartial(IssueUnsupportedConstruct)
			}
		}

		if !writeRune(r) {
			return lexemes, false
		}
	}

	if quote != 0 {
		out.markInvalid(IssueInvalidSyntax)
		return lexemes, false
	}
	if !flush() {
		return lexemes, false
	}
	return lexemes, true
}

func windowsExtendedPathPrefixQuestion(
	prefix string,
	current rune,
	runes []rune,
	index int,
) bool {
	return current == '?' &&
		(prefix == `\\` || prefix == "//") &&
		index+1 < len(runes) &&
		(runes[index+1] == '\\' || runes[index+1] == '/')
}

func powerShellStaticSwitchBoolean(
	runes []rune,
	start int,
	prefix string,
) (literal string, end int, ok bool) {
	if !strings.HasSuffix(prefix, ":") || start < 0 || start >= len(runes) {
		return "", 0, false
	}
	for _, candidate := range []string{"$true", "$false"} {
		candidateRunes := []rune(candidate)
		if start+len(candidateRunes) > len(runes) ||
			!strings.EqualFold(
				string(runes[start:start+len(candidateRunes)]),
				candidate,
			) {
			continue
		}
		after := start + len(candidateRunes)
		if after < len(runes) && !unicode.IsSpace(runes[after]) &&
			!strings.ContainsRune(";|&><", runes[after]) {
			continue
		}
		return candidate, after - 1, true
	}
	return "", 0, false
}

func windowsPowerShellCallPosition(lexemes []windowsLexeme) bool {
	if len(lexemes) == 0 {
		return true
	}
	switch lexemes[len(lexemes)-1].kind {
	case windowsSeparatorLexeme, windowsPipeLexeme:
		return true
	default:
		return false
	}
}

func windowsPowerShellQuotedCallTarget(runes []rune, start int) bool {
	for start < len(runes) && runes[start] != '\n' && runes[start] != '\r' &&
		unicode.IsSpace(runes[start]) {
		start++
	}
	return start < len(runes) && (runes[start] == '\'' || runes[start] == '"')
}

func windowsLooksLikeURLQuery(prefix string, r rune) bool {
	return r == '?' && (strings.HasPrefix(strings.ToLower(prefix), "http://") ||
		strings.HasPrefix(strings.ToLower(prefix), "https://"))
}

func windowsAllDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func windowsFDDuplicationEnd(runes []rune, redirectIndex int) (int, bool) {
	if redirectIndex+2 >= len(runes) || runes[redirectIndex+1] != '&' {
		return 0, false
	}
	end := redirectIndex + 2
	if runes[end] < '0' || runes[end] > '9' {
		return 0, false
	}
	for end+1 < len(runes) && runes[end+1] >= '0' && runes[end+1] <= '9' {
		end++
	}
	if end+1 < len(runes) && !unicode.IsSpace(runes[end+1]) &&
		!strings.ContainsRune("|&;<>", runes[end+1]) {
		return 0, false
	}
	return end, true
}

func windowsBuildCommands(
	lexemes []windowsLexeme,
	out *parseOutput,
) ([]windowsParsedCommand, []windowsPipelineEdge, bool) {
	var commands []windowsParsedCommand
	var edges []windowsPipelineEdge
	var current windowsParsedCommand
	var pending *windowsRedirect
	pipelineFrom := -1
	ok := true

	flush := func() int {
		if pending != nil {
			out.markInvalid(IssueInvalidSyntax)
			ok = false
			pending = nil
		}
		if len(current.words) == 0 {
			if len(current.redirects) > 0 {
				out.markInvalid(IssueInvalidSyntax)
				ok = false
			}
			current = windowsParsedCommand{}
			return -1
		}
		if len(commands) >= maxCommands {
			out.markLimit(IssueFactLimit)
			ok = false
			current = windowsParsedCommand{}
			return -1
		}
		index := len(commands)
		commands = append(commands, current)
		current = windowsParsedCommand{}
		if pipelineFrom >= 0 {
			edges = append(edges, windowsPipelineEdge{from: pipelineFrom, to: index})
			pipelineFrom = -1
		}
		return index
	}

	for _, lexeme := range lexemes {
		switch lexeme.kind {
		case windowsWordLexeme:
			if current.callOperator && len(current.words) == 0 &&
				(lexeme.word.expands || !lexeme.word.quotedOnly ||
					lexeme.word.quote != QuoteSingle && lexeme.word.quote != QuoteDouble ||
					lexeme.word.value == "") {
				lexeme.word.expands = true
				out.markPartial(IssueUnsupportedConstruct)
			}
			if pending != nil {
				pending.target = lexeme.word
				current.redirects = append(current.redirects, *pending)
				pending = nil
				continue
			}
			current.words = append(current.words, lexeme.word)

		case windowsCallLexeme:
			if pending != nil || current.callOperator || len(current.words) != 0 ||
				len(current.redirects) != 0 {
				out.markInvalid(IssueInvalidSyntax)
				ok = false
				continue
			}
			current.callOperator = true

		case windowsRedirectLexeme:
			if pending != nil {
				out.markInvalid(IssueInvalidSyntax)
				ok = false
			}
			access := PathAccessWrite
			fd := int64(1)
			operator := lexeme.operator
			for len(operator) > 0 && operator[0] >= '0' && operator[0] <= '9' {
				operator = operator[1:]
			}
			if len(operator) < len(lexeme.operator) {
				rawFD := strings.TrimSuffix(lexeme.operator, operator)
				parsedFD, err := strconv.ParseInt(rawFD, 10, 64)
				if err != nil || parsedFD < 0 || parsedFD > 9 {
					out.markPartial(IssueUnsupportedConstruct)
				} else {
					fd = parsedFD
				}
			}
			switch operator {
			case "<":
				access = PathAccessRead
				if len(operator) == len(lexeme.operator) {
					fd = 0
				}
			case ">>":
				access = PathAccessAppend
			}
			pending = &windowsRedirect{fd: fd, access: access}

		case windowsPipeLexeme:
			from := flush()
			if from < 0 {
				out.markInvalid(IssueInvalidSyntax)
				ok = false
			} else {
				pipelineFrom = from
			}

		case windowsSeparatorLexeme:
			if flush() < 0 {
				out.markInvalid(IssueInvalidSyntax)
				ok = false
			}
			pipelineFrom = -1
		}
	}
	if len(current.words) > 0 || len(current.redirects) > 0 || pending != nil {
		flush()
	}
	if pipelineFrom >= 0 {
		out.markInvalid(IssueInvalidSyntax)
		ok = false
	}
	return commands, edges, ok
}

func windowsProjectCommands(
	parsed []windowsParsedCommand,
	edges []windowsPipelineEdge,
	dialect windowsDialect,
	out *parseOutput,
) {
	if len(parsed) == 0 {
		out.markInvalid(IssueInvalidSyntax)
		return
	}
	ids := make([]int64, len(parsed))
	pipelineIDs := make([]int64, len(parsed))
	for i := range parsed {
		ids[i] = out.nextCommandID()
	}
	for _, edge := range edges {
		if edge.from < 0 || edge.from >= len(ids) || edge.to < 0 || edge.to >= len(ids) {
			out.markInvalid(IssueInternalParserFailure)
			continue
		}
		pipelineID := pipelineIDs[edge.from]
		if pipelineID == 0 {
			pipelineID = ids[edge.from]
		}
		pipelineIDs[edge.from] = pipelineID
		pipelineIDs[edge.to] = pipelineID
	}

	builder := newWindowsFactBuilder(out)
	steps := 0
	for i, parsedCommand := range parsed {
		steps += len(parsedCommand.words) + len(parsedCommand.redirects)
		if steps > maxClassificationSteps {
			out.markLimit(IssueNodeLimit)
			return
		}
		command := windowsCommandFact(ids[i], pipelineIDs[i], parsedCommand, dialect, out)
		for _, redirect := range parsedCommand.redirects {
			if redirect.target.expands || redirect.target.wildcard {
				out.markPartial(IssueDynamicWord)
				continue
			}
			target, ok := windowsCanonicalPathFactValue(redirect.target.value)
			if !ok {
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			if !out.appendRedirects(&command, RedirectFact{
				FD: redirect.fd, Access: redirect.access,
				Target: target,
			}) {
				break
			}
		}
		if parsedCommand.callOperator && len(parsedCommand.words) > 0 &&
			!parsedCommand.words[0].expands &&
			windowsPathFlavor(parsedCommand.words[0].value) == PathFlavorWindows {
			builder.addPath(command.ID, PathAccessExecute, parsedCommand.words[0].value)
		}
		windowsClassifyCommand(&command, parsedCommand.words[1:], dialect, builder)
		out.appendCommand(command)
	}

	for _, edge := range edges {
		if edge.from >= 0 && edge.from < len(ids) && edge.to >= 0 && edge.to < len(ids) {
			builder.addFlow(DataFlowFact{
				FromCommandID: ids[edge.from],
				ToCommandID:   ids[edge.to],
				From:          DataStdout,
				To:            DataStdin,
			})
		}
	}
}

func windowsCommandFact(
	id, pipelineID int64,
	parsed windowsParsedCommand,
	dialect windowsDialect,
	out *parseOutput,
) CommandFact {
	factDialect := DialectCMD
	if dialect == windowsPowerShell {
		factDialect = DialectPowerShell
	}
	command := CommandFact{
		ID:           id,
		PipelineID:   pipelineID,
		Dialect:      factDialect,
		Effect:       EffectExecute,
		ArgvComplete: true,
	}
	if len(parsed.words) == 0 {
		command.ArgvComplete = false
		return command
	}
	executableWord := parsed.words[0]
	if dialect == windowsPowerShell && !parsed.callOperator &&
		executableWord.quote != QuoteNone {
		// A quoted string in PowerShell is an expression, not an invocation,
		// unless it follows the call operator. Do not turn inert string data
		// into an external command fact.
		executableWord.expands = true
		out.markPartial(IssueUnsupportedConstruct)
	}
	if executableWord.expands {
		command.Effect = EffectUncertain
		command.ArgvComplete = false
		out.markPartial(IssueDynamicWord)
	} else {
		command.Executable = windowsExecutable(executableWord.value)
		command.Program = commandProgramForDialect(
			executableWord.value,
			factDialect,
		)
		if command.Executable == "" {
			command.Effect = EffectUncertain
			command.ArgvComplete = false
			out.markPartial(IssueDynamicWord)
		}
	}
	for _, word := range parsed.words {
		command.Arguments = append(command.Arguments, ArgumentFact{
			Value: word.value, Quote: word.quote, Expands: word.expands,
		})
		if word.expands {
			command.Effect = EffectUncertain
			command.ArgvComplete = false
		}
	}
	if command.ArgvComplete {
		command.Argv = windowsWordValues(parsed.words)
	}
	return command
}

func windowsExecutable(value string) string {
	// Recognized shell quotes have already been removed by windowsLex. In cmd,
	// single quotes are ordinary filename characters and must not be stripped:
	// treating 'del' as the built-in del command would invent semantics.
	if value == "" || strings.TrimSpace(value) != value {
		return ""
	}
	value = strings.ReplaceAll(value, `\`, `/`)
	base := path.Base(value)
	if base == "." || base == "/" {
		return ""
	}
	return strings.ToLower(base)
}

func windowsExecutableFamily(command *CommandFact, family string) bool {
	if command == nil {
		return false
	}
	return command.Executable == family ||
		command.Executable == family+".exe"
}

func windowsWordValues(words []windowsWord) []string {
	if len(words) == 0 {
		return nil
	}
	out := make([]string, len(words))
	for i := range words {
		out[i] = words[i].value
	}
	return out
}

func windowsAddOperation(command *CommandFact, operation OperationKind) {
	for _, existing := range command.Operations {
		if existing == operation {
			return
		}
	}
	command.Operations = append(command.Operations, operation)
}

type windowsFactBuilder struct {
	out         *parseOutput
	pathSeen    map[string]struct{}
	networkSeen map[string]struct{}
	flowSeen    map[string]struct{}
}

func newWindowsFactBuilder(out *parseOutput) *windowsFactBuilder {
	return &windowsFactBuilder{
		out:         out,
		pathSeen:    make(map[string]struct{}),
		networkSeen: make(map[string]struct{}),
		flowSeen:    make(map[string]struct{}),
	}
}

func (b *windowsFactBuilder) addPath(commandID int64, access PathAccess, value string) {
	if value == "" {
		return
	}
	canonical, ok := windowsCanonicalPathFactValue(value)
	if !ok {
		b.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	value = canonical
	// In a raw PowerShell or cmd command, '*' and '?' are filesystem
	// patterns rather than exact path characters. Keep the owning operation
	// for detection, but do not mint a path that normalization could resolve
	// as an exact enforcement target.
	if strings.ContainsAny(value, "*?") {
		b.out.markPartial(IssueDynamicWord)
		return
	}
	b.addCanonicalPath(commandID, access, value, windowsPathFlavor(value))
}

func (b *windowsFactBuilder) addCanonicalPath(
	commandID int64,
	access PathAccess,
	value string,
	flavor PathFlavor,
) {
	key := strconv.FormatInt(commandID, 10) + "\x00" + string(access) + "\x00" + value
	if _, exists := b.pathSeen[key]; exists {
		return
	}
	b.pathSeen[key] = struct{}{}
	if !b.out.appendPath(PathFact{
		CommandID: commandID,
		Access:    access,
		Flavor:    flavor,
		Value:     value,
	}) {
		return
	}
}

func windowsCanonicalPathFactValue(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value ||
		windowsEnvironmentProviderPath(value) {
		return "", false
	}
	if _, ok := canonicalRegistryPath(value); ok {
		return value, true
	}
	if looksLikeRegistryPath(value) {
		return "", false
	}
	return canonicalWindowsFilesystemPath(value)
}

func windowsPathFlavor(value string) PathFlavor {
	if value == "" || strings.TrimSpace(value) != value {
		return PathFlavorUnknown
	}
	lower := strings.ToLower(value)
	switch {
	case windowsRegistryPath(value):
		return PathFlavorRegistry
	case strings.HasPrefix(lower, `\\.\`), strings.HasPrefix(lower, `\\?\`),
		strings.HasPrefix(lower, `//./`), strings.HasPrefix(lower, `//?/`):
		return PathFlavorDevice
	default:
		// Operands accepted by the PowerShell/cmd classifiers are Windows
		// paths even when they use forward slashes. Keeping this authority
		// local avoids changing generic POSIX path ownership.
		return PathFlavorWindows
	}
}

func windowsRegistryPath(value string) bool {
	_, ok := canonicalRegistryPath(value)
	return ok
}

func looksLikeRegistryPath(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{
		"registry::",
		`microsoft.powershell.core\registry::`,
		"hkcu", "hklm", "hkcr", "hku", "hkcc",
		"hkey_current_user", "hkey_local_machine", "hkey_classes_root",
		"hkey_users", "hkey_current_config",
	} {
		if lower == prefix || strings.HasPrefix(lower, prefix+`\`) ||
			strings.HasPrefix(lower, prefix+":") {
			return true
		}
	}
	return false
}

func (b *windowsFactBuilder) addNetwork(
	commandID int64,
	action NetworkAction,
	scheme, host string,
	port int64,
) {
	key := strconv.FormatInt(commandID, 10) + "\x00" + string(action) + "\x00" +
		scheme + "\x00" + host + "\x00" + strconv.FormatInt(port, 10)
	if _, exists := b.networkSeen[key]; exists {
		return
	}
	b.networkSeen[key] = struct{}{}
	if !b.out.appendNetwork(NetworkFact{
		CommandID: commandID,
		Action:    action,
		Scheme:    scheme,
		Host:      host,
		Port:      port,
	}) {
		return
	}
}

func (b *windowsFactBuilder) addFlow(fact DataFlowFact) {
	key := strconv.FormatInt(fact.FromCommandID, 10) + "\x00" +
		strconv.FormatInt(fact.ToCommandID, 10) + "\x00" +
		string(fact.From) + "\x00" + string(fact.To)
	if _, exists := b.flowSeen[key]; exists {
		return
	}
	b.flowSeen[key] = struct{}{}
	b.out.appendDataFlow(fact)
}

func windowsClassifyCommand(
	command *CommandFact,
	args []windowsWord,
	dialect windowsDialect,
	builder *windowsFactBuilder,
) {
	windowsAddOperation(command, OperationExecute)
	if command.Executable == "" {
		builder.out.markPartial(IssueDynamicWord)
		return
	}
	if len(command.Arguments) == 0 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	expectedProgram := commandProgramForDialect(
		command.Arguments[0].Value,
		command.Dialect,
	)
	if expectedProgram == "" || command.Program != expectedProgram {
		// Basenames alone are not enough to trust a path-qualified binary:
		// C:\tmp\reg.exe does not inherit the grammar of the system reg.exe.
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if dialect == windowsPowerShell {
		windowsClassifyPowerShell(command, args, builder)
		return
	}
	windowsClassifyCMD(command, args, builder)
}

func windowsClassifyPowerShell(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	name := command.Program
	if name != "stop-process" &&
		!windowsScannerProgram(name) &&
		windowsHasWildcard(args) {
		builder.out.markPartial(IssueDynamicWord)
	}
	if effect, specified := powerShellPreviewEffect(name, args); specified &&
		(powerShellSupportsPreview(name) || powerShellPreviewAlias(name)) {
		if effect == EffectPreview && powerShellPreviewAlias(name) {
			effect = EffectUncertain
		}
		command.Effect = effect
		switch effect {
		case EffectPreview:
			// Preserve the intended operation and operands for detection.
			// EnforcementProjection removes preview-owned semantics while
			// retaining any shell redirections that still execute.
		case EffectUncertain:
			builder.out.markPartial(IssueUnsupportedConstruct)
			return
		}
		args = powerShellArgsWithoutPreviewControl(name, args)
	}
	if windowsInformationalInvocation(args, "-?") &&
		windowsMutatingProgram(name) {
		command.Effect = EffectPreview
		return
	}
	switch name {
	case "echo", "write-output", "write-host", "get-date", "whoami", "whoami.exe",
		"hostname", "hostname.exe", "pwd":
		return
	case "get-content", "gc", "cat", "type":
		filesystem, environment := windowsAddPowerShellPaths(
			command.ID,
			PathAccessRead,
			args,
			true,
			builder,
		)
		if filesystem {
			windowsAddOperation(command, OperationRead)
		}
		if environment {
			windowsAddOperation(command, OperationEnvironmentRead)
		}
	case "set-content", "out-file":
		windowsAddOperation(command, OperationWrite)
		windowsAddPowerShellPrimaryPath(command.ID, PathAccessWrite, args, true, builder)
	case "add-content":
		windowsAddOperation(command, OperationAppend)
		windowsAddPowerShellPrimaryPath(command.ID, PathAccessAppend, args, true, builder)
	case "remove-item", "ri", "rm", "del", "erase", "rmdir", "rd":
		windowsAddOperation(command, OperationDelete)
		windowsAddPowerShellPaths(command.ID, PathAccessDelete, args, false, builder)
	case "get-childitem", "gci", "ls", "dir":
		filesystem, environment := windowsAddPowerShellPaths(
			command.ID,
			PathAccessList,
			args,
			true,
			builder,
		)
		if filesystem {
			windowsAddOperation(command, OperationList)
		}
		if environment {
			windowsAddOperation(command, OperationEnvironmentRead)
		}
	case "new-item", "ni":
		windowsAddOperation(command, OperationWrite)
		windowsAddPowerShellNewItemPath(command.ID, args, builder)
	case "mkdir", "md":
		// PowerShell implements these names as wrapper functions rather than
		// aliases with New-Item's exact parameter grammar. Keep raw shell input
		// aligned with structured argv until that wrapper binding is owned.
		builder.out.markPartial(IssueUnknownOperandGrammar)
	case "test-path", "get-item", "gi":
		windowsAddPowerShellPrimaryPath(command.ID, PathAccessMetadata, args, false, builder)
	case "get-itemproperty", "gp":
		classifyStructuredPowerShellRegistryProperty(builder.out, command, name)
	case "set-item":
		windowsAddOperation(command, OperationConfigChange)
		windowsAddPowerShellPrimaryPath(command.ID, PathAccessWrite, args, true, builder)
	case "set-itemproperty", "sp", "new-itemproperty",
		"remove-itemproperty", "rp":
		classifyStructuredPowerShellRegistryProperty(builder.out, command, name)
	case "copy-item", "copy", "cp":
		windowsAddOperation(command, OperationCopy)
		windowsAddPowerShellSourceDestination(command.ID, args, false, builder)
	case "move-item", "move", "mv", "rename-item", "rni":
		windowsAddOperation(command, OperationMove)
		windowsAddPowerShellSourceDestination(command.ID, args, true, builder)
	case "select-string":
		windowsAddOperation(command, OperationSearch)
		windowsAddPowerShellPaths(command.ID, PathAccessRead, args, false, builder)
	case "invoke-webrequest", "iwr", "invoke-restmethod", "irm",
		"curl", "curl.exe", "wget", "wget.exe":
		windowsClassifyWeb(command, args, true, builder)
	case "reg", "reg.exe":
		windowsClassifyRegistry(command, args, builder)
	case "nmap", "nmap.exe", "masscan", "masscan.exe", "fping", "fping.exe":
		windowsClassifyNetworkScanner(command, args, builder)
	case "naabu", "naabu.exe":
		windowsClassifyNaabu(command, args, builder)
	case "nc", "nc.exe", "ncat", "ncat.exe", "netcat", "netcat.exe":
		windowsClassifyNetcat(command, args, builder)
	case "ssh", "ssh.exe", "autossh", "autossh.exe", "sftp", "sftp.exe":
		windowsClassifySSH(command, args, builder)
	case "git", "git.exe":
		windowsClassifyGit(command, args, builder)
	case "codex", "codex.exe":
		windowsClassifyCodex(command, args, builder)
	case "start-process":
		windowsAddPowerShellPrimaryPath(command.ID, PathAccessExecute, args, true, builder)
		if windowsStartProcessHasActionArguments(args) {
			// Start-Process reparses ArgumentList inside the child process.
			// Until that nested argv is parsed narrowly, retain the executable
			// fact but do not make the surrounding analysis authoritative.
			builder.out.markPartial(IssueUnsupportedConstruct)
		}
	case "clear-disk":
		windowsClassifyClearDisk(command, args, builder)
	case "stop-process":
		windowsClassifyStopProcess(command, args, builder)
	case "add-localgroupmember":
		windowsClassifyAddLocalGroupMember(command, args, builder)
	case "register-scheduledtask":
		windowsClassifyRegisterScheduledTask(command, args, builder)
	case "add-adgroupmember":
		windowsClassifyAddADGroupMember(command, args, builder)
	case "get-localgroupmember":
		windowsClassifyGetLocalGroupMember(command, args, builder)
	case "get-adgroupmember":
		windowsClassifyGetADGroupMember(command, args, builder)
	case "get-process":
		if command.PipelineID == 0 || len(args) != 0 {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		windowsAddOperation(command, OperationList)
	case "remove-process":
		windowsAddOperation(command, OperationProcessKill)
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe",
		"start-job":
		builder.out.markPartial(IssueUnsupportedConstruct)
	case "invoke-expression", "iex":
		if command.PipelineID == 0 || len(args) != 0 {
			builder.out.markPartial(IssueUnsupportedConstruct)
		}
	case "for", "foreach", "if", "switch", "function", "class", "trap":
		builder.out.markUnsupported(IssueUnsupportedConstruct)
	default:
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
}

func windowsClassifyCMD(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if command.Program != "taskkill" && command.Program != "taskkill.exe" &&
		!windowsScannerProgram(command.Program) &&
		windowsHasWildcard(args) {
		builder.out.markPartial(IssueDynamicWord)
	}
	if windowsInformationalInvocation(args, "/?") &&
		windowsMutatingProgram(command.Program) {
		command.Effect = EffectPreview
		return
	}
	switch command.Program {
	case "echo", "ver", "whoami", "whoami.exe", "hostname", "hostname.exe", "rem":
		return
	case "type", "more":
		windowsAddOperation(command, OperationRead)
		windowsAddCMDPaths(command.ID, PathAccessRead, args, builder)
	case "dir":
		windowsAddOperation(command, OperationList)
		windowsAddCMDPaths(command.ID, PathAccessList, args, builder)
	case "del", "erase", "rmdir", "rd":
		windowsAddOperation(command, OperationDelete)
		windowsValidateCMDDeleteOptions(command.Program, args, builder)
		windowsAddCMDPaths(command.ID, PathAccessDelete, args, builder)
	case "mkdir", "md":
		windowsAddOperation(command, OperationWrite)
		windowsAddCMDPaths(command.ID, PathAccessWrite, args, builder)
	case "copy", "xcopy", "xcopy.exe", "robocopy", "robocopy.exe":
		windowsAddOperation(command, OperationCopy)
		windowsAddSourceDestination(command.ID, args, false, builder)
	case "move":
		windowsAddOperation(command, OperationMove)
		windowsAddSourceDestination(command.ID, args, true, builder)
	case "curl", "curl.exe", "wget", "wget.exe":
		windowsClassifyWeb(command, args, false, builder)
	case "certutil", "certutil.exe":
		windowsClassifyCertutil(command, args, builder)
	case "reg", "reg.exe":
		windowsClassifyRegistry(command, args, builder)
	case "icacls", "icacls.exe":
		windowsClassifyICACLS(command, args, builder)
	case "takeown", "takeown.exe":
		windowsClassifyTakeown(command, args, builder)
	case "taskkill", "taskkill.exe":
		windowsClassifyTaskkill(command, args, builder)
	case "schtasks":
		windowsClassifySchtasks(command, args, builder)
	case "net":
		windowsClassifyNetLocalGroup(command, args, builder)
	case "nmap", "nmap.exe", "masscan", "masscan.exe", "fping", "fping.exe":
		windowsClassifyNetworkScanner(command, args, builder)
	case "naabu", "naabu.exe":
		windowsClassifyNaabu(command, args, builder)
	case "nc", "ncat", "netcat":
		windowsClassifyNetcat(command, args, builder)
	case "ssh", "ssh.exe", "autossh", "autossh.exe", "sftp", "sftp.exe":
		windowsClassifySSH(command, args, builder)
	case "git", "git.exe":
		windowsClassifyGit(command, args, builder)
	case "codex", "codex.exe":
		windowsClassifyCodex(command, args, builder)
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe",
		"call", "for", "if", "start", "set", "setlocal":
		builder.out.markPartial(IssueUnsupportedConstruct)
	default:
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
}

func windowsHasWildcard(args []windowsWord) bool {
	for _, arg := range args {
		if arg.wildcard {
			return true
		}
	}
	return false
}

func windowsClassifyClearDisk(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	valid := true
	targetSeen := false
	removeData := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.quote != QuoteNone {
			valid = false
			continue
		}
		switch strings.ToLower(arg.value) {
		case "-number":
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || targetSeen {
				valid = false
				continue
			}
			if _, err := strconv.ParseUint(value.value, 10, 32); err != nil {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				valid = false
				continue
			}
			targetSeen = true
		case "-inputobject":
			value, _ := windowsPowerShellParameterValue(args, &i, builder)
			if value.wildcard {
				builder.out.markPartial(IssueDynamicWord)
			}
			// InputObject may be a rich or pipeline-bound Disk object whose
			// identity cannot be proven from this literal command surface.
			// Consume the operand, but never let it establish an authoritative
			// target.
			valid = false
		case "-removedata":
			if removeData {
				valid = false
				continue
			}
			removeData = true
		default:
			if !windowsPowerShellConfirmControl(arg) {
				valid = false
			}
		}
	}
	if !valid || !targetSeen || !removeData {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationDiskWrite)
}

func windowsClassifyStopProcess(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if command.PipelineID != 0 && windowsPipelineStopProcessArgs(args) {
		windowsAddOperation(command, OperationProcessKill)
		return
	}
	valid := true
	nameSeen := false
	forceSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.quote != QuoteNone {
			valid = false
			continue
		}
		switch strings.ToLower(arg.value) {
		case "-name":
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || nameSeen {
				valid = false
				continue
			}
			if value.wildcard && value.value != "*" {
				builder.out.markPartial(IssueDynamicWord)
				valid = false
				continue
			}
			nameSeen = true
		case "-force":
			if forceSeen {
				valid = false
				continue
			}
			forceSeen = true
		default:
			if !windowsPowerShellConfirmControl(arg) {
				valid = false
			}
		}
	}
	if !valid || !nameSeen {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationProcessKill)
}

func windowsPipelineStopProcessArgs(args []windowsWord) bool {
	return len(args) == 1 &&
		!args[0].expands &&
		!args[0].wildcard &&
		args[0].quote == QuoteNone &&
		strings.EqualFold(args[0].value, "-force")
}

func windowsClassifyAddLocalGroupMember(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	windowsClassifyAddGroupMember(
		command,
		args,
		"-group",
		"-member",
		builder,
	)
}

func windowsClassifyAddADGroupMember(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	windowsClassifyAddGroupMember(
		command,
		args,
		"-identity",
		"-members",
		builder,
	)
}

func windowsClassifyAddGroupMember(
	command *CommandFact,
	args []windowsWord,
	groupParameter string,
	memberParameter string,
	builder *windowsFactBuilder,
) {
	valid := true
	memberSeen := false
	groupSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.quote != QuoteNone {
			valid = false
			continue
		}
		switch strings.ToLower(arg.value) {
		case memberParameter:
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || memberSeen || value.wildcard {
				if value.wildcard {
					builder.out.markPartial(IssueDynamicWord)
				}
				valid = false
				continue
			}
			memberSeen = true
		case groupParameter:
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || groupSeen || value.wildcard {
				if value.wildcard {
					builder.out.markPartial(IssueDynamicWord)
				}
				valid = false
				continue
			}
			groupSeen = true
		default:
			if !windowsPowerShellConfirmControl(arg) {
				valid = false
			}
		}
	}
	if !valid || !memberSeen || !groupSeen {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationAccountChange)
}

func windowsClassifyGetLocalGroupMember(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	valid := true
	groupSeen := false
	memberSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.quote != QuoteNone {
			valid = false
			continue
		}
		switch strings.ToLower(arg.value) {
		case "-group":
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || groupSeen || value.wildcard {
				valid = false
				continue
			}
			groupSeen = true
		case "-member":
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || memberSeen || value.wildcard {
				valid = false
				continue
			}
			memberSeen = true
		default:
			valid = false
		}
	}
	if !valid || !groupSeen {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationList)
}

func windowsClassifyGetADGroupMember(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	valid := true
	identitySeen := false
	recursiveSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.quote != QuoteNone {
			valid = false
			continue
		}
		switch strings.ToLower(arg.value) {
		case "-identity":
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || identitySeen || value.wildcard {
				valid = false
				continue
			}
			identitySeen = true
		case "-recursive":
			if recursiveSeen {
				valid = false
				continue
			}
			recursiveSeen = true
		default:
			valid = false
		}
	}
	if !valid || !identitySeen {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationList)
}

func windowsClassifyRegisterScheduledTask(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	valid := true
	taskSeen := false
	actionSeen := false
	forceSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.quote != QuoteNone {
			valid = false
			continue
		}
		switch strings.ToLower(arg.value) {
		case "-taskname":
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || taskSeen || value.wildcard {
				if value.wildcard {
					builder.out.markPartial(IssueDynamicWord)
				}
				valid = false
				continue
			}
			taskSeen = true
		case "-action":
			value, ok := windowsPowerShellParameterValue(args, &i, builder)
			if !ok || actionSeen || value.wildcard {
				if value.wildcard {
					builder.out.markPartial(IssueDynamicWord)
				}
				valid = false
				continue
			}
			actionSeen = true
		case "-force":
			if forceSeen {
				valid = false
				continue
			}
			forceSeen = true
		default:
			if !windowsPowerShellConfirmControl(arg) {
				valid = false
			}
		}
	}
	if !valid || !taskSeen || !actionSeen {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationSchedule)
}

func windowsPowerShellParameterValue(
	args []windowsWord,
	index *int,
	builder *windowsFactBuilder,
) (windowsWord, bool) {
	if *index+1 >= len(args) {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return windowsWord{}, false
	}
	(*index)++
	value := args[*index]
	if value.expands || value.value == "" ||
		value.quote == QuoteNone && strings.HasPrefix(value.value, "-") {
		if value.expands {
			builder.out.markPartial(IssueDynamicWord)
		} else {
			builder.out.markPartial(IssueUnknownOperandGrammar)
		}
		return windowsWord{}, false
	}
	return value, true
}

func windowsPowerShellConfirmControl(arg windowsWord) bool {
	if arg.expands || arg.quote != QuoteNone {
		return false
	}
	name, value, hasValue := strings.Cut(strings.ToLower(arg.value), ":")
	if name != "-confirm" {
		return false
	}
	return !hasValue || value == "$true" || value == "$false"
}

func windowsClassifyICACLS(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if len(args) == 0 || args[0].expands || args[0].wildcard ||
		strings.HasPrefix(args[0].value, "/") &&
			!windowsCMDPathOperand(args[0].value) {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	target := args[0].value
	valid := true
	mutates := false
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.wildcard {
			valid = false
			continue
		}
		lower := strings.ToLower(arg.value)
		switch {
		case lower == "/grant", lower == "/grant:r",
			lower == "/deny", lower == "/deny:r",
			lower == "/remove", lower == "/remove:g",
			lower == "/remove:d", lower == "/setintegritylevel":
			if i+1 >= len(args) || args[i+1].expands ||
				args[i+1].wildcard || args[i+1].value == "" ||
				windowsCMDOptionLikeValue(args[i+1]) {
				valid = false
				continue
			}
			i++
			mutates = true
		case lower == "/reset",
			lower == "/inheritance:e",
			lower == "/inheritance:d",
			lower == "/inheritance:r":
			mutates = true
		case lower == "/verify", lower == "/t", lower == "/c",
			lower == "/l", lower == "/q":
		default:
			valid = false
		}
	}
	if !valid {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	builder.addPath(command.ID, PathAccessMetadata, target)
	if mutates {
		windowsAddOperation(command, OperationPermissionChange)
	} else {
		windowsAddOperation(command, OperationList)
	}
}

func windowsClassifyTakeown(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	valid := true
	target := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.wildcard {
			valid = false
			continue
		}
		switch strings.ToLower(arg.value) {
		case "/f":
			if i+1 >= len(args) || target != "" || args[i+1].expands ||
				args[i+1].wildcard || args[i+1].value == "" ||
				windowsCMDOptionLikeValue(args[i+1]) {
				valid = false
				continue
			}
			i++
			target = args[i].value
		case "/a", "/r", "/skipsl":
		case "/d":
			if i+1 >= len(args) || args[i+1].expands ||
				windowsCMDOptionLikeValue(args[i+1]) ||
				!strings.EqualFold(args[i+1].value, "Y") &&
					!strings.EqualFold(args[i+1].value, "N") {
				valid = false
				continue
			}
			i++
		default:
			valid = false
		}
	}
	if !valid || target == "" {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	builder.addPath(command.ID, PathAccessMetadata, target)
	windowsAddOperation(command, OperationPermissionChange)
}

func windowsClassifyTaskkill(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	valid := true
	targetSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.quote != QuoteNone {
			valid = false
			continue
		}
		lower := strings.ToLower(arg.value)
		switch lower {
		case "/f", "/t":
		case "/fi", "/s", "/u", "/p":
			if i+1 >= len(args) || args[i+1].expands ||
				args[i+1].value == "" ||
				windowsCMDOptionLikeValue(args[i+1]) {
				valid = false
				continue
			}
			i++
		case "/im":
			if i+1 >= len(args) || args[i+1].expands ||
				args[i+1].value == "" ||
				windowsCMDOptionLikeValue(args[i+1]) {
				valid = false
				continue
			}
			i++
			if args[i].wildcard && args[i].value != "*" {
				valid = false
				continue
			}
			targetSeen = true
		case "/pid":
			if i+1 >= len(args) || args[i+1].expands ||
				args[i+1].wildcard {
				valid = false
				continue
			}
			i++
			if _, err := strconv.ParseUint(args[i].value, 10, 32); err != nil {
				valid = false
				continue
			}
			targetSeen = true
		default:
			valid = false
		}
	}
	if !valid || !targetSeen {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationProcessKill)
}

func windowsClassifySchtasks(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	valid := true
	mode := ""
	taskName := ""
	taskRun := ""
	schedule := ""
	format := ""
	force := false
	verbose := false
	noHeader := false
	help := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !windowsStaticOption(arg) {
			valid = false
			continue
		}
		switch strings.ToLower(arg.value) {
		case "/?":
			if help {
				valid = false
				continue
			}
			help = true
		case "/create", "/query":
			if mode != "" {
				valid = false
				continue
			}
			mode = strings.ToLower(arg.value)
		case "/tn":
			value, ok := windowsNextStaticValue(args, &i, false, true)
			if !ok || taskName != "" {
				valid = false
				continue
			}
			taskName = value.value
		case "/tr":
			value, ok := windowsNextStaticValue(args, &i, false, true)
			if !ok || taskRun != "" {
				valid = false
				continue
			}
			taskRun = value.value
		case "/sc":
			value, ok := windowsNextStaticValue(args, &i, false, true)
			if !ok || schedule != "" {
				valid = false
				continue
			}
			switch strings.ToLower(value.value) {
			case "onlogon", "onstart":
				schedule = strings.ToLower(value.value)
			default:
				valid = false
			}
		case "/fo":
			value, ok := windowsNextStaticValue(args, &i, false, true)
			if !ok || format != "" {
				valid = false
				continue
			}
			switch strings.ToLower(value.value) {
			case "table", "list", "csv":
				format = strings.ToLower(value.value)
			default:
				valid = false
			}
		case "/f":
			if force {
				valid = false
				continue
			}
			force = true
		case "/v":
			if verbose {
				valid = false
				continue
			}
			verbose = true
		case "/nh":
			if noHeader {
				valid = false
				continue
			}
			noHeader = true
		default:
			valid = false
		}
	}
	if help {
		if valid && taskName == "" && taskRun == "" && schedule == "" &&
			format == "" && !force && !verbose && !noHeader &&
			(mode == "" || mode == "/create" || mode == "/query") {
			command.Effect = EffectPreview
			return
		}
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	switch mode {
	case "/create":
		if taskName == "" || taskRun == "" || schedule == "" || format != "" ||
			verbose || noHeader {
			valid = false
		}
		if valid {
			windowsAddOperation(command, OperationSchedule)
			return
		}
	case "/query":
		if taskRun != "" || schedule != "" || force {
			valid = false
		}
		if valid {
			command.Effect = EffectPreview
			windowsAddOperation(command, OperationList)
			return
		}
	default:
		valid = false
	}
	if !valid {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
}

func windowsClassifyNetLocalGroup(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if windowsNetHelpInvocation(args) {
		command.Effect = EffectPreview
		return
	}
	if len(args) == 0 || !windowsStaticOption(args[0]) ||
		!strings.EqualFold(args[0].value, "localgroup") {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	operands := args[1:]
	for _, operand := range operands {
		if operand.expands || operand.wildcard || operand.value == "" {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return
		}
	}
	switch len(operands) {
	case 0:
		command.Effect = EffectPreview
		windowsAddOperation(command, OperationList)
	case 1:
		if windowsCMDOptionLikeValue(operands[0]) {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		command.Effect = EffectPreview
		windowsAddOperation(command, OperationList)
	case 3:
		if windowsCMDOptionLikeValue(operands[0]) ||
			windowsCMDOptionLikeValue(operands[1]) ||
			!windowsStaticOption(operands[2]) ||
			!strings.EqualFold(operands[2].value, "/add") {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		windowsAddOperation(command, OperationAccountChange)
	default:
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
}

func windowsNetHelpInvocation(args []windowsWord) bool {
	if len(args) == 0 {
		return false
	}
	for index, arg := range args {
		if !windowsStaticOption(arg) {
			continue
		}
		lower := strings.ToLower(arg.value)
		if lower == "/?" || lower == "/help" ||
			index == 0 && lower == "help" {
			return true
		}
	}
	return false
}

func windowsClassifyNetworkScanner(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	switch command.Program {
	case "nmap", "masscan", "fping":
	default:
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !windowsExecutableFamily(command, command.Program) {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	classifyNetworkScanner(builder.out, command, command.Program)
	for _, arg := range args {
		if arg.expands {
			command.Effect = EffectUncertain
			builder.out.markPartial(IssueDynamicWord)
		}
	}
}

func windowsScannerProgram(program string) bool {
	switch program {
	case "nmap", "masscan", "fping":
		return true
	default:
		return false
	}
}

func windowsClassifyNaabu(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if !windowsExecutableFamily(command, "naabu") {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	valid := true
	hasSource := false
	var targets []string
	var targetFiles []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.wildcard || arg.value == "" {
			valid = false
			continue
		}
		if arg.quote == QuoteNone {
			switch arg.value {
			case "-h", "--help", "-version", "--version", "/?":
				command.Effect = EffectPreview
				return
			case "-silent", "--silent", "-ping", "--ping":
				continue
			case "-list", "--list", "-l":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok {
					valid = false
				} else {
					targetFiles = append(targetFiles, value.value)
					hasSource = true
				}
				continue
			case "-host", "--host":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || !windowsValidScanTarget(value.value) {
					valid = false
				} else {
					targets = append(targets, value.value)
					hasSource = true
				}
				continue
			case "-p", "-port", "--port", "-ports", "--ports":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || !windowsValidPortSet(value.value) {
					valid = false
				}
				continue
			case "-rate", "--rate":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || !windowsPositiveCount(value.value) {
					valid = false
				}
				continue
			case "-exclude-hosts", "--exclude-hosts":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || !windowsValidScanTarget(value.value) {
					valid = false
				}
				continue
			}
			switch {
			case strings.HasPrefix(arg.value, "--list="):
				value := strings.TrimPrefix(arg.value, "--list=")
				if value == "" || strings.HasPrefix(value, "-") {
					valid = false
				} else {
					targetFiles = append(targetFiles, value)
					hasSource = true
				}
				continue
			case strings.HasPrefix(arg.value, "--host="):
				value := strings.TrimPrefix(arg.value, "--host=")
				if !windowsValidScanTarget(value) {
					valid = false
				} else {
					targets = append(targets, value)
					hasSource = true
				}
				continue
			case strings.HasPrefix(arg.value, "-"):
				valid = false
				continue
			}
		}
		if !windowsValidScanTarget(arg.value) {
			valid = false
			continue
		}
		targets = append(targets, arg.value)
		hasSource = true
	}
	if !valid || !hasSource {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationNetworkScan)
	for _, target := range targets {
		builder.addNetwork(command.ID, NetworkScan, "", target, 0)
	}
	for _, targetFile := range targetFiles {
		builder.addPath(command.ID, PathAccessRead, targetFile)
		builder.addFlow(DataFlowFact{
			ToCommandID: command.ID,
			From:        DataFile,
			To:          DataProcess,
		})
	}
}

func windowsValidScanTarget(value string) bool {
	normalized, _, kind, _ := deriveNetworkTarget(value)
	return normalized != "" && kind != NetworkTargetUnknown
}

func windowsPositiveCount(value string) bool {
	count, err := strconv.ParseUint(value, 10, 31)
	return err == nil && count > 0
}

func windowsValidPortSet(value string) bool {
	if value == "" {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		first, last, ranged := strings.Cut(item, "-")
		firstPort, err := strconv.ParseUint(first, 10, 16)
		if err != nil || firstPort == 0 {
			return false
		}
		if !ranged {
			continue
		}
		lastPort, err := strconv.ParseUint(last, 10, 16)
		if err != nil || lastPort == 0 || lastPort < firstPort {
			return false
		}
	}
	return true
}

func windowsClassifyNetcat(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	switch command.Program {
	case "nc", "ncat", "netcat":
	default:
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	switch command.Executable {
	case "nc", "nc.exe", "ncat", "ncat.exe", "netcat", "netcat.exe":
	default:
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	valid := true
	listen := false
	udp := false
	sourceHost := ""
	sourcePort := int64(0)
	executable := ""
	var positionals []string
	ncat := command.Program == "ncat"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.wildcard || arg.value == "" {
			valid = false
			continue
		}
		if arg.quote == QuoteNone {
			switch arg.value {
			case "-h", "--help", "/?":
				command.Effect = EffectPreview
				return
			case "-l":
				if listen {
					valid = false
				}
				listen = true
				continue
			case "-u":
				if udp {
					valid = false
				}
				udp = true
				continue
			case "-n", "-v", "-z", "-k":
				continue
			case "-e":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || executable != "" ||
					strings.ContainsAny(value.value, " \t\r\n") {
					valid = false
				} else {
					executable = value.value
				}
				continue
			case "-c":
				// This operand is reparsed by a shell and cannot be projected
				// as a static executable path.
				_, _ = windowsNextStaticValue(args, &i, false, false)
				valid = false
				continue
			case "-w":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || !windowsPositiveCount(value.value) {
					valid = false
				}
				continue
			case "-s":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok {
					valid = false
					continue
				}
				host, ok := canonicalNetworkHost(value.value)
				if !ok || sourceHost != "" {
					valid = false
				} else {
					sourceHost = host
				}
				continue
			case "-p":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok {
					valid = false
					continue
				}
				port, ok := windowsNetworkPort(value.value)
				if !ok || sourcePort != 0 {
					valid = false
				} else {
					sourcePort = port
				}
				continue
			case "--listen":
				if !ncat || listen {
					valid = false
				} else {
					listen = true
				}
				continue
			case "--udp", "--verbose", "--keep-open":
				if !ncat {
					valid = false
				} else if arg.value == "--udp" {
					udp = true
				}
				continue
			case "--exec":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ncat || !ok || executable != "" ||
					strings.ContainsAny(value.value, " \t\r\n") {
					valid = false
				} else {
					executable = value.value
				}
				continue
			case "--sh-exec":
				_, _ = windowsNextStaticValue(args, &i, false, false)
				valid = false
				continue
			case "--wait":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ncat || !ok || !windowsPositiveCount(value.value) {
					valid = false
				}
				continue
			case "--source":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ncat || !ok {
					valid = false
					continue
				}
				host, ok := canonicalNetworkHost(value.value)
				if !ok || sourceHost != "" {
					valid = false
				} else {
					sourceHost = host
				}
				continue
			case "--source-port":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ncat || !ok {
					valid = false
					continue
				}
				port, ok := windowsNetworkPort(value.value)
				if !ok || sourcePort != 0 {
					valid = false
				} else {
					sourcePort = port
				}
				continue
			}
			switch {
			case ncat && strings.HasPrefix(arg.value, "--exec="):
				value := strings.TrimPrefix(arg.value, "--exec=")
				if value == "" || executable != "" ||
					strings.ContainsAny(value, " \t\r\n") {
					valid = false
				} else {
					executable = value
				}
				continue
			case ncat && strings.HasPrefix(arg.value, "--wait="):
				value := strings.TrimPrefix(arg.value, "--wait=")
				if !windowsPositiveCount(value) {
					valid = false
				}
				continue
			case ncat && strings.HasPrefix(arg.value, "--source="):
				value := strings.TrimPrefix(arg.value, "--source=")
				host, ok := canonicalNetworkHost(value)
				if !ok || sourceHost != "" {
					valid = false
				} else {
					sourceHost = host
				}
				continue
			case ncat && strings.HasPrefix(arg.value, "--source-port="):
				value := strings.TrimPrefix(arg.value, "--source-port=")
				port, ok := windowsNetworkPort(value)
				if !ok || sourcePort != 0 {
					valid = false
				} else {
					sourcePort = port
				}
				continue
			case strings.HasPrefix(arg.value, "-"):
				valid = false
				continue
			}
		}
		positionals = append(positionals, arg.value)
	}
	scheme := "tcp"
	if udp {
		scheme = "udp"
	}
	networkHost := ""
	networkPort := int64(0)
	action := NetworkConnect
	operation := OperationConnect
	if listen {
		action = NetworkListen
		operation = OperationListen
		switch len(positionals) {
		case 1:
			port, ok := windowsNetworkPort(positionals[0])
			if !ok {
				valid = false
			} else {
				networkHost = sourceHost
				networkPort = port
			}
		case 2:
			host, ok := canonicalNetworkHost(positionals[0])
			port, portOK := windowsNetworkPort(positionals[1])
			if !ok || !portOK {
				valid = false
			} else {
				networkHost = host
				networkPort = port
			}
		case 0:
			if sourcePort == 0 {
				valid = false
			} else {
				networkHost = sourceHost
				networkPort = sourcePort
			}
		default:
			valid = false
		}
	} else if len(positionals) == 2 {
		host, ok := canonicalNetworkHost(positionals[0])
		port, portOK := windowsNetworkPort(positionals[1])
		if !ok || !portOK {
			valid = false
		} else {
			networkHost = host
			networkPort = port
		}
	} else {
		valid = false
	}
	if !valid {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, operation)
	builder.addNetwork(command.ID, action, scheme, networkHost, networkPort)
	if executable != "" {
		builder.addPath(command.ID, PathAccessExecute, executable)
	}
}

func windowsNetworkPort(value string) (int64, bool) {
	port, err := strconv.ParseInt(value, 10, 64)
	return port, err == nil && port > 0 && port <= 65535
}

func windowsClassifySSH(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	switch command.Program {
	case "ssh", "ssh.exe", "autossh", "autossh.exe", "sftp", "sftp.exe":
	default:
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !command.ArgvComplete || len(command.Argv) != len(args)+1 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	for _, arg := range args {
		if arg.expands || arg.wildcard || arg.value == "" {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return
		}
	}

	// Once Windows shell tokenization has produced a static argv, OpenSSH has
	// the same option and destination grammar on every host. Keeping one
	// classifier avoids raw CMD/PowerShell drifting from structured tool-call
	// facts.
	classifySSH(builder.out, command, command.Program)
}

func windowsValidSSHTunnelSpec(option string, value string) bool {
	if value == "" || strings.ContainsAny(value, `/\`) {
		// StreamLocal forwarding has path and cleanup semantics that are not
		// represented by the current network fact.
		return false
	}
	parts, ok := splitSSHTunnelFields(value)
	if !ok {
		return false
	}
	switch option {
	case "-R":
		if len(parts) == 1 {
			return validSSHTunnelPort(parts[0], true)
		}
		return validSSHForwardFields(parts, true)
	case "-L":
		return validSSHForwardFields(parts, false)
	case "-D":
		if len(parts) == 1 {
			return validSSHTunnelPort(parts[0], false)
		}
		if len(parts) != 2 ||
			!validSSHTunnelHost(parts[0], true) {
			return false
		}
		return validSSHTunnelPort(parts[1], false)
	default:
		return false
	}
}

func validSSHForwardFields(parts []string, allowRemoteZero bool) bool {
	if len(parts) != 3 && len(parts) != 4 {
		return false
	}
	offset := 0
	if len(parts) == 4 {
		if !validSSHTunnelHost(parts[0], true) {
			return false
		}
		offset = 1
	}
	return validSSHTunnelPort(parts[offset], allowRemoteZero) &&
		validSSHTunnelHost(parts[offset+1], false) &&
		validSSHTunnelPort(parts[offset+2], false)
}

func splitSSHTunnelFields(value string) ([]string, bool) {
	var (
		parts        []string
		start        int
		insideBraces bool
	)
	for index, char := range value {
		switch char {
		case '[':
			if insideBraces {
				return nil, false
			}
			insideBraces = true
		case ']':
			if !insideBraces {
				return nil, false
			}
			insideBraces = false
		case ':':
			if !insideBraces {
				parts = append(parts, value[start:index])
				start = index + 1
			}
		}
	}
	if insideBraces {
		return nil, false
	}
	return append(parts, value[start:]), true
}

func validSSHTunnelHost(value string, bindAddress bool) bool {
	if bindAddress && (value == "" || value == "*") {
		return true
	}
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		if len(value) < 4 ||
			!strings.HasPrefix(value, "[") ||
			!strings.HasSuffix(value, "]") {
			return false
		}
		ip := value[1 : len(value)-1]
		return strings.Contains(ip, ":") && net.ParseIP(ip) != nil
	}
	if strings.ContainsAny(value, "[]:") {
		return false
	}
	_, ok := canonicalSSHNetworkHost(value)
	return ok
}

func validSSHTunnelPort(value string, allowZero bool) bool {
	if allowZero && value == "0" {
		return true
	}
	_, ok := windowsNetworkPort(value)
	return ok
}

func windowsClassifyGit(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if !windowsExecutableFamily(command, "git") {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	subcommand, _, _, complete := ownedCLISubcommand(
		command.Argv,
		exactOptionSet(
			"-c", "-C", "--config-env", "--exec-path", "--git-dir",
			"--namespace", "--super-prefix", "--work-tree",
		),
		exactOptionSet(
			"-p", "--paginate", "--no-pager", "--bare",
			"--no-replace-objects", "--literal-pathspecs",
			"--glob-pathspecs", "--noglob-pathspecs",
			"--icase-pathspecs", "--no-optional-locks",
		),
		exactOptionSet("--help", "--version"),
	)
	if complete && subcommand == "remote" ||
		len(command.Argv) > 1 &&
			strings.EqualFold(command.Argv[1], "remote") {
		for _, arg := range args {
			if arg.expands || arg.wildcard || arg.value == "" {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				return
			}
		}
		classifyGit(builder.out, command)
		return
	}
	valid := true
	index := 0
	for index < len(args) {
		arg := args[index]
		if arg.expands || arg.wildcard || arg.value == "" {
			valid = false
			index++
			continue
		}
		if arg.quote == QuoteNone {
			switch arg.value {
			case "--help", "-h", "--version":
				command.Effect = EffectPreview
				return
			case "-C", "-c", "--git-dir", "--work-tree":
				value, ok := windowsNextStaticValue(
					args,
					&index,
					arg.value != "-c",
					false,
				)
				if !ok || value.value == "" {
					valid = false
				}
				index++
				continue
			}
		}
		break
	}
	if index >= len(args) || args[index].expands ||
		!strings.EqualFold(args[index].value, "commit") {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	index++
	dryRun := false
	var readPaths []string
	for index < len(args) {
		arg := args[index]
		if arg.expands || arg.wildcard || arg.value == "" {
			valid = false
			index++
			continue
		}
		if arg.quote == QuoteNone {
			switch arg.value {
			case "--help", "-h":
				command.Effect = EffectPreview
				return
			case "--dry-run":
				dryRun = true
				index++
				continue
			case "-n", "--no-verify", "-a", "--all", "--allow-empty",
				"--amend", "--signoff", "-s":
				index++
				continue
			case "-m", "--message":
				value, ok := windowsNextStaticValue(args, &index, false, false)
				if !ok || windowsGitMessageMasksNoVerify(value.value) {
					valid = false
				}
				index++
				continue
			case "-F", "--file":
				value, ok := windowsNextStaticValue(args, &index, true, false)
				if !ok {
					valid = false
				} else {
					readPaths = append(readPaths, value.value)
				}
				index++
				continue
			case "--author", "--date", "--cleanup":
				value, ok := windowsNextStaticValue(
					args,
					&index,
					false,
					false,
				)
				if !ok || windowsGitMessageMasksNoVerify(value.value) {
					valid = false
				}
				index++
				continue
			case "--":
				valid = false
				index++
				continue
			}
			switch {
			case strings.HasPrefix(arg.value, "--message="):
				value := strings.TrimPrefix(arg.value, "--message=")
				if value == "" || windowsGitMessageMasksNoVerify(value) {
					valid = false
				}
				index++
				continue
			case strings.HasPrefix(arg.value, "-m") &&
				len(arg.value) > len("-m"):
				index++
				continue
			case strings.HasPrefix(arg.value, "-"):
				valid = false
				index++
				continue
			}
		}
		// A bounded static pathspec is data to git commit, not an option.
		index++
	}
	if !valid {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	for _, readPath := range readPaths {
		builder.addPath(command.ID, PathAccessRead, readPath)
	}
	if dryRun {
		command.Effect = EffectPreview
	}
}

func windowsGitMessageMasksNoVerify(value string) bool {
	return value == "-n" || value == "--no-verify"
}

func windowsClassifyCodex(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if !windowsExecutableFamily(command, "codex") || len(args) == 0 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if windowsStaticOption(args[0]) {
		switch args[0].value {
		case "--help", "-h", "--version", "-V":
			command.Effect = EffectPreview
			return
		}
	}
	if args[0].expands || !strings.EqualFold(args[0].value, "exec") {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	valid := true
	payloadSeen := false
	sandboxSeen := false
	approvalSeen := false
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg.expands || arg.wildcard || arg.value == "" {
			valid = false
			continue
		}
		if arg.quote == QuoteNone {
			switch arg.value {
			case "--help", "-h":
				command.Effect = EffectPreview
				return
			case "--full-auto", "--json", "--skip-git-repo-check",
				"--ephemeral", "--dangerously-bypass-approvals-and-sandbox":
				continue
			case "--sandbox", "-s":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || sandboxSeen ||
					!windowsKnownCodexSandbox(value.value) {
					valid = false
				} else {
					sandboxSeen = true
				}
				continue
			case "--ask-for-approval", "--approval-policy", "-a":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || approvalSeen ||
					!windowsKnownCodexApproval(value.value) {
					valid = false
				} else {
					approvalSeen = true
				}
				continue
			case "--message":
				value, ok := windowsNextStaticValue(args, &i, false, false)
				if !ok || payloadSeen ||
					windowsCodexMessageMasksControl(value.value) {
					valid = false
				} else {
					payloadSeen = true
				}
				continue
			case "--model", "-m":
				_, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok {
					valid = false
				}
				continue
			case "--color":
				value, ok := windowsNextStaticValue(args, &i, true, false)
				if !ok || value.value != "always" &&
					value.value != "never" &&
					value.value != "auto" {
					valid = false
				}
				continue
			}
			switch {
			case strings.HasPrefix(arg.value, "--sandbox="):
				value := strings.TrimPrefix(arg.value, "--sandbox=")
				if sandboxSeen || !windowsKnownCodexSandbox(value) {
					valid = false
				} else {
					sandboxSeen = true
				}
				continue
			case strings.HasPrefix(arg.value, "-s="):
				value := strings.TrimPrefix(arg.value, "-s=")
				if sandboxSeen || !windowsKnownCodexSandbox(value) {
					valid = false
				} else {
					sandboxSeen = true
				}
				continue
			case strings.HasPrefix(arg.value, "--ask-for-approval="):
				value := strings.TrimPrefix(arg.value, "--ask-for-approval=")
				if approvalSeen || !windowsKnownCodexApproval(value) {
					valid = false
				} else {
					approvalSeen = true
				}
				continue
			case strings.HasPrefix(arg.value, "--approval-policy="):
				value := strings.TrimPrefix(arg.value, "--approval-policy=")
				if approvalSeen || !windowsKnownCodexApproval(value) {
					valid = false
				} else {
					approvalSeen = true
				}
				continue
			case strings.HasPrefix(arg.value, "-a="):
				value := strings.TrimPrefix(arg.value, "-a=")
				if approvalSeen || !windowsKnownCodexApproval(value) {
					valid = false
				} else {
					approvalSeen = true
				}
				continue
			case strings.HasPrefix(arg.value, "--message="):
				value := strings.TrimPrefix(arg.value, "--message=")
				if value == "" || payloadSeen ||
					windowsCodexMessageMasksControl(value) {
					valid = false
				} else {
					payloadSeen = true
				}
				continue
			case strings.HasPrefix(arg.value, "-"):
				valid = false
				continue
			}
		}
		if payloadSeen {
			valid = false
			continue
		}
		payloadSeen = true
	}
	if !valid || !payloadSeen {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
}

func windowsKnownCodexSandbox(value string) bool {
	switch value {
	case "read-only", "workspace-write", "danger-full-access":
		return true
	default:
		return false
	}
}

func windowsKnownCodexApproval(value string) bool {
	switch value {
	case "untrusted", "on-failure", "on-request", "never":
		return true
	default:
		return false
	}
}

func windowsCodexMessageMasksControl(value string) bool {
	switch value {
	case "--sandbox", "-s", "--ask-for-approval", "--approval-policy", "-a",
		"--dangerously-bypass-approvals-and-sandbox":
		return true
	default:
		return false
	}
}

func windowsStaticOption(word windowsWord) bool {
	return !word.expands && !word.wildcard &&
		word.quote == QuoteNone && word.value != ""
}

func windowsNextStaticValue(
	args []windowsWord,
	index *int,
	rejectDash bool,
	rejectSlash bool,
) (windowsWord, bool) {
	if *index+1 >= len(args) {
		return windowsWord{}, false
	}
	(*index)++
	value := args[*index]
	if value.expands || value.wildcard || value.value == "" {
		return windowsWord{}, false
	}
	if value.quote == QuoteNone &&
		(rejectDash && strings.HasPrefix(value.value, "-") ||
			rejectSlash && windowsCMDOptionLikeValue(value)) {
		return windowsWord{}, false
	}
	return value, true
}

func windowsCMDOptionLikeValue(word windowsWord) bool {
	return strings.HasPrefix(word.value, "/") &&
		!windowsCMDPathOperand(word.value)
}

func windowsValidateCMDDeleteOptions(
	program string,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	for _, arg := range args {
		if arg.expands || !strings.HasPrefix(arg.value, "/") ||
			windowsCMDPathOperand(arg.value) {
			continue
		}
		lower := strings.ToLower(arg.value)
		known := false
		switch program {
		case "rmdir", "rd":
			known = lower == "/s" || lower == "/q"
		case "del", "erase":
			known = lower == "/p" || lower == "/f" ||
				lower == "/s" || lower == "/q" ||
				lower == "/a" || strings.HasPrefix(lower, "/a:")
		}
		if !known {
			builder.out.markPartial(IssueUnknownOperandGrammar)
		}
	}
}

func windowsAddPowerShellPaths(
	commandID int64,
	access PathAccess,
	args []windowsWord,
	allowEnvironment bool,
	builder *windowsFactBuilder,
) (bool, bool) {
	pathParams := map[string]bool{
		"-path": true, "-literalpath": true, "-filepath": true,
	}
	valueParams := map[string]bool{
		"-value": true, "-encoding": true, "-filter": true, "-include": true,
		"-exclude": true, "-erroraction": true, "-warningaction": true,
		"-name": true, "-type": true,
	}
	switchParams := map[string]bool{
		"-force": true, "-recurse": true, "-raw": true, "-quiet": true,
		"-confirm": true, "-whatif": true, "-stream": true,
	}
	found := false
	filesystemFound := false
	environmentFound := false
	addOperand := func(value string) {
		if windowsEnvironmentProviderPath(value) {
			if allowEnvironment {
				environmentFound = true
			} else {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
			found = true
			return
		}
		builder.addPath(commandID, access, value)
		found = true
		filesystemFound = true
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			continue
		}
		lower := strings.ToLower(arg.value)
		unquoted := arg.quote == QuoteNone
		if unquoted && pathParams[lower] {
			if i+1 >= len(args) || args[i+1].expands {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			i++
			addOperand(args[i].value)
			continue
		}
		if unquoted && valueParams[lower] {
			i++
			if i >= len(args) {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
			continue
		}
		if unquoted && (switchParams[lower] ||
			strings.HasPrefix(lower, "-confirm:") ||
			strings.HasPrefix(lower, "-whatif:")) {
			continue
		}
		if unquoted && strings.HasPrefix(lower, "-") {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		addOperand(arg.value)
	}
	if !found {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
	return filesystemFound, environmentFound
}

// windowsAddPowerShellNewItemPath owns New-Item's separate -Path and -Name
// parameters. When both are present, -Name is a child of -Path; it is not an
// unrelated value and the parent alone is not the write target.
func windowsAddPowerShellNewItemPath(
	commandID int64,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	valueParams := map[string]string{
		"-value":               "-value",
		"-target":              "-value",
		"-type":                "-itemtype",
		"-itemtype":            "-itemtype",
		"-credential":          "-credential",
		"-erroraction":         "-erroraction",
		"-errorvariable":       "-errorvariable",
		"-informationaction":   "-informationaction",
		"-informationvariable": "-informationvariable",
		"-outbuffer":           "-outbuffer",
		"-outvariable":         "-outvariable",
		"-pipelinevariable":    "-pipelinevariable",
		"-progressaction":      "-progressaction",
		"-warningaction":       "-warningaction",
		"-warningvariable":     "-warningvariable",
	}
	switchParams := map[string]string{
		"-force":          "-force",
		"-debug":          "-debug",
		"-verbose":        "-verbose",
		"-usetransaction": "-usetransaction",
		"-confirm":        "-confirm",
		"-whatif":         "-whatif",
	}
	var parent *windowsWord
	var name *windowsWord
	var itemType string
	var positionals []windowsWord
	seenParams := make(map[string]struct{})
	targetValid := true
	recordParam := func(name string) bool {
		if _, duplicate := seenParams[name]; duplicate {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return false
		}
		seenParams[name] = struct{}{}
		return true
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		lower := strings.ToLower(arg.value)
		unquoted := arg.quote == QuoteNone
		rawParameter, joinedValue, joined := strings.Cut(arg.value, ":")
		parameterKey := lower
		if unquoted && joined {
			parameterKey = strings.ToLower(rawParameter)
		}
		parameterKey = canonicalPowerShellNewItemParameter(parameterKey)
		valueParam, isValueParam := valueParams[parameterKey]
		switchParam, isSwitchParam := switchParams[parameterKey]
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			switch {
			case unquoted && (parameterKey == "-path" ||
				parameterKey == "-name"):
				recordParam(parameterKey)
				targetValid = false
			case unquoted && parameterKey == "-literalpath":
				targetValid = false
			case unquoted && joined && isValueParam:
				recordParam(valueParam)
			case unquoted && joined && isSwitchParam:
				recordParam(switchParam)
			default:
				// A dynamic positional may be the parent path.
				targetValid = false
			}
			continue
		}
		switchValueValid := true
		if unquoted && joined {
			switch switchParam {
			case "-force", "-debug", "-verbose", "-usetransaction",
				"-confirm", "-whatif":
				switchValueValid =
					strings.EqualFold(joinedValue, "$true") ||
						strings.EqualFold(joinedValue, "$false")
			}
		}
		switch {
		case unquoted && parameterKey == "-path":
			unique := recordParam("-path")
			if joined {
				if !unique || joinedValue == "" {
					builder.out.markPartial(IssueUnknownOperandGrammar)
					targetValid = false
					continue
				}
				joinedArg := arg
				joinedArg.value = joinedValue
				parent = &joinedArg
				continue
			}
			if !unique || !windowsPowerShellLiteralParameterValue(
				args,
				i+1,
			) {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				targetValid = false
				if i+1 < len(args) {
					i++
				}
				continue
			}
			i++
			parent = &args[i]
		case unquoted && parameterKey == "-literalpath":
			// New-Item has no LiteralPath parameter. Consume a literal value
			// only to keep it from being reinterpreted as a positional target.
			builder.out.markPartial(IssueUnknownOperandGrammar)
			targetValid = false
			if !joined &&
				windowsPowerShellLiteralParameterValue(args, i+1) {
				i++
			}
		case unquoted && parameterKey == "-name":
			unique := recordParam("-name")
			if joined {
				if !unique || joinedValue == "" {
					builder.out.markPartial(IssueUnknownOperandGrammar)
					targetValid = false
					continue
				}
				joinedArg := arg
				joinedArg.value = joinedValue
				name = &joinedArg
				continue
			}
			if !unique || !windowsPowerShellLiteralParameterValue(
				args,
				i+1,
			) {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				targetValid = false
				if i+1 < len(args) {
					i++
				}
				continue
			}
			i++
			name = &args[i]
		case unquoted && isValueParam:
			recordParam(valueParam)
			if valueParam == "-value" {
				// -Value and its -Target alias carry content or a link
				// relationship. Preserve the destination below, but do not
				// treat that unprojected semantic as authoritative.
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
			if joined {
				if joinedValue == "" {
					builder.out.markPartial(IssueUnknownOperandGrammar)
				} else if valueParam == "-itemtype" {
					itemType = joinedValue
				} else if !powerShellNewItemCommonValueAuthoritative(
					valueParam,
					joinedValue,
				) {
					builder.out.markPartial(IssueUnknownOperandGrammar)
				}
				continue
			}
			i++
			if i >= len(args) || args[i].value == "" ||
				args[i].expands ||
				strings.HasPrefix(args[i].value, "-") &&
					args[i].quote == QuoteNone {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			if valueParam == "-itemtype" {
				itemType = args[i].value
			} else if !powerShellNewItemCommonValueAuthoritative(
				valueParam,
				args[i].value,
			) {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
		case unquoted && isSwitchParam:
			recordParam(switchParam)
			if !switchValueValid {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
		case unquoted && strings.HasPrefix(lower, "-"):
			builder.out.markPartial(IssueUnknownOperandGrammar)
		default:
			positionals = append(positionals, arg)
		}
	}

	if parent == nil && len(positionals) > 0 {
		parent = &positionals[0]
		positionals = positionals[1:]
	}
	if len(positionals) > 0 {
		// The remaining positional binding depends on the selected provider
		// and parameter set. Preserve the proven target, but keep the command
		// off the authoritative path unless those operands are named.
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
	if !targetValid {
		return
	}
	parentValue := ""
	if parent != nil {
		parentValue = parent.value
	}
	nameValue := ""
	if name != nil {
		nameValue = name.value
	}
	target, flavor, ok := windowsPowerShellNewItemTarget(
		parentValue,
		nameValue,
	)
	if !ok {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !powerShellNewItemTypeAuthoritative(itemType, flavor) {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
	if flavor != PathFlavorPOSIX && flavor != PathFlavorUnknown {
		builder.addPath(commandID, PathAccessWrite, target)
		return
	}
	if target == "" {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if strings.ContainsAny(target, "*?") {
		builder.out.markPartial(IssueDynamicWord)
		return
	}
	builder.addCanonicalPath(
		commandID,
		PathAccessWrite,
		target,
		flavor,
	)
}

func windowsPowerShellNewItemTarget(
	parent string,
	name string,
) (string, PathFlavor, bool) {
	if parent == "" && name == "" {
		return "", PathFlavorUnknown, false
	}
	if name == "" {
		flavor, ok := windowsPowerShellNewItemPathFlavor(parent)
		return parent, flavor, ok
	}
	if parent == "" {
		flavor, ok := windowsPowerShellNewItemPathFlavor(name)
		return name, flavor, ok
	}

	parentFlavor, ok := windowsPowerShellNewItemPathFlavor(parent)
	if !ok || parentFlavor == PathFlavorUnknown ||
		strings.HasSuffix(parent, ":") {
		return "", PathFlavorUnknown, false
	}
	syntax := syntaxForPath(parent, parentFlavor, "")
	if parentFlavor == PathFlavorRegistry {
		syntax = pathSyntaxWindows
	}
	separator := byte(0)
	switch syntax {
	case pathSyntaxPOSIX:
		if strings.HasPrefix(name, "/") {
			return "", PathFlavorUnknown, false
		}
		separator = '/'
		parentFlavor = PathFlavorPOSIX
	case pathSyntaxWindows:
		if strings.HasPrefix(name, `\`) || strings.HasPrefix(name, "/") ||
			len(name) >= 2 && isASCIILetter(name[0]) &&
				name[1] == ':' ||
			strings.Contains(strings.ToLower(name), "::") {
			return "", PathFlavorUnknown, false
		}
		separator = '\\'
		if lastSlash := strings.LastIndex(parent, "/"); lastSlash >
			strings.LastIndex(parent, `\`) {
			separator = '/'
		}
	default:
		return "", PathFlavorUnknown, false
	}
	if strings.HasSuffix(parent, `\`) || strings.HasSuffix(parent, "/") {
		return parent + name, parentFlavor, true
	}
	return parent + string(separator) + name, parentFlavor, true
}

func windowsPowerShellNewItemPathFlavor(
	value string,
) (PathFlavor, bool) {
	if value == "" {
		return PathFlavorUnknown, false
	}
	if _, ok := canonicalRegistryPath(value); ok {
		return PathFlavorRegistry, true
	}
	if looksLikeRegistryPath(value) ||
		strings.Contains(strings.ToLower(value), "::") ||
		windowsNonFilesystemProviderPath(value) {
		return PathFlavorUnknown, false
	}
	flavor := pathFlavor(value)
	if flavor == PathFlavorUnknown &&
		!strings.ContainsAny(value, `/\`) &&
		!looksWindowsPath(value) {
		return PathFlavorUnknown, true
	}
	switch syntaxForPath(value, flavor, "") {
	case pathSyntaxPOSIX:
		return PathFlavorPOSIX, true
	case pathSyntaxWindows:
		return PathFlavorWindows, true
	default:
		if strings.Contains(value, ":") {
			return PathFlavorUnknown, false
		}
		return PathFlavorUnknown, true
	}
}

// windowsAddPowerShellPrimaryPath handles cmdlets whose first positional
// operand is the path and whose remaining positionals are values or arguments.
// This avoids turning Set-Content's value into a second write target.
func windowsAddPowerShellPrimaryPath(
	commandID int64,
	access PathAccess,
	args []windowsWord,
	allowTrailingValues bool,
	builder *windowsFactBuilder,
) {
	pathParams := map[string]bool{
		"-path": true, "-literalpath": true, "-filepath": true,
	}
	valueParams := map[string]bool{
		"-value": true, "-encoding": true, "-filter": true, "-include": true,
		"-exclude": true, "-erroraction": true, "-warningaction": true,
		"-name": true, "-type": true, "-itemtype": true, "-argumentlist": true,
		"-workingdirectory": true, "-verb": true, "-credential": true,
		"-width": true, "-wi": true,
	}
	switchParams := map[string]bool{
		"-force": true, "-recurse": true, "-raw": true, "-quiet": true,
		"-confirm": true, "-whatif": true, "-nonewwindow": true,
		"-wait": true, "-passthru": true, "-usenewenvironment": true,
	}
	var positionals []windowsWord
	found := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			continue
		}
		lower := strings.ToLower(arg.value)
		unquoted := arg.quote == QuoteNone
		if unquoted && pathParams[lower] {
			if i+1 >= len(args) || args[i+1].expands {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			i++
			builder.addPath(commandID, access, args[i].value)
			found = true
			continue
		}
		if unquoted && valueParams[lower] {
			i++
			if i >= len(args) {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
			continue
		}
		if unquoted && (switchParams[lower] ||
			strings.HasPrefix(lower, "-confirm:") ||
			strings.HasPrefix(lower, "-whatif:")) {
			continue
		}
		if unquoted && strings.HasPrefix(lower, "-") {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		positionals = append(positionals, arg)
	}
	if !found && len(positionals) > 0 {
		builder.addPath(commandID, access, positionals[0].value)
		found = true
	}
	if !allowTrailingValues && len(positionals) > 1 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
	if !found {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
}

func windowsAddCMDPaths(
	commandID int64,
	access PathAccess,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	found := false
	for _, arg := range args {
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			continue
		}
		if strings.HasPrefix(arg.value, "/") && !windowsCMDPathOperand(arg.value) {
			continue
		}
		builder.addPath(commandID, access, arg.value)
		found = true
	}
	if !found && access != PathAccessList {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
}

func windowsDriveRelativePath(value string) bool {
	return len(value) >= 3 && isASCIILetter(value[0]) && value[1] == ':' &&
		(value[2] == '/' || value[2] == '\\')
}

// windowsCMDPathOperand distinguishes forward-slash Windows paths from cmd's
// slash-prefixed switches. A second separator proves path structure; a lone
// segment such as /s remains an option because its ownership is ambiguous.
func windowsCMDPathOperand(value string) bool {
	if windowsDriveRelativePath(value) {
		return true
	}
	if strings.HasPrefix(value, "//") {
		return true
	}
	return strings.HasPrefix(value, "/") &&
		strings.ContainsAny(value[1:], `/\`)
}

func windowsAddSourceDestination(
	commandID int64,
	args []windowsWord,
	deleteSource bool,
	builder *windowsFactBuilder,
) {
	var operands []windowsWord
	for _, arg := range args {
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			continue
		}
		if strings.HasPrefix(arg.value, "-") ||
			strings.HasPrefix(arg.value, "/") && !windowsCMDPathOperand(arg.value) {
			continue
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	builder.addPath(commandID, PathAccessRead, operands[0].value)
	if deleteSource {
		builder.addPath(commandID, PathAccessDelete, operands[0].value)
	}
	builder.addPath(commandID, PathAccessWrite, operands[len(operands)-1].value)
	if len(operands) > 2 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
}

func windowsAddPowerShellSourceDestination(
	commandID int64,
	args []windowsWord,
	deleteSource bool,
	builder *windowsFactBuilder,
) {
	valueParams := map[string]bool{
		"-filter": true, "-include": true, "-exclude": true,
		"-credential": true, "-fromsession": true, "-tosession": true,
		"-erroraction": true, "-warningaction": true,
	}
	switchParams := map[string]bool{
		"-force": true, "-passthru": true, "-confirm": true, "-whatif": true,
	}
	var source *windowsWord
	var destination *windowsWord
	var positionals []windowsWord
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			continue
		}
		lower := strings.ToLower(arg.value)
		unquoted := arg.quote == QuoteNone
		switch {
		case unquoted && (lower == "-path" || lower == "-literalpath"):
			if source != nil || !windowsPowerShellLiteralParameterValue(args, i+1) {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				if i+1 < len(args) {
					i++
				}
				continue
			}
			i++
			source = &args[i]
		case unquoted && lower == "-destination":
			if destination != nil || !windowsPowerShellLiteralParameterValue(args, i+1) {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				if i+1 < len(args) {
					i++
				}
				continue
			}
			i++
			destination = &args[i]
		default:
			switch {
			case unquoted && valueParams[lower]:
				i++
				if i >= len(args) || args[i].expands ||
					strings.HasPrefix(args[i].value, "-") && args[i].quote == QuoteNone {
					builder.out.markPartial(IssueUnknownOperandGrammar)
				}
			case unquoted && (switchParams[lower] ||
				strings.HasPrefix(lower, "-confirm:") ||
				strings.HasPrefix(lower, "-whatif:")):
			case unquoted && strings.HasPrefix(lower, "-"):
				builder.out.markPartial(IssueUnknownOperandGrammar)
			default:
				positionals = append(positionals, arg)
			}
		}
	}

	if source == nil && len(positionals) > 0 {
		source = &positionals[0]
		positionals = positionals[1:]
	}
	if destination == nil && len(positionals) > 0 {
		destination = &positionals[len(positionals)-1]
		positionals = positionals[:len(positionals)-1]
	}
	if len(positionals) > 0 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
	if source == nil || destination == nil {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	builder.addPath(commandID, PathAccessRead, source.value)
	if deleteSource {
		builder.addPath(commandID, PathAccessDelete, source.value)
	}
	builder.addPath(commandID, PathAccessWrite, destination.value)
}

func windowsPowerShellLiteralParameterValue(args []windowsWord, index int) bool {
	if index < 0 || index >= len(args) || args[index].value == "" ||
		args[index].expands {
		return false
	}
	return !strings.HasPrefix(args[index].value, "-") ||
		args[index].quote != QuoteNone
}

func windowsStartProcessHasActionArguments(args []windowsWord) bool {
	filePathNamed := false
	var positionals []windowsWord
	for i := 0; i < len(args); i++ {
		arg := args[i]
		lower := strings.ToLower(arg.value)
		unquoted := arg.quote == QuoteNone
		name, joinedValue, joined := strings.Cut(lower, ":")
		if unquoted && len(name) >= 2 &&
			strings.HasPrefix("-argumentlist", name) {
			if joined {
				return joinedValue != ""
			}
			if i+1 >= len(args) {
				return true
			}
			i++
			if args[i].expands || args[i].value != "" {
				return true
			}
			continue
		}
		if unquoted && (lower == "-filepath" || lower == "-literalpath" ||
			lower == "-path") {
			filePathNamed = true
			i++
			continue
		}
		if unquoted && (lower == "-workingdirectory" || lower == "-verb" ||
			lower == "-credential" || lower == "-windowstyle") {
			i++
			continue
		}
		if unquoted && (lower == "-nonewwindow" || lower == "-wait" ||
			lower == "-passthru" || lower == "-usenewenvironment" ||
			lower == "-whatif" || lower == "-confirm" ||
			strings.HasPrefix(lower, "-whatif:") ||
			strings.HasPrefix(lower, "-confirm:")) {
			continue
		}
		if unquoted && strings.HasPrefix(lower, "-") {
			continue
		}
		positionals = append(positionals, arg)
	}

	start := 1
	if filePathNamed {
		start = 0
	}
	if start >= len(positionals) {
		return false
	}
	for _, positional := range positionals[start:] {
		if positional.expands || positional.value != "" {
			return true
		}
	}
	return false
}

func powerShellPreviewEffect(
	program string,
	args []windowsWord,
) (CommandEffect, bool) {
	effect := EffectExecute
	specified := false
	for _, arg := range args {
		if arg.quote != QuoteNone {
			continue
		}
		lower := strings.ToLower(arg.value)
		name, value, hasValue := strings.Cut(lower, ":")
		current := EffectExecute
		recognized := true
		switch name {
		case "-wh", "-wha", "-what", "-whati", "-whatif":
			if arg.expands {
				current = EffectUncertain
				break
			}
			switch {
			case !hasValue, value == "$true":
				current = EffectPreview
			case value == "$false":
				current = EffectExecute
			default:
				current = EffectUncertain
			}
		case "-wi":
			// Out-File owns -Width, so -Wi is not a safe abbreviation for
			// the common WhatIf parameter on that cmdlet.
			if program == "out-file" {
				recognized = false
				break
			}
			if arg.expands {
				current = EffectUncertain
				break
			}
			switch {
			case !hasValue, value == "$true":
				current = EffectPreview
			case value == "$false":
				current = EffectExecute
			default:
				current = EffectUncertain
			}
		default:
			recognized = false
		}
		if !recognized {
			continue
		}
		if specified {
			return EffectUncertain, true
		}
		effect = current
		specified = true
	}
	return effect, specified
}

func powerShellArgsWithoutPreviewControl(
	program string,
	args []windowsWord,
) []windowsWord {
	filtered := make([]windowsWord, 0, len(args))
	for _, arg := range args {
		if arg.quote == QuoteNone {
			name, _, _ := strings.Cut(strings.ToLower(arg.value), ":")
			switch name {
			case "-wh", "-wha", "-what", "-whati", "-whatif":
				continue
			case "-wi":
				if program != "out-file" {
					continue
				}
			}
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func powerShellSupportsPreview(program string) bool {
	switch program {
	case "set-content", "out-file", "add-content", "remove-item",
		"new-item",
		"set-item", "set-itemproperty", "sp", "new-itemproperty",
		"remove-itemproperty", "rp",
		"copy-item", "move-item", "rename-item",
		"start-process", "stop-process", "remove-process",
		"clear-disk", "add-localgroupmember", "add-adgroupmember",
		"register-scheduledtask":
		return true
	default:
		return false
	}
}

func powerShellPreviewAlias(program string) bool {
	switch program {
	case "ac", "copy", "cp", "cpi", "mi", "move", "mv", "ni", "rni",
		"del", "erase", "rd", "ri", "rm", "rmdir":
		return true
	default:
		return false
	}
}

func windowsInformationalInvocation(args []windowsWord, option string) bool {
	for _, arg := range args {
		if arg.expands || arg.quote != QuoteNone {
			continue
		}
		if strings.EqualFold(arg.value, option) {
			return true
		}
	}
	return false
}

func windowsMutatingProgram(program string) bool {
	switch program {
	case "set-content", "out-file", "add-content",
		"remove-item", "ri", "rm", "del", "erase", "rmdir", "rd",
		"new-item", "ni", "mkdir", "md",
		"set-item", "set-itemproperty", "sp", "new-itemproperty",
		"remove-itemproperty", "rp",
		"copy-item", "copy", "cp", "move-item", "move", "mv",
		"rename-item", "rni",
		"start-process", "stop-process", "remove-process",
		"clear-disk", "add-localgroupmember", "add-adgroupmember",
		"register-scheduledtask",
		"xcopy", "xcopy.exe", "robocopy", "robocopy.exe",
		"icacls", "icacls.exe", "takeown", "takeown.exe",
		"taskkill", "taskkill.exe":
		return true
	default:
		return false
	}
}

func windowsClassifyWeb(
	command *CommandFact,
	args []windowsWord,
	powerShell bool,
	builder *windowsFactBuilder,
) {
	if command.Executable == "curl.exe" ||
		!powerShell && command.Executable == "curl" {
		windowsClassifyCurl(command, args, builder)
		return
	}
	if command.Program == "wget" &&
		(!powerShell || command.Executable == "wget.exe") {
		// PowerShell's unqualified wget alias owns Invoke-WebRequest
		// parameters such as -InFile. A real wget executable has a different
		// option grammar; keep it on the non-authoritative fallback until that
		// grammar is parsed independently.
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !powerShell {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}

	action := NetworkDownload
	operation := OperationFetch
	hasPayload := false
	hasUploadFile := false
	var endpoints []windowsWord
	var uploadFiles []windowsWord
	var output *windowsWord
	seenParameters := make(map[string]struct{})
	duplicateParameter := false
	validGrammar := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			validGrammar = false
			continue
		}
		lower := strings.ToLower(arg.value)
		isParameter := arg.quote == QuoteNone
		if isParameter {
			if key, ok := powerShellWebParameterKey(lower); ok {
				if _, duplicate := seenParameters[key]; duplicate {
					duplicateParameter = true
					builder.out.markPartial(IssueUnknownOperandGrammar)
				} else {
					seenParameters[key] = struct{}{}
				}
			}
		}
		switch {
		case isParameter && lower == "-uri":
			if i+1 < len(args) {
				i++
				endpoints = append(endpoints, args[i])
				if args[i].value == "" || args[i].expands {
					builder.out.markPartial(IssueUnknownOperandGrammar)
					validGrammar = false
				}
			} else {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				validGrammar = false
			}
		case isParameter && lower == "-outfile":
			if i+1 < len(args) {
				i++
				output = &args[i]
				if output.value == "" || output.expands {
					builder.out.markPartial(IssueUnknownOperandGrammar)
					validGrammar = false
				}
			} else {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				validGrammar = false
			}
		case isParameter && (lower == "-infile" || lower == "-body"):
			if i+1 < len(args) {
				i++
				if args[i].expands {
					builder.out.markPartial(IssueDynamicWord)
					validGrammar = false
					continue
				}
				if args[i].value == "" {
					continue
				}
				hasPayload = true
				action = NetworkUpload
				operation = OperationUpload
				if lower == "-infile" {
					uploadFiles = append(uploadFiles, args[i])
					hasUploadFile = true
				}
			} else {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				validGrammar = false
			}
		case isParameter && lower == "-method":
			if i+1 < len(args) {
				i++
				if args[i].expands || !knownHTTPMethod(args[i].value) {
					builder.out.markPartial(IssueUnknownOperandGrammar)
					validGrammar = false
				}
			} else {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				validGrammar = false
			}
		case isParameter && (lower == "-usebasicparsing" ||
			lower == "-skipcertificatecheck"):
		default:
			if isParameter && strings.HasPrefix(lower, "-") {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				validGrammar = false
			} else if _, _, _, ok := windowsEndpoint(arg); ok {
				endpoints = append(endpoints, arg)
			} else {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				validGrammar = false
			}
		}
	}
	if !validGrammar || duplicateParameter || len(endpoints) != 1 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	hasOutputFile := false
	if output != nil {
		if output.expands {
			builder.out.markPartial(IssueDynamicWord)
		} else if output.value != "" {
			builder.addPath(command.ID, PathAccessWrite, output.value)
			hasOutputFile = true
		}
	}
	for _, uploadFile := range uploadFiles {
		builder.addPath(command.ID, PathAccessRead, uploadFile.value)
	}
	windowsAddOperation(command, operation)
	if len(endpoints) == 0 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	hasNetwork := false
	for _, endpoint := range endpoints {
		scheme, host, port, ok := windowsEndpoint(endpoint)
		if !ok {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		builder.addNetwork(command.ID, action, scheme, host, port)
		hasNetwork = true
	}
	if hasNetwork && hasPayload {
		if hasUploadFile {
			builder.addFlow(DataFlowFact{
				ToCommandID: command.ID,
				From:        DataFile,
				To:          DataProcess,
			})
		}
		builder.addFlow(DataFlowFact{
			FromCommandID: command.ID,
			From:          DataProcess,
			To:            DataNetwork,
		})
	}
	if hasNetwork && (operation == OperationFetch || hasOutputFile) {
		builder.addFlow(DataFlowFact{
			ToCommandID: command.ID,
			From:        DataNetwork,
			To:          DataProcess,
		})
	}
	if hasNetwork && hasOutputFile {
		builder.addFlow(DataFlowFact{
			FromCommandID: command.ID,
			From:          DataProcess,
			To:            DataFile,
		})
	}
}

func windowsClassifyCurl(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	action := NetworkDownload
	operation := OperationFetch
	var endpoints []windowsWord
	var proxy *windowsWord
	var outputs []windowsWord
	outputsValid := true
	var (
		hasUploadFile    bool
		hasUploadStdin   bool
		hasProcessUpload bool
		cookieOutput     *windowsWord
	)
	markUpload := func() {
		action = NetworkUpload
		operation = OperationUpload
	}

	nextValue := func(index *int) (windowsWord, bool) {
		if *index+1 >= len(args) {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return windowsWord{}, false
		}
		(*index)++
		value := args[*index]
		if value.expands {
			builder.out.markPartial(IssueDynamicWord)
			return windowsWord{}, false
		}
		return value, true
	}
	nextBenignValue := func(index *int) (windowsWord, bool) {
		value, ok := nextValue(index)
		if !ok {
			return windowsWord{}, false
		}
		if value.quote == QuoteNone && strings.HasPrefix(value.value, "-") {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return windowsWord{}, false
		}
		return value, true
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			continue
		}
		switch arg.value {
		case "-o", "--output":
			if value, ok := nextValue(&i); ok {
				if value.value == "" {
					builder.out.markPartial(IssueUnknownOperandGrammar)
					outputsValid = false
				} else {
					outputs = append(outputs, value)
				}
			} else {
				outputsValid = false
			}
		case "-A", "--user-agent", "-b", "--cookie":
			// These values are request metadata, not upload bodies or paths.
			_, _ = nextBenignValue(&i)
		case "-c", "--cookie-jar":
			cookieOutput = nil
			if i+1 < len(args) && args[i+1].value == "-" {
				i++
				cookieOutput = &args[i]
			} else if _, ok := nextBenignValue(&i); ok {
				// curl applies only the final cookie-jar destination.
				if args[i].value == "" {
					builder.out.markPartial(IssueUnknownOperandGrammar)
				} else {
					cookieOutput = &args[i]
				}
			}
		case "-O", "--remote-name":
			// The destination is derived from response metadata or the URL,
			// so it is not a statically proven path.
			builder.out.markPartial(IssueUnknownOperandGrammar)
		case "-T", "--upload-file":
			if value, ok := nextValue(&i); ok {
				if value.value == "-" {
					markUpload()
					hasUploadStdin = true
					continue
				}
				if value.value != "" {
					markUpload()
					builder.addPath(command.ID, PathAccessRead, value.value)
					hasUploadFile = true
				}
			}
		case "-d", "--data", "--data-binary", "--data-urlencode":
			if value, ok := nextValue(&i); ok {
				if file, stdin, isFile := webDataFile(value.value); isFile {
					markUpload()
					if stdin {
						hasUploadStdin = true
					} else {
						builder.addPath(command.ID, PathAccessRead, file)
						hasUploadFile = true
					}
				} else if value.value != "" {
					markUpload()
					hasProcessUpload = true
				}
			}
		case "--data-raw":
			if value, ok := nextValue(&i); ok && value.value != "" {
				markUpload()
				hasProcessUpload = true
			}
		case "-F", "--form":
			if value, ok := nextValue(&i); ok {
				if file, stdin, isFile := webFormFile(value.value); isFile {
					markUpload()
					if stdin {
						hasUploadStdin = true
					} else {
						builder.addPath(command.ID, PathAccessRead, file)
						hasUploadFile = true
					}
				} else if value.value != "" {
					markUpload()
					hasProcessUpload = true
				}
			}
		case "--form-string":
			if value, ok := nextValue(&i); ok && value.value != "" {
				markUpload()
				hasProcessUpload = true
			}
		case "-X", "--request":
			if value, ok := nextValue(&i); ok {
				if !knownHTTPMethod(value.value) {
					builder.out.markPartial(IssueUnknownOperandGrammar)
				}
			}
		case "-x", "--proxy":
			if _, ok := nextValue(&i); ok {
				// curl applies the final proxy value. Retaining overridden
				// peers would create authoritative facts for connections that
				// do not occur.
				proxy = &args[i]
			}
		case "-f", "--fail", "--fail-with-body", "-L", "--location",
			"-s", "--silent", "-S", "--show-error", "-k", "--insecure",
			"--compressed", "-I", "--head":
		default:
			if strings.HasPrefix(arg.value, "-") {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			} else if _, _, _, ok := windowsEndpoint(arg); ok {
				endpoints = append(endpoints, arg)
			} else {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
		}
	}

	hasOutputFile := false
	if outputsValid {
		for index, output := range outputs {
			if index >= len(endpoints) {
				break
			}
			if output.value == "" || output.value == "-" {
				continue
			}
			builder.addPath(command.ID, PathAccessWrite, output.value)
			hasOutputFile = true
		}
	}
	hasCookieOutput := cookieOutput != nil &&
		cookieOutput.value != "" &&
		cookieOutput.value != "-"
	if hasCookieOutput {
		builder.addPath(command.ID, PathAccessWrite, cookieOutput.value)
	}
	windowsAddOperation(command, operation)
	if proxy != nil {
		scheme, host, port, ok := windowsEndpoint(*proxy)
		if !ok {
			builder.out.markPartial(IssueUnknownOperandGrammar)
		} else {
			builder.addNetwork(command.ID, NetworkConnect, scheme, host, port)
		}
	}
	if len(endpoints) == 0 {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	hasNetwork := false
	for _, endpoint := range endpoints {
		scheme, host, port, ok := windowsEndpoint(endpoint)
		if !ok {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		builder.addNetwork(command.ID, action, scheme, host, port)
		hasNetwork = true
	}
	if hasNetwork && operation == OperationUpload {
		if hasUploadFile {
			builder.addFlow(DataFlowFact{
				ToCommandID: command.ID,
				From:        DataFile,
				To:          DataProcess,
			})
		}
		if hasUploadStdin {
			builder.addFlow(DataFlowFact{
				FromCommandID: command.ID,
				From:          DataStdin,
				To:            DataNetwork,
			})
		}
		if hasUploadFile || hasProcessUpload {
			builder.addFlow(DataFlowFact{
				FromCommandID: command.ID,
				From:          DataProcess,
				To:            DataNetwork,
			})
		}
	}
	hasResponseFile := hasOutputFile || hasCookieOutput
	if hasNetwork && (operation == OperationFetch || hasResponseFile) {
		builder.addFlow(DataFlowFact{
			ToCommandID: command.ID,
			From:        DataNetwork,
			To:          DataProcess,
		})
	}
	if hasNetwork && hasResponseFile {
		builder.addFlow(DataFlowFact{
			FromCommandID: command.ID,
			From:          DataProcess,
			To:            DataFile,
		})
	}
}

func windowsClassifyCertutil(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	mode := ""
	hasSplit := false
	uncertain := false
	var operands []windowsWord
	for _, arg := range args {
		if arg.expands {
			builder.out.markPartial(IssueDynamicWord)
			uncertain = true
			continue
		}
		switch strings.ToLower(arg.value) {
		case "-urlcache":
			if mode != "" {
				uncertain = true
				builder.out.markPartial(IssueUnknownOperandGrammar)
			} else {
				mode = "urlcache"
			}
		case "-decode":
			if mode != "" {
				uncertain = true
				builder.out.markPartial(IssueUnknownOperandGrammar)
			} else {
				mode = "decode"
			}
		case "-decodehex":
			if mode != "" {
				uncertain = true
				builder.out.markPartial(IssueUnknownOperandGrammar)
			} else {
				mode = "decodehex"
			}
		case "-split":
			hasSplit = true
		case "-f":
		default:
			if strings.HasPrefix(arg.value, "-") {
				uncertain = true
				builder.out.markPartial(IssueUnknownOperandGrammar)
			} else {
				operands = append(operands, arg)
			}
		}
	}
	if uncertain || mode == "" {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}

	switch mode {
	case "urlcache":
		if len(operands) != 2 {
			// In particular, never reinterpret a third positional argument as
			// the output path of an otherwise invalid invocation.
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		scheme, host, port, ok := windowsEndpoint(operands[0])
		if !ok {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		windowsAddOperation(command, OperationFetch)
		builder.addNetwork(command.ID, NetworkDownload, scheme, host, port)
		builder.addPath(command.ID, PathAccessWrite, operands[1].value)

	case "decode", "decodehex":
		if hasSplit || mode == "decode" && len(operands) != 2 ||
			mode == "decodehex" && (len(operands) < 2 || len(operands) > 3) {
			builder.out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		if mode == "decodehex" && len(operands) == 3 {
			if !allDecimalDigits(operands[2].value) {
				builder.out.markPartial(IssueUnknownOperandGrammar)
				return
			}
		}
		windowsAddOperation(command, OperationDecode)
		builder.addPath(command.ID, PathAccessRead, operands[0].value)
		builder.addPath(command.ID, PathAccessWrite, operands[1].value)
		builder.addFlow(DataFlowFact{
			ToCommandID: command.ID,
			From:        DataFile,
			To:          DataProcess,
		})
		builder.addFlow(DataFlowFact{
			FromCommandID: command.ID,
			From:          DataProcess,
			To:            DataFile,
		})
	}
}

func windowsClassifyRegistry(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if len(args) < 2 || args[0].expands || args[1].expands {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	verb := strings.ToLower(args[0].value)
	access := PathAccessMetadata
	switch verb {
	case "add":
		access = PathAccessWrite
		windowsAddOperation(command, OperationConfigChange)
	case "delete":
		access = PathAccessDelete
		windowsAddOperation(command, OperationConfigChange)
	case "query":
		windowsAddOperation(command, OperationRead)
	default:
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	builder.addPath(command.ID, access, args[1].value)

	valueSwitches := map[string]bool{"/v": true, "/t": true, "/d": true, "/se": true}
	flagSwitches := map[string]bool{
		"/ve": true, "/va": true, "/f": true, "/reg:32": true, "/reg:64": true, "/z": true,
	}
	if verb == "add" {
		valueSwitches["/s"] = true
	} else if verb == "query" {
		flagSwitches["/s"] = true
	}
	seen := make(map[string]struct{})
	for i := 2; i < len(args); i++ {
		if args[i].expands {
			builder.out.markPartial(IssueDynamicWord)
			continue
		}
		lower := strings.ToLower(args[i].value)
		if valueSwitches[lower] {
			if _, duplicate := seen[lower]; duplicate {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
			seen[lower] = struct{}{}
			i++
			if i >= len(args) || args[i].expands {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
			continue
		}
		if flagSwitches[lower] {
			if _, duplicate := seen[lower]; duplicate {
				builder.out.markPartial(IssueUnknownOperandGrammar)
			}
			seen[lower] = struct{}{}
			continue
		}
		builder.out.markPartial(IssueUnknownOperandGrammar)
	}
	if _, named := seen["/v"]; named {
		if _, defaultValue := seen["/ve"]; defaultValue {
			builder.out.markPartial(IssueUnknownOperandGrammar)
		}
	}
}

func windowsEndpoint(word windowsWord) (string, string, int64, bool) {
	if word.expands {
		return "", "", 0, false
	}
	parsed, err := url.Parse(word.value)
	if err != nil || parsed.Hostname() == "" {
		return "", "", 0, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https", "ftp", "ftps":
	default:
		return "", "", 0, false
	}
	port := int64(0)
	if rawPort := parsed.Port(); rawPort != "" {
		value, err := strconv.ParseInt(rawPort, 10, 64)
		if err != nil || value < 1 || value > 65535 {
			return "", "", 0, false
		}
		port = value
	}
	host, ok := canonicalNetworkHost(parsed.Hostname())
	if !ok {
		return "", "", 0, false
	}
	return scheme, host, port, true
}
