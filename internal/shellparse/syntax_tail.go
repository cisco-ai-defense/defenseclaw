// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"mvdan.cc/sh/v3/syntax"
)

// The bounds of ReadSyntaxTail. Past one the reading stops and says so
// (SyntaxTail.Truncated): the statements read before it are kept and judged,
// and the caller judges the call at least at the unknown tier of the pack
// (the bound rule, internal/guardrail/bounded).
const (
	// MaxSyntaxTailStatements bounds the readable statements of one text
	// (the statement budget of one call).
	MaxSyntaxTailStatements = 128
	// maxSyntaxTailPieces bounds the pieces the token split makes of the
	// text after the error.
	maxSyntaxTailPieces = 512
	// maxSyntaxTailRun bounds the pieces one statement may span.
	maxSyntaxTailRun = 8
)

// SyntaxTail is the reading of a text the shell parser rejects with a syntax
// error (ReadSyntaxTail).
type SyntaxTail struct {
	// Statements are the readable parts of the text, in order: first the
	// longest prefix that parses (the statements complete before the error),
	// then each run of the text after it that parses on its own.
	Statements []string
	// Truncated holds the caps the reading stopped at: bounded.Items for the
	// statements or pieces, bounded.Bytes for the parse budget.
	Truncated bounded.CapSet
}

// ReadSyntaxTail reads a command the Bash and POSIX grammars both reject
// with a syntax error (rel-1-0-10:GAP-0526). The shell runs the statements
// before the error (a script or a -c body is read and run statement by
// statement), and another shell, or a retry with the tail fixed, runs the
// rest. A command judged only when it parses as a whole would lose every rule
// of its statements to one bad token after them. The reading is:
//
//   - the longest parsable prefix: the statements the parser finished
//     before the error (syntax.Parser.StmtsSeq) and, when the error is
//     inside the next statement, that statement up to the error, cut back
//     to the last word boundary where the text parses (a stray ")" or an
//     unclosed quote after the last word of a command). It is kept as one
//     text, so its shell state (cd, variables) holds for its later
//     statements;
//   - the text after it, split at newlines and at the list and pipe
//     operators outside quotes (the token fallback): each shortest run of
//     pieces that parses on its own.
//
// What is left unread is the caller's to record; a reading cut at a cap is
// at least the unknown tier of the pack. ok is false for a command that
// parses, one past the reading budget (TooDeep), text that is not valid
// UTF-8, and one the parser faults on (ErrParserFault): those keep their own
// paths.
func ReadSyntaxTail(command string) (tail SyntaxTail, ok bool) {
	if strings.TrimSpace(command) == "" || !utf8.ValidString(command) || TooDeep(command) {
		return SyntaxTail{}, false
	}
	if cached, hit := syntaxTailMemo.get(command); hit {
		return cached.tail, cached.ok
	}
	tail, ok = readSyntaxTail(command)
	syntaxTailMemo.put(command, tail, ok)
	return tail, ok
}

// syntaxTailMemo keeps the last readings: one hook call asks for the same
// text from several readers (the per-command split, the target scans at each
// nesting depth, the gateway's unread-part check), and each reading parses
// the text up to MaxSyntaxTailRun times per piece.
var syntaxTailMemo = &syntaxTailCache{entries: map[string]syntaxTailEntry{}}

const syntaxTailCacheEntries = 32

type syntaxTailEntry struct {
	tail SyntaxTail
	ok   bool
}

type syntaxTailCache struct {
	mu      sync.Mutex
	entries map[string]syntaxTailEntry
}

func (c *syntaxTailCache) get(command string) (syntaxTailEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, hit := c.entries[command]
	if hit {
		entry.tail.Statements = slices.Clone(entry.tail.Statements)
	}
	return entry, hit
}

func (c *syntaxTailCache) put(command string, tail SyntaxTail, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= syntaxTailCacheEntries {
		clear(c.entries)
	}
	tail.Statements = slices.Clone(tail.Statements)
	c.entries[command] = syntaxTailEntry{tail: tail, ok: ok}
}

func readSyntaxTail(command string) (tail SyntaxTail, ok bool) {
	if _, parsed := Parse(command); parsed {
		return SyntaxTail{}, false
	}
	end, errorAt, faulted := completeStatementsEnd(command)
	if faulted {
		return SyntaxTail{}, false
	}
	var trunc bounded.Truncated
	budget := bounded.NewCounter(&trunc, bounded.Bytes, 4*len(command)+(64<<10))
	statements := bounded.NewCounter(&trunc, bounded.Items, MaxSyntaxTailStatements)
	add := func(statement string) {
		if statements.Take() {
			tail.Statements = append(tail.Statements, statement)
		}
	}
	// The error is inside the statement after the complete ones: the text
	// up to it, cut back word by word, is the longest prefix that parses.
	for at, tries := errorAt, 0; at > end && tries < maxSyntaxTailRun*2; tries++ {
		if prefix := trimSeparators(command[:at]); prefix != "" && parsesAlone(prefix, &budget) {
			end = at
			break
		}
		at = previousWordBoundary(command, end, at)
	}
	if prefix := trimSeparators(command[:end]); prefix != "" && parsesAlone(prefix, &budget) {
		add(prefix)
	}
	rest := command[end:]
	pieces, split := tokenPieces(rest)
	if !split {
		trunc.Hit(bounded.Items)
	}
	for start := 0; start < len(pieces) && !trunc.Set().Any(); {
		next := start + 1
		for stop := start; stop < len(pieces) && stop < start+maxSyntaxTailRun; stop++ {
			run := trimSeparators(rest[pieces[start].from:pieces[stop].to])
			if run == "" {
				break
			}
			if parsesAlone(run, &budget) {
				add(run)
				next = stop + 1
				break
			}
		}
		start = next
	}
	tail.Truncated = trunc.Set(&budget, &statements)
	return tail, true
}

// completeStatementsEnd is the end of the last top-level statement the Bash
// parser completed before its error, and the offset of the error (len for an
// error without a position); faulted reports a parser fault.
func completeStatementsEnd(command string) (end, errorAt int, faulted bool) {
	_, err := containParse(nil, func() (*syntax.File, error) {
		for stmt, err := range syntax.NewParser(syntax.Variant(syntax.LangBash)).StmtsSeq(Reader(command)) {
			if err != nil {
				return nil, err
			}
			if offset := int(stmt.End().Offset()); offset > end && offset <= len(command) {
				end = offset
			}
		}
		return nil, nil
	})
	errorAt = len(command)
	var parseErr syntax.ParseError
	var langErr syntax.LangError
	switch {
	case errors.As(err, &parseErr) && parseErr.Pos.IsValid():
		errorAt = int(parseErr.Pos.Offset())
	case errors.As(err, &langErr) && langErr.Pos.IsValid():
		errorAt = int(langErr.Pos.Offset())
	}
	return end, min(max(errorAt, end), len(command)), errors.Is(err, ErrParserFault)
}

// previousWordBoundary is the last offset after floor and before at where
// a word of command ends (a blank, a newline or a list or pipe operator
// follows it), or floor.
func previousWordBoundary(command string, floor, at int) int {
	for i := at - 1; i > floor; i-- {
		if strings.IndexByte(" \t\n;&|", command[i]) >= 0 {
			for i > floor && strings.IndexByte(" \t\n;&|", command[i-1]) >= 0 {
				i--
			}
			return i
		}
	}
	return floor
}

// parsesAlone parses statement with the Bash grammar, outside the parse
// cache (the runs are throwaway text), within budget.
func parsesAlone(statement string, budget *bounded.Counter) bool {
	if !budget.TakeN(len(statement)) || TooDeep(statement) {
		return false
	}
	// The Bash grammar only: what it rejects the POSIX grammar rejects too,
	// but for the aggregate redirects actionfacts normalizes itself.
	_, err := containParse(nil, func() (*syntax.File, error) {
		return syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(Reader(statement), "")
	})
	return err == nil
}

// tokenPiece is a byte range of the text after the error, ending after the
// separator that closes it.
type tokenPiece struct{ from, to int }

// tokenPieces splits text at newlines and at the ; & | operators outside
// single quotes, double quotes and backslash escapes. ok is false past
// maxSyntaxTailPieces (the pieces before the cap are returned).
func tokenPieces(text string) (pieces []tokenPiece, ok bool) {
	from := 0
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
			continue
		case c == '\\':
			i++
			continue
		case quote == '"':
			if c == '"' {
				quote = 0
			}
			continue
		case c == '\'' || c == '"':
			quote = c
			continue
		case c != '\n' && c != ';' && c != '&' && c != '|':
			continue
		}
		for i+1 < len(text) && strings.IndexByte("\n;&|", text[i+1]) >= 0 {
			i++
		}
		pieces = append(pieces, tokenPiece{from, i + 1})
		from = i + 1
		if len(pieces) >= maxSyntaxTailPieces {
			return pieces, from >= len(text)
		}
	}
	if from < len(text) {
		pieces = append(pieces, tokenPiece{from, len(text)})
	}
	return pieces, true
}

// trimSeparators drops the space, operators and newlines around a run.
func trimSeparators(run string) string {
	return strings.TrimSpace(strings.TrimRight(strings.TrimSpace(run), "\n;&|"))
}
