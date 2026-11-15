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
	// then each run of the text after it that parses on its own, outside the
	// bodies of HereDocs.
	Statements []string
	// HereDocs are the quoted here-documents opened in the statement with
	// the error or after it whose bodies hold readable runs of the text after
	// the error. Those runs are input of the here-document's command, not
	// statements of the text: they are read here and left out of Statements,
	// and the caller judges them as statements only when that command runs
	// its standard input as shell code (rel-1-0-10:GAP-0876).
	HereDocs []SyntaxTailHereDoc
	// Truncated holds the caps the reading stopped at: bounded.Items for the
	// statements or pieces, bounded.Bytes for the parse budget.
	Truncated bounded.CapSet
}

// SyntaxTailHereDoc is a quoted here-document of a text with a syntax error
// (SyntaxTail.HereDocs).
type SyntaxTailHereDoc struct {
	// Consumer is the command the body is the input of, as written on the
	// line of the opener: the text from the start of that command to the <<
	// and the rest of the line after the delimiter word (a pipe into another
	// program stays in it). It is empty when the start was not found.
	Consumer string
	// Script is the text that runs before Consumer in the same script, as
	// the shell that runs it reads it: for an opener inside a quoted
	// argument (a script passed as one argument), the value of that
	// argument up to the command; for an opener outside quotes, empty.
	// ScriptKnown is false when the value cannot be read (an expansion in
	// it, a quote the split cannot follow): the caller cannot tell what the
	// script binds before the consumer (rel-1-0-10:GAP-0913).
	Script      string
	ScriptKnown bool
	// Statements are the runs of the body that parse on their own, in order.
	Statements []string
}

func (tail SyntaxTail) clone() SyntaxTail {
	tail.Statements = slices.Clone(tail.Statements)
	tail.HereDocs = slices.Clone(tail.HereDocs)
	for index := range tail.HereDocs {
		tail.HereDocs[index].Statements = slices.Clone(tail.HereDocs[index].Statements)
	}
	return tail
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
// A quoted here-document opened in the statement with the error, or after it,
// whose body runs into the text after the error (the opener is often inside a
// quoted argument of a program, so the shell's quotes no longer match the
// author's): the runs of its body are its command's input, not statements of
// the text, and are kept apart in SyntaxTail.HereDocs with that command
// (rel-1-0-10:GAP-0876).
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
		entry.tail = entry.tail.clone()
	}
	return entry, hit
}

func (c *syntaxTailCache) put(command string, tail SyntaxTail, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= syntaxTailCacheEntries {
		clear(c.entries)
	}
	c.entries[command] = syntaxTailEntry{tail: tail.clone(), ok: ok}
}

func readSyntaxTail(command string) (tail SyntaxTail, ok bool) {
	if _, parsed := Parse(command); parsed {
		return SyntaxTail{}, false
	}
	end, errorAt, faulted := completeStatementsEnd(command)
	if faulted {
		return SyntaxTail{}, false
	}
	// The here-documents are found from the statement with the error on: a
	// statement the parser completed before it closed its own quotes and
	// here-documents.
	var trunc bounded.Truncated
	budget := bounded.NewCounter(&trunc, bounded.Bytes, 4*len(command)+(64<<10))
	statements := bounded.NewCounter(&trunc, bounded.Items, MaxSyntaxTailStatements)
	// The work on the here-document openers has a budget of its own, of the
	// same size, so a text of many openers is TRUNCATED without starving the
	// reading of its statements (rel-1-0-10:GAP-0928, GAP-0930).
	var openerTrunc bounded.Truncated
	openers := bounded.NewCounter(&openerTrunc, bounded.Bytes, 4*len(command)+(64<<10))
	docs := quotedHereDocs(command, end, &openers)
	docRuns := make([][]string, len(docs))
	add := func(statement string, doc int) {
		if !statements.Take() {
			return
		}
		if doc < 0 {
			tail.Statements = append(tail.Statements, statement)
		} else {
			docRuns[doc] = append(docRuns[doc], statement)
		}
	}
	// The error is inside the statement after the complete ones: the text
	// up to it, cut back word by word, is the longest prefix that parses.
	// Past the tries the cut stops; the part not read stays the call's
	// detection-only ACTION-PARSE-FAILURE record (lead ruling (a) on
	// rel-1-0-10:GAP-0745: a TRUNCATED report here added 82 strict owner-trace
	// blocks, over the 0.1% bar).
	for at, tries := errorAt, 0; at > end && tries < maxSyntaxTailRun*2; tries++ {
		if prefix := trimSeparators(command[:at]); prefix != "" && parsesAlone(prefix, &budget) {
			end = at
			break
		}
		at = previousWordBoundary(command, end, at)
	}
	if prefix := trimSeparators(command[:end]); prefix != "" && parsesAlone(prefix, &budget) {
		add(prefix, -1)
	}
	rest := command[end:]
	pieces, split := tokenPieces(rest)
	if !split {
		trunc.Hit(bounded.Items)
	}
	// A statement longer than maxSyntaxTailRun pieces is not read; like the
	// cut-back tries above, that is the detection-only record, not a cap
	// (lead ruling (a) on GAP-0745).
	// A run stays within one here-document body, or outside every one.
	docOf := func(piece tokenPiece) int { return hereDocAt(docs, end+piece.from) }
	for start := 0; start < len(pieces) && !trunc.Set().Any(); {
		next := start + 1
		doc := docOf(pieces[start])
		for stop := start; stop < len(pieces) && stop < start+maxSyntaxTailRun && docOf(pieces[stop]) == doc; stop++ {
			run := trimSeparators(rest[pieces[start].from:pieces[stop].to])
			if run == "" {
				break
			}
			if parsesAlone(run, &budget) {
				add(run, doc)
				next = stop + 1
				break
			}
		}
		start = next
	}
	for index, runs := range docRuns {
		if len(runs) > 0 {
			doc := SyntaxTailHereDoc{Consumer: docs[index].consumer,
				Script: docs[index].script, ScriptKnown: docs[index].scriptKnown, Statements: runs}
			// The consumer reading parses the script of each of these
			// documents again: that work is counted, so the sum of the
			// scripts handed on stays within the opener budget (GAP-0928).
			if !openers.TakeN(len(doc.Script)) {
				doc.Script, doc.ScriptKnown = "", false
			}
			tail.HereDocs = append(tail.HereDocs, doc)
		}
	}
	tail.Truncated = trunc.Set(&budget, &statements).Union(openerTrunc.Set(&openers))
	return tail, true
}

// quotedHereDoc is the body of a quoted here-document found by
// quotedHereDocs: the byte range [from, to) of its lines, and its command.
type quotedHereDoc struct {
	from, to int
	consumer string
	// script and scriptKnown are SyntaxTailHereDoc.Script and ScriptKnown
	// (readHereDocScripts).
	script      string
	scriptKnown bool
}

// quotedHereDocs finds the here-documents with a quoted delimiter word
// (<<'EOF', <<"EOF", <<\EOF, and the same written inside a quoted argument,
// <<'"'"'EOF'"'"') opened at or after offset from, whose body is closed by a
// line holding the word (a quote that closes the argument may follow it). A
// quoted delimiter keeps the body free of expansions, so its lines are input
// of the command and nothing else. A body that is not closed is not one: its
// lines stay text of the call.
//
// The quotes are followed with the split's own reading (tokenScan, from
// offset from, where the complete statements end outside quotes). An opener
// outside quotes is one. An opener inside quotes is one only in the shape of
// a script passed as one quoted argument: the argument is still open at the
// end of the opener line, so the lines after it are the argument's text, its
// body. An opener spelled in a string that closes on its own line (echo
// "a <<'X'") is text, and the lines after it stay statements
// (rel-1-0-10:GAP-0890).
// unreadQuote marks an offset tokenScan did not read (quotedHereDocs).
const unreadQuote byte = 0xff

func quotedHereDocs(command string, from int, budget *bounded.Counter) []quotedHereDoc {
	const unread = unreadQuote
	quotes := make([]byte, len(command)-from)
	for index := range quotes {
		quotes[index] = unread
	}
	tokenScan(command[from:], func(at int, quote byte) { quotes[at] = quote })
	quoteAt := func(at int) byte { return quotes[at-from] }
	var docs []quotedHereDoc
	var starts []int
	for at := from; at+2 < len(command); at++ {
		index := strings.Index(command[at:], "<<")
		if index < 0 {
			break
		}
		at += index
		if at > 0 && command[at-1] == '<' || strings.HasPrefix(command[at:], "<<<") {
			at += 2
			continue
		}
		word, dash, quoted, afterWord := quotedHereDocWord(command, at+2)
		lineEnd := strings.IndexByte(command[at:], '\n')
		if word == "" || !quoted || lineEnd < 0 || afterWord > at+lineEnd {
			at++
			continue
		}
		lineEnd += at
		if opener, end := quoteAt(at), quoteAt(lineEnd); opener == unread ||
			opener != 0 && (end == 0 || end == unread) {
			at++
			continue
		}
		bodyFrom := lineEnd + 1
		bodyTo, closed := quotedHereDocClose(command, bodyFrom, word, dash)
		// The search for the closing line reads the text after the opener
		// (to the end of the text when none closes): the bytes it read are
		// counted, so a text of many openers that one late line closes, or
		// that nothing closes, stops at the budget and is TRUNCATED
		// (rel-1-0-10:GAP-0928, GAP-0930).
		read := len(command) - bodyFrom
		if closed {
			read = bodyTo - bodyFrom
		}
		if !budget.TakeN(read) {
			break
		}
		if !closed {
			at++
			continue
		}
		start := hereDocConsumerStart(command, at)
		docs = append(docs, quotedHereDoc{from: bodyFrom, to: bodyTo,
			consumer: hereDocConsumer(command, at, afterWord, lineEnd)})
		starts = append(starts, start)
		at++
	}
	readHereDocScripts(command, from, quoteAt, docs, starts, budget)
	return docs
}

// quotedHereDocWord reads the delimiter after a << at offset at: an optional
// -, blanks, the quote and backslash characters before the word (quoted is
// set when there is one), then the word. afterWord is the offset after it and
// the quote characters that follow it.
func quotedHereDocWord(command string, at int) (word string, dash, quoted bool, afterWord int) {
	if at < len(command) && command[at] == '-' {
		dash = true
		at++
	}
	for at < len(command) && (command[at] == ' ' || command[at] == '\t') {
		at++
	}
	for at < len(command) && strings.IndexByte(`'"\`, command[at]) >= 0 {
		quoted = true
		at++
	}
	start := at
	for at < len(command) && strings.IndexByte(" \t\n;&|<>()'\"\\`", command[at]) < 0 {
		at++
	}
	word = command[start:at]
	for at < len(command) && strings.IndexByte(`'"\`, command[at]) >= 0 {
		at++
	}
	return word, dash, quoted, at
}

// quotedHereDocClose is the offset of the line that closes a body starting at
// from: the word alone, after tabs for <<-, or followed by a quote character
// (the end of the argument that holds the script).
func quotedHereDocClose(command string, from int, word string, dash bool) (int, bool) {
	for at := from; at < len(command); {
		end := strings.IndexByte(command[at:], '\n')
		line := command[at:]
		if end >= 0 {
			line = command[at : at+end]
		}
		if dash {
			line = strings.TrimLeft(line, "\t")
		}
		if rest, found := strings.CutPrefix(line, word); found && (rest == "" || rest[0] == '\'' || rest[0] == '"') {
			return at, true
		}
		if end < 0 {
			break
		}
		at += end + 1
	}
	return 0, false
}

// hereDocConsumer is the command of a here-document opened at offset at:
// the text from the start of its command (after the last newline, list or
// pipe operator, group character or quote before the opener) to the <<, and
// the rest of the opener line after the delimiter word (afterWord to
// lineEnd). It is empty when no command text is found before the opener.
func hereDocConsumer(command string, at, afterWord, lineEnd int) string {
	start := hereDocConsumerStart(command, at)
	before := strings.TrimSpace(command[start:at])
	if before == "" {
		return ""
	}
	return strings.TrimSpace(before + " " + strings.TrimSpace(command[afterWord:lineEnd]))
}

// hereDocConsumerStart is the offset where the command of a here-document
// opened at offset at starts (hereDocConsumer).
func hereDocConsumerStart(command string, at int) int {
	start := at
	for start > 0 && strings.IndexByte("\n;&|(){}`'\"", command[start-1]) < 0 {
		start--
	}
	return start
}

// hereDocScriptStart finds, for the consumer starts of the openers in
// ascending order, the offset where the argument that holds each one begins
// (hereDocScripts). It scans the text once, forward: the argument starts
// after the last blank or operator outside quotes before the consumer, and
// is not readable (ok false) when the split did not read a byte between that
// blank and the consumer.
type hereDocScriptStart struct {
	command string
	from    int
	quoteAt func(int) byte
	// next is the first offset not scanned yet; stop is the last offset at
	// or after from that ends the argument (a blank or operator outside
	// quotes, or a byte the split did not read), or -1; stopUnread says
	// which.
	next, stop int
	stopUnread bool
}

func (s *hereDocScriptStart) wordStart(start int) (word int, ok bool) {
	for ; s.next < start; s.next++ {
		state := s.quoteAt(s.next)
		switch {
		case state == unreadQuote:
			s.stop, s.stopUnread = s.next, true
		case state == 0 && strings.IndexByte(" \t\n;&|()<>", s.command[s.next]) >= 0:
			s.stop, s.stopUnread = s.next, false
		}
	}
	if s.stop < 0 {
		return s.from, true
	}
	return s.stop + 1, !s.stopUnread
}

// readHereDocScripts sets the script and scriptKnown of each of docs, whose
// consumers start at starts (SyntaxTailHereDoc.Script). quoteAt is the quote
// the split is in at an offset at or after from (unreadQuote where it did
// not read). The argument that holds the script starts after the last blank
// or operator outside quotes; its raw text up to the consumer, closed with
// the quote it is in, is parsed as one word and unquoted. An opener outside
// quotes has no script of its own.
//
// The openers of one argument share one parse: the argument is parsed once
// up to its last opener, and the script of each opener is the head of that
// value up to its consumer (a substring, not a copy). The parse is counted
// against budget; past the budget the scripts left are not known, and the
// reading is TRUNCATED (rel-1-0-10:GAP-0928). An earlier version parsed the
// argument again for every opener, so the time grew with the square of the
// text.
func readHereDocScripts(command string, from int, quoteAt func(int) byte, docs []quotedHereDoc, starts []int, budget *bounded.Counter) {
	scan := &hereDocScriptStart{command: command, from: from, quoteAt: quoteAt, next: from, stop: -1}
	type opener struct {
		doc, start int
		quote      byte
	}
	var group []opener
	groupWord := -1
	flush := func() {
		if len(group) == 0 {
			return
		}
		defer func() { group, groupWord = group[:0], -1 }()
		last := group[len(group)-1]
		if !budget.TakeN(last.start - groupWord) {
			return
		}
		file, ok := Parse("x " + command[groupWord:last.start] + string(last.quote))
		if !ok || len(file.Stmts) != 1 {
			return
		}
		call, isCall := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if !isCall || len(call.Args) != 2 {
			return
		}
		cuts := make([]int, len(group))
		for index, o := range group {
			cuts[index] = 2 + o.start - groupWord
		}
		value, ends, known := wordPrefixValues(call.Args[1], cuts)
		for index, o := range group {
			if known[index] {
				docs[o.doc].script, docs[o.doc].scriptKnown = value[:ends[index]], true
			}
		}
	}
	for index, start := range starts {
		if start <= from || start >= len(command) {
			docs[index].script, docs[index].scriptKnown = "", true
			continue
		}
		quote := quoteAt(start)
		if quote == 0 {
			docs[index].script, docs[index].scriptKnown = "", true
			continue
		}
		if quote != '\'' && quote != '"' {
			continue
		}
		word, ok := scan.wordStart(start)
		if !ok {
			continue
		}
		if len(group) > 0 && (word != groupWord || quote != group[0].quote) {
			flush()
		}
		groupWord = word
		group = append(group, opener{doc: index, start: start, quote: quote})
	}
	flush()
}

// wordPrefixValues is the value of word (literalWordValue) up to each of
// cuts, offsets in the text word was parsed from, ascending. value is the
// value of the literal text of the word; ends[i] is the length of the value
// of the text before cuts[i], so value[:ends[i]] is the value of that text,
// and known[i] is false when that text holds a part that is not literal, a
// literal whose text is not its source (a line continuation), or a cut that
// splits an escape. The prefix values are heads of one string.
func wordPrefixValues(word *syntax.Word, cuts []int) (value string, ends []int, known []bool) {
	var out strings.Builder
	ends, known = make([]int, len(cuts)), make([]bool, len(cuts))
	next, unknown := 0, false
	set := func(ok bool) {
		ends[next], known[next] = out.Len(), ok && !unknown
		next++
	}
	// literal writes text as literalWordValue does, which starts at source
	// offset textFrom, and sets every cut it reaches.
	literal := func(text string, textFrom int, verbatim, double bool) {
		for index := 0; index < len(text); index++ {
			for next < len(cuts) && cuts[next] <= textFrom+index {
				set(true)
			}
			if !verbatim && text[index] == '\\' && index+1 < len(text) && (!double || strings.IndexByte("$`\"\\\n", text[index+1]) >= 0) {
				for next < len(cuts) && cuts[next] == textFrom+index+1 {
					set(false)
				}
				index++
				if text[index] == '\n' {
					continue
				}
			}
			out.WriteByte(text[index])
		}
	}
	// atom is one piece of the word: literal text of source length n at
	// from, or any other part (text ignored, opaque).
	atom := func(from, to int, text string, textFrom, textLen int, verbatim, double, opaque bool) {
		for next < len(cuts) && cuts[next] <= from {
			set(true)
		}
		if opaque || textLen != len(text) {
			unknown = true
			return
		}
		literal(text, textFrom, verbatim, double)
	}
	for _, part := range word.Parts {
		pos, end := int(part.Pos().Offset()), int(part.End().Offset())
		switch typed := part.(type) {
		case *syntax.Lit:
			atom(pos, end, typed.Value, pos, end-pos, false, false, false)
		case *syntax.SglQuoted:
			atom(pos, end, typed.Value, pos+1, end-pos-2, true, false, typed.Dollar)
		case *syntax.DblQuoted:
			if typed.Dollar {
				atom(pos, end, "", pos, 0, false, true, true)
				continue
			}
			for _, inner := range typed.Parts {
				from, to := int(inner.Pos().Offset()), int(inner.End().Offset())
				if lit, isLit := inner.(*syntax.Lit); isLit {
					atom(from, to, lit.Value, from, to-from, false, true, false)
				} else {
					atom(from, to, "", from, 0, false, true, true)
				}
			}
		default:
			atom(pos, end, "", pos, 0, false, false, true)
		}
	}
	for next < len(cuts) {
		set(true)
	}
	return out.String(), ends, known
}

// literalWordValue is the value of a word with no expansion: literal text
// (a backslash escapes the next character), single-quoted text and
// double-quoted literal text. ok is false for any other part.
func literalWordValue(word *syntax.Word) (string, bool) {
	var value strings.Builder
	unescape := func(text string, double bool) {
		for index := 0; index < len(text); index++ {
			if text[index] == '\\' && index+1 < len(text) && (!double || strings.IndexByte("$`\"\\\n", text[index+1]) >= 0) {
				index++
				if text[index] == '\n' {
					continue
				}
			}
			value.WriteByte(text[index])
		}
	}
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			unescape(typed.Value, false)
		case *syntax.SglQuoted:
			if typed.Dollar {
				return "", false
			}
			value.WriteString(typed.Value)
		case *syntax.DblQuoted:
			if typed.Dollar {
				return "", false
			}
			for _, inner := range typed.Parts {
				lit, isLit := inner.(*syntax.Lit)
				if !isLit {
					return "", false
				}
				unescape(lit.Value, true)
			}
		default:
			return "", false
		}
	}
	return value.String(), true
}

// hereDocAt is the index of the body of docs that holds offset at, or -1.
func hereDocAt(docs []quotedHereDoc, at int) int {
	for index, doc := range docs {
		if at >= doc.from && at < doc.to {
			return index
		}
	}
	return -1
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
// single quotes, double quotes and backslash escapes. A here-document body
// stays in the piece of the statement that opens it, through its delimiter
// line: its lines are data (rel-1-0-10:GAP-0746). ok is false past
// maxSyntaxTailPieces (the pieces before the cap are returned).
func tokenPieces(text string) (pieces []tokenPiece, ok bool) {
	return tokenScan(text, nil)
}

// The quote states of tokenScan beside ' and ": an ANSI-C string ($'...',
// whose backslash escapes a quote) and a comment (# at the start of a word,
// to the end of its line).
const (
	ansiQuote    byte = 'A'
	commentQuote byte = '#'
)

// tokenScan is tokenPieces; visit, when set, is called with the offset and
// the quote the shell is in there (', ", ansiQuote, commentQuote or 0) for
// each byte the split reads: not the byte after a backslash, not a
// here-document body, and nothing past maxSyntaxTailPieces. It follows the
// shell's quotes, $'...' escapes and # comments, so a here-document opener
// in a comment or a string is text (rel-1-0-10:GAP-0890, GAP-0903).
func tokenScan(text string, visit func(at int, quote byte)) (pieces []tokenPiece, ok bool) {
	from := 0
	var quote byte
	var pending []heredocMark
	for i := 0; i < len(text); i++ {
		c := text[i]
		if visit != nil {
			visit(i, quote)
		}
		switch {
		case quote == ansiQuote:
			// $'...': a backslash escapes the next byte, a quote closes it.
			switch c {
			case '\\':
				i++
			case '\'':
				quote = 0
			}
			continue
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
		case c == '$' && i+1 < len(text) && text[i+1] == '\'':
			quote = ansiQuote
			i++
			if visit != nil {
				visit(i, quote)
			}
			continue
		case c == '#' && (i == 0 || strings.IndexByte(" \t\n;&|()", text[i-1]) >= 0):
			// A comment runs to the end of its line; an opener or a quote in
			// it is text (rel-1-0-10:GAP-0903).
			for i+1 < len(text) && text[i+1] != '\n' {
				i++
				if visit != nil {
					visit(i, commentQuote)
				}
			}
			continue
		case c == '\'' || c == '"':
			quote = c
			continue
		case c == '<' && strings.HasPrefix(text[i:], "<<") && !strings.HasPrefix(text[i:], "<<<"):
			if mark, next, found := heredocMarkAt(text, i+2); found {
				pending = append(pending, mark)
				i = next - 1
			}
			continue
		case c == '\n' && len(pending) > 0:
			// The bodies start on the next line: the piece runs through the
			// last delimiter line (or to the end of the text).
			i = heredocBodiesEnd(text, i+1, pending) - 1
			pending = nil
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

// heredocMark is the delimiter of one here-document; dash strips leading
// tabs from its lines (<<-).
type heredocMark struct {
	word string
	dash bool
}

// heredocMarkAt reads the delimiter word after a << at offset at: an optional
// -, blanks, then the word with its quotes removed. next is the offset after
// the word.
func heredocMarkAt(text string, at int) (mark heredocMark, next int, found bool) {
	if at < len(text) && text[at] == '-' {
		mark.dash = true
		at++
	}
	for at < len(text) && (text[at] == ' ' || text[at] == '\t') {
		at++
	}
	var word strings.Builder
	var quote byte
	for ; at < len(text); at++ {
		c := text[at]
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '\\' && at+1 < len(text) {
			at++
			word.WriteByte(text[at])
			continue
		}
		if strings.IndexByte(" \t\n;&|<>()", c) >= 0 {
			break
		}
		word.WriteByte(c)
	}
	mark.word = word.String()
	return mark, at, mark.word != ""
}

// heredocBodiesEnd is the offset after the delimiter line of the last of
// marks, whose bodies start at offset at, or len(text) when one is not closed.
func heredocBodiesEnd(text string, at int, marks []heredocMark) int {
	for _, mark := range marks {
		for {
			if at >= len(text) {
				return len(text)
			}
			end := strings.IndexByte(text[at:], '\n')
			line := text[at:]
			if end >= 0 {
				line = text[at : at+end]
			}
			if mark.dash {
				line = strings.TrimLeft(line, "\t")
			}
			if end < 0 {
				at = len(text)
			} else {
				at += end + 1
			}
			if line == mark.word {
				break
			}
		}
	}
	return at
}

// trimSeparators drops the space, operators and newlines around a run.
func trimSeparators(run string) string {
	return strings.TrimSpace(strings.TrimRight(strings.TrimSpace(run), "\n;&|"))
}
