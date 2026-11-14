// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The cap floor: the one place a shell call that hit a reading cap keeps the
// blocks proven on the text the cap did not take (rel-1-0-10:GAP-0312,
// GAP-0360, GAP-0435, GAP-0381, GAP-0532).
//
// A call past a nesting, size, statement or reading cap is judged at the
// unknown tier of its pack (the evaluation-limit finding, ACTION-COMPOUND-LIMIT:
// an alert in the default and permissive packs, a block in strict). That is a
// floor, not the verdict: a statement of the call that names a protected
// target or the DefenseClaw state is still a command the shell runs, and the
// full readers judge it on its own, as the call it is (a cap piece twin). A
// block they prove there counts for the call, with its rule ids, whatever the
// cap did to the rest of it. The pieces are cut from the text, never parsed:
// at ; & | && || ( ) $( ` a line end and the { and } words, never inside a
// quoted string, a comment or a here-document body. The static body of a shell
// program (bash -c '...', a here-document fed to a shell) is a piece of its
// own, judged as the script it is; a body that hits a cap is cut again.
//
// A here-document fed to a shell is the script the shell runs whether or not
// a cap was hit: the readers read its words for path rules but the state
// proof does not read it (GAP-0532, at every size), so its body is judged as a
// call too.
//
// The floor only adds findings the twin proves (an authoritative proof that is
// not itself an evaluation limit or a parse failure), so it never lowers a
// verdict, and a call that names no protected target or state gets no twin:
// a cap alone keeps the evaluation-limit verdict it has on rel.
const (
	// capFloorMaxTwins bounds the pieces judged for one hook call, nested
	// bodies included: half from the start of the call, half from its end,
	// where a command sits beside the padding that put the call past a cap.
	capFloorMaxTwins = 16
	// capFloorMaxDepth bounds how many times a body twin that hits a cap is
	// cut again (bash -c inside bash -c ...).
	capFloorMaxDepth = 2
	// capFloorPieceBytes bounds a statement judged on its own: the padding
	// that put the call past a cap is a statement of many bytes.
	capFloorPieceBytes = 4 << 10
	// capFloorBodyBytes bounds a shell body judged on its own: a larger body
	// is past the reading budget, which its twin then decides.
	capFloorBodyBytes = 256 << 10
	// capFloorHeadScan and capFloorTailScan bound the bytes cut into pieces:
	// the start and the end of a call of hundreds of KiB. Its middle is
	// padding the cap already judged at the unknown tier.
	capFloorHeadScan = 64 << 10
	capFloorTailScan = 32 << 10
)

// capFloorState is the shared state of one hook call's cap floor.
type capFloorState struct {
	twins int // pieces judged so far, for capFloorMaxTwins
}

// withCapFloor adds to the findings of the call in request the blocks its cap
// pieces prove (see the comment above).
//
// analysisStopped reports that the action analysis of the call stopped at its
// syntax depth or node bound and holds no path of it (capFloorAnalysisStopped,
// a state write inside 30 nested subshells was allowed in every tier): the
// pieces of such a call are judged too. No limit finding is added for it, so
// a call whose pieces prove nothing keeps its rel verdict.
func withCapFloor(parent context.Context, request trustedActionRequest, findings []RuleFinding, analysisStopped bool) []RuleFinding {
	if request.capFloor == nil || request.capFloorDepth > capFloorMaxDepth ||
		!trustedBashExecutionTool(request.Input.Tool) ||
		request.Input.DialectHint != "" && request.Input.DialectHint != actionfacts.DialectPOSIX {
		return findings
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || command == "" {
		return findings
	}
	cwd, home := request.Input.CWD, request.Input.ActiveHome
	capped := analysisStopped || boundedLimitIndex(findings) >= 0
	if !capped && !strings.Contains(command, "<<") {
		return findings
	}
	head, tail := capFloorPieces(command)
	if !capped {
		// No cap: only a here-document fed to a shell is judged as the
		// script it is.
		notFed := func(p capFloorPiece) bool { return !p.fedBody }
		head, tail = slices.DeleteFunc(head, notFed), slices.DeleteFunc(tail, notFed)
	}
	whole := strings.TrimSpace(command)
	for _, piece := range capFloorPick(head, tail, command, cwd, home, capFloorMaxTwins-request.capFloor.twins) {
		text := piece.text(command)
		if text == "" || text == whole || len(text) > capFloorPieceBytes && !piece.isBody() || len(text) > capFloorBodyBytes {
			continue
		}
		if request.capFloor.twins >= capFloorMaxTwins {
			break
		}
		request.capFloor.twins++
		findings = withTwinProvenBlocks(findings, capFloorProven(dispatchTrustedAction(parent, capFloorTwin(request, text))))
	}
	return findings
}

// capFloorTwin is request with text as its whole command, judged by every
// reader and allowed to cut its own pieces one level deeper.
func capFloorTwin(request trustedActionRequest, text string) trustedActionRequest {
	twin := request
	twin.Input.Command, twin.Input.Args, twin.Input.Argv = text, nil, nil
	twin.LegacyText = text
	twin.conflictSource = nil
	twin.record, twin.recordTelemetry = nil, nil
	twin.capFloorSeen = false
	twin.capFloorDepth = request.capFloorDepth + 1
	if _, ok := request.ResolvedWriteTargets[hookpaths.UnprovenReasonKey]; ok {
		// The hook client's reason is its reading of the whole call (the
		// shell-parse bound of the cap, a parser uncertainty), not of the
		// piece: the piece is read again by the gateway readers.
		twin.ResolvedWriteTargets = maps.Clone(request.ResolvedWriteTargets)
		delete(twin.ResolvedWriteTargets, hookpaths.UnprovenReasonKey)
	}
	return twin
}

// capFloorProven keeps the findings of a piece twin that a reader proved: an
// enforcing finding with an authoritative proof that is not an evaluation
// limit or a parse failure (a cap the piece hits is the call's own unknown
// tier already).
func capFloorProven(found []RuleFinding) []RuleFinding {
	return slices.DeleteFunc(found, func(f RuleFinding) bool {
		return !f.contributesToEnforcement() || !f.proof.authorizes(f.RuleID) ||
			f.proof.kind == findingProofEvaluationFailure
	})
}

// capFloorPiece is one statement (a byte range of the command) or one static
// shell body of the command.
type capFloorPiece struct {
	start, end int
	// body is the value of a shell body (see capFloorSingleQuoted); "" for
	// a statement.
	body string
	// fedBody marks a here-document body fed to a shell.
	fedBody bool
}

func (p capFloorPiece) isBody() bool { return p.body != "" }

func (p capFloorPiece) text(command string) string {
	if p.body != "" {
		return strings.TrimSpace(p.body)
	}
	return capFloorStripKeywords(strings.TrimSpace(command[p.start:p.end]))
}

// capFloorPick returns at most limit pieces that may name a protected target
// or the DefenseClaw state (hookpaths.BoundCallMayNameProtected): the first
// half from the start of the call (head), the rest from its end (tail, or
// head again when the call was cut whole). The pieces that name one are found
// by halving: a range of pieces whose text names none is dropped whole, so a
// call of thousands of statements costs a pass over its text for each level
// of the halving.
func capFloorPick(head, tail []capFloorPiece, command, cwd, home string, limit int) []capFloorPiece {
	if limit <= 0 {
		return nil
	}
	front := newCapFloorRegion(head, command, cwd, home)
	back := front
	if tail != nil {
		back = newCapFloorRegion(tail, command, cwd, home)
	}
	front.find(0, len(head), true, (limit+1)/2)
	back.find(0, len(back.pieces), false, limit-len(front.picked)+len(back.picked))
	out := front.chosen()
	if tail != nil {
		out = append(out, back.chosen()...)
	}
	return out
}

// capFloorRegion is the halving search over the pieces of one cut region.
type capFloorRegion struct {
	pieces    []capFloorPiece
	command   string
	cwd, home string
	reach     []int
	picked    map[int]bool
}

func newCapFloorRegion(pieces []capFloorPiece, command, cwd, home string) *capFloorRegion {
	// Pieces are in the order of their start; a body lies inside the
	// statement that runs it, so a range of pieces spans up to the furthest
	// end before its last piece (reach).
	reach := make([]int, len(pieces))
	for i, piece := range pieces {
		reach[i] = piece.end
		if i > 0 && reach[i-1] > reach[i] {
			reach[i] = reach[i-1]
		}
	}
	return &capFloorRegion{pieces: pieces, command: command, cwd: cwd, home: home, reach: reach, picked: map[int]bool{}}
}

func (r *capFloorRegion) names(lo, hi int) bool {
	text := ""
	if hi-lo == 1 {
		text = r.pieces[lo].text(r.command)
	} else {
		text = r.command[r.pieces[lo].start:max(r.reach[hi-1], r.pieces[lo].start)]
	}
	return text != "" && hookpaths.BoundCallMayNameProtected(text, r.cwd, r.home)
}

// find picks, in order (forward from the start, else from the end), the
// pieces of [lo, hi) that name a target until want are picked.
func (r *capFloorRegion) find(lo, hi int, forward bool, want int) {
	if lo >= hi || len(r.picked) >= want || !r.names(lo, hi) {
		return
	}
	if hi-lo == 1 {
		r.picked[lo] = true
		return
	}
	mid := (lo + hi) / 2
	if forward {
		r.find(lo, mid, forward, want)
		r.find(mid, hi, forward, want)
	} else {
		r.find(mid, hi, forward, want)
		r.find(lo, mid, forward, want)
	}
}

func (r *capFloorRegion) chosen() []capFloorPiece {
	var out []capFloorPiece
	for i, piece := range r.pieces {
		if r.picked[i] {
			out = append(out, piece)
		}
	}
	return out
}

// capFloorPieces cuts command into pieces (see capFloorPiece): head is the
// whole command, or, for a command of more than
// capFloorHeadScan+capFloorTailScan bytes, its start, and tail its end, each
// cut from a statement boundary (nil when the command was cut whole).
func capFloorPieces(command string) (head, tail []capFloorPiece) {
	if len(command) <= capFloorHeadScan+capFloorTailScan {
		return capFloorCut(command, 0, len(command)), nil
	}
	headEnd := capFloorHeadScan
	if i := strings.LastIndexAny(command[:headEnd], ";\n"); i > 0 {
		headEnd = i
	}
	tailStart := len(command) - capFloorTailScan
	if i := strings.IndexAny(command[tailStart:], ";\n"); i >= 0 {
		tailStart += i + 1
	}
	return capFloorCut(command, 0, headEnd), capFloorCut(command, tailStart, len(command))
}

// capFloorHeredoc is a here-document whose body starts after the next line
// end.
type capFloorHeredoc struct {
	delimiter string
	stripTabs bool
	fed       bool // the statement feeds it to a shell as its script
}

// capFloorCut cuts command[from:to] into statements and shell bodies, reading
// the text once.
func capFloorCut(command string, from, to int) []capFloorPiece {
	var pieces []capFloorPiece
	var pending []capFloorHeredoc
	// open holds the open double quotes (") and subshells or command
	// substitutions (() around i: a $( inside a double-quoted string is
	// code again, and its ) returns to the string.
	var open []byte
	start := from
	cut := func(end, next int) {
		if end > start {
			pieces = append(pieces, capFloorPiece{start: start, end: end})
		}
		start = next
	}
	wordStart := func(i int) bool {
		j := i - 1
		for j > from && command[j] == '\n' && command[j-1] == '\\' && !capFloorEscaped(command, from, j-1) {
			// A line continuation is removed before the word is read.
			j -= 2
		}
		return j < from || strings.IndexByte(" \t\n;&|()`", command[j]) >= 0 && !capFloorEscaped(command, from, j)
	}
	wordEnd := func(i int) bool { return i+1 >= to || strings.IndexByte(" \t\n;&|)`", command[i+1]) >= 0 }
	for i := from; i < to; {
		c := command[i]
		if n := len(open); n > 0 && open[n-1] == '"' {
			switch {
			case c == '\\':
				i += 2
			case c == '"':
				open = open[:n-1]
				i++
			case c == '$' && i+1 < to && command[i+1] == '(':
				cut(i, i+2)
				open = append(open, '(')
				i += 2
			case c == '`':
				cut(i, i+1)
				i++
			default:
				i++
			}
			continue
		}
		switch {
		case c == '\\':
			i += 2
			continue
		case c == '\'':
			body, end := capFloorSingleQuoted(command, i, to)
			if end < 0 {
				// An unclosed quote: the rest is one word.
				i = to
				continue
			}
			if capFloorShellDashC(command[start:i]) {
				pieces = append(pieces, capFloorPiece{start: i, end: end, body: body})
			}
			i = end
			continue
		case c == '"':
			open = append(open, '"')
			i++
			continue
		case c == '#' && wordStart(i):
			cut(i, i)
			end := strings.IndexByte(command[i:to], '\n')
			if end < 0 {
				i, start = to, to
				continue
			}
			i, start = i+end, i+end
			continue
		case c == '<' && strings.HasPrefix(command[i:to], "<<<"):
			// A here-string: a word, not a here-document.
			i += 3
			continue
		case c == '<' && strings.HasPrefix(command[i:to], "<<"):
			doc, end, ok := capFloorHeredocAt(command, i, to)
			if ok {
				doc.fed = capFloorShellStdin(command[start:i])
				pending = append(pending, doc)
				i = end
				continue
			}
			i += 2
			continue
		case c == '\n':
			cut(i, i+1)
			i++
			for _, doc := range pending {
				bodyStart := i
				lineEnd := i
				for i < to {
					lineEnd = strings.IndexByte(command[i:to], '\n')
					if lineEnd < 0 {
						lineEnd = to
					} else {
						lineEnd += i
					}
					line := command[i:lineEnd]
					if doc.stripTabs {
						line = strings.TrimLeft(line, "\t")
					}
					if line == doc.delimiter {
						break
					}
					i = min(lineEnd+1, to)
				}
				if doc.fed && i > bodyStart {
					pieces = append(pieces, capFloorPiece{start: bodyStart, end: i, body: command[bodyStart:i], fedBody: true})
				}
				i = min(lineEnd+1, to)
			}
			pending = nil
			start = i
			continue
		case c == ';' || c == '`':
			cut(i, i+1)
		case c == '(' || c == '$' && i+1 < to && command[i+1] == '(':
			next := i + 1
			if c == '$' {
				next++
			}
			cut(i, next)
			open = append(open, '(')
			i = next
			continue
		case c == ')':
			cut(i, i+1)
			if n := len(open); n > 0 && open[n-1] == '(' {
				open = open[:n-1]
			}
		case c == '|' || c == '&':
			if i > from && (command[i-1] == '>' || command[i-1] == '<') || i+1 < to && command[i+1] == '>' {
				// A redirect (2>&1, &>, >|), not a list operator.
				break
			}
			next := i + 1
			if next < to && command[next] == c {
				next++
			}
			cut(i, next)
			i = next
			continue
		case (c == '{' || c == '}') && wordStart(i) && wordEnd(i):
			cut(i, i+1)
		}
		i++
	}
	cut(to, to)
	// A body piece is added when its quote or here-document is read, before
	// the statement around it ends: order the pieces by their start.
	slices.SortStableFunc(pieces, func(a, b capFloorPiece) int { return a.start - b.start })
	return pieces
}

// capFloorSingleQuoted reads the single-quoted word at command[i] and the
// joins that continue it (a quote, a backslash and two quotes put one quote
// in the value): its value and the index after it, or end -1 when it is not
// closed.
func capFloorSingleQuoted(command string, i, to int) (value string, end int) {
	var b strings.Builder
	for {
		close := strings.IndexByte(command[i+1:to], '\'')
		if close < 0 {
			return "", -1
		}
		close += i + 1
		b.WriteString(command[i+1 : close])
		end = close + 1
		if strings.HasPrefix(command[end:to], `\''`) {
			b.WriteByte('\'')
			i = end + 2
			continue
		}
		return b.String(), end
	}
}

// capFloorEscaped reports whether command[i] is escaped: an odd number of
// backslashes (from from on) precede it.
func capFloorEscaped(command string, from, i int) bool {
	n := 0
	for j := i - 1; j >= from && command[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// capFloorHeredocAt reads the here-document operator at command[i] (<< or
// <<-) and its delimiter word: the delimiter as the shell compares it (quotes
// and backslashes removed) and the index after the word.
func capFloorHeredocAt(command string, i, to int) (doc capFloorHeredoc, end int, ok bool) {
	j := i + 2
	if j < to && command[j] == '-' {
		doc.stripTabs = true
		j++
	}
	for j < to && (command[j] == ' ' || command[j] == '\t') {
		j++
	}
	var b strings.Builder
	for j < to && strings.IndexByte(" \t\r\n;|&()<>", command[j]) < 0 {
		switch c := command[j]; c {
		case '\'', '"':
			close := strings.IndexByte(command[j+1:to], c)
			if close < 0 {
				return capFloorHeredoc{}, 0, false
			}
			b.WriteString(command[j+1 : j+1+close])
			j += close + 2
		case '\\':
			if j+1 < to {
				b.WriteByte(command[j+1])
			}
			j += 2
		default:
			b.WriteByte(c)
			j++
		}
	}
	doc.delimiter = b.String()
	return doc, min(j, to), doc.delimiter != ""
}

// capFloorShellWords are the words of a statement prefix with their quotes
// removed.
func capFloorShellWords(prefix string) []string {
	words := strings.Fields(prefix)
	for i, word := range words {
		words[i] = strings.Trim(word, `'"`)
	}
	return words
}

// capFloorShellAt is the index of the first POSIX shell program word of
// words (bash, /bin/sh, behind sudo, env, nohup or any other word), or -1.
func capFloorShellAt(words []string) int {
	for i, word := range words {
		switch path.Base(word) {
		case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash":
			return i
		}
	}
	return -1
}

// capFloorDashCOption reports a shell option word that takes the script from
// the next word (-c, -lc, -ec).
func capFloorDashCOption(word string) bool {
	return strings.HasPrefix(word, "-") && !strings.HasPrefix(word, "--") &&
		!strings.ContainsAny(word, "=/") && strings.Contains(word[1:], "c")
}

// capFloorShellDashC reports a statement prefix that ends with a shell and its
// -c option: the quoted word that follows is the script it runs.
func capFloorShellDashC(prefix string) bool {
	words := capFloorShellWords(prefix)
	at := capFloorShellAt(words)
	return at >= 0 && at+1 < len(words) && capFloorDashCOption(words[len(words)-1])
}

// capFloorShellStdin reports a statement prefix that runs a shell with no
// script operand and no -c: the shell reads its script from standard input,
// so a here-document of the statement is that script.
func capFloorShellStdin(prefix string) bool {
	words := capFloorShellWords(prefix)
	at := capFloorShellAt(words)
	if at < 0 {
		return false
	}
	for _, word := range words[at+1:] {
		if !strings.HasPrefix(word, "-") || capFloorDashCOption(word) {
			return false
		}
	}
	return true
}

// capFloorStripKeywords drops the reserved words that start a piece (then,
// do, if, ! ...): the piece is judged as the command that follows them.
func capFloorStripKeywords(text string) string {
	for {
		word, rest, _ := strings.Cut(text, " ")
		switch word {
		case "if", "then", "else", "elif", "do", "while", "until", "!", "time", "fi", "done", "esac", "{", "}":
			text = strings.TrimSpace(rest)
			continue
		}
		return text
	}
}

// capFloorAnalysisStopped reports an action analysis that stopped at its
// syntax depth or node bound (actionfacts StatusLimitExceeded): its facts hold
// no path of the call.
func capFloorAnalysisStopped(facts actionfacts.Facts) bool {
	return facts.Parse.Status == actionfacts.StatusLimitExceeded &&
		(slices.Contains(facts.Parse.Issues, actionfacts.IssueDepthLimit) ||
			slices.Contains(facts.Parse.Issues, actionfacts.IssueNodeLimit))
}
