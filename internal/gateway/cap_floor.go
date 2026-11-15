// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
// at ; & | && || ( ) $( ` a line end (a pipeline is also one piece) and the { and } words, never inside a
// quoted string, a comment or a here-document body. The static body of a shell
// program (bash -c '...', a here-document fed to a shell) is a piece of its
// own, judged as the script it is; a body that hits a cap is cut again.
//
// A here-document fed to a shell (the shell is the command word of its
// statement) is the script the shell runs whether or not
// a cap was hit: the readers read its words for path rules but the state
// proof does not read it (GAP-0532, at every size), so its body is judged as a
// call too.
//
// The floor only adds findings the twin proves (an authoritative proof that is
// not itself an evaluation limit or a parse failure), so it never lowers a
// verdict, and a call that names no protected target or state gets no twin.
// Every limit of its own (below) is reported as a cap of the call.
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
	// stopped holds the caps the floor itself stopped at, in the call or in
	// any of its pieces: a piece it left unjudged that may name a target
	// (more than capFloorMaxTwins of them, a nest past capFloorMaxDepth, a
	// statement or a body past its size bound, the middle of a call too big
	// to cut), or a piece whose own analysis hit a bound. The call owner
	// reports them as one truncation (the bound rule), so no limit of the
	// floor is a silent allow (rel-1-0-10:GAP-0690).
	stopped bounded.CapSet
}

// withCapFloor adds to the findings of the call in request the blocks its cap
// pieces prove (see the comment above).
//
// analyzed is the cap set of the action analysis of the call
// (capFloorAnalysisCaps): it stopped at a bound of its own (syntax depth or
// nodes, wrappers, facts, input) and holds no, or not all, of the paths and
// commands of the call (rel-1-0-10:GAP-0547: a state write inside 30 nested
// subshells was allowed in every tier, with no finding; GAP-0688: so was the
// delete of the home folder). Every such call is truncated in the sense of
// the bound rule, whatever it names: it gets the evaluation-limit finding
// naming the cap (withBoundedTruncation, at least the unknown tier of the
// pack), and its pieces are judged as for every other cap. The bound is a
// syntax-tree depth: 30 terms of a pipe or && list reach it, so a long benign
// script alerts at the unknown tier like any call the readers did not finish.
//
// The floor reports its own limits the same way: a piece that names a target
// and is left unjudged (past capFloorMaxTwins, a nest past capFloorMaxDepth, a
// statement or body past its size bound, the middle of a call too big to cut)
// is a cap of the call (capFloorState.stopped), never a silent allow
// (GAP-0690).
//
// statementsOnly (a call past the nested-body bound, decided at once by the
// owner rule of GAP-0677) judges only the statements, never a shell body: a
// body is what took the readers seconds there.
func withCapFloor(parent context.Context, request trustedActionRequest, findings []RuleFinding, analyzed bounded.CapSet, statementsOnly bool) []RuleFinding {
	state := request.capFloor
	if state == nil {
		return findings
	}
	findings = capFloorJudge(parent, request, findings, analyzed, statementsOnly)
	if request.capFloorDepth == 0 && state.stopped.Any() {
		// A limit of the floor itself, or of a piece, is the call's: at
		// least the unknown tier, whatever the pieces proved.
		findings = withBoundedTruncation(findings, state.stopped, request)
	}
	return findings
}

// capFloorJudge is withCapFloor for one call or piece twin: it judges the
// pieces and records the caps it stops at in the shared state.
func capFloorJudge(parent context.Context, request trustedActionRequest, findings []RuleFinding, analyzed bounded.CapSet, statementsOnly bool) []RuleFinding {
	state := request.capFloor
	owner := request.capFloorDepth == 0
	if analyzed.Any() {
		// The analysis bound is a bound-rule cap for every call, whatever
		// it names (rel-1-0-10:GAP-0688): the readers saw nothing of it
		// past the bound, so a proven finding of the text before the bound
		// still decides (the pieces below) and the rest is the unknown tier
		// of the pack. A piece of the call reports it to the call.
		if owner {
			findings = withBoundedTruncation(findings, analyzed, request)
		} else {
			state.stopped = state.stopped.Union(analyzed)
		}
	}
	command, known := trustedBashCommandInput(request.Input)
	if !trustedBashExecutionTool(request.Input.Tool) ||
		request.Input.DialectHint != "" && request.Input.DialectHint != actionfacts.DialectPOSIX ||
		!known || command == "" {
		return findings
	}
	capped := boundedLimitIndex(findings) >= 0 || analyzed.Any()
	if !capped && !strings.Contains(command, "<<") || !analyzed.Any() && !capFloorMayNameProtected(request) {
		// A call whose text names no protected target or state has no
		// piece worth judging: one pass over the text the cut would read,
		// no cut.
		return findings
	}
	head, tail := capFloorPieces(command, request.Input.ActiveHome)
	if request.capFloorDepth > capFloorMaxDepth {
		// A piece nested past the bound is judged as it is but never cut
		// again: what a cut would judge is unread.
		if capped || capFloorHasBody(head) || capFloorHasBody(tail) {
			state.stopped = state.stopped.Union(bounded.Of(bounded.Depth))
		}
		return findings
	}
	if tail != nil {
		state.stopped = state.stopped.Union(bounded.Of(bounded.Bytes))
	}
	if statementsOnly {
		head, tail = slices.DeleteFunc(head, capFloorPiece.isBody), slices.DeleteFunc(tail, capFloorPiece.isBody)
	}
	if !capped {
		// No cap: only a here-document fed to a shell is judged as the
		// script it is.
		notFed := func(p capFloorPiece) bool { return !p.fedBody }
		head, tail = slices.DeleteFunc(head, notFed), slices.DeleteFunc(tail, notFed)
	}
	cwd, home := request.Input.CWD, request.Input.ActiveHome
	whole := strings.TrimSpace(command)
	picked, more := capFloorPick(head, tail, command, cwd, home, analyzed.Any(), capFloorMaxTwins-state.twins)
	if more {
		state.stopped = state.stopped.Union(bounded.Of(bounded.Items))
	}
	for _, piece := range picked {
		text := piece.text(command)
		if text == "" || text == whole {
			continue
		}
		if len(text) > capFloorPieceBytes && !piece.isBody() || len(text) > capFloorBodyBytes {
			state.stopped = state.stopped.Union(bounded.Of(bounded.Bytes))
			continue
		}
		state.twins++
		findings = withTwinProvenBlocks(findings, capFloorProven(dispatchTrustedAction(parent, capFloorTwin(request, text))))
	}
	return findings
}

// capFloorHasBody reports a shell script among the pieces: a body of a shell
// (-c, a here-document fed to it).
func capFloorHasBody(pieces []capFloorPiece) bool {
	return slices.ContainsFunc(pieces, capFloorPiece.isBody)
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
// limit or a parse failure, by proof and by rule id (a cap or a parse failure
// the piece meets is the call's own unknown tier already, whatever pass
// re-proved it).
func capFloorProven(found []RuleFinding) []RuleFinding {
	return slices.DeleteFunc(found, func(f RuleFinding) bool {
		id := canonicalTrustedRuleID(f.RuleID)
		return !f.contributesToEnforcement() || !f.proof.authorizes(f.RuleID) ||
			f.proof.kind == findingProofEvaluationFailure ||
			id == evaluationLimitRuleID || id == canonicalTrustedRuleID(parseFailureRuleID)
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
// of the halving. more reports a piece that names one and is left unjudged
// at the limit: the floor stopped there (a bound the call owner reports).
func capFloorPick(head, tail []capFloorPiece, command, cwd, home string, anyPath bool, limit int) (picked []capFloorPiece, more bool) {
	front := newCapFloorRegion(head, command, cwd, home, anyPath)
	back := front
	if tail != nil {
		back = newCapFloorRegion(tail, command, cwd, home, anyPath)
	}
	if limit > 0 {
		front.find(0, len(head), true, (limit+1)/2)
		back.find(0, len(back.pieces), false, limit-len(front.picked)+len(back.picked))
		picked = front.chosen()
		if tail != nil {
			picked = append(picked, back.chosen()...)
		}
	}
	// One more search each way: a piece naming a target past the limit.
	if len(picked) >= limit {
		n := len(front.picked)
		front.find(0, len(head), true, n+1)
		more = len(front.picked) > n
		if tail != nil && !more {
			n = len(back.picked)
			back.find(0, len(back.pieces), false, n+1)
			more = len(back.picked) > n
		}
	}
	return picked, more
}

// capFloorRegion is the halving search over the pieces of one cut region.
type capFloorRegion struct {
	pieces    []capFloorPiece
	command   string
	cwd, home string
	anyPath   bool
	reach     []int
	picked    map[int]bool
}

func newCapFloorRegion(pieces []capFloorPiece, command, cwd, home string, anyPath bool) *capFloorRegion {
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
	return &capFloorRegion{pieces: pieces, command: command, cwd: cwd, home: home, anyPath: anyPath, reach: reach, picked: map[int]bool{}}
}

func (r *capFloorRegion) names(lo, hi int) bool {
	text := ""
	if hi-lo == 1 {
		text = r.pieces[lo].text(r.command)
	} else {
		text = r.command[r.pieces[lo].start:max(r.reach[hi-1], r.pieces[lo].start)]
	}
	return text != "" && (hookpaths.BoundCallMayNameProtected(text, r.cwd, r.home) || r.anyPath && capFloorMayNamePath(text))
}

// capFloorMayNamePath reports a text that may name a path or a value built at
// run time (a slash, a tilde, a variable): the pieces of a call the action
// analysis stopped on that are worth judging whatever they name, since the
// analysis proved nothing of them (GAP-0688: the delete of a folder, a
// credential read piped out). A piece of plain words (true, echo done) names
// none.
func capFloorMayNamePath(text string) bool {
	return strings.ContainsAny(text, "/~$%\\")
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
func capFloorPieces(command, home string) (head, tail []capFloorPiece) {
	if len(command) <= capFloorHeadScan+capFloorTailScan {
		return capFloorCut(command, home, 0, len(command)), nil
	}
	headEnd := capFloorHeadScan
	if i := strings.LastIndexAny(command[:headEnd], ";\n"); i > 0 {
		headEnd = i
	}
	tailStart := len(command) - capFloorTailScan
	if i := strings.IndexAny(command[tailStart:], ";\n"); i >= 0 {
		tailStart += i + 1
	}
	return capFloorCut(command, home, 0, headEnd), capFloorCut(command, home, tailStart, len(command))
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
func capFloorCut(command, home string, from, to int) []capFloorPiece {
	var pieces []capFloorPiece
	var pending []capFloorHeredoc
	// open holds the open double quotes (") and subshells or command
	// substitutions (() around i: a $( inside a double-quoted string is
	// code again, and its ) returns to the string.
	var open []byte
	start := from
	// stmt is the start of the statement in progress at the current nesting:
	// a $( or ( starts a statement of its own, and its ) returns to the
	// statement around it (stmtOpen). The consumer of a here-document or a
	// quoted script is the COMMAND word of that statement, which a command
	// substitution inside one of its words does not change (gh pr create
	// --title "$(git log -1)" --body-file - <<EOF reads its body as data).
	stmt := from
	var stmtOpen []int
	// pipeFrom is the start of the pipeline in progress (-1 for none): a
	// pipeline is judged whole as well as stage by stage, since what it
	// proves (a download run by a shell, a credential piped out) needs the
	// stages together (GAP-0688).
	pipeFrom := -1
	cut := func(end, next int) {
		if pipeFrom >= 0 && end > pipeFrom {
			pieces = append(pieces, capFloorPiece{start: pipeFrom, end: end})
		}
		pipeFrom = -1
		if end > start {
			pieces = append(pieces, capFloorPiece{start: start, end: end})
		}
		start, stmt = next, next
	}
	cutPipe := func(end, next int) {
		if pipeFrom < 0 {
			pipeFrom = start
		}
		if end > start {
			pieces = append(pieces, capFloorPiece{start: start, end: end})
		}
		start, stmt = next, next
	}
	// enter opens a $( or ( at i whose statement starts at next.
	enter := func(i, next int) {
		stmtOpen = append(stmtOpen, stmt)
		cut(i, next)
		open = append(open, '(')
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
				enter(i, i+2)
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
			if capFloorShellDashC(command[stmt:i], home) {
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
				doc.fed = capFloorShellStdin(command[stmt:i], home)
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
			start, stmt = i, i
			continue
		case c == ';' || c == '`':
			cut(i, i+1)
		case c == '(' || c == '$' && i+1 < to && command[i+1] == '(':
			next := i + 1
			if c == '$' {
				next++
			}
			enter(i, next)
			i = next
			continue
		case c == ')':
			cut(i, i+1)
			if n := len(open); n > 0 && open[n-1] == '(' {
				open = open[:n-1]
				stmt = stmtOpen[len(stmtOpen)-1]
				stmtOpen = stmtOpen[:len(stmtOpen)-1]
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
			if c == '|' && next == i+1 {
				cutPipe(i, next)
			} else {
				cut(i, next)
			}
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

// capFloorShells are the POSIX shell programs: a program that reads its
// script from a file or from standard input.
var capFloorShells = []string{"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash"}

// capFloorConsumer reads the program a statement prefix runs, the one that
// takes the here-document or the quoted word that follows (the real consumer
// of the data): its COMMAND word, behind the wrappers that pass the rest of
// argv on (sudo, env NAME=value, nohup, exec, nice, command, time,
// timeout...), with its static argument words ("" for a word built at run
// time). known is false when the prefix cannot be read to that point (a
// program built at run time, an unknown wrapper option): the caller then
// judges as if the consumer were a shell, since a here-document that may be
// a script is read, never skipped (the bound rule).
func capFloorConsumer(prefix, home string) (program string, args []string, known bool) {
	return hookpaths.StatementProgram(capFloorStripKeywords(strings.TrimSpace(prefix)), home)
}

// capFloorDashCOption reports a shell option word that takes the script from
// the next word (-c, -lc, -ec).
func capFloorDashCOption(word string) bool {
	return strings.HasPrefix(word, "-") && !strings.HasPrefix(word, "--") &&
		!strings.ContainsAny(word, "=/") && strings.Contains(word[1:], "c")
}

// capFloorShellDashC reports a statement prefix that ends with a shell and its
// -c option: the quoted word that follows is the script it runs. The shell
// is the command word of the statement, not any word of it (GAP-0691).
func capFloorShellDashC(prefix, home string) bool {
	program, args, known := capFloorConsumer(prefix, home)
	return known && slices.Contains(capFloorShells, program) && len(args) > 0 && capFloorDashCOption(args[len(args)-1])
}

// capFloorShellStdin reports a statement prefix whose command word is a shell
// with no script operand and no -c: the shell reads its script from standard
// input, so a here-document of the statement is that script. A program the
// prefix does not let us read is taken as a shell; grep, which, echo, cat,
// an interpreter or ssh with a word "bash" among its operands is not one: its
// data is not a shell script run here.
func capFloorShellStdin(prefix, home string) bool {
	program, args, known := capFloorConsumer(prefix, home)
	if !known {
		return true
	}
	if !slices.Contains(capFloorShells, program) {
		return false
	}
	for _, word := range args {
		if word != "" && (!strings.HasPrefix(word, "-") || capFloorDashCOption(word)) {
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

// capFloorAnalysisCaps is the cap set of an action analysis of a shell call
// that stopped at a bound of its own (actionfacts StatusLimitExceeded): its
// syntax depth or node bound, the wrapper bound or the fact bound. The facts
// of such a call hold no, or only some of the, paths and commands of the
// text, so no reader proved what the call does (rel-1-0-10:GAP-0688,
// GAP-0689). The input bound is not here: posixParseTruncation truncates a
// call that stopped at a byte bound or at the inline program bound
// (GAP-0382, GAP-0689), with the data-word and padding twins it reads
// instead. Other tools keep their own bounds.
func capFloorAnalysisCaps(facts actionfacts.Facts) bounded.CapSet {
	var set bounded.CapSet
	if !trustedBashExecutionTool(facts.Tool) {
		return set
	}
	if prefixWrapperChainPastBound(facts) {
		// A chain of plain prefix wrappers (sudo -n sudo -n ... rm) longer
		// than the readers unwrap: the program it runs is not read, whatever
		// the status of the analysis (rel-1-0-10:GAP-0689).
		set = set.Union(bounded.Of(bounded.Depth))
	}
	if facts.Parse.Status != actionfacts.StatusLimitExceeded {
		return set
	}
	for _, issue := range facts.Parse.Issues {
		switch issue {
		case actionfacts.IssueDepthLimit, actionfacts.IssueWrapperLimit:
			set = set.Union(bounded.Of(bounded.Depth))
		case actionfacts.IssueNodeLimit:
			set = set.Union(bounded.Of(bounded.Nodes))
		case actionfacts.IssueFactLimit:
			set = set.Union(bounded.Of(bounded.Items))
		}
	}
	return set
}

// prefixWrapperChainPastBound reports a command of the facts whose chain of
// plain prefix wrappers (sudo, env, command, nohup, ...) is longer than the
// action analysis unwraps (actionfacts.MaxWrapperDepth). A dynamic word
// after such a chain (a ~ or $HOME operand) stops the analysis at the first
// wrapper as a partial parse, with no wrapper limit, so the program the
// chain runs was never read; the readers that unwrap further still prove a
// block of their own (rel-1-0-10:GAP-0689).
//
// A chain the inline hand-off reads to its interpreter child
// (actionfacts.InlineCodeHandoff, up to actionfacts.InlineChainWrappers
// wrappers) is read: the hand-off judges the child's code and reports its own
// cap depth past its bound, so the floor does not stand in for it (the
// tamper-min lane of rel-1-0-10:GAP-0827 / GAP-0663).
func prefixWrapperChainPastBound(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if len(command.Argv) <= actionfacts.MaxWrapperDepth || command.Dialect != actionfacts.DialectPOSIX {
			continue
		}
		if handoff := actionfacts.InlineCodeHandoff(command.Argv); !handoff.Caps.Any() &&
			(handoff.From >= 0 || handoff.ProvenReads) {
			continue
		}
		static := make([]bool, len(command.Argv))
		for i := range static {
			static[i] = len(command.Arguments) != len(command.Argv) || !command.Arguments[i].Expands
		}
		if run, wrapped := actionfacts.StaticPrefixWrapperChild(command.Argv, static); wrapped && run.Length > actionfacts.MaxWrapperDepth {
			return true
		}
	}
	return false
}

// capFloorMayNameProtected reports a call whose command text may name a
// protected target or the DefenseClaw state, however it is quoted
// (hookpaths.BoundCallMayNameProtected), in the start and the end the cut
// reads (capFloorPieces) of a call over capFloorHeadScan+capFloorTailScan
// bytes.
func capFloorMayNameProtected(request trustedActionRequest) bool {
	command := request.Input.Command
	if command == "" {
		if field, present, valid := trustedTopLevelCommandField(request.Input.Args); valid && present {
			command = field
		}
	}
	if len(command) > capFloorHeadScan+capFloorTailScan {
		command = command[:capFloorHeadScan] + "\n" + command[len(command)-capFloorTailScan:]
	}
	return command != "" && hookpaths.BoundCallMayNameProtected(command, request.Input.CWD, request.Input.ActiveHome)
}
