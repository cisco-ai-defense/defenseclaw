package shellparse

import (
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap0930Shape is a script passed as one quoted argument with n openers of
// one delimiter that a single late line closes, and a syntax error in its
// body: the shape of rel-1-0-10:GAP-0928 and GAP-0930.
func gap0930Shape(n int) string {
	var b strings.Builder
	b.WriteString("tool '")
	for i := 0; i < n; i++ {
		b.WriteString("cat <<'\"'\"'E'\"'\"'\n")
	}
	b.WriteString("E\nit's (x)\necho after'")
	return b.String()
}

// rel-1-0-10:GAP-0930. The many openers of one broken argument are counted
// against the budget of the reading: past it the reading is TRUNCATED (the
// unknown tier of the pack), at 9, 18, 36 and 72 KB alike, never a plain
// unread part (allow LOW).
func TestReadSyntaxTailManyOpenersIsTruncated(t *testing.T) {
	for _, n := range []int{500, 1000, 2000, 4000} {
		command := gap0930Shape(n)
		tail, ok := ReadSyntaxTail(command)
		if !ok {
			t.Fatalf("n=%d (%d bytes): not read", n, len(command))
		}
		if !tail.Truncated.Has(bounded.Bytes) {
			t.Errorf("n=%d (%d bytes): truncated %+v, want the byte budget", n, len(command), tail.Truncated)
		}
		if len(tail.Statements) == 0 {
			t.Errorf("n=%d (%d bytes): no statement read, want the statements before the cap kept", n, len(command))
		}
	}
}

// A script of a few openers, the ordinary case, is read in full.
func TestReadSyntaxTailFewOpenersIsNotTruncated(t *testing.T) {
	for _, n := range []int{1, 2, 5, 10} {
		command := gap0930Shape(n)
		tail, ok := ReadSyntaxTail(command)
		if !ok || tail.Truncated.Any() {
			t.Errorf("n=%d: ok %v truncated %+v, want a full reading", n, ok, tail.Truncated)
		}
	}
}

// rel-1-0-10:GAP-0928. The reading of the openers of one argument does not
// parse the argument again for each opener: the time of doubling the text is
// less than four times, and a 72 KB text is read in well under a second (the
// per-opener parse took 27 s).
func TestReadSyntaxTailOpenerCostScales(t *testing.T) {
	measure := func(n int) time.Duration {
		command := gap0930Shape(n)
		best := time.Duration(1 << 62)
		for try := 0; try < 3; try++ {
			syntaxTailMemo.put(command, SyntaxTail{}, false) // not memoized
			start := time.Now()
			readSyntaxTail(command)
			best = min(best, time.Since(start))
		}
		return best
	}
	small, large := measure(2000), measure(4000)
	t.Logf("GAP-0928 36 KB %s, 72 KB %s", small, large)
	if large > 4*small && large > 50*time.Millisecond {
		t.Errorf("doubling the text took %s -> %s, want less than four times", small, large)
	}
	if large > time.Second {
		t.Errorf("72 KB took %s, want well under a second", large)
	}
}

// scriptOfOneParsePerOpener is the reading of the script before the command
// that starts at start that parsed the argument again for each opener (the
// reading before rel-1-0-10:GAP-0928): the reference for the shared parse.
func scriptOfOneParsePerOpener(command string, from, start int, quoteAt func(int) byte) (string, bool) {
	if start <= from || start >= len(command) {
		return "", true
	}
	quote := quoteAt(start)
	if quote == 0 {
		return "", true
	}
	if quote != '\'' && quote != '"' {
		return "", false
	}
	word := from
	for at := start - 1; at >= from; at-- {
		state := quoteAt(at)
		if state == unreadQuote {
			return "", false
		}
		if state == 0 && strings.IndexByte(" \t\n;&|()<>", command[at]) >= 0 {
			word = at + 1
			break
		}
	}
	file, ok := Parse("x " + command[word:start] + string(quote))
	if !ok || len(file.Stmts) != 1 {
		return "", false
	}
	call, isCall := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !isCall || len(call.Args) != 2 {
		return "", false
	}
	return literalWordValue(call.Args[1])
}

// The script of each opener from the shared parse is the one the per-opener
// parse gave, known or not: literal text, quotes, escapes and a line
// continuation before it, and an expansion (the script is not known from
// there on).
func TestReadSyntaxTailSharedScriptParseMatchesPerOpener(t *testing.T) {
	for index, command := range []string{
		"tool \"A=1; cat <<'E'\nx\nE\nB=2; cat <<'F'\ny\nF\nC='z w'; cat <<'G'\nq\nG\n\"",
		"tool \"A=1; cat <<'E'\nx\nE\nB=$X; cat <<'F'\ny\nF\nC=3; cat <<'G'\nq\nG\n\"",
		"tool \"A=\\\"1\\\"; cat <<'E'\nx\nE\nB=\\$X; cat <<'F'\ny\nF\n\"",
		"tool 'A=1; cat <<'\"'\"'E'\"'\"'\nx\nE\nB=2; cat <<'\"'\"'F'\"'\"'\ny\nF\nC=\"$Y\"; cat <<'\"'\"'G'\"'\"'\nq\nG\n'",
		"tool \"A=1; cat <<'E'\nx\nE\nB=`id`; cat <<'F'\ny\nF\n\"",
		"tool \"A=1; cat <<'E'\nx\nE\nB=$'\\t'; cat <<'F'\ny\nF\n\"",
		"tool \"A=1; \\\ncat <<'E'\nx\nE\nB=2; cat <<'F'\ny\nF\n\"",
		"cat <<'E'\nx\nE\ntool \"B=2; cat <<'F'\ny\nF\n\"",
		gap0930Shape(3),
	} {
		end := 0
		quotes := make([]byte, len(command)-end)
		for at := range quotes {
			quotes[at] = unreadQuote
		}
		tokenScan(command[end:], func(at int, quote byte) { quotes[at] = quote })
		quoteAt := func(at int) byte { return quotes[at-end] }
		var trunc bounded.Truncated
		budget := bounded.NewCounter(&trunc, bounded.Bytes, 1<<30)
		docs := quotedHereDocs(command, end, &budget)
		if len(docs) == 0 {
			t.Fatalf("row %d: no here-document in %q", index, command)
		}
		var openers []int
		for opener := end; ; opener++ {
			i := strings.Index(command[opener:], "<<'")
			if i < 0 {
				break
			}
			opener += i
			openers = append(openers, opener)
		}
		if len(openers) != len(docs) {
			t.Fatalf("row %d: %d openers, %d here-documents", index, len(openers), len(docs))
		}
		for at, doc := range docs {
			want, wantKnown := scriptOfOneParsePerOpener(command, end, hereDocConsumerStart(command, openers[at]), quoteAt)
			if doc.script != want || doc.scriptKnown != wantKnown {
				t.Errorf("row %d doc %d: script %q known %v, want %q known %v", index, at, doc.script, doc.scriptKnown, want, wantKnown)
			}
		}
	}
}
