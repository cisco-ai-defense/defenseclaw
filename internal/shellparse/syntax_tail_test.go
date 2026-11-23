// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// rel-1-0-10:GAP-0526: the readable statements of a text with a plain syntax
// error.
func TestReadSyntaxTail(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		want          []string
	}{
		{"closing keyword on the next line", "echo a\nfi", []string{"echo a"}},
		{"closing keyword on the same line", "echo a; fi", []string{"echo a"}},
		{"closing keyword after a list operator", "echo a && fi", []string{"echo a"}},
		{"stray bracket after the last word", "echo a )", []string{"echo a"}},
		{"unclosed quote after the last word", "echo a 'b", []string{"echo a"}},
		{"unclosed substitution", "echo a $(", []string{"echo a"}},
		{"state kept in the prefix", "cd /tmp\necho a\ndone", []string{"cd /tmp\necho a"}},
		{"statement after the error", "fi\necho b", []string{"echo b"}},
		{"statements on both sides", "echo a\ndone\necho b; esac\necho c", []string{"echo a", "echo b", "echo c"}},
		{"multi-line statement after the error", "fi\nif true; then\necho b\nfi", []string{"if true; then\necho b\nfi"}},
		{"separator inside quotes is data", "fi\necho 'x; y'", []string{"echo 'x; y'"}},
		{"nothing readable", "fi", nil},
		// The longest parsable prefix ends before the quote: the statement it
		// opens keeps its words before it.
		{"unclosed quote to the end", "echo a\necho 'b\necho c", []string{"echo a\necho"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tail, ok := ReadSyntaxTail(tc.command)
			if !ok {
				t.Fatalf("ReadSyntaxTail(%q) not ok", tc.command)
			}
			if !slices.Equal(tail.Statements, tc.want) {
				t.Fatalf("ReadSyntaxTail(%q) = %q, want %q", tc.command, tail.Statements, tc.want)
			}
			for _, statement := range tail.Statements {
				if _, parsed := Parse(statement); !parsed {
					t.Errorf("statement %q does not parse", statement)
				}
			}
			if tail.Truncated.Any() {
				t.Errorf("truncated: %s", tail.Truncated.Reason())
			}
		})
	}
}

// A text that parses, one past the reading budget, invalid UTF-8 and the
// parser fault text of GAP-0437 keep their own paths.
func TestReadSyntaxTailLeavesOtherPathsAlone(t *testing.T) {
	for name, command := range map[string]string{
		"parses":       "echo a; echo b",
		"bash only":    "cat <(echo a)",
		"empty":        "  \n ",
		"invalid utf8": "echo a\nfi\xff",
		"too deep":     strings.Repeat("(", MaxNestingDepth+8) + "fi",
	} {
		if tail, ok := ReadSyntaxTail(command); ok {
			t.Errorf("%s: ReadSyntaxTail = %q, want not ok", name, tail.Statements)
		}
	}
}

// The reading stops at its caps and says so; what it read before is kept.
func TestReadSyntaxTailCaps(t *testing.T) {
	command := strings.Repeat("echo a\nfi\n", MaxSyntaxTailStatements+10)
	tail, ok := ReadSyntaxTail(command)
	if !ok {
		t.Fatal("not ok")
	}
	// The statement cap or the parse budget stops it, whichever comes first.
	if len(tail.Statements) == 0 || len(tail.Statements) > MaxSyntaxTailStatements ||
		!tail.Truncated.Has(bounded.Items) && !tail.Truncated.Has(bounded.Bytes) {
		t.Fatalf("statements %d truncated %q, want at most %d and a cap", len(tail.Statements), tail.Truncated.Reason(), MaxSyntaxTailStatements)
	}
	pieces := strings.Repeat("fi;", maxSyntaxTailPieces+10) + "echo z"
	tail, ok = ReadSyntaxTail(pieces)
	if !ok || !tail.Truncated.Has(bounded.Items) {
		t.Fatalf("pieces past the cap: ok %v truncated %q, want the items cap", ok, tail.Truncated.Reason())
	}
}

func FuzzReadSyntaxTail(f *testing.F) {
	for _, seed := range []string{"echo a\nfi", "echo a )", "fi\necho b", "echo 'a\nfi", "h=$((t d", "a && b ||"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, command string) {
		if len(command) > 4096 {
			return
		}
		tail, ok := ReadSyntaxTail(command)
		if !ok {
			return
		}
		if len(tail.Statements)-len(tail.Extended) > MaxSyntaxTailStatements || len(tail.Extended) > MaxSyntaxTailStatements {
			t.Fatalf("%d statements (%d of the longer reading) past the caps", len(tail.Statements), len(tail.Extended))
		}
		for _, statement := range tail.Statements {
			if strings.TrimSpace(statement) == "" || !strings.Contains(command, statement) {
				t.Fatalf("statement %q is not a part of the text", statement)
			}
			if _, parsed := Parse(statement); !parsed {
				t.Fatalf("statement %q does not parse", statement)
			}
		}
	})
}

// rel-1-0-10:GAP-0745 and GAP-0746: text past the run window that no
// statement can be read from is not a cap (the call keeps its detection-only
// record), and a here-document body stays in its statement.
func TestReadSyntaxTailWindowIsARecordAndHereDocsAreData(t *testing.T) {
	long := "fi\nif true\n" + strings.Repeat("then\n", syntaxTailRunWindow+2) + "x"
	if tail, ok := ReadSyntaxTail(long); !ok || tail.Truncated.Any() {
		t.Errorf("a statement past the run window: ok %v truncated %q, want no cap", ok, tail.Truncated.Reason())
	}
	heredoc := "fi\ncat <<'EOF'\n" + strings.Repeat("echo data\n", syntaxTailRunWindow+3) + "EOF\necho c"
	tail, ok := ReadSyntaxTail(heredoc)
	if !ok || slices.Contains(tail.Statements, "echo data") || !slices.Contains(tail.Statements, "echo c") {
		t.Errorf("a here-document after the error: %q, want its body kept as data and the next statement read", tail.Statements)
	}
}

// gap0876Script is the GAP-0876 shape: program's single-quoted argument holds
// a script whose command consumer reads a quoted here-document (<<'EOF'
// spelled inside the argument) with body as its lines. The first body line
// has a lone apostrophe that closes the argument's quote, so the outer text
// has a syntax error at its parenthesis and the next body lines are outside
// quotes for the token split.
func gap0876Script(program, consumer, body string) string {
	return program + " '" + consumer + " <<'\"'\"'EOF'\"'\"'\nit's (x)\n" + body + "\nEOF\necho after'"
}

// rel-1-0-10:GAP-0876: the runs of a quoted here-document body after the
// error are its command's input, kept apart with that command, not
// statements of the text; a here-document whose body is not closed is not
// one.
func TestReadSyntaxTailQuotedHereDocBodyIsItsCommandsInput(t *testing.T) {
	for _, tc := range []struct {
		name, command, consumer string
	}{
		{"in an argument", gap0876Script("tool -", "cat > notes.txt", "echo data"), "cat > notes.txt"},
		{"piped on", "tool - 'cat <<'\"'\"'EOF'\"'\"' | sh\nit's (x)\necho data\nEOF\necho after'", "cat | sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tail, ok := ReadSyntaxTail(tc.command)
			if !ok {
				t.Fatalf("%q: not read", tc.command)
			}
			if slices.Contains(tail.Statements, "echo data") {
				t.Errorf("the body is read as a statement of the text: %q", tail.Statements)
			}
			if len(tail.HereDocs) != 1 || tail.HereDocs[0].Consumer != tc.consumer ||
				!slices.Contains(tail.HereDocs[0].Statements, "echo data") {
				t.Errorf("here-documents %+v, want one of %q holding echo data", tail.HereDocs, tc.consumer)
			}
		})
	}
	unclosed := "tool '" + "cat <<'\"'\"'EOF'\"'\"'\nit's (x)\necho data\n'"
	if tail, ok := ReadSyntaxTail(unclosed); !ok || len(tail.HereDocs) != 0 || !slices.Contains(tail.Statements, "echo data") {
		t.Errorf("a body that is not closed: %+v, want its lines read as statements", tail)
	}
	if tail, ok := ReadSyntaxTail("fi\ncat <<EOF\necho data\nEOF"); ok && len(tail.HereDocs) != 0 {
		t.Errorf("an unquoted here-document is kept apart: %+v", tail.HereDocs)
	}
}

// rel-1-0-10:GAP-0745: a statement of more pieces than the run window is
// read whole (with the statements the parser completes after it), and the cut-back reads the part of the statement with the
// error before it past its word steps; neither stops silently.
func TestReadSyntaxTailReadsPastTheWindowAndTheWordSteps(t *testing.T) {
	loop := "for i in 1; do touch a.txt" + strings.Repeat("; :", 3*syntaxTailRunWindow) + "; done"
	tail, ok := ReadSyntaxTail("fi\n" + loop + "\necho c")
	if !ok || tail.Truncated.Any() || !slices.ContainsFunc(tail.Statements, func(s string) bool { return strings.HasPrefix(s, loop) }) || !slices.Contains(tail.Statements, "echo c") {
		t.Errorf("a loop past the run window: ok %v truncated %q statements %q, want it read whole", ok, tail.Truncated.Reason(), tail.Statements)
	}
	words := strings.Repeat(" w", 3*syntaxTailRunWindow)
	tail, ok = ReadSyntaxTail("echo ok; touch done.txt `" + words)
	if !ok || tail.Truncated.Any() || !slices.ContainsFunc(tail.Statements, func(s string) bool { return strings.HasSuffix(s, "touch done.txt") }) {
		t.Errorf("an unclosed backquote past the word steps: ok %v truncated %q statements %q, want the command before it read", ok, tail.Truncated.Reason(), tail.Statements)
	}
}
