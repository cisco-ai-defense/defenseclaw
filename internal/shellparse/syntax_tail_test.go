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
		if len(tail.Statements) > MaxSyntaxTailStatements {
			t.Fatalf("%d statements past the cap", len(tail.Statements))
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

// rel-1-0-10:GAP-0745 (lead ruling (a)) and GAP-0746: a statement longer
// than the run window is left unread without a cap (the call keeps its
// detection-only record), and a here-document body stays in its statement.
func TestReadSyntaxTailWindowIsARecordAndHereDocsAreData(t *testing.T) {
	long := "fi\nif true\n" + strings.Repeat("then\n", maxSyntaxTailRun+2) + "x"
	if tail, ok := ReadSyntaxTail(long); !ok || tail.Truncated.Any() {
		t.Errorf("a statement past the run window: ok %v truncated %q, want no cap", ok, tail.Truncated.Reason())
	}
	heredoc := "fi\ncat <<'EOF'\n" + strings.Repeat("echo data\n", maxSyntaxTailRun+3) + "EOF\necho c"
	tail, ok := ReadSyntaxTail(heredoc)
	if !ok || slices.Contains(tail.Statements, "echo data") || !slices.Contains(tail.Statements, "echo c") {
		t.Errorf("a here-document after the error: %q, want its body kept as data and the next statement read", tail.Statements)
	}
}
