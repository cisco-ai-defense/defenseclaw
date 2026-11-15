package shellparse

import (
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0890. A here-document opener spelled inside a string that
// the shell closes on the opener line is text: the lines after it stay
// statements of the text. The opener of a script passed as one quoted
// argument (the argument still open at the end of the opener line) keeps
// its body apart (GAP-0876).
func TestReadSyntaxTailOpenerInsideAClosedStringIsText(t *testing.T) {
	for _, command := range []string{
		"fi\necho \"a <<'X'\"\ntouch y\nX",                // the reviewer's repro (s7-p3rev)
		"fi\necho 'a <<\"X\"'\ntouch y\nX",                // single-quoted string
		"fi\nprintf '%s' \"x\" \"a <<'X'\" z\ntouch y\nX", // not the first argument
		"fi\necho \"a <<'X'\" | cat\ntouch y\nX",          // a pipe after the string
	} {
		tail, ok := ReadSyntaxTail(command)
		if !ok {
			t.Fatalf("%q: not read", command)
		}
		if !slices.Contains(tail.Statements, "touch y") || len(tail.HereDocs) != 0 {
			t.Errorf("%q: statements %q, here-documents %+v; want touch y read as a statement",
				command, tail.Statements, tail.HereDocs)
		}
	}
	tail, ok := ReadSyntaxTail(gap0876Script("tool -", "cat > notes.txt", "echo data"))
	if !ok || len(tail.HereDocs) != 1 || slices.Contains(tail.Statements, "echo data") {
		t.Errorf("the GAP-0876 argument shape: %+v, want its body kept apart", tail)
	}
}

// rel-1-0-10:GAP-0903. A here-document opener in a comment or in an ANSI-C
// string ($'...', whose \' does not close it) is text: the next lines stay
// statements. A real opener after a comment line, and a comment after a real
// opener, keep the body in the opener's piece (GAP-0746).
func TestReadSyntaxTailOpenerInACommentOrAnsiStringIsText(t *testing.T) {
	for _, command := range []string{
		"fi\n# a <<'X'\ntouch y\nX",
		"fi\necho $'a\\' <<'X\ntouch y\nX",
		"fi\necho x # it's a <<'X'\ntouch y\nX",
	} {
		tail, ok := ReadSyntaxTail(command)
		if !ok {
			t.Fatalf("%q: not read", command)
		}
		if !slices.Contains(tail.Statements, "touch y") || len(tail.HereDocs) != 0 {
			t.Errorf("%q: statements %q, here-documents %+v; want touch y read as a statement",
				command, tail.Statements, tail.HereDocs)
		}
	}
	for _, command := range []string{
		"fi\n# note\ncat <<'X'\ntouch y\nX",
		"fi\ncat <<'X' # note\ntouch y\nX",
		"fi\necho a#b; cat <<'X'\ntouch y\nX",
	} {
		tail, ok := ReadSyntaxTail(command)
		if !ok || slices.Contains(tail.Statements, "touch y") {
			t.Errorf("%q: %+v, want the body kept in the opener's piece", command, tail)
		}
	}
}
