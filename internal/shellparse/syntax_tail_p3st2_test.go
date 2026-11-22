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

// rel-1-0-10:GAP-0913. A here-document opened inside a script passed as one
// quoted argument reports the script before its command, unquoted, so the
// consumer reading can parse what it binds; an expansion in it makes it not
// known. An opener outside quotes has no script of its own.
func TestReadSyntaxTailHereDocScript(t *testing.T) {
	for _, row := range []struct {
		consumer, script string
		known            bool
	}{
		{"cat > notes.txt", "", true},
		{"export PATH=/tmp/x; cat > notes.txt", "export PATH=/tmp/x;", true},
		{"export PA\"\"TH=/tmp/x; cat > notes.txt", "export PA\"\"TH=/tmp/x;", true},
		{"alias cat=sh; cat > notes.txt", "alias cat=sh;", true},
		{"cd /tmp && cat > notes.txt", "cd /tmp &&", true},
	} {
		tail, ok := ReadSyntaxTail(gap0876Script("tool -", row.consumer, "echo data"))
		if !ok || len(tail.HereDocs) != 1 {
			t.Fatalf("%q: %+v, want one here-document", row.consumer, tail)
		}
		if doc := tail.HereDocs[0]; doc.Script != row.script || doc.ScriptKnown != row.known {
			t.Errorf("%q: script %q known %v, want %q %v", row.consumer, doc.Script, doc.ScriptKnown, row.script, row.known)
		}
	}
	tail, ok := ReadSyntaxTail("tool - \"export PATH=$X; cat > notes.txt <<'EOF'\nit's (x\necho data\nEOF\necho after\"")
	if ok && len(tail.HereDocs) == 1 && tail.HereDocs[0].ScriptKnown {
		t.Errorf("a script with an expansion: %+v, want it not known", tail.HereDocs[0])
	}
}
