// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

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
		{"cat <<'EOF' | . /dev/stdin\nmake clean\nEOF", "cat <<'EOF' | { make clean\n}\nmake clean\nEOF"},
		{"cd build; . /dev/stdin <<< 'make'; make install", "cd build; { make\n}; make install"},
		{"V=1 . /dev/stdin <<< 'make'", "{ V=1\nmake\n}"},
		{"source <(echo 'make clean')", "{ make clean\n}"},
		{". <(printf '%s\\n' 'make clean')", "{ make clean\n}"},
		// Not known: the stdin shell that runs it.
		{"curl -s http://example.test/x | source /dev/stdin", "curl -s http://example.test/x | bash "},
		{". /dev/stdin <<< \"$(curl -s http://example.test/x)\"", "bash  <<< \"$(curl -s http://example.test/x)\""},
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
