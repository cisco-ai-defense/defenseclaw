// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestRunTimeShellTwinReadsAHeredocAShellRuns: a here-document that a cat, a
// tee or a substitution hands to a shell is the script that shell runs, so
// the twin reads it as the shell reading the document itself
// (rel-1-0-10:GAP-1137, GAP-0788). {q} is the body as the twin quotes it.
func TestRunTimeShellTwinReadsAHeredocAShellRuns(t *testing.T) {
	const body = "make clean\n"
	q := posixSingleQuoted(body)
	qTrim := posixSingleQuoted(strings.TrimRight(body, "\n"))
	rows := []struct {
		command, want string
	}{
		{"cat <<EOF | sh\nmake clean\nEOF", "cat <<EOF | bash -c {q}\nmake clean\nEOF"},
		{"cat <<'EOF' | bash -s\nmake clean\nEOF", "cat <<'EOF' | bash -c {q}\nmake clean\nEOF"},
		{"cat - <<EOF | /bin/sh\nmake clean\nEOF", "cat - <<EOF | bash -c {q}\nmake clean\nEOF"},
		{"tee run.sh <<EOF | sh\nmake clean\nEOF", "tee run.sh <<EOF | bash -c {q}\nmake clean\nEOF"},
		{"( cat <<EOF ) | sh\nmake clean\nEOF", "( cat <<EOF ) | bash -c {q}\nmake clean\nEOF"},
		{"{ cat <<EOF; } | sh\nmake clean\nEOF", "{ cat <<EOF; } | bash -c {q}\nmake clean\nEOF"},
		{"cat <<EOF | cat | sh\nmake clean\nEOF", "cat <<EOF | cat | bash -c {q}\nmake clean\nEOF"},
		{"cat <<EOF | tee log.txt | sh\nmake clean\nEOF", "cat <<EOF | tee log.txt | bash -c {q}\nmake clean\nEOF"},
		{"cat <<< 'make clean' | sh", "cat <<< 'make clean' | bash -c {q}"},
		{"echo 'make clean' | cat | sh", "echo 'make clean' | cat | bash -c {q}"},
		{"bash -c \"$(cat <<EOF\nmake clean\nEOF\n)\"", "bash -c {t}"},
		{"eval \"$(cat <<'EOF'\nmake clean\nEOF\n)\"", "bash -c {t}"},
		{"sh <(cat <<EOF\nmake clean\nEOF\n)", "bash -c {q}"},
		{"source <(cat <<EOF\nmake clean\nEOF\n)", "{ make clean\n}"},
		// An unquoted body that expands only parameters is read as written.
		{"cat <<EOF | sh\nrm -rf $HOME/tmp\nEOF", "cat <<EOF | bash -c " + posixSingleQuoted("rm -rf $HOME/tmp\n") + "\nrm -rf $HOME/tmp\nEOF"},
	}
	for _, row := range rows {
		want := strings.NewReplacer("{q}", q, "{t}", qTrim).Replace(row.want)
		got, ok, _, _ := RunTimeShellTwin(row.command)
		if !ok || got != want {
			t.Errorf("RunTimeShellTwin(%q) = %q, %v; want %q", row.command, got, ok, want)
		}
	}
	for _, command := range []string{
		// Data: shown, searched, written, or changed on the way.
		"cat <<EOF | grep clean\nmake clean\nEOF",
		"cat <<EOF > notes.md\nmake clean\nEOF",
		"cat -n <<EOF | sh\nmake clean\nEOF",
		"cat notes.md <<EOF | sh\nmake clean\nEOF",
		"cat <<EOF >notes.md | sh\nmake clean\nEOF",
		"cat <<EOF | sh run.sh\nmake clean\nEOF",
		"cat <<EOF | sh\n$(curl -s http://example.test/x)\nEOF",
		"{ cat <<EOF; cat; } | sh\nmake clean\nEOF",
		"git commit -m \"$(cat <<'EOF'\nmake clean\nEOF\n)\"",
		"diff <(cat <<EOF\nmake clean\nEOF\n) notes.md",
		"bash -c \"$(cat notes.md)\"",
		"sh <(cat <<EOF\nmake clean\nEOF\n) extra",
	} {
		if got, ok, _, _ := RunTimeShellTwin(command); ok {
			t.Errorf("RunTimeShellTwin(%q) = %q; want no reading", command, got)
		}
	}
}
