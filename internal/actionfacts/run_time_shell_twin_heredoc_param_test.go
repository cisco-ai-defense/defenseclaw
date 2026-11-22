// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestRunTimeShellTwinHeredocParametersAsTheHoldingShellExpands: the shell
// that holds an unquoted here-document expands its parameters before the
// shell it feeds parses the text, so the text is read with its parameters as
// written only where the running shell expands each of them the same way. A
// parameter inside single quotes, after an escaped backslash or in a quoted
// document of its own, a name the body binds, and a positional or special
// parameter make the text unknown, and a shell that runs it is unread
// (rel-1-0-10:GAP-1193). Rows from the g1137 round-2 review (s7-g1137rev2).
func TestRunTimeShellTwinHeredocParametersAsTheHoldingShellExpands(t *testing.T) {
	q := posixSingleQuoted
	piped := func(body string) (string, string) {
		return "cat <<EOF | sh\n" + body + "\nEOF", "cat <<EOF | bash -c "
	}
	direct := func(body string) (string, string) {
		return "sh <<EOF\n" + body + "\nEOF", "bash -c "
	}
	// Read as written: the running shell expands every parameter as the
	// holding shell does, or the body is quoted and literal.
	read := []struct {
		body, script string
	}{
		{"ls $HOME/x", "ls $HOME/x\n"},
		{"ls \"$HOME\"/x ${HOME}/y", "ls \"$HOME\"/x ${HOME}/y\n"},
		{"# in $HOME\nls", "# in $HOME\nls\n"},
		{"ls \\\\\\\\$HOME", "ls \\\\$HOME\n"},
		{"ls \\$HOME", "ls $HOME\n"},
	}
	for _, row := range read {
		for _, form := range []func(string) (string, string){piped, direct} {
			command, prefix := form(row.body)
			want := prefix + q(row.script) + "\n" + row.body + "\nEOF"
			if prefix == "bash -c " {
				// The here-document that supplies the script is the -c
				// STRING of the twin and not its stdin (rel-1-0-10:GAP-1088).
				want = prefix + q(row.script)
			}
			got, ok, _, unread := RunTimeShellTwin(command)
			if !ok || got != want || unread {
				t.Errorf("RunTimeShellTwin(%q) = %q, %v, unread %v; want %q", command, got, ok, unread, want)
			}
		}
	}
	quoted := "cat <<'EOF' | sh\nD=build\nmake -C $D\nEOF"
	if got, ok, _, unread := RunTimeShellTwin(quoted); !ok || unread ||
		got != "cat <<'EOF' | bash -c "+q("D=build\nmake -C $D\n")+"\nD=build\nmake -C $D\nEOF" {
		t.Errorf("RunTimeShellTwin(%q) = %q, %v, unread %v; want the literal body", quoted, got, ok, unread)
	}
	// Not read as written: unread, and no twin of the text as written.
	unknown := []string{
		"D=build\nmake -C $D",
		"X='a b'; printf '<%s>' $X",
		"ls '$HOME'/x",
		"ls \\\\$HOME/x",
		"for f in a b; do ls $f; done",
		"read n; ls $n",
		"((i++)); ls $i",
		"printf -v D %s x; ls $D",
		"ls ${D:=build}; ls $D",
		"ls ${HOME:-/tmp}/x",
		"ls $1",
		"ls $@",
		"cat <<'IN'\n$HOME\nIN",
	}
	for _, body := range unknown {
		for _, form := range []func(string) (string, string){piped, direct} {
			command, _ := form(body)
			if got, _, _, unread := RunTimeShellTwin(command); !unread {
				t.Errorf("RunTimeShellTwin(%q) = %q: unread false; want true", command, got)
			}
		}
	}
	// eval and a -c STRING of such a document run it too.
	for _, command := range []string{
		"eval \"$(cat <<EOF\nD=build\nmake -C $D\nEOF\n)\"",
		"bash -c \"$(cat <<EOF\nD=build\nmake -C $D\nEOF\n)\"",
	} {
		if got, _, _, unread := RunTimeShellTwin(command); !unread {
			t.Errorf("RunTimeShellTwin(%q) = %q: unread false; want true", command, got)
		}
	}
}
