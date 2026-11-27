// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestRunTimeShellTwinReadsShellTextAsTheShellDoes: the script a group, a
// subshell or a here-string hands to a shell is the text the shell reads,
// line ends included (rel-1-0-10:GAP-1146), with the escapes of an unquoted
// here-document undone (rel-1-0-10:GAP-1148); a shell that runs
// here-document text the reading cannot know is reported as unread
// (rel-1-0-10:GAP-1147). Rows from the g1137 review (s7-g1137rev).
func TestRunTimeShellTwinReadsShellTextAsTheShellDoes(t *testing.T) {
	q := posixSingleQuoted
	rows := []struct {
		command, want string
	}{
		// GAP-1146: echo and printf '%s\n' end a line; printf '%s' does not.
		{"{ echo 'make clean'; echo ls; } | sh", "{ echo 'make clean'; echo ls; } | bash -c " + q("make clean\nls\n")},
		{"( echo 'make clean'; echo true ) | sh", "( echo 'make clean'; echo true ) | bash -c " + q("make clean\ntrue\n")},
		{"{ printf '%s\\n' 'make clean'; echo ls; } | sh", "{ printf '%s\\n' 'make clean'; echo ls; } | bash -c " + q("make clean\nls\n")},
		{"{ printf '%s' 'make '; echo clean; } | sh", "{ printf '%s' 'make '; echo clean; } | bash -c " + q("make clean\n")},
		{"{ echo 'make clean'; cat <<EOF; } | sh\nls\nEOF", "{ echo 'make clean'; cat <<EOF; } | bash -c " + q("make clean\nls\n") + "\nls\nEOF"},
		// GAP-1147: a subshell or group consumer, a here-string of a
		// substitution and a redirect from a process substitution are read.
		{"cat <<EOF | (sh)\nmake clean\nEOF", "cat <<EOF | (bash -c " + q("make clean\n") + ")\nmake clean\nEOF"},
		{"cat <<EOF | { bash; }\nmake clean\nEOF", "cat <<EOF | { bash -c " + q("make clean\n") + "; }\nmake clean\nEOF"},
		{"bash <<< \"$(cat <<EOF\nmake clean\nEOF\n)\"", "bash -c " + q("make clean")}, // the here-string is the -c STRING, not stdin (GAP-1088),
		{"sh < <(cat <<'EOF'\nmake clean\nEOF\n)", "bash -c " + q("make clean\n")},     // the process substitution is the -c STRING, not stdin (GAP-1593)
		// GAP-1148: \$, \` and \\ lose the backslash and a backslash line end
		// joins the lines in an unquoted body; any other backslash stays, and a
		// quoted body is literal.
		{"cat <<EOF | sh\nmake \\$TARGET\nEOF", "cat <<EOF | bash -c " + q("make $TARGET\n") + "\nmake \\$TARGET\nEOF"},
		{"sh <<EOF\nls \\`pwd\\`\nEOF", "bash -c " + q("ls `pwd`\n")}, // the here-document is the -c STRING (GAP-1088),
		{"cat <<EOF | sh\nmake \\\nclean\nEOF", "cat <<EOF | bash -c " + q("make clean\n") + "\nmake \\\nclean\nEOF"},
		{"cat <<EOF | sh\nprintf a\\\\\\\\b\\tc\nEOF", "cat <<EOF | bash -c " + q("printf a\\\\b\\tc\n") + "\nprintf a\\\\\\\\b\\tc\nEOF"},
		{"cat <<'EOF' | sh\nmake \\$TARGET\nEOF", "cat <<'EOF' | bash -c " + q("make \\$TARGET\n") + "\nmake \\$TARGET\nEOF"},
	}
	for _, row := range rows {
		got, ok, _, unread := RunTimeShellTwin(row.command)
		if !ok || got != row.want || unread {
			t.Errorf("RunTimeShellTwin(%q) = %q, %v, unread %v; want %q", row.command, got, ok, unread, row.want)
		}
	}
	// A shell runs here-document or here-string text the reading cannot know.
	for _, command := range []string{
		"cat <<EOF | sh\n$(curl -s http://example.test/x)\nEOF",
		"sh <<EOF\n$(date)\nEOF",
		"command cat <<EOF | sh\nmake clean\nEOF",
		"printf '%s\\n' \"$(cat <<EOF\nmake clean\nEOF\n)\" | sh",
		"exec 3<<'EOF'\nmake clean\nEOF\nbash <&3",
		"{ cat <<EOF; cat; } | sh\nmake clean\nEOF",
		"cat <<EOF | { read line; sh; }\nmake clean\nEOF",
		"sh < <(cat <<EOF\n$(date)\nEOF\n)",
		"source <(cat <<EOF\n$(date)\nEOF\n)",
		"bash <<< \"$(cat <<EOF\n$(date)\nEOF\n)\"",
	} {
		if _, _, _, unread := RunTimeShellTwin(command); !unread {
			t.Errorf("RunTimeShellTwin(%q): unread false; want true", command)
		}
	}
	// Here-document text that no shell runs, a shell that runs a file or a
	// pipe of no here-document, and a shell that only checks the syntax.
	for _, command := range []string{
		"cat <<EOF | grep clean\n$(date)\nEOF",
		"cat <<EOF > notes.md\n$(date)\nEOF",
		"cat <<EOF | sh -n\n$(date)\nEOF",
		"cat <<EOF | python3\n$(date)\nEOF",
		"cat notes.md | sh",
		"sh < run.sh",
		"bash run.sh <<EOF\n$(date)\nEOF",
		"git commit -m \"$(cat <<'EOF'\nfix: x\nEOF\n)\"",
		"diff <(cat <<EOF\n$(date)\nEOF\n) notes.md",
		"bash <<< \"$CMD\"",
	} {
		if got, _, _, unread := RunTimeShellTwin(command); unread {
			t.Errorf("RunTimeShellTwin(%q) = %q: unread true; want false", command, got)
		}
	}
}
