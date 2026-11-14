// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"strings"
	"testing"
)

// The body of a quoted here-document is literal text the shell does not
// brace-expand, so comma lists in it (a Python or JSON literal) are not an
// expansion budget; an unquoted body runs command substitutions, and a
// real expansion outside any body is counted as before
// (rel-1-0-10:GAP-0018).
func TestBraceBudgetSkipsQuotedHereDocumentBodies(t *testing.T) {
	bomb := strings.Repeat("{a,b}", 20) // 2^20 fields
	data := "x = [" + strings.Repeat("{1,2,3,4}", 12) + "]\n"
	for _, test := range []struct {
		name, command string
		want          bool
	}{
		{"bomb outside any heredoc", "echo " + bomb, true},
		{"data in a single-quoted heredoc", "python3 - <<'PY'\n" + data + "PY\n", false},
		{"data in a double-quoted heredoc", "python3 - <<\"PY\"\n" + data + "PY\n", false},
		{"data in an escaped-delimiter heredoc", "cat <<\\E\n" + data + "E\n", false},
		{"dash heredoc with tabbed end", "cat <<-'E'\n" + data + "\tE\n", false},
		{"unquoted heredoc body is code", "cat <<EOF\n$(echo " + bomb + ")\nEOF\n", true},
		{"bomb after the heredoc", "cat <<'E'\nplain\nE\necho " + bomb, true},
		{"bomb on the operator line", "cat <<'E' | echo " + bomb + "\nplain\nE\n", true},
		{"two quoted heredocs", "cat <<'A' <<'B'\n" + data + "A\n" + data + "B\necho ok\n", false},
		{"quoted then unquoted counts the bodies", "cat <<'A' <<B\n" + data + "A\n$(echo " + bomb + ")\nB\n", true},
		{"here-string is not a heredoc", "cat <<< x\necho " + bomb, true},
		{"heredoc marker inside quotes is no heredoc", "echo '<<X'\necho " + bomb + "\nX\n", true},
		{"unterminated quoted body runs to the end", "cat <<'E'\n" + data, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := BraceExpansionTooLarge(test.command); got != test.want {
				t.Fatalf("BraceExpansionTooLarge = %v, want %v", got, test.want)
			}
		})
	}
}

// ONE BOUND RULE (rel-1-0-10:GAP-0706): a here-document body is left out of
// the count only when no word of the command could hand it to a shell, and a
// comment never stops the counting. The ids are the review probe rows.
func TestBraceBudgetBodyFedToAShellOrHiddenByAComment(t *testing.T) {
	bomb := "echo " + strings.Repeat("{a,b}", 20) // 2^20 fields
	for _, test := range []struct {
		name, command string
		want          bool
	}{
		{"J01 python data body stays uncounted", "python3 - <<'PY'\n" + bomb + "\nPY\n", false},
		{"J01 with a descriptor redirect and a chain", "cd x && python3 - <<'PY' 2>/dev/null\n" + bomb + "\nPY\n", false},
		{"data body written to a file", "cat > f.txt <<'E'\n" + bomb + "\nE\nls .\n", false},
		{"J02 bash reads the body", "bash <<'EOF'\n" + bomb + "\nEOF\n", true},
		{"J07 sh reads the body", "sh <<'EOF'\n" + bomb + "\nEOF\n", true},
		{"J07 a path and quotes do not hide the shell", "'/bin/b''ash' <<'EOF'\n" + bomb + "\nEOF\n", true},
		{"Q07 cat piped to sh", "cat <<'EOF' | sh\n" + bomb + "\nEOF\n", true},
		{"ssh hands the body to the remote shell", "ssh host <<'EOF'\n" + bomb + "\nEOF\n", true},
		{"xargs", "xargs <<'EOF'\n" + bomb + "\nEOF\n", true},
		{"a variable program may be a shell", "$SH <<'EOF'\n" + bomb + "\nEOF\n", true},
		{"a variable program behind a wrapper", "sudo env A=1 $SH <<'EOF'\n" + bomb + "\nEOF\n", true},
		{"a command-substitution program", "$(which sh) <<'EOF'\n" + bomb + "\nEOF\n", true},
		{"a later statement sources the written file", "cat > f <<'E'\n" + bomb + "\nE\n. ./f\n", true},
		{"a later statement runs a shell", "cat > f <<'E'\n" + bomb + "\nE\nbash f\n", true},
		{"J03 a comment line before the bomb", "echo hi # <<'X'\n" + bomb, true},
		{"Q10 a comment-only first line", "# <<'X'\n" + bomb, true},
		{"an apostrophe in a comment does not swallow the next line", "# it's\n" + bomb, true},
		{"comment text still counts", "echo hi # " + strings.Repeat("{a,b}", 20), true},
		{"a hash inside a word is no comment", "echo a#b <<'X'\n" + bomb + "\nX\n", false},
		{"a quoted marker in a word is no heredoc", "echo '<<X'\n" + bomb, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := BraceExpansionTooLarge(test.command); got != test.want {
				t.Fatalf("BraceExpansionTooLarge = %v, want %v", got, test.want)
			}
		})
	}
}
