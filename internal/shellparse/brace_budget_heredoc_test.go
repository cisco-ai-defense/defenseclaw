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
