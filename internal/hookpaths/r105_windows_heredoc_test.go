// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestR105WindowsQuotedHeredocIsText (GAP-2397, GAP-1779 review row RV2-1):
// on a Windows home the Git Bash reading treats a here-document with a
// quoted delimiter (<<'EOF', << "EOF", <<\EOF, <<-'EOF') as text, so a
// script that only mentions a key read is not a key read. An unquoted
// delimiter's body is expanded and still blocks, a real read after the
// delimiter line still blocks, and a << inside a comment or a double-quoted
// string is not a here-document. Text after an unterminated Git Bash
// backtick never runs (a PowerShell escape such as "`$(...)" is literal).
func TestR105WindowsQuotedHeredocIsText(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, tc := range []struct {
		command string
		want    bool
	}{
		// Benign: quoted-delimiter bodies are not expanded.
		{"cat > notes.txt <<'EOF2'\n$(cat ~/.ssh/id_rsa)\nEOF2", false},
		{"cat > deploy.sh << \"EOF\"\nKEY=$(cat ~/.ssh/id_ed25519)\nEOF", false},
		{"cat > deploy.sh <<\\EOF\nKEY=$(cat ~/.ssh/id_ed25519)\nEOF", false},
		{"cat > deploy.sh <<-'EOF'\n\tKEY=$(cat ~/.ssh/id_ed25519)\n\tEOF\necho done", false},
		{"cat > deploy.sh <<E\"O\"F\r\nKEY=$(cat ~/.ssh/id_ed25519)\r\nEOF\r\n", false},
		{"cat > a <<'A' > b <<'B'\n$(cat ~/.ssh/id_rsa)\nA\n$(cat ~/.ssh/id_ed25519)\nB", false},
		{"Write-Output \"`$(Get-Content ~/.ssh/id_ed25519)\"", false},
		{"cat > d.sh <<$'EOF'\n$(cat ~/.ssh/id_ed25519)\nEOF", false},
		{"cat > d.sh <<$\"EOF\"\nKEY=$(cat ~/.ssh/id_ed25519)\nEOF\necho ok", false},
		// Still key reads.
		{"cat > deploy.sh <<EOF\nKEY=$(cat ~/.ssh/id_ed25519)\nEOF", true},
		{"cat > notes.txt <<'EOF'\nhello\nEOF\necho \"$(cat ~/.ssh/id_rsa)\"", true},
		{"cat > a <<'A' > b <<'B'\nx\nA\ny\nB\necho $(cat ~/.ssh/id_rsa)", true},
		{"cat > notes.txt <<'EOF'\nEOF2\n EOF\nEOF\n$(cat ~/.ssh/id_rsa)", true},
		{"# cat <<'EOF'\necho $(cat ~/.ssh/id_rsa)\nEOF", true},
		{"echo \"<<'EOF'\"\necho $(cat ~/.ssh/id_rsa)\nEOF", true},
		{"cat <<< \"$(cat ~/.ssh/id_rsa)\"", true},
		// RV3-1: ANSI-C/locale-quoted delimiters end at the unquoted word, and a
		// delimiter line that is never found keeps the rest scanned.
		{"cat > d.sh <<$'EOF'\nhello\nEOF\necho $(cat ~/.ssh/id_ed25519)", true},
		{"cat > d.sh <<$'EOF'\nhello\nEOF\necho \"$(cat ~/.ssh/id_ed25519)\"", true},
		{"cat > d.sh <<$\"EOF\"\nhello\nEOF\necho $(cat ~/.ssh/id_ed25519)", true},
		{"cat > d.sh <<$'E\\x4fF'\nhello\nEOF\necho $(cat ~/.ssh/id_ed25519)", true},
		{"cat > notes.txt <<'EOF'\n$(cat ~/.ssh/id_rsa)", true},
		{"echo `date` $(cat ~/.ssh/id_rsa)", true},
		{"Write-Output \"a`nb $(Get-Content ~/.ssh/id_ed25519)\"", true},
		// RV4-1: an unquoted here-document before a quoted one on the same
		// line keeps its expanded body scanned.
		{"cat <<B; cat <<'A'\n$(cat ~/.ssh/id_ed25519)\nB\nhello\nA", true},
		{"cat <<B <<'A'\n$(cat ~/.ssh/id_ed25519)\nB\nhello\nA", true},
		{"cat <<B > x; cat <<'A' > y\necho $(cat ~/.ssh/id_rsa)\nB\nhello\nA\necho done", true},
		// RV5-1: PowerShell has no here-documents; after the stop-parsing
		// token --% the rest of the line is verbatim text and the next line
		// runs.
		{"cmd /c echo --% <<'A'\necho $(Get-Content ~/.ssh/id_ed25519)\nA", true},
		{"cmd /c echo --% <<'A'\nWrite-Output (Get-Content ~/.ssh/id_ed25519)\nA", true},
		{"cmd /c echo --% don't\nWrite-Output (Get-Content ~/.ssh/id_ed25519)", true},
		{"cmd /c echo --% <<'A'\nhello\nA", false},
		// RV5-2: a << inside ${...}, arithmetic or a subscript is not a
		// here-document, and the bodies start after the line that ends the
		// command.
		{"echo ${x/<<\"A\"/}\necho $(cat ~/.ssh/id_ed25519)\nA/}", true},
		{"echo $((1<<\"2\"))\necho $(cat ~/.ssh/id_ed25519)\n2", true},
		{"echo $((1<<\"2\"))\necho \"$(cat ~/.ssh/id_ed25519)\"\n2", true},
		{"((x=1<<\"2\"))\necho $(cat ~/.ssh/id_ed25519)\n2", true},
		{"a[1<<\"2\"]=x\necho $(cat ~/.ssh/id_ed25519)\n2", true},
		{"cat <<'A' $(echo x\necho $(cat ~/.ssh/id_ed25519) >&2)\nhello\nA", true},
		{"echo $((1<<2)); cat > notes.txt <<'EOF'\n$(cat ~/.ssh/id_rsa)\nEOF", false},
		// RV6-1: in PowerShell only a << that starts a token is a parse
		// error; inside a bareword or a braced variable name it is text and
		// the rest of the command runs.
		{"${<<} = 1; Write-Output (Get-Content ~/.ssh/id_ed25519)", true},
		{"${a<<b} = 1\nWrite-Output (Get-Content ~/.ssh/id_ed25519)", true},
		{"Write-Output a<<b; Write-Output (Get-Content ~/.ssh/id_ed25519)", true},
		{"{}#<<\nWrite-Output (Get-Content ~/.ssh/id_ed25519)", true},
		{"Write-Output a#<<\nWrite-Output (Get-Content ~/.ssh/id_ed25519)", true},
		{"${a'b} = 1; Write-Output (Get-Content ~/.ssh/id_ed25519)", true},
		{"Write-Output a<<b; Write-Output (Get-Content .\\notes.txt)", false},
		{"${a<<b} = 1; Write-Output ${a<<b}", false},
		{"echo ${x:-a}; cat > notes.txt <<'EOF'\n$(cat ~/.ssh/id_rsa)\nEOF", false},
	} {
		if got := ActionPrivateKeyRead(tc.command, cwd, home); got != tc.want {
			t.Errorf("ActionPrivateKeyRead(%q) = %t, want %t", tc.command, got, tc.want)
		}
	}
}
