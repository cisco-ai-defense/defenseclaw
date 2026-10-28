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
		{"cat > notes.txt <<'EOF'\n$(cat ~/.ssh/id_rsa)", false},
		{"cat > a <<'A' > b <<'B'\n$(cat ~/.ssh/id_rsa)\nA\n$(cat ~/.ssh/id_ed25519)\nB", false},
		{"Write-Output \"`$(Get-Content ~/.ssh/id_ed25519)\"", false},
		// Still key reads.
		{"cat > deploy.sh <<EOF\nKEY=$(cat ~/.ssh/id_ed25519)\nEOF", true},
		{"cat > notes.txt <<'EOF'\nhello\nEOF\necho \"$(cat ~/.ssh/id_rsa)\"", true},
		{"cat > a <<'A' > b <<'B'\nx\nA\ny\nB\necho $(cat ~/.ssh/id_rsa)", true},
		{"cat > notes.txt <<'EOF'\nEOF2\n EOF\nEOF\n$(cat ~/.ssh/id_rsa)", true},
		{"# cat <<'EOF'\necho $(cat ~/.ssh/id_rsa)\nEOF", true},
		{"echo \"<<'EOF'\"\necho $(cat ~/.ssh/id_rsa)\nEOF", true},
		{"cat <<< \"$(cat ~/.ssh/id_rsa)\"", true},
		{"echo `date` $(cat ~/.ssh/id_rsa)", true},
		{"Write-Output \"a`nb $(Get-Content ~/.ssh/id_ed25519)\"", true},
	} {
		if got := ActionPrivateKeyRead(tc.command, cwd, home); got != tc.want {
			t.Errorf("ActionPrivateKeyRead(%q) = %t, want %t", tc.command, got, tc.want)
		}
	}
}
