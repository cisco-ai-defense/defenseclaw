// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hp4Rows are the rel-1-0-6 GAP-0311..0315 rows: writes, removals and mode
// changes of the keys file whose operand only the user's view resolves (a
// pattern bash expands in a redirect word, a text-built or brace word, a
// pwsh -Command body, a directory link) and a brace word past the field cap.
// Each must-block row has must-allow neighbours of the same shape. want ""
// is a logged probe.
var hp4Rows = []struct{ name, command, want string }{
	// GAP-0311: an unquoted expansion in a redirect word is a pattern.
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
	{"0311-assign-quoted-glob", "f='keyl*'; echo m >> $f", "alert"},
	{"0311-echo-quoted-glob", "f=$(echo 'keyl*'); echo m >> $f", "alert"},
	{"0311-assign-bare-glob", "f=keyl*; echo m >> $f", "alert"},
	{"0311-assign-glob-dirlink", "f='sshlink/authorized_k*'; echo m >> $f", "alert"},
	{"0311-literal-glob", "echo m >> keyl*", "alert"},
	{"0311-argument-glob", "f='keyl*'; touch $f", "alert"},
	{"0311-for-glob", "p='keyl*'; for f in $p; do echo k >> $f; done", "alert"},
	{"0311-allow-quoted-use", "f='keyl*'; echo m >> \"$f\"", "allow"},
	{"0311-allow-no-match", "f='notes*'; echo m >> $f", "allow"},
	{"0311-allow-ordinary-match", "f='a.t*'; echo m >> $f", "allow"},
	{"0311-allow-plain-var", "f=out.txt; echo m >> $f", "allow"},
	// GAP-0312: a redirect target built at run time onto a project link.
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
	{"0312-echo-e", "f=$(echo -e keylink); echo m >> \"$f\"", "alert"},
	{"0312-echo-brace", "f=$(echo {keylink,}); echo m >> \"$f\"", "alert"},
	{"0312-echo-brace-bare", "echo m >> $(echo {keylink,})", "alert"},
	{"0312-brace-redirect-one", "echo m >> {keylink,}", "alert"},
	{"0312-printf-target", "echo m >> $(printf %s keylink)", "alert"},
	{"0312-dirlink-subst", "echo m >> $(echo -e sshlink/authorized_keys)", "alert"},
	{"0312-allow-echo-e", "f=$(echo -e out.txt); echo m >> \"$f\"", "allow"},
	{"0312-allow-brace-one", "echo m >> {out.txt,}", "allow"},
	{"0312-allow-printf", "echo m >> $(printf %s out.txt)", "allow"},
	{"0312-allow-date", "echo m >> log-$(date +%s).txt", "allow"},
	// GAP-0313: a writer in a pwsh -Command body through a project link.
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
	{"0313-split-link-writer", "pwsh -Command Get-ChildItem keylink \";\" Add-Content keylink k", "alert"},
	{"0313-quoted-link-writer", "pwsh -Command \"Add-Content keylink k\"", "alert"},
	{"0313-quoted-dirlink-writer", "pwsh -Command \"Set-Content sshlink/authorized_keys k\"", "alert"},
	{"0313-out-file-link", "pwsh -c \"Get-Date | Out-File keylink\"", "alert"},
	{"0313-named-path-link", "pwsh -c \"Set-Content -Value k -Path keylink\"", "alert"},
	{"0313-named-literalpath-link", "pwsh -c \"Add-Content -Encoding utf8 -LiteralPath keylink -Value k\"", "alert"},
	{"0313-named-filepath-link", "pwsh -c \"Get-Date | Out-File -Encoding utf8 -FilePath keylink\"", "alert"},
	{"0313-positional-after-value-link", "pwsh -c \"Set-Content -Value k keylink\"", "alert"},
	{"0313-positional-after-encoding-link", "pwsh -c \"Add-Content -Encoding utf8 -Value k keylink\"", "alert"},
	{"0313-colon-path-link", "pwsh -c \"Set-Content -Path:keylink -Value k\"", "alert"},
	{"0313-colon-literalpath-link", "pwsh -c \"Add-Content -LiteralPath:keylink -Value k\"", "alert"},
	{"0313-colon-filepath-link", "pwsh -c \"Get-Date | Out-File -FilePath:keylink\"", "alert"},
	{"0313-allow-list-link", "pwsh -Command Get-ChildItem keylink", "allow"},
	{"0313-allow-read-link", "pwsh -Command \"Get-Content keylink\"", ""},
	{"0313-allow-writer-ordinary", "pwsh -Command \"Add-Content out.txt k\"", "allow"},
	{"0313-probe-value-link", "pwsh -c \"Set-Content -Value keylink -Path out.txt\"", ""},
	// GAP-0314: removal or mode change of the keys file through a link.
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
	{"0314-rm-dirlink", "rm sshlink/authorized_keys", "alert"},
	{"0314-rm-f-dirlink", "rm -f keylink sshlink/authorized_keys", "alert"},
	{"0314-find-delete", "find sshlink/ -name authorized_keys -delete", "alert"},
	{"0314-chmod-dirlink", "chmod 700 sshlink/authorized_keys", "alert"},
	{"0314-chmod-filelink", "chmod 666 keylink", "alert"},
	{"0314-unlink-dirlink", "unlink sshlink/authorized_keys", "alert"},
	{"0314-chown-dirlink", "chown alice sshlink/authorized_keys", "alert"},
	{"0314-allow-rm-link", "rm keylink", "allow"},
	{"0314-allow-rm-ordinary", "rm -f a.txt notes.txt", "allow"},
	{"0314-allow-find-delete", "find . -name '*.tmp' -delete", "allow"},
	{"0314-allow-find-list", "find sshlink/ -name authorized_keys", "allow"},
	{"0314-allow-chmod-ordinary", "chmod 600 a.txt", "allow"},
	{"0314-allow-ls-dirlink", "ls -l sshlink/", "allow"},
	{"0314-allow-cat-link", "cat keylink", "allow"},
	{"0314-allow-read-link-to-file", "cat keylink > out.txt", ""},
	{"0314-allow-cp-from-link", "cp keylink out.txt", ""},
	// GAP-0315: a brace word past the field cap.
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
	{"0315-brace-cap-touch", "touch ../.ssh/authorized_key{s,{1..300}}", "alert"},
	{"0315-brace-cap-touch-home", "touch ~/.ssh/authorized_key{s,{1..300}}", "alert"},
	{"0315-brace-cap-touch-link", "touch key{link,{1..300}}", "alert"},
	{"0315-allow-brace-cap-ordinary", "touch notes{,{1..300}}.txt", "allow"},
	{"0315-allow-brace-cap-dir", "touch ordinary/f{1..400}.txt", "allow"},
	{"0315-allow-brace-cap-data-link", "printf '%s\\n' key{link,{1..300}}", "allow"},
	{"0315-allow-brace-small", "touch ~/.ssh/known_hosts{,.old}", ""},
}

// TestGAP0311To0315KeysWritesEveryMode runs hp4Rows on claudecode and codex,
// managed and per-user, with the project keylink and an sshlink to the .ssh
// folder; the decoy keys file must not change.
func TestGAP0311To0315KeysWritesEveryMode(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "sshlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range hp4Rows {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			if strings.HasPrefix(call.body, `{"action":"alert"`) {
				call.verdict = "alert" // rel-1-0-6:GAP-0675
			}
			t.Logf("HP4ROW %s | %s | want %s", call.name, call.verdict, row.want)
			if row.want != "" && call.verdict != row.want {
				t.Errorf("%s: verdict %s, want %s; body %.160s", call.name, call.verdict, row.want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}
