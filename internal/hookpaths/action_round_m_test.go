// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Round m (1b7708e7 review): every documented wrapper (sudo, doas, env,
// nice, nohup, timeout, stdbuf, ionice, setsid, command, exec) passes a
// quoted tilde on as written, and a static sh -c / bash -c body is judged
// in its own quoting, so a tilde quoted inside it is literal. Controls: an
// unquoted tilde, a body that expands it, eval, sudo -s/-i and an option
// that changes the directory or starts a shell stay protected-named.
func TestR104RoundMQuotedTildeThroughEveryWrapper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native POSIX fixture")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`sudo cp payload '~/.ssh/authorized_keys'`,
		`sudo -n -u root cp payload "~/.ssh/authorized_keys"`,
		`sudo --user=root -E cp payload '~/.ssh/authorized_keys'`,
		`sudo -nE git -C docs commit -m 'Document ~/.ssh/authorized_keys'`,
		`sudo -- mv payload \~/.ssh/authorized_keys`,
		`doas -u root cp payload '~/.ssh/authorized_keys'`,
		`timeout 30 cp payload '~/.ssh/authorized_keys'`,
		`timeout -k 5 30s git commit -m 'Document ~/.ssh/authorized_keys'`,
		`timeout --preserve-status -s TERM 10 grep -n '~/.ssh/authorized_keys' report.txt`,
		`timeout --kill-after=5 1m cp payload '~/.ssh/authorized_keys'`,
		`stdbuf -oL grep -n '~/.ssh/authorized_keys' report.txt`,
		`stdbuf -o L -e 0 cp payload '~/.ssh/authorized_keys'`,
		`ionice -c3 cp payload '~/.ssh/authorized_keys'`,
		`ionice -c 2 -n 7 cp payload '~/.ssh/authorized_keys'`,
		`setsid -f cp payload '~/.ssh/authorized_keys'`,
		`env -u PAGER cp payload '~/.ssh/authorized_keys'`,
		`nice cp payload '~/.ssh/authorized_keys'`,
		`sudo timeout 30 nice -n 5 cp payload '~/.ssh/authorized_keys'`,
		`command env sudo cp payload '~/.ssh/authorized_keys'`,
		`bash -c "git commit -m 'Document ~/.ssh/authorized_keys'"`,
		`sh -c "cp payload '~/.ssh/authorized_keys'"`,
		`bash -lc "grep -n '~/.ssh/authorized_keys' report.txt"`,
		`sudo bash -c "echo '~/.ssh/authorized_keys'"`,
		`timeout 30 sh -c "cp payload '~/.ssh/authorized_keys'"`,
		`bash -c 'cp payload \~/.ssh/authorized_keys'`,
		`bash -c "sh -c \"cp payload '~/.ssh/authorized_keys'\""`,
		`env -S "cp payload '~/.ssh/authorized_keys'"`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("ActionCommandDecision = %q, want allow", got)
			}
		})
	}
	for _, command := range []string{
		`sudo cp payload ~/.ssh/authorized_keys`,
		`sudo -s cp payload '~/.ssh/authorized_keys'`,
		`sudo -i cp payload '~/.ssh/authorized_keys'`,
		`sudo -D /tmp cp payload '~/.ssh/authorized_keys'`,
		`sudo -e '~/.ssh/authorized_keys'`,
		`sudo PAGER=x cp payload '~/.ssh/authorized_keys'`,
		`doas -s cp payload '~/.ssh/authorized_keys'`,
		`timeout 30 cp payload ~/.ssh/authorized_keys`,
		`timeout cp payload '~/.ssh/authorized_keys'`,
		`stdbuf -oL cp payload ~/.ssh/authorized_keys`,
		`setsid cp payload ~/.ssh/authorized_keys`,
		`env -C .. cp payload '~/.ssh/authorized_keys'`,
		`bash -c 'cp payload ~/.ssh/authorized_keys'`,
		`bash -c "cp payload ~/.ssh/authorized_keys"`,
		`sh -c "cp payload \"$HOME/.ssh/authorized_keys\""`,
		`sudo sh -c 'cat payload >> ~/.ssh/authorized_keys'`,
		`timeout 5 sh -c 'cp payload ~/.ssh/authorized_keys'`,
		`bash -c 'cp payload "$1"' _ ~/.ssh/authorized_keys`,
		`bash -c 'cp payload "$1"' _ '~/.ssh/authorized_keys'`,
		`eval cp payload '~/.ssh/authorized_keys'`,
		`bash -c "eval cp payload '~/.ssh/authorized_keys'"`,
		`sh -c "sh -c 'cp payload ~/.ssh/authorized_keys'"`,
		`bash -c "cp payload '~/.ssh/authorized_keys'" && cp payload ~/.ssh/authorized_keys`,
		`env -S 'cp payload ~/.ssh/authorized_keys'`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("ActionCommandDecision = %q, want protected-target", got)
			}
		})
	}
}

// GAP-1460: a managed gateway behind ProtectHome cannot open the user's
// project, so a glob through a directory alias of ~/.ssh used to expand to
// nothing and the write was allowed. A directory it cannot see is not "no
// match": a pattern whose last component can name a key stays protected,
// while a glob that cannot name one still allows.
func TestR104GlobAliasBehindHiddenHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission fixture")
	}
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh, filepath.Join(cwd, "docs"), filepath.Join(cwd, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ssh, filepath.Join(cwd, "keydir")); err != nil {
		t.Fatal(err)
	}
	blocked := []string{
		`cp payload keyd*/authorized_keys`,
		`cat payload >> keyd*/authorized_keys`,
		`tee keyd*/authorized_keys < payload`,
		`cp payload k*/authorized_key?`,
		`cp payload keyd*/*_keys`,
		`cp payload ./keyd[i]r/authorized_keys2`,
		`cp payload ` + cwd + `/keyd*/authorized_keys`,
		`cd docs && cp payload ../keyd*/authorized_keys`,
		`for f in keyd*/authorized_keys; do cp payload "$f"; done`,
		`cp payload keyd*/a*`,
		`cp payload keyd*/*`,
		`cp payload */authorized_keys`,
	}
	allowed := []string{
		`cp src/*.txt docs/`,
		`cat docs/*.md > notes.txt`,
		`rm -f src/*.log`,
		`cp payload d*/notes.txt`,
		`git add *`,
		`cp payload docs/*`,
		`chmod 644 src/[a-z]*`,
	}
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for _, hidden := range []bool{false, true} {
		mode := os.FileMode(0o700)
		if hidden {
			mode = 0
		}
		if err := os.Chmod(homes, mode); err != nil {
			t.Fatal(err)
		}
		for _, command := range blocked {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Errorf("hidden=%t %s: ActionCommandDecision = %q, want protected-target", hidden, command, got)
			}
		}
		for _, command := range allowed {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Errorf("hidden=%t %s: ActionCommandDecision = %q, want allow", hidden, command, got)
			}
		}
	}
}
