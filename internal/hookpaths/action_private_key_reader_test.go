// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0281: every common program that prints a file's content reads a
// private key named as its operand, as cat, head and tail do; metadata
// programs, the public key and ordinary files are not key reads.
func TestActionPrivateKeyReadCoversEveryContentReader(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"id_ed25519", "id_ed25519.pub"} {
		if err := os.WriteFile(filepath.Join(home, ".ssh", name), []byte("decoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		"less ~/.ssh/id_ed25519", "more ~/.ssh/id_ed25519", "grep -v x ~/.ssh/id_ed25519",
		"xxd ~/.ssh/id_ed25519", "strings ~/.ssh/id_ed25519", "cut -c1-10 ~/.ssh/id_ed25519",
		"nl ~/.ssh/id_ed25519", "tac ~/.ssh/id_ed25519", "awk 1 ~/.ssh/id_ed25519",
		"od -c ~/.ssh/id_ed25519", "hexdump -C ~/.ssh/id_ed25519", "sort ~/.ssh/id_ed25519",
		"rev ~/.ssh/id_ed25519", "diff ~/.ssh/id_ed25519 /dev/null", "egrep . ~/.ssh/id_ed25519",
		"cat ~/.ssh/id_ed25519",
		// A reader fed by stdin (RV20-2) and inline interpreter reads.
		"xxd < ~/.ssh/id_ed25519", "od -c < ~/.ssh/id_ed25519", "sort < ~/.ssh/id_ed25519",
		"grep . < ~/.ssh/id_ed25519", "less < $HOME/.ssh/id_ed25519",
		`python3 -c "print(open('` + filepath.Join(home, ".ssh", "id_ed25519") + `').read())"`,
		`python3 -c "import os; print(open(os.path.expanduser('~/.ssh/id_ed25519')).read())"`,
		`python3 -c "from pathlib import Path; print((Path.home() / '.ssh' / 'id_ed25519').read_text())"`,
		`env python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`,
		`node -e "console.log(require('fs').readFileSync(require('os').homedir() + '/.ssh/id_ed25519', 'utf8'))"`,
		`ruby -e 'puts File.read(File.expand_path("~/.ssh/id_ed25519"))'`,
		`perl -e 'open(my $f, "<", "$ENV{HOME}/.ssh/id_ed25519"); print <$f>'`,
	} {
		if !posixShellPrivateKeyRead(command, cwd, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
	for _, command := range []string{
		"less ~/.ssh/id_ed25519.pub", "grep ssh ~/.ssh/id_ed25519.pub", "xxd README.md",
		"ls -l ~/.ssh/id_ed25519", "stat ~/.ssh/id_ed25519", "ssh -i ~/.ssh/id_ed25519 host true",
		"sort notes.txt", "awk 1 notes.txt",
		"xxd < README.md", "sort < notes.txt", "wc -l < ~/.ssh/id_ed25519.pub",
		"cp notes.txt b.txt < ~/.ssh/id_ed25519",
		`python3 -c "print(open('` + filepath.Join(home, ".ssh", "id_ed25519.pub") + `').read())"`,
		`python3 -c "print(open('notes.txt').read())"`,
		`python3 -c "import os; print(os.path.exists(os.path.expanduser('~/.ssh/id_ed25519')))"`,
		`python3 -c "# open('~/.ssh/id_ed25519')
print('ok')"`,
		`python3 -c "print('see ~/.ssh/id_ed25519; open() it yourself')"`,
	} {
		if posixShellPrivateKeyRead(command, cwd, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = true, want no key read", command)
		}
	}
}
