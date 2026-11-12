// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0013 (and the class of rel-1-0-10:GAP-0004): the
// authorized-keys rule blocked benign file work as an SSH key write in every
// pack, because a reader gap made the target unknown and unknown was judged
// as the key file. A file name with a star, quote, newline, space or
// semicolon is a file name; a link command whose names are absolute does not
// depend on the working directory. A write the proof can only hold as
// unknown away from the home warns in the default and permissive tiers and
// blocks in strict and managed; one in the home, and a target it finds
// protected, block everywhere.
func TestGAP0013ProtectedTargetBlocksOnlyWhenKnownClaudeCode(t *testing.T) {
	gap0013EveryCell(t, "claudecode")
}

func TestGAP0013ProtectedTargetBlocksOnlyWhenKnownCodex(t *testing.T) {
	gap0013EveryCell(t, "codex")
}

func gap0013EveryCell(t *testing.T, connectorName string) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	data := t.TempDir()
	for _, name := range []string{"a.dat", "b.dat"} {
		if err := os.WriteFile(filepath.Join(data, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const keys = "persistence.ssh_authorized_keys_command"
	allow := map[string]string{"default": "allow", "permissive": "allow", "strict": "allow", "managed": "allow"}
	block := map[string]string{"default": "block", "permissive": "block", "strict": "block", "managed": "block"}
	warn := map[string]string{"default": "alert", "permissive": "alert", "strict": "block", "managed": "block"}
	a, b := filepath.Join(data, "a.dat"), filepath.Join(data, "b.dat")
	rows := []struct {
		name, cwd, command string
		want               map[string]string
	}{
		{"link then move to a starred name", cwd, fmt.Sprintf("ln %s /tmp/gap13l && mv /tmp/gap13l '%s/file*with*stars.dat'", a, data), allow},
		{"link then move to a quoted name", cwd, fmt.Sprintf(`ln %s /tmp/gap13l && mv /tmp/gap13l $'%s/file"with"quotes.dat'`, a, data), allow},
		{"link then move to a newline name", cwd, fmt.Sprintf(`ln %s /tmp/gap13l && mv /tmp/gap13l $'%s/file\nwith\nnewlines.dat'`, a, data), allow},
		{"link then move to a spaced name", cwd, fmt.Sprintf("ln %s /tmp/gap13l && mv /tmp/gap13l '%s/file with spaces.dat'", a, data), allow},
		{"link then move to a semicolon name", cwd, fmt.Sprintf("ln %s /tmp/gap13l && mv /tmp/gap13l '%s/file;with;semicolon.dat'", a, data), allow},
		{"link then move, escaped star", cwd, fmt.Sprintf(`ln %s /tmp/gap13l && mv /tmp/gap13l %s/file\*star.dat`, a, data), allow},
		{"absolute link then move, no cwd", "", fmt.Sprintf("ln %s /tmp/gap13l && mv /tmp/gap13l %s", a, b), allow},
		{"interpreter link to a runtime target then write, outside the home", data, `python3 -c "import os,sys; os.symlink(sys.argv[1], 'gap13lnk')" "$T"; echo marker >> gap13lnk`, warn},
		{"interpreter link to a runtime target then write, in the home", cwd, `python3 -c "import os,sys; os.symlink(sys.argv[1], 'gap13lnk')" "$T"; echo marker >> gap13lnk`, block},
		{"archive extract before a write", cwd, fmt.Sprintf("tar -xf %s/missing.tar -C %s && echo marker >> %s/ledger.db", data, data, data), warn},
		{"keys: symbolic link then append", cwd, "ln -s ~/.ssh/authorized_keys /tmp/gap13k && echo marker >> /tmp/gap13k", block},
		{"keys: hard link then append", cwd, "ln ~/.ssh/authorized_keys gap13hl && echo marker >> gap13hl", block},
		{"keys: link onto the keys file", cwd, "ln -s notes.txt ~/.ssh/authorized_keys", block},
		{"keys: move onto the keys file", cwd, "mv notes.txt ~/.ssh/authorized_keys", block},
		{"keys: link then move onto the keys file", cwd, fmt.Sprintf("ln %s /tmp/gap13l && mv /tmp/gap13l ~/.ssh/authorized_keys", a), block},
		{"keys: copy to authorized_keys2", cwd, "cp notes.txt ~/.ssh/authorized_keys2", block},
		{"keys: tee append", cwd, "echo marker | tee -a ~/.ssh/authorized_keys", block},
		{"keys: link to .ssh then append", cwd, "ln -s ~/.ssh gap13d && echo marker >> gap13d/authorized_keys", block},
		{"keys: starred link name then append", cwd, "ln -s ~/.ssh/authorized_keys /tmp/gap13s && mv /tmp/gap13s '/tmp/gap13*s' && echo marker >> '/tmp/gap13*s'", block},
		{"keys: interpreter link to the keys file", cwd, `python3 -c "import os; os.symlink(os.path.expanduser('~/.ssh/authorized_keys'), 'gap13p')"; echo marker >> gap13p`, block},
		{"keys: linked home", cwd, "ln -s ~ /tmp/gap13h && echo marker >> /tmp/gap13h/.ssh/authorized_keys", block},
	}
	for _, row := range rows {
		for _, cell := range []string{"default", "permissive", "strict", "managed"} {
			posture, managed := cell, false
			if cell == "managed" {
				posture, managed = "default", true
			}
			t.Run(fmt.Sprintf("%s %s %s", connectorName, cell, row.name), func(t *testing.T) {
				action, rules := shellProtectedFileRoute(t, home, row.cwd, connectorName, posture, managed, row.command)
				want := row.want[cell]
				if action != want {
					t.Fatalf("action = %q (rules %v), want %q", action, rules, want)
				}
				if want != "allow" && !slices.Contains(rules, keys) {
					t.Fatalf("rules = %v, want %s", rules, keys)
				}
			})
		}
	}
}
