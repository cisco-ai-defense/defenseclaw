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

// rel-1-0-10:GAP-0839: four benign shell calls of the internal agent-trace
// set (held out) blocked in the default pack as SSH key writes, because the
// link reading could not read one word and then held every write of the call
// as unknown. Each row is the shape of one case, with neutral names:
//
//   - archive: an archive created from a pathname pattern (04-*.raw) was read
//     as an option that may select extraction, and a nested shell body that
//     changes its own directory before any scope opens made every later write
//     unknown (at/codex/92da3b7143c1eebb/w432);
//   - redirect: a target spelled from the root (/tmp/x.$$) after a directory
//     change the walk cannot place (at/codex/79ee6e25eb0d8886/119);
//   - loop: a cp in a for loop over fixed plain names, spelled with the loop
//     name (at/codex/0e15efbb8276057f/127);
//   - assigned: a cp destination spelled with a name a top-level assignment
//     fixed (at/claude-code/e8246b44e638b28f/169).
//
// The controls keep their reading: a name the body or a later statement may
// rebind, a pattern that may start with a dash, a relative dynamic target.
func TestGAP0839CopyAndArchiveWordsClaudeCode(t *testing.T) {
	gap0839EveryCell(t, "claudecode")
}

func TestGAP0839CopyAndArchiveWordsCodex(t *testing.T) {
	gap0839EveryCell(t, "codex")
}

func gap0839EveryCell(t *testing.T, connectorName string) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, _ := shellProtectedFileHome(t)
	for _, dir := range []string{"proj", "evidence/a04", "evidence/b01/scripts", "evidence/c03"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const keys = "persistence.ssh_authorized_keys_command"
	notBlocked := map[string]bool{"default": true, "permissive": true}
	rows := []struct {
		name, command string
		// fixed: the call does not block in the default and permissive
		// packs; otherwise it blocks in every pack, as on rel.
		fixed bool
	}{
		{"archive from a pattern, then extract", "sudo bash -c 'cd ~/proj && tar -czf /tmp/g0839a.tgz 04-*.raw && chmod 644 /tmp/g0839a.tgz'; " +
			"scp -q box:/tmp/g0839a.tgz /tmp/g0839a.tgz; tar -C ~/evidence/a04 -xzf /tmp/g0839a.tgz; rm /tmp/g0839a.tgz", true},
		{"redirect from the root after an unplaced cd", `cd "$WORK" || exit 1; [p]grep -f marker >/tmp/g0839d.$$; rm -f /tmp/g0839d.$$`, true},
		{"loop copy over plain names", "for f in a.log b-2.tsv; do sudo cp /var/tmp/g0839stage/$f /var/tmp/g0839-$f; sudo chmod 600 /var/tmp/g0839-$f; done; " +
			"cat /var/tmp/g0839-a.log > ~/evidence/c03/readback.raw", true},
		{"copy to an assigned folder", "E=~/evidence/b01; D=$E/run; printf x > /tmp/g0839b.txt; scp -q /tmp/g0839b.txt box:/tmp/; " +
			"cp /tmp/g0839b.txt $E/scripts/; $S status >/dev/null", true},
		{"control: the loop body may rebind the name", "for f in a.log b-2.tsv; do read f; sudo cp /var/tmp/g0839stage/$f /var/tmp/g0839-$f; done; " +
			"cat /var/tmp/g0839-a.log > ~/evidence/c03/readback.raw", false},
		{"control: a statement may rebind the assigned name", "E=~/evidence/b01; read E; printf x > /tmp/g0839b.txt; " +
			"cp /tmp/g0839b.txt $E/scripts/; $S status >/dev/null", false},
		{"control: a pattern that may start with a dash", "sudo bash -c 'cd ~/proj && tar -czf /tmp/g0839a.tgz *.raw'; " +
			"scp -q box:/tmp/g0839a.tgz /tmp/g0839a.tgz; tar -C ~/evidence/a04 -xzf /tmp/g0839a.tgz", false},
		{"control: a relative target after an unplaced cd", `cd "$WORK" || exit 1; [p]grep -f marker >g0839d.$$`, false},
		{"control: the nested body writes in the background", "sudo bash -c 'cd ~/evidence/a04 && { sleep 2; cat x.raw >> 04-n.raw; } &'; " +
			"scp -q box:/tmp/g0839a.tgz /tmp/g0839a.tgz; tar -C ~/evidence/a04 -xzf /tmp/g0839a.tgz", false},
	}
	for _, row := range rows {
		for _, cell := range []string{"default", "permissive", "strict", "managed"} {
			posture, managed := cell, false
			if cell == "managed" {
				posture, managed = "default", true
			}
			t.Run(fmt.Sprintf("%s %s %s", connectorName, cell, row.name), func(t *testing.T) {
				action, rules := shellProtectedFileRoute(t, home, home, connectorName, posture, managed, row.command)
				if row.fixed && notBlocked[cell] {
					if action == "block" {
						t.Fatalf("action = block (rules %v), want no block", rules)
					}
					return
				}
				if !row.fixed && action != "block" {
					t.Fatalf("action = %q (rules %v), want block", action, rules)
				}
				if action == "block" && !slices.Contains(rules, keys) {
					t.Fatalf("rules = %v, want %s", rules, keys)
				}
			})
		}
	}
}
