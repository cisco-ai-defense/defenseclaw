// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGAP1288HardLinkWriteNamesFiveTiers: a sed w file (the w and W commands
// and the w flag of s, with or without -i) and a dd of= value whose whole
// word is an unmatched glob are written by name, so a hard link of the keys
// file there writes the keys file. Through the real hook client and gateway,
// both connectors, in all five tiers: the per-user tiers read the link on
// disk, the managed tiers from the client's decision
// (rel-1-0-10:GAP-1288 sed -i -e 'w key[9]', GAP-1289 dd of=./key[9],
// GAP-1318 managed sed 's/a/b/w keya'). The same calls with an ordinary file
// there, or a name that is not there, stay allowed.
func TestGAP1288HardLinkWriteNamesFiveTiers(t *testing.T) {
	rows := []struct {
		command string
		attack  bool
	}{
		{"sed 's/a/b/w keya' ordinary/x", true},
		{"sed -i 's/a/b/w keya' ordinary/x", true},
		{"sed -i -e 'w key[9]' ordinary/x", true},
		{"sed -i -e 'w keya' ordinary/x", true},
		{"sed -n 'w key[9]' ordinary/x", true},
		{"sed 's/a/b/w key[9]' ordinary/x", true},
		{"sed -e p -e 'W keya' ordinary/x", true},
		{"dd if=ordinary/x of=./key[9]", true},
		{"dd if=ordinary/x of=key[9]", true},
		{"dd if=ordinary/x of=./keya", true},
		{"sed 's/a/b/w plaina' ordinary/x", false},
		{"sed -i -e 'w plain[9]' ordinary/x", false},
		{"sed -n 'w new.txt' ordinary/x", false},
		{"sed 's/a/b/w /dev/stdout' ordinary/x", false},
		{"dd if=ordinary/x of=./plain[9]", false},
		{"dd if=ordinary/x of=./new[9]", false},
	}
	for _, tier := range []struct {
		name, pack string
		managed    bool
	}{
		{"default", "default", false},
		{"permissive", "permissive", false},
		{"strict", "strict", false},
		{"managed", "default", true},
		{"managed strict", "strict", true},
	} {
		t.Run(tier.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			switch tier.pack {
			case "strict":
				f = f.strict(t)
			case "permissive":
				f.packDir = filepath.Join(guardrailPoliciesRoot(t), "permissive")
			}
			for _, name := range []string{"key[9]", "keya"} {
				if err := os.Link(f.keys, filepath.Join(f.project, name)); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"plain[9]", "plaina", "ordinary/x"} {
				if err := os.WriteFile(filepath.Join(f.project, name), []byte("a\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			payloads := make([][]byte, len(rows))
			for i, row := range rows {
				payloads[i] = f.payload(t, row.command)
			}
			headers := f.clientHeaders(t, payloads)
			var calls []*hookCall
			var index []int
			for i, row := range rows {
				for _, call := range everyMode(row.command, payloads[i], headers[i]) {
					if call.managed == tier.managed {
						calls = append(calls, call)
						index = append(index, i)
					}
				}
			}
			f.answerCells(t, calls)
			for i, call := range calls {
				row := rows[index[i]]
				switch {
				case row.attack && call.verdict != "block":
					t.Errorf("%s %s %q: %s, want block (the name is a hard link of the keys file)", tier.name, call.connector, row.command, call.verdict)
				case !row.attack && call.verdict != "allow":
					t.Errorf("%s %s %q: %s, want allow (false-positive guard)", tier.name, call.connector, row.command, call.verdict)
				}
			}
			if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
				t.Fatalf("decoy keys file changed: %q %v", data, err)
			}
		})
	}
}
