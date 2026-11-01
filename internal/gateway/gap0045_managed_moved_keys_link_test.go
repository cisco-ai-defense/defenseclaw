// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestR106ManagedMovedKeysLinkBlocksAsPerUser (rel-1-0-6:GAP-0045): on a
// managed host (ProtectHome) a move of an existing project link to the keys
// file to a new name, then a write through the new name, was allowed in
// action mode: the gateway cannot see the link, and the hook client's
// concrete-write reading resolved the new name on the disk as it was before
// the move. Managed now blocks as per-user does, Claude Code and Codex. A
// moved link to an ordinary file, a write to another name, plain reads
// through the keys link and ordinary moves stay allowed on both.
func TestR106ManagedMovedKeysLinkBlocksAsPerUser(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
	}{
		{`mv keylink k2; echo x >> k2`, "block"},
		{`ln -s README.md docs.md; mv keylink k2; echo x >> k2`, "block"},
		{`cd ~/project && mv keylink k2; echo x >> k2`, "block"},
		{`mv keylink k2 && printf y >> k2`, "block"},
		{`mv keylink k2; cat notes.txt >> k2`, "block"},
		{`mv -f keylink k2 && echo x | tee -a k2`, "block"},
		{`mv readlink k2; echo x >> k2`, "allow"},
		{`mv notes.txt n2; echo x >> n2`, "allow"},
		{`grep x keylink`, "allow"},
		{`cat keylink`, "allow"},
		{`ls -la keylink`, "allow"},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			perUser, managed := r106Verdicts(t, connector, tc.command)
			if perUser != tc.want || managed != tc.want {
				t.Errorf("%s %q: per-user %s, managed %s, want %s", connector, tc.command, perUser, managed, tc.want)
			}
		}
	}
}
