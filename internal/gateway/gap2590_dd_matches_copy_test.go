// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestR106DDThroughKeysLinkMatchesCopy (rel-1-0-4:GAP-2590 row T03, lead
// ruling 10-31 00:57): a dd that reads the keys file through a project link
// into a project file gets the verdict of the equivalent cp of that file,
// Claude Code and Codex, per-user and managed (ProtectHome). On a per-user
// gateway a copy source of the keys file is a non-read use that action mode
// denies by design (owner decision 2, TGT-0194), so both block. A managed
// gateway gives both the same answer too; that it allows a copy source it
// cannot see behind the hidden link is pinned by the GAP-2428 rows and is a
// lead question, not this row. The same dd and cp of an ordinary project
// file are allowed everywhere.
func TestR106DDThroughKeysLinkMatchesCopy(t *testing.T) {
	for _, tc := range []struct {
		dd, cp, perUser string
	}{
		{`dd if=keylink of=out.txt`, `cp keylink out.txt`, "block"},
		{`dd if=~/.ssh/authorized_keys of=out.txt`, `cp ~/.ssh/authorized_keys out.txt`, "block"},
		{`dd if=notes.txt of=out.txt`, `cp notes.txt out.txt`, "allow"},
		{`dd if=readlink of=out.txt`, `cp readlink out.txt`, "allow"},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			ddPerUser, ddManaged := r106Verdicts(t, connector, tc.dd)
			cpPerUser, cpManaged := r106Verdicts(t, connector, tc.cp)
			if ddPerUser != tc.perUser || cpPerUser != tc.perUser || ddManaged != cpManaged ||
				tc.perUser == "allow" && ddManaged != "allow" {
				t.Errorf("%s: %q per-user %s managed %s; %q per-user %s managed %s; want per-user %s and equal managed verdicts",
					connector, tc.dd, ddPerUser, ddManaged, tc.cp, cpPerUser, cpManaged, tc.perUser)
			}
		}
	}
}
