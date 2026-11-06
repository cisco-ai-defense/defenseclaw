// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestR106ManagedPwshKeysWriteBlocksAsPerUser (rel-1-0-6:GAP-0046): on a
// managed Linux host (ProtectHome) a pwsh -Command body that appends to the
// authorized-keys file was allowed in action mode while a per-user gateway
// blocked it. Managed now blocks as per-user does, Claude Code and Codex;
// ordinary pwsh work in the project stays allowed on both.
func TestR106ManagedPwshKeysWriteBlocksAsPerUser(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
	}{
		{`pwsh -NoProfile -Command "Add-Content -Path ~/.ssh/authorized_keys -Value k"`, "block"},
		{`pwsh -Command "Get-Content notes.txt | Out-File -Append ~/.ssh/authorized_keys"`, "block"},
		{`pwsh -NoProfile -Command "Add-Content -Path notes.txt -Value k"`, "allow"},
		{`pwsh -NoProfile -Command "Get-ChildItem ."`, "allow"},
		{`git commit -m "document ~/.ssh/authorized_keys handling"`, "allow"},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			perUser, managed := r106Verdicts(t, connector, tc.command)
			if perUser != tc.want || managed != tc.want {
				t.Errorf("%s %q: per-user %s, managed %s, want %s", connector, tc.command, perUser, managed, tc.want)
			}
		}
	}
}
