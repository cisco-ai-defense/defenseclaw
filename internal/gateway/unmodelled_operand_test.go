// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"
)

// A keys-file path handed as an operand to a program the scan has no model of
// (a script, an unfamiliar program, a variable program) is a use of unknown
// role: the per-user default and permissive packs alert, the strict pack and
// every managed install block (owner rule, lead ruling on rel-1-0-10:GAP-0708).
// Rows are the review probe ids.
func TestUnmodelledProgramWithAKeysOperandIsUnknownRole(t *testing.T) {
	home, cwd := shellProtectedFileHome(t)
	rows := []struct{ id, command string }{
		{"A01", "./deploy.sh ~/.ssh/authorized_keys"},
		{"A02", "python3 add.py ~/.ssh/authorized_keys"},
		{"A03", "$T ~/.ssh/authorized_keys"},
		{"A05", "mytool -o ~/.ssh/authorized_keys"},
		{"A06", "sync-keys notes.txt ~/.ssh/authorized_keys"},
		{"A07", "echo k | mytool ~/.ssh/authorized_keys"},
		{"U14", "sha256sum ~/.ssh/authorized_keys; ./add.sh ~/.ssh/authorized_keys"},
		{"U17", "printf x | ./add.sh ~/.ssh/authorized_keys"},
		{"U21", "FOO=1 ./add.sh ~/.ssh/authorized_keys"},
		{"U22", "/opt/tools/add-key ~/.ssh/authorized_keys"},
	}
	tiers := []struct {
		name, posture string
		managed       bool
		want          string
	}{
		{"default", "default", false, "alert"},
		{"permissive", "permissive", false, "alert"},
		{"strict", "strict", false, "block"},
		{"managed", "default", true, "block"},
		{"managed-strict", "strict", true, "block"},
	}
	for _, row := range rows {
		for _, tier := range tiers {
			t.Run(row.id+"/"+tier.name, func(t *testing.T) {
				action, rules := shellProtectedFileRoute(t, home, cwd, "claudecode", tier.posture, tier.managed, row.command)
				if action != tier.want || !slices.Contains(rules, "persistence.ssh_authorized_keys_command") {
					t.Fatalf("%s %s = %s %v, want %s on persistence.ssh_authorized_keys_command", row.id, tier.name, action, rules, tier.want)
				}
			})
		}
	}
}
