// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestGAP0968WindowsGenericRouteKeepsTheKeysOperandBlock pins
// rel-1-0-10:GAP-0968 as by design (DET111 ruling 2026-11-24, option a).
// On a Windows host the generic hook route gives a Copilot, OpenCode or
// Hermes shell call no dialect hint, and the Windows reading has no
// unknown-role operand model, so a keys-file operand of a program the scan
// does not model blocks in every tier, default and permissive too. That is
// the 1.0.10 verdict on every OS and stronger than the unknown-role tier
// (TestUnmodelledProgramWithAKeysOperandIsUnknownRole: alert in default and
// permissive on the Claude Code route). Lowering it to that tier is an owner
// question (CONFIRM-LIST), so the block is kept. The rows are those of the
// unknown-role test, at the shipped default configuration of each pack.
//
// The home has no link (the keys link of shellProtectedFileHome needs the
// symlink privilege a standard user lacks), so the row runs, and must pass,
// as a standard user and as an administrator alike.
func TestGAP0968WindowsGenericRouteKeepsTheKeysOperandBlock(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(cwd, "notes.txt"),
	} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
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
	}{
		{"default", "default", false},
		{"permissive", "permissive", false},
		{"strict", "strict", false},
		{"managed", "default", true},
		{"managed-strict", "strict", true},
	}
	for _, connectorName := range []string{"copilot", "opencode", "hermes"} {
		for _, row := range rows {
			for _, tier := range tiers {
				t.Run(connectorName+"/"+row.id+"/"+tier.name, func(t *testing.T) {
					action, rules := shellProtectedFileRoute(t, home, cwd, connectorName, tier.posture, tier.managed, row.command)
					if action != "block" || !slices.Contains(rules, "persistence.ssh_authorized_keys_command") {
						t.Fatalf("%s %s %s = %s %v, want block on persistence.ssh_authorized_keys_command (1.0.10 verdict, GAP-0968 by design)",
							connectorName, row.id, tier.name, action, rules)
					}
				})
			}
		}
	}
}
