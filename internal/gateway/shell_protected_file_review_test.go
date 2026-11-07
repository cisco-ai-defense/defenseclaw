// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-6:GAP-0675 review 4. The rows below are the parity cells the review
// asked for: a known copy of a link to the keys file blocks per-user and
// managed; a dead value, an ordinary file with a protected look-alike name and
// the removal of an ordinary project file in a recovered parse (GAP-0534) are
// not blocked in the balanced profile.

func TestGAP0675KnownCopiedLinksBlockPerUserAndManaged(t *testing.T) {
	rows := []selfProtRow{
		{"T17", `ln -s build/out bin; cp -a . ../dist; echo key >> ../dist/keylink`, "block"},
		{"E01", `env -C ~ cp -r project project-bak; echo key >> ~/project-bak/keylink`, "block"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				got := selfProtVerdict(t, row, managed, connector)
				t.Logf("COPIED_LINK row=%s connector=%s managed=%t action=%s", row.id, connector, managed, got)
				if got != "block" {
					t.Errorf("%s %s managed=%t: known copied link got %s, want block", row.id, connector, managed, got)
				}
			}
		}
	}
}

func TestGAP0675OrdinaryDeadValuesAreNotBlocked(t *testing.T) {
	rows := []selfProtRow{
		{"reassigned-echo", `f=keylink; f=a.txt; echo m >> "$f"`, "allow"},
		{"reassigned-copy", `f=keylink; f=a.txt; cp b.txt "$f"`, "allow"},
		{"for-then-reassign", `for f in keylink; do :; done; f=a.txt; echo m >> "$f"`, "allow"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				got := selfProtVerdict(t, row, managed, connector)
				t.Logf("DEAD_VALUE row=%s connector=%s managed=%t action=%s", row.id, connector, managed, got)
				// A copy onto a dead value is an alert at worst: the proof of the
				// writer covers echo, printf, cat, tee, install and rsync.
				if got != "allow" && !(row.id == "reassigned-copy" && strings.HasPrefix(got, "status 200")) {
					t.Errorf("%s %s managed=%t: ordinary write got %s, want allow", row.id, connector, managed, got)
				}
			}
		}
	}
}

func TestGAP0675ProjectFilesWithProtectedNamesAreOrdinary(t *testing.T) {
	rows := []selfProtRow{
		{"project-keys-file", `echo x >> ordinary/authorized_keys`, "allow"},
		{"project-rc-file", `echo x >> ordinary/.bashrc`, "allow"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				got := selfProtVerdict(t, row, managed, connector)
				t.Logf("ORDINARY_NAME row=%s connector=%s managed=%t action=%s", row.id, connector, managed, got)
				// A copy onto a dead value is an alert at worst: the proof of the
				// writer covers echo, printf, cat, tee, install and rsync.
				if got != "allow" && !(row.id == "reassigned-copy" && strings.HasPrefix(got, "status 200")) {
					t.Errorf("%s %s managed=%t: ordinary write got %s, want allow", row.id, connector, managed, got)
				}
			}
		}
	}
}

func TestGAP0675RecoveredParseOrdinaryFileWarnsInBalancedBlocksInStrict(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"notes.txt", "settings.json", "hooks.json"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, posture := range []string{"default", "strict"} {
			installToolCallCorpusProfileConnector(t, connector, posture)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			tool := "PowerShell"
			if connector == "codex" {
				tool = "exec_command"
			}
			for _, managed := range []bool{false, true} {
				for _, name := range []string{"notes.txt", "settings.json", "hooks.json"} {
					cmd := `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/project/` + name
					got := gap0568ToolHookAction(t, api, connector, tool, f.home, f.project, cmd, true, managed)
					t.Logf("G534B_RECOVERED connector=%s posture=%s managed=%t file=%s action=%s", connector, posture, managed, name, got)
					want := "alert"
					if posture == "strict" {
						want = "block"
					}
					if got != want {
						t.Errorf("%s/%s managed=%t %s: got %s, want %s", connector, posture, managed, name, got, want)
					}
				}
			}
		}
	}
}
