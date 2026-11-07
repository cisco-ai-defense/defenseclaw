// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestGAP0675RecoveredParseNearVariantsAndLinks pins the over-limit
// (recovered parse) call, per-user and as a managed peer behind ProtectHome:
// an ordinary project file or dotfile warns in the default and permissive
// profiles, and a protected file, a file or folder link to one, and a link to
// the DefenseClaw state keep their block in every profile. Strict blocks all.
func TestGAP0675RecoveredParseNearVariantsAndLinks(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"settings.json", ".editorconfig", ".gitignore", "ordinary/.cache/config.json"} {
		path := filepath.Join(f.project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.home, ".ssh", "config"), []byte("Host test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/config", filepath.Join(f.project, "file_alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.home, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.home, ".defenseclaw", "config.yaml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.defenseclaw", filepath.Join(f.project, "state_alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.defenseclaw/config.yaml", filepath.Join(f.project, "state_file_alias")); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, target, wantDefault string }{
		{"ordinary settings", "~/project/settings.json", "alert"},
		{"ordinary dotfile", "~/project/.editorconfig", "alert"},
		{"ordinary gitignore", "~/project/.gitignore", "alert"},
		{"ordinary nested dotdir", "~/project/ordinary/.cache/config.json", "alert"},
		{"direct ssh config", "~/.ssh/config", "block"},
		{"direct link to ssh config", "~/project/file_alias", "block"},
		{"directory link to ssh config", "~/project/alias/config", "block"},
		{"directory link to DefenseClaw state", "~/project/state_alias/config.yaml", "block"},
		{"file link to DefenseClaw state", "~/project/state_file_alias", "block"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, posture := range []string{"default", "permissive", "strict"} {
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
				for _, row := range rows {
					command := "Write-Output $(.\\a[1]<#x#>); Remove-Item -Recurse -Force " + row.target
					got := gap0568ToolHookAction(t, api, connector, tool, f.home, f.project, command, true, managed)
					want := row.wantDefault
					if posture == "strict" {
						want = "block"
					}
					t.Logf("GAP0675_RECOVERED connector=%s posture=%s managed=%t row=%s got=%s want=%s", connector, posture, managed, row.name, got, want)
					if got != want {
						t.Errorf("%s/%s managed=%t %s: got %s, want %s", connector, posture, managed, row.name, got, want)
					}
				}
			}
		}
	}
}

// TestGAP0675OrdinaryAndKnownLinkMutants pins the near variants of the
// ordinary call (a value overwritten before the write, a name that looks
// protected in an ordinary folder) and of the known link.
func TestGAP0675OrdinaryAndKnownLinkMutants(t *testing.T) {
	rows := []struct{ name, command, want string }{
		{"dead echo", "f=keylink; f=a.txt; echo m >> \"$f\"", "allow"},
		{"dead copy", "f=keylink; f=a.txt; cp b.txt \"$f\"", "nonblock"},
		{"dead then live link", "f=keylink; f=a.txt; echo m >> \"$f\"; echo key >> keylink", "block"},
		{"ordinary cd with protected-looking name", "cd ordinary && echo m >> authorized_keys", "nonblock"},
		{"ordinary cd with startup-looking name", "cd ordinary && echo m >> .bashrc", "nonblock"},
		{"ordinary cd and copy", "cd ordinary && cp ../a.txt copied.txt", "nonblock"},
		{"known link chmod", "chmod 600 keylink", "block"},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				got := selfProtVerdict(t, selfProtRow{row.name, row.command, row.want}, managed, connector)
				t.Logf("GAP0675_MUTANT connector=%s managed=%t row=%s got=%s want=%s", connector, managed, row.name, got, row.want)
				if row.want == "nonblock" {
					if got == "block" {
						t.Errorf("%s managed=%t %s: ordinary command blocked", connector, managed, row.name)
					}
				} else if got != row.want {
					t.Errorf("%s managed=%t %s: got %s, want %s", connector, managed, row.name, got, row.want)
				}
			}
		}
	}
}
