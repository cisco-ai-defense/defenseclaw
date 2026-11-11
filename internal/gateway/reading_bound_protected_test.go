// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// readingBoundTierTestAPI is a gateway in action mode (block at HIGH) with
// the tier rule pack for connector.
func readingBoundTierTestAPI(t *testing.T, connector, tier string) *APIServer {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connector, tier)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.BlockAt = "HIGH"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier)
	return &APIServer{scannerCfg: cfg}
}

func readingBoundNest(levels int, body string) string {
	for i := 0; i < levels; i++ {
		body = "bash -c \x27" + strings.ReplaceAll(body, "\x27", "\x27\\\x27\x27") + "\x27"
	}
	return body
}

type readingBoundRow struct {
	name, tool, command string
	// want is the action in the default tier; the strict tier blocks every
	// row whose default action is not allow.
	want string
}

// readingBoundCells judges each row through the hook client evidence and
// the gateway hook route in four cells that cover both connectors, per
// user and as a managed peer, in the default and the strict tier.
func readingBoundCells(t *testing.T, rows []readingBoundRow, window time.Duration) {
	t.Helper()
	readingBoundCellsIn(t, rows, window, nil, readingBoundAllCells)
}

type readingBoundCell struct {
	connector, tier string
	managed         bool
}

// readingBoundAllCells covers both connectors, per user and managed, in the
// default and the strict tier; readingBoundDefaultCells is its default-tier
// half, for rows whose strict answer another test already pins.
var (
	readingBoundAllCells = []readingBoundCell{
		{"claudecode", config.HookPolicyTierDefault, false},
		{"codex", config.HookPolicyTierDefault, true},
		{"codex", config.HookPolicyTierStrict, false},
		{"claudecode", config.HookPolicyTierStrict, true},
	}
	readingBoundDefaultCells = readingBoundAllCells[:2]
)

// readingBoundCellsIn is readingBoundCells with setup, which lays out the
// home and the project (links, files) before the first cell runs.
func readingBoundCellsIn(t *testing.T, rows []readingBoundRow, window time.Duration, setup func(home, cwd string), cells []readingBoundCell) {
	t.Helper()
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if setup != nil {
		setup(home, cwd)
	}
	for _, cell := range cells {
		api := readingBoundTierTestAPI(t, cell.connector, cell.tier)
		name := cell.connector + "/" + cell.tier + map[bool]string{false: "/per-user", true: "/managed"}[cell.managed]
		for _, row := range rows {
			want := row.want
			if cell.tier == config.HookPolicyTierStrict && want != guardrailActionAllow {
				want = guardrailActionBlock
			}
			tool := row.tool
			if cell.connector == "codex" {
				tool = "exec_command"
			}
			start := time.Now()
			got := gap0568ToolHookAction(t, api, cell.connector, tool, home, cwd, row.command, true, cell.managed)
			if took := time.Since(start); window > 0 && took > window {
				t.Errorf("%s %s (%d bytes): decided in %s", name, row.name, len(row.command), took)
			}
			if got != want {
				t.Errorf("%s %s: action=%s, want %s", name, row.name, got, want)
			}
		}
	}
}

// GAP-0534: the recovered-parse form the hook client stops at
// (shell-parse-bound) blocked every target in the default tier. A target
// the text may name as protected (directly, split or through a known
// value, the home itself) still blocks in every tier; an ordinary target
// is read by the gateway readers and runs with an alert in the default
// tier, and the strict tier blocks it.
func TestGAP0534RecoveredParseBoundIsGradedByTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hookexec sends no client write evidence; POSIX homes and a mode 0 homes folder")
	}
	// One row per target kind; the two recovered-parse prefixes alternate.
	prefixes := []string{`Write-Output $(.\a[1]<#x#>); `, "0`@A>`; "}
	var rows []readingBoundRow
	for index, target := range []string{"~/project/output", "/tmp/x"} {
		rows = append(rows, readingBoundRow{"ordinary " + target, "PowerShell", prefixes[index%2] + "Remove-Item -Recurse -Force " + target, guardrailActionAlert})
	}
	for index, target := range []string{
		"~/.defenseclaw/config.yaml", "~/.ssh/authorized_keys", "~/.claude/settings.json", "~/.codex/hooks.json",
		"CLAUDE.md", "~/.bashrc", "/etc/sudoers", "$HOME",
	} {
		rows = append(rows, readingBoundRow{"protected " + target, "PowerShell", prefixes[index%2] + "Remove-Item -Recurse -Force " + target, guardrailActionBlock})
	}
	rows = append(rows, readingBoundRow{"known protected value", "PowerShell",
		`$p = "~/.ssh"; ` + prefixes[1] + "Remove-Item -Recurse -Force $p", guardrailActionBlock})
	rows = append(rows, readingBoundRow{"benign", "PowerShell", "Get-ChildItem -Name", guardrailActionAllow})
	readingBoundCells(t, rows, 0)
}

// GAP-0677: a call whose nested shell bodies are past
// shellparse.MaxNestedBodyBytes is decided at once, within the hook window.
// An ordinary target runs with an alert in the default tier (the strict
// tier blocks it); a protected target named directly or through a known
// value blocks in every tier. Nested calls under the bound are read in
// full and an ordinary one allows.
func TestGAP0677NestedBodiesPastTheBoundAreGradedByTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	threeLevels := func(words int) string {
		return "bash -c " + "\x27ssh host \"sh -c \x27\\\x27\x27printf %s " + strings.Repeat("a b ", words) + "\x27\\\x27\x27\"\x27"
	}
	// The ordinary row in all four cells (strict blocks it); the others in
	// the default cells, as strict blocks every row (test budget).
	readingBoundCells(t, []readingBoundRow{
		{"ordinary ten levels", "Bash", readingBoundNest(10, "rm -rf ~/project/output"), guardrailActionAlert},
	}, 2*time.Second)
	readingBoundCellsIn(t, []readingBoundRow{
		{"ordinary three levels of 20 KB", "Bash", threeLevels(5000), guardrailActionAlert},
		{"known protected value", "Bash", "export protected=~/.defenseclaw; " + readingBoundNest(10, "rm -rf \"$protected\""), guardrailActionBlock},
	}, 2*time.Second, nil, readingBoundDefaultCells)
	// Under the bound the readers read the call in full; the default cells
	// carry these rows (test budget).
	readingBoundCellsIn(t, []readingBoundRow{
		{"ordinary nine levels", "Bash", readingBoundNest(9, "rm -rf ~/project/output"), guardrailActionAllow},
	}, 0, nil, readingBoundDefaultCells[:1])
	readingBoundCellsIn(t, []readingBoundRow{
		// Past shellparse.MaxNestedBodyProofBytes the readers read the call
		// but do not prove its protected target.
		{"known protected value nine levels", "Bash", "export protected=~/.defenseclaw; " + readingBoundNest(9, "rm -rf \"$protected\""), guardrailActionBlock},
	}, 0, nil, readingBoundDefaultCells[1:])
}
