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

// gap0607ReplayGuard is a shell regression found by the 1.0.9 replays
// (plans/r109/reg/VERIFY-REG.md). Want holds the ratified 1.0.9 verdict per
// cell. Pending pins the current decision of a cell whose product change is
// owned by another gap; a changed result, including the ratified one,
// fails until the entry is reviewed and removed.
type gap0607ReplayGuard struct {
	Replay, Gap, Command string
	Want                 map[string]string
	Pending              map[string]d1PendingProductDecision
}

func gap0607GuardAPI(t *testing.T, connector string, strict bool) *APIServer {
	t.Helper()
	if !strict {
		return d1TestAPI(t, connector)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePack = "strict"
	return &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
}

func gap0607Cells() []string {
	var cells []string
	for _, connector := range []string{"claudecode", "codex"} {
		for _, tier := range []string{"oss", "managed-balanced", "strict"} {
			cells = append(cells, connector+"/"+tier)
		}
	}
	return cells
}

// gap0607Tiered returns the same verdict for both connectors: balanced for
// the OSS default and managed balanced cells, strict for the strict cell.
func gap0607Tiered(balanced, strict string) map[string]string {
	want := make(map[string]string)
	for _, cell := range gap0607Cells() {
		want[cell] = balanced
		if strings.HasSuffix(cell, "/strict") {
			want[cell] = strict
		}
	}
	return want
}

// gap0607PendingCells pins the current decision of the named tiers.
func gap0607PendingCells(gap string, want map[string]string, current d1ReplayVerdict, tiers ...string) map[string]d1PendingProductDecision {
	pending := make(map[string]d1PendingProductDecision)
	for _, cell := range gap0607Cells() {
		for _, tier := range tiers {
			if strings.HasSuffix(cell, "/"+tier) {
				pending[cell] = d1PendingProductDecision{Gap: gap, Want: want[cell], Current: current}
			}
		}
	}
	return pending
}

// The ratified 1.0.9 verdicts follow rel-1-0-6 GAP-0675: a protected user
// file finding alerts in the balanced tiers and blocks in strict. Its policy
// change (fix/r109-ghpw) is not yet on the release branch, so the balanced
// cells are pinned to the current block and fail once it lands, for review.
// The detection redesign of these shapes is the 1.0.10 round (#1189).
func gap0607ReplayGuards() []gap0607ReplayGuard {
	finding := gap0607Tiered("alert", "block")
	ordinary := gap0607Tiered("allow", "allow")
	block := d1ReplayVerdict{Decision: "block", RuleID: "persistence.ssh_authorized_keys_command"}
	allow := d1ReplayVerdict{Decision: "allow", RuleID: "-"}
	policy := func(command, replay, gap string) gap0607ReplayGuard {
		return gap0607ReplayGuard{Replay: replay, Gap: gap, Command: command, Want: finding,
			Pending: gap0607PendingCells("GAP-0675", finding, block, "oss", "managed-balanced")}
	}
	return []gap0607ReplayGuard{
		// A write through a name a preceding pull may materialize has no
		// finding yet: expected to fail until the detection round.
		{Replay: "R2-T1-24", Gap: "GAP-0493", Command: `git -C sub pull && echo marker >> future`, Want: finding,
			Pending: gap0607PendingCells("GAP-0675 #1189", finding, allow, "oss", "managed-balanced", "strict")},
		{Replay: "R2-T1-24 twin", Gap: "GAP-0493", Command: `git -C sub pull && echo marker >> notes.txt`, Want: ordinary},
		policy(`node -e "require(fs).writeFileSync(/tmp/report.txt, see /Users/vnarajal/.ssh/authorized_keys)"`, "R8-T1-17 data", "GAP-1266"),
		policy(`echo "check ~/.ssh/authorized_keys" >> ~/app.log`, "R8-T1-17 log", "GAP-1267"),
		policy(`diff ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak`, "R5-T1-08 diff", "GAP-1183"),
		policy(`cp ~/.ssh/authorized_keys /var/tmp/keys.bak`, "R5-T1-08 copy", "GAP-1183"),
		policy(`echo marker >> ~/.ssh/authorized_keys`, "protected twin", "GAP-1267"),
		{Replay: "benign twin", Gap: "GAP-1267", Command: `echo marker >> ~/app.log`, Want: ordinary},
	}
}

func TestGAP0607ReplayRegressionGuards(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(cwd, ".git"), filepath.Join(cwd, "sub"), filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	apis := make(map[string]*APIServer)
	for _, connector := range []string{"claudecode", "codex"} {
		apis[connector+"/balanced"] = gap0607GuardAPI(t, connector, false)
		apis[connector+"/strict"] = gap0607GuardAPI(t, connector, true)
	}
	record := os.Getenv("DC_GUARD_RECORD") == "1"
	for _, guard := range gap0607ReplayGuards() {
		t.Run(guard.Replay+" "+guard.Gap, func(t *testing.T) {
			row := d1ReplayRow{ID: guard.Replay, Kind: "shell", Command: guard.Command, Expected: guard.Want}
			for _, cell := range gap0607Cells() {
				connector, tier, _ := strings.Cut(cell, "/")
				api := apis[connector+"/balanced"]
				if tier == "strict" {
					api = apis[connector+"/strict"]
				}
				got := d1Evaluate(t, api, row, connector, tier == "managed-balanced", home, cwd)
				if record {
					t.Logf("GUARD %s %s %s %s", guard.Replay, cell, got.Decision, got.RuleID)
					continue
				}
				if err := d1CheckPublicVerdict(row, cell, got, gap0607PendingByRow(guard)); err != nil {
					t.Errorf("%s %s %s: %v", guard.Replay, guard.Gap, cell, err)
				}
			}
		})
	}
}

func gap0607PendingByRow(guard gap0607ReplayGuard) map[string]d1PendingProductDecision {
	pending := make(map[string]d1PendingProductDecision, len(guard.Pending))
	for cell, item := range guard.Pending {
		pending[guard.Replay+" "+cell] = item
	}
	return pending
}
