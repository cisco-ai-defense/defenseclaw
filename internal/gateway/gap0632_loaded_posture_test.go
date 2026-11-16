// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestGAP0632LoadedPostureUsesPinnedManifestBytes(t *testing.T) {
	root := guardrailPoliciesRoot(t)
	dir := filepath.Join(t.TempDir(), "operator-pack")
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, "strict"))); err != nil {
		t.Fatal(err)
	}
	pin, err := guardrail.RulePackDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.RulePack = "operator"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
		"operator": {Path: dir, Digest: "sha256:" + pin},
	}
	t.Cleanup(func() { pendingPackPostures.Delete(dir); packPostures.Delete(dir) })
	cfg.CheckCustomRulePacks()
	pack, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
	if err != nil {
		t.Fatal(err)
	}
	if pack.Posture() != "strict" {
		t.Fatalf("loaded posture = %q, want strict", pack.Posture())
	}
	if err := os.WriteFile(filepath.Join(dir, guardrail.PackManifestFile), []byte(`{"posture":"default"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	buildThresholdTable(cfg, nil)
	if got := resolveThresholds(cfg, ""); got.Block != "MEDIUM" || got.Alert != "LOW" {
		t.Fatalf("published levels = %+v, want the loaded strict posture", got)
	}
}

func TestGAP0632PinnedPostureGovernsOutageAndAuditFailures(t *testing.T) {
	root := guardrailPoliciesRoot(t)
	for _, row := range []struct {
		name, edited, outage string
		auditBlock           bool
	}{
		{"strict", "default", "closed", true},
		{"default", "strict", "open", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "operator-pack")
			if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, row.name))); err != nil {
				t.Fatal(err)
			}
			pin, err := guardrail.RulePackDigest(dir)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.RulePack = "operator"
			cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
				"operator": {Path: dir, Digest: "sha256:" + pin},
			}
			t.Cleanup(func() { pendingPackPostures.Delete(dir); packPostures.Delete(dir) })
			cfg.CheckCustomRulePacks()
			if _, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global"); err != nil {
				t.Fatal(err)
			}
			buildThresholdTable(cfg, nil)
			if err := os.WriteFile(filepath.Join(dir, guardrail.PackManifestFile),
				[]byte(`{"posture":"`+row.edited+`"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := cfg.HookPolicyTierForConnector("codex"); got != row.name {
				t.Errorf("pinned tier = %q, want %q", got, row.name)
			}
			if got := cfg.EffectiveHookOutageFailModeForConnector("codex"); got != row.outage {
				t.Errorf("pinned outage mode = %q, want %q", got, row.outage)
			}
			api := &APIServer{scannerCfg: cfg}
			ctx := withPinnedGeneration(context.Background(), &Generation{N: 1, Config: cfg})
			verdict := &ToolInspectVerdict{Action: "allow", RawAction: "allow", Severity: "NONE"}
			if got := api.inspectAuditFailureVerdict(ctx, "codex", &ToolInspectRequest{Tool: "exec", Direction: "tool_call"}, verdict); got != row.auditBlock {
				t.Errorf("pinned audit failure block = %t, want %t; verdict = %+v", got, row.auditBlock, verdict)
			}
		})
	}
}
