// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
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
