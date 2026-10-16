// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestCustomPackDigestRefusalNamesThePinLine(t *testing.T) {
	policyDir := repoPolicyDir(t)
	cfg := &config.Config{PolicyDir: policyDir}
	cfg.Guardrail.RulePack = "acme"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
		"acme": {Path: filepath.Join(policyDir, "guardrail", "strict"), Digest: "sha256:" + strings.Repeat("0", 64)},
	}
	_, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
	if err == nil {
		t.Fatal("stale custom pack digest was accepted")
	}
	// internal/cli/rulepack.go prints this label in text mode; files_digest is JSON-only.
	if message := err.Error(); !strings.Contains(message, "custom_packs pin") || strings.Contains(message, "files_digest") {
		t.Fatalf("digest refusal = %q, want the text-mode pin label", message)
	}
}
