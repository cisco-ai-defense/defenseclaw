// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-0632: a pin that does not match the files is the entry's config error
// (the selection runs the built-in pack), and a pack edited after the
// configuration was read is still refused by the loader, both naming the pin
// line.
func TestCustomPackDigestRefusalNamesThePinLine(t *testing.T) {
	policyDir := repoPolicyDir(t)
	strictDir := filepath.Join(policyDir, "guardrail", "strict")
	stale := &config.Config{PolicyDir: policyDir}
	stale.Guardrail.RulePack = "acme"
	stale.Guardrail.CustomPacks = map[string]config.CustomRulePack{
		"acme": {Path: strictDir, Digest: "sha256:" + strings.Repeat("0", 64)},
	}
	problems := stale.CustomRulePackErrors()
	if len(problems) != 1 {
		t.Fatalf("stale custom pack digest config errors = %v, want one", problems)
	}
	// internal/cli/rulepack.go prints this label in text mode; files_digest is JSON-only.
	if message := problems[0].Error(); !strings.Contains(message, "custom_packs pin") || strings.Contains(message, "files_digest") {
		t.Fatalf("digest config error = %q, want the text-mode pin label", message)
	}
	if _, err := loadGlobalRulePack(guardrail.NewRulePackCache(), stale, "global"); err != nil {
		t.Fatalf("stale custom pack digest: %v, want the built-in fallback", err)
	}

	dir := filepath.Join(t.TempDir(), "acme")
	edited := &config.Config{PolicyDir: policyDir}
	edited.Guardrail.RulePack = "acme"
	edited.Guardrail.CustomPacks = map[string]config.CustomRulePack{"acme": {Path: dir, Digest: copyShippedPack(t, "strict", dir)}}
	edited.CheckCustomRulePacks()
	if err := edited.CustomRulePackError("acme"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, guardrail.PackManifestFile), []byte(`{"posture": "strict"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadGlobalRulePack(guardrail.NewRulePackCache(), edited, "global")
	if err == nil {
		t.Fatal("custom pack edited after the configuration was read was accepted")
	}
	if message := err.Error(); !strings.Contains(message, "custom_packs pin") || strings.Contains(message, "files_digest") {
		t.Fatalf("digest refusal = %q, want the text-mode pin label", message)
	}
}
