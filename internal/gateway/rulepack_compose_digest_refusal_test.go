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

// GAP-0632: a pin that does not match the files is the entry config error
// (status shows it) and an integrity refusal: the gateway does not load the
// pack, and does not run a built-in pack in its place. A pack edited after the
// configuration was read is refused the same way. Both name the pin line.
func TestCustomPackDigestRefusalNamesThePinLine(t *testing.T) {
	policyDir := repoPolicyDir(t)
	strictDir := filepath.Join(policyDir, "guardrail", "strict")
	stale := &config.Config{PolicyDir: policyDir}
	stale.Guardrail.RulePack = "acme"
	stale.Guardrail.CustomPacks = map[string]config.CustomRulePack{
		"acme": {Path: strictDir, Digest: "sha256:" + strings.Repeat("0", 64)},
	}
	problems := stale.CustomRulePackErrors()
	if len(problems) != 1 || !config.IsStalePinError(problems[0]) {
		t.Fatalf("stale custom pack digest config errors = %v, want one stale pin", problems)
	}
	if stale.CustomRulePackFallsBack("acme") {
		t.Fatal("a stale pin must not fall back to a built-in pack")
	}
	// internal/cli/rulepack.go prints this label in text mode; files_digest is JSON-only.
	if message := problems[0].Error(); !strings.Contains(message, "custom_packs pin") || strings.Contains(message, "files_digest") {
		t.Fatalf("digest config error = %q, want the text-mode pin label", message)
	}
	_, err := loadGlobalRulePack(guardrail.NewRulePackCache(), stale, "global")
	if err == nil {
		t.Fatal("stale custom pack digest was accepted")
	}
	if message := err.Error(); !strings.Contains(message, "custom_packs pin") || strings.Contains(message, "files_digest") {
		t.Fatalf("digest refusal = %q, want the text-mode pin label", message)
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
	_, err = loadGlobalRulePack(guardrail.NewRulePackCache(), edited, "global")
	if err == nil {
		t.Fatal("custom pack edited after the configuration was read was accepted")
	}
	if message := err.Error(); !strings.Contains(message, "custom_packs pin") || strings.Contains(message, "files_digest") {
		t.Fatalf("digest refusal = %q, want the text-mode pin label", message)
	}
}
