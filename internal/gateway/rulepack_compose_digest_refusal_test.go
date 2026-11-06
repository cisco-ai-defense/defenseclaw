// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// On a managed install the gateway is not on the PATH, so the digest refusal
// names it by its path; a per-user install has it on the PATH (cowork-1-0-8
// GAP-0081).
func TestRulePackValidateCommandNamesTheManagedGatewayByItsPath(t *testing.T) {
	user := &config.Config{}
	managedCfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	managedCfg.Enterprise.Profile = "standalone"
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		goos string
		want string
	}{
		{"per-user linux", user, "linux", "defenseclaw-gateway rulepack validate --dir <pack dir>"},
		{"per-user windows", user, "windows", "defenseclaw-gateway rulepack validate --dir <pack dir>"},
		{"managed linux", managedCfg, "linux", "/opt/defenseclaw/bin/defenseclaw-gateway rulepack validate --dir <pack dir>"},
		{"managed darwin", managedCfg, "darwin", "/opt/cisco/defenseclaw/bin/defenseclaw-gateway rulepack validate --dir <pack dir>"},
	} {
		if got := rulePackValidateCommand(tc.cfg, tc.goos); got != tc.want {
			t.Errorf("%s: command = %q, want %q", tc.name, got, tc.want)
		}
	}
	windows := rulePackValidateCommand(managedCfg, "windows")
	if !strings.HasPrefix(windows, "& '") || !strings.Contains(windows, `defenseclaw-gateway.exe' rulepack validate --dir`) {
		t.Errorf("managed windows command = %q, want the installed defenseclaw-gateway.exe", windows)
	}
}

func TestCustomPackDigestRefusalNamesTheManagedGatewayByItsPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows form is covered by TestRulePackValidateCommandNamesTheManagedGatewayByItsPath")
	}
	policyDir := repoPolicyDir(t)
	cfg := &config.Config{PolicyDir: policyDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = "standalone"
	cfg.Guardrail.RulePack = "acme"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
		"acme": {Path: filepath.Join(policyDir, "guardrail", "strict"), Digest: "sha256:" + strings.Repeat("0", 64)},
	}
	_, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
	if err == nil {
		t.Fatal("stale custom pack digest was accepted")
	}
	want := "`" + managed.StandaloneGatewayPath(runtime.GOOS) + " rulepack validate"
	if message := err.Error(); !strings.Contains(message, want) || strings.Contains(message, "`defenseclaw-gateway") {
		t.Fatalf("digest refusal = %q, want %q", message, want)
	}
}
