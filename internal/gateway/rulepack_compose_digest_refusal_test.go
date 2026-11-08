// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// On a standalone managed install the gateway is not on the PATH, so the digest
// refusal names it by its path; a per-user install has it on the PATH
// (cowork-1-0-8 GAP-0081). Secure Client, whether the profile is explicit or
// the default of a managed config, keeps the text of release 1.0.5 byte for
// byte on every OS (review round 4, S1).
func TestRulePackValidateCommandNamesTheManagedGatewayByItsPath(t *testing.T) {
	user := &config.Config{}
	managedCfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	managedCfg.Enterprise.Profile = managed.ProfileStandalone
	secureClient := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	secureClient.Enterprise.Profile = managed.ProfileSecureClient
	secureClientDefault := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	const releasedText = "defenseclaw-gateway rulepack validate --dir <pack dir>"
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
		{"secure_client linux", secureClient, "linux", releasedText},
		{"secure_client darwin", secureClient, "darwin", releasedText},
		{"secure_client windows", secureClient, "windows", releasedText},
		{"managed without a profile (secure_client) darwin", secureClientDefault, "darwin", releasedText},
		{"managed without a profile (secure_client) windows", secureClientDefault, "windows", releasedText},
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

// A Secure Client computer's digest refusal is the text of release 1.0.5: the
// bare gateway name, not the standalone path (review round 4, S1).
func TestCustomPackDigestRefusalOnSecureClientKeepsTheReleasedText(t *testing.T) {
	policyDir := repoPolicyDir(t)
	for name, profile := range map[string]string{"explicit": managed.ProfileSecureClient, "default": ""} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{PolicyDir: policyDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Enterprise.Profile = profile
			cfg.Guardrail.RulePack = "acme"
			cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
				"acme": {Path: filepath.Join(policyDir, "guardrail", "strict"), Digest: "sha256:" + strings.Repeat("0", 64)},
			}
			_, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
			if err == nil {
				t.Fatal("stale custom pack digest was accepted")
			}
			want := "(`defenseclaw-gateway rulepack validate --dir <pack dir>` prints it on the"
			if message := err.Error(); !strings.Contains(message, want) || strings.Contains(message, "/bin/defenseclaw-gateway") {
				t.Fatalf("digest refusal = %q, want %q", message, want)
			}
		})
	}
}
