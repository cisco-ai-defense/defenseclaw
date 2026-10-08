// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const standaloneGatewayCheckConfig = `config_version: 8
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
  rule_pack_dir: ""
  connectors:
    claudecode:
      enabled: true
    codex:
      enabled: true
`

func writeStandaloneGatewayCheckConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A config the gateway cannot load is refused with the file, the
// location and the reason, not installed and left to fail at service start.
func TestStandaloneGatewayConfigCheckNamesTheFileAndTheReason(t *testing.T) {
	dataDir := t.TempDir()
	valid := writeStandaloneGatewayCheckConfig(t, standaloneGatewayCheckConfig)
	if err := validateStandaloneGatewayConfig(valid, dataDir, ""); err != nil {
		t.Fatalf("valid standalone config refused: %v", err)
	}

	noVersion := writeStandaloneGatewayCheckConfig(t, strings.TrimPrefix(standaloneGatewayCheckConfig, "config_version: 8\n"))
	err := validateStandaloneGatewayConfig(noVersion, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), noVersion) || !strings.Contains(err.Error(), "config_version_required") {
		t.Fatalf("config without config_version = %v, want its path and config_version_required", err)
	}

	// trust.mode "" means unset and is valid. The schema's mode values are
	// case-sensitive, so a value the lifecycle would read case-insensitively
	// still fails the gateway's compiler.
	emptyTrust := writeStandaloneGatewayCheckConfig(t, strings.Replace(standaloneGatewayCheckConfig,
		"  profile: standalone\n", "  profile: standalone\n  trust:\n    mode: \"\"\n", 1))
	if err := validateStandaloneGatewayConfig(emptyTrust, dataDir, ""); err != nil {
		t.Fatalf("config with trust.mode \"\" (unset) refused: %v", err)
	}
	unknownTrust := writeStandaloneGatewayCheckConfig(t, strings.Replace(standaloneGatewayCheckConfig,
		"  profile: standalone\n", "  profile: standalone\n  trust:\n    mode: AUTHENTICODE\n", 1))
	err = validateStandaloneGatewayConfig(unknownTrust, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "$.enterprise.trust.mode") || !strings.Contains(err.Error(), "config_schema_invalid") {
		t.Fatalf("config with trust.mode AUTHENTICODE = %v, want the schema location", err)
	}

	missingPack := filepath.Join(t.TempDir(), "missing-pack")
	noPack := writeStandaloneGatewayCheckConfig(t, strings.Replace(standaloneGatewayCheckConfig,
		`  rule_pack_dir: ""`, "  rule_pack_dir: '"+missingPack+"'", 1))
	err = validateStandaloneGatewayConfig(noPack, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), missingPack) || !strings.Contains(err.Error(), "directory_not_found") {
		t.Fatalf("config naming a missing rule pack = %v, want the directory and directory_not_found", err)
	}
}

// GAP-0095: the gateway service account's own read access is checked with
// the account the preflight pins, and its refusal (which names the account
// and the icacls fix) comes before the pack is loaded as an administrator.
func TestStandaloneGatewayConfigCheckAsksTheServiceAccount(t *testing.T) {
	pack := filepath.Join(t.TempDir(), "pack")
	if err := os.MkdirAll(pack, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := writeStandaloneGatewayCheckConfig(t, strings.Replace(standaloneGatewayCheckConfig,
		`  rule_pack_dir: ""`, "  rule_pack_dir: '"+pack+"'", 1))
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawGateway`)
	restore := standaloneServiceCanReadTree
	t.Cleanup(func() { standaloneServiceCanReadTree = restore })
	var asked []string
	standaloneServiceCanReadTree = func(root, label, account string) error {
		asked = append(asked, label+"|"+root+"|"+account)
		return errors.New(label + " " + root + ": the gateway service account " + account + " cannot read it; grant it Read & execute, for example: icacls")
	}
	err := validateStandaloneGatewayConfig(configPath, t.TempDir(), "")
	if err == nil || !strings.Contains(err.Error(), `NT SERVICE\DefenseClawGateway`) || !strings.Contains(err.Error(), "icacls") {
		t.Fatalf("service-unreadable pack = %v, want the account and the icacls fix", err)
	}
	if len(asked) != 1 || asked[0] != "guardrail.rule_pack_dir|"+pack+`|NT SERVICE\DefenseClawGateway` {
		t.Fatalf("service read check calls = %q", asked)
	}
}

// GAP-0039: a connector that inherits the selected custom pack is not the key
// a refusal names, and a custom_packs entry nothing selects is not loaded.
func TestStandaloneGatewayRulePackDirsNameTheKeysTheAdminWrote(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.RulePack = "acme"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
		"acme":   {Path: "/packs/acme"},
		"unused": {Path: "/packs/unused"},
	}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"amp": {}, "codex": {}}
	got := standaloneGatewayRulePackDirs(cfg)
	if len(got) != 1 || got[0].label != "guardrail.rule_pack" || got[0].dir != "/packs/acme" {
		t.Fatalf("rule pack checks = %+v, want one guardrail.rule_pack /packs/acme", got)
	}
}

// GAP-0188: a custom_packs pin the gateway refuses at start is refused here,
// with the digest to pin, so a Windows upgrade that keeps the config fails
// before it stops the services instead of after the readiness wait.
func TestStandaloneGatewayConfigCheckRefusesAStaleCustomPackPin(t *testing.T) {
	pack := t.TempDir()
	suppressions := "version: 1\npre_judge_strips: []\nfinding_suppressions: []\ntool_suppressions: []\n"
	if err := os.WriteFile(filepath.Join(pack, "suppressions.yaml"), []byte(suppressions), 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(strings.Replace(standaloneGatewayCheckConfig, "config_version: 8\n", "config_version: 9\n", 1),
		`  rule_pack_dir: ""`, "  rule_pack: acme\n  custom_packs:\n    acme:\n      path: '"+pack+"'\n      digest: sha256:"+strings.Repeat("0", 64), 1)
	err := validateStandaloneGatewayConfig(writeStandaloneGatewayCheckConfig(t, body), t.TempDir(), "")
	if err == nil || !strings.Contains(err.Error(), "does not match guardrail.custom_packs.acme.digest") ||
		!strings.Contains(err.Error(), "rulepack validate --dir") {
		t.Fatalf("stale custom pack pin = %v, want the digest to pin and the command that prints it", err)
	}
}
