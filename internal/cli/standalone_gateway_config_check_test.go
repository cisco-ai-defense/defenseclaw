// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if err := validateStandaloneGatewayConfig(valid, dataDir); err != nil {
		t.Fatalf("valid standalone config refused: %v", err)
	}

	noVersion := writeStandaloneGatewayCheckConfig(t, strings.TrimPrefix(standaloneGatewayCheckConfig, "config_version: 8\n"))
	err := validateStandaloneGatewayConfig(noVersion, dataDir)
	if err == nil || !strings.Contains(err.Error(), noVersion) || !strings.Contains(err.Error(), "config_version_required") {
		t.Fatalf("config without config_version = %v, want its path and config_version_required", err)
	}

	// trust.mode "" means unset and is valid. The schema's mode values are
	// case-sensitive, so a value the lifecycle would read case-insensitively
	// still fails the gateway's compiler.
	emptyTrust := writeStandaloneGatewayCheckConfig(t, strings.Replace(standaloneGatewayCheckConfig,
		"  profile: standalone\n", "  profile: standalone\n  trust:\n    mode: \"\"\n", 1))
	if err := validateStandaloneGatewayConfig(emptyTrust, dataDir); err != nil {
		t.Fatalf("config with trust.mode \"\" (unset) refused: %v", err)
	}
	unknownTrust := writeStandaloneGatewayCheckConfig(t, strings.Replace(standaloneGatewayCheckConfig,
		"  profile: standalone\n", "  profile: standalone\n  trust:\n    mode: AUTHENTICODE\n", 1))
	err = validateStandaloneGatewayConfig(unknownTrust, dataDir)
	if err == nil || !strings.Contains(err.Error(), "$.enterprise.trust.mode") || !strings.Contains(err.Error(), "config_schema_invalid") {
		t.Fatalf("config with trust.mode AUTHENTICODE = %v, want the schema location", err)
	}

	missingPack := filepath.Join(t.TempDir(), "missing-pack")
	noPack := writeStandaloneGatewayCheckConfig(t, strings.Replace(standaloneGatewayCheckConfig,
		`  rule_pack_dir: ""`, "  rule_pack_dir: '"+missingPack+"'", 1))
	err = validateStandaloneGatewayConfig(noPack, dataDir)
	if err == nil || !strings.Contains(err.Error(), missingPack) || !strings.Contains(err.Error(), "directory_not_found") {
		t.Fatalf("config naming a missing rule pack = %v, want the directory and directory_not_found", err)
	}
}
