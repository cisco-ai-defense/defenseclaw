// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0252: `config validate <file>` is read-only and names the profile.
func TestConfigValidateCommandReportsTheProfile(t *testing.T) {
	path, dir := writeSandboxProfileConfig(t, "", "        allowed: false\n        required_for: [claudecode]\n")
	out := &strings.Builder{}
	configValidateCmd.SetOut(out)
	t.Cleanup(func() { configValidateCmd.SetOut(nil); configValidateJSON, configValidateDataDir = false, "" })
	configValidateDataDir = dir
	err := configValidateCmd.RunE(configValidateCmd, []string{path})
	if err == nil || !strings.Contains(err.Error(), `guardrail.profiles["contractors"]`) ||
		!strings.Contains(err.Error(), "allowed: false contradicts required_for") {
		t.Fatalf("config validate error = %v", err)
	}

	good, goodDir := writeSandboxProfileConfig(t, "", "        required_for: [claudecode]\n")
	configValidateDataDir = goodDir
	out.Reset()
	if err := configValidateCmd.RunE(configValidateCmd, []string{good}); err != nil {
		t.Fatalf("config validate refused a valid config: %v", err)
	}
	if !strings.Contains(out.String(), "valid (config_version 9)") {
		t.Fatalf("config validate output = %q", out.String())
	}
	configValidateJSON = true
	out.Reset()
	if err := configValidateCmd.RunE(configValidateCmd, []string{good}); err != nil {
		t.Fatal(err)
	}
	var wire configV8WireResponse
	if err := json.Unmarshal([]byte(out.String()), &wire); err != nil || wire.Valid == nil || !*wire.Valid {
		t.Fatalf("config validate --json = %q (%v)", out.String(), err)
	}
}

// Owner decision 2026-10-20: a managed computer's fail mode is the
// administrator's choice, so config validate accepts an explicit open on the
// standalone profile and names no ignored setting (the fail_open_ignored
// warning of rel-1-0-3 GAP-0091 is gone with the override it reported).
func TestConfigValidateAcceptsManagedFailOpenSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	source := fmt.Sprintf("config_version: 9\ndata_dir: %s\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"+
		"guardrail:\n  mode: observe\n  hook_fail_mode: open\n  connectors:\n    hermes:\n      hook_fail_mode: open\n", dir)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &strings.Builder{}
	configValidateCmd.SetOut(out)
	t.Cleanup(func() { configValidateCmd.SetOut(nil); configValidateJSON, configValidateDataDir = false, "" })
	configValidateDataDir = dir
	if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
		t.Fatalf("config validate refused the managed config: %v", err)
	}
	if strings.Contains(out.String(), "fail_open_ignored") || strings.Contains(out.String(), "open is ignored") {
		t.Fatalf("config validate text = %q, want no ignored fail-open warning", out.String())
	}
	configValidateJSON = true
	out.Reset()
	if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
		t.Fatal(err)
	}
	var wire configV8WireResponse
	if err := json.Unmarshal([]byte(out.String()), &wire); err != nil || wire.Valid == nil || !*wire.Valid {
		t.Fatalf("config validate --json = %q (%v)", out.String(), err)
	}
	for _, warning := range wire.Warnings {
		if strings.Contains(warning, "fail_open_ignored") || strings.Contains(warning, "open is ignored") {
			t.Fatalf("config validate --json warnings = %q, want no ignored fail-open warning", wire.Warnings)
		}
	}
}
