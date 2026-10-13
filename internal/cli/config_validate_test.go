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
