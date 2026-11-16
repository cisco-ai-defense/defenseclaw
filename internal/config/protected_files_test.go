// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// releasedGuardrailShapes are the guardrail blocks 1.0.2 to 1.0.5 write
// (config_version 9): none names protected_files.
var releasedGuardrailShapes = map[string]string{
	"1.0.2": "guardrail:\n  mode: observe\n",
	"1.0.3": "guardrail:\n  mode: action\n  rule_pack: default\n",
	"1.0.4": "guardrail:\n  mode: action\n  hook_fail_mode: open\n  connectors:\n    claudecode:\n      mode: action\n",
	"1.0.5": "guardrail:\n  mode: action\n  rule_pack: strict\n  hook_self_heal: true\n",
}

// An upgrade from 1.0.2-1.0.5 reads the config unchanged and gets the
// default watch (alert, no restore); nothing writes the key back, so a
// rollback to 1.0.4 or 1.0.5 still validates the file.
func TestProtectedFilesUpgradeFromReleasedConfigs(t *testing.T) {
	for release, guardrail := range releasedGuardrailShapes {
		t.Run(release, func(t *testing.T) {
			raw := []byte("config_version: 9\n" + guardrail + "observability: {}\n")
			path := filepath.Join(t.TempDir(), DefaultConfigName)
			if err := ValidateCandidate(path, raw); err != nil {
				t.Fatalf("this release refuses a %s config: %v", release, err)
			}
			cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(path, raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Guardrail.ProtectedFiles.EffectiveOnChange(); got != ProtectedFilesAlert {
				t.Fatalf("on_change = %q, want alert", got)
			}
			out, err := yaml.Marshal(cfg.Guardrail)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), "protected_files") {
				t.Fatalf("an unset watch is written back:\n%s", out)
			}
		})
	}
}

func TestProtectedFilesSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultConfigName)
	ok := []byte("config_version: 9\nguardrail:\n  protected_files:\n    on_change: restore\n    paths: [.ssh/authorized_keys, .config/autostart/]\nobservability: {}\n")
	if err := ValidateCandidate(path, ok); err != nil {
		t.Fatalf("a valid block was refused: %v", err)
	}
	for _, bad := range []string{
		"guardrail:\n  protected_files:\n    on_change: block\n",
		"guardrail:\n  protected_files:\n    watch: true\n",
	} {
		if err := ValidateCandidate(path, []byte("config_version: 9\n"+bad+"observability: {}\n")); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
