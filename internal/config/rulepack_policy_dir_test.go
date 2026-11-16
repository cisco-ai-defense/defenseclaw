// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2126: the implicit default rule pack is the default preset under the
// policy_dir config.yaml names (where the CLI seeds it), not a folder under
// data_dir; a policy_dir without that folder keeps the data_dir pack.
func TestImplicitRulePackFollowsTheConfiguredPolicyDir(t *testing.T) {
	for _, tc := range []struct {
		name   string
		seeded bool
	}{{"seeded policy_dir", true}, {"policy_dir without packs", false}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dataDir := filepath.Join(dir, "dcdata")
			policyDir := filepath.Join(dir, "inst-home", "policies")
			if tc.seeded {
				if err := os.MkdirAll(filepath.Join(policyDir, "guardrail", "default"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, "config.yaml")
			raw := []byte("config_version: 9\ndata_dir: " + dataDir + "\npolicy_dir: " + policyDir + "\nobservability: {}\n")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(dataDir, "policies", "guardrail", "default")
			if tc.seeded {
				want = filepath.Join(policyDir, "guardrail", "default")
			}
			if cfg.Guardrail.RulePackDir != want {
				t.Fatalf("guardrail.rule_pack_dir = %q, want %q", cfg.Guardrail.RulePackDir, want)
			}
		})
	}
}
