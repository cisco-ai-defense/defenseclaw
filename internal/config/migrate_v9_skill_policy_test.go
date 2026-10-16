// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
)

func migratedSkillScanner(t *testing.T, migrated []byte) (string, AssetFileRef) {
	t.Helper()
	var got struct {
		Scanners struct {
			SkillScanner struct {
				Policy     string       `yaml:"policy"`
				PolicyFile AssetFileRef `yaml:"policy_file"`
			} `yaml:"skill_scanner"`
		} `yaml:"scanners"`
	}
	if err := yaml.Unmarshal(migrated, &got); err != nil {
		t.Fatal(err)
	}
	return got.Scanners.SkillScanner.Policy, got.Scanners.SkillScanner.PolicyFile
}

// GAP-1286: 0.8.x had no custom policy name, so a v8
// scanners.skill_scanner.policy of custom is the path of a policy file, which
// 0.8.x read relative to the working directory. The migration kept it as the
// 1.0 name with no policy_file, and the upgrade failed validation. The file
// is now pinned by its absolute path, which a gateway started in another
// directory still reads.
func TestMigrateV9PinsAV8PolicyFileNamedCustom(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	t.Chdir(dir)
	policy := []byte("policy_name: team\n")
	if err := os.WriteFile(filepath.Join(dir, "custom"), policy, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nscanners:\n  skill_scanner:\n    policy: custom\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("MigrateV9 with a v8 policy file named custom: %v", err)
	}
	name, ref := migratedSkillScanner(t, result.Migrated)
	if name != SkillScannerPolicyCustom || ref.Digest != "sha256:"+cfgtxn.SHA256Hex(policy) {
		t.Fatalf("policy = %q, policy_file = %+v; want custom pinned to the file:\n%s", name, ref, result.Migrated)
	}
	if !filepath.IsAbs(ref.Path) {
		t.Fatalf("policy_file.path %q is relative to the migration's working directory", ref.Path)
	}
	t.Chdir(t.TempDir())
	if _, err := ref.ReadVerified(); err != nil {
		t.Fatalf("the pinned policy does not read from another directory: %v", err)
	}
	if raw, err := os.ReadFile(configPath); err != nil || string(raw) != string(result.Migrated) {
		t.Fatalf("config.yaml after the migration = %q (%v)", raw, err)
	}
}

// A v8 source that already has the 1.0 form, custom with its pinned
// policy_file, keeps it as it is.
func TestMigrateV9KeepsAPinnedCustomPolicy(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	policyPath := filepath.Join(dir, "team-policy.yaml")
	policy := []byte("policy_name: team\n")
	if err := os.WriteFile(policyPath, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + cfgtxn.SHA256Hex(policy)
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nscanners:\n  skill_scanner:\n    policy: custom\n" +
		"    policy_file:\n      path: " + policyPath + "\n      digest: " + digest + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if name, ref := migratedSkillScanner(t, result.Migrated); name != SkillScannerPolicyCustom ||
		ref.Path != policyPath || ref.Digest != digest {
		t.Fatalf("policy = %q, policy_file = %+v; want the pinned file kept:\n%s", name, ref, result.Migrated)
	}
}
