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

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// writeShippedRulePacks writes this binary's shipped packs where a managed
// Windows Setup puts them under root and returns their folder.
func writeShippedRulePacks(t *testing.T, root string) string {
	t.Helper()
	name, err := policyassets.ShippedRulePackFolderName()
	if err != nil {
		t.Fatal(err)
	}
	files, err := policyassets.ShippedRulePackFiles()
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, name)
	for _, file := range files {
		path := filepath.Join(folder, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, file.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return folder
}

// TestShippedRulePacksOnManagedWindows covers #1445 (before it, GAP-1041
// refused strict with no policy_dir): a managed Windows standalone install
// loads strict and permissive from the folder its Setup ships with no
// policy_dir; a folder whose files are not this release's is refused, and a
// missing one names the repair; an explicit policy_dir folder still wins and
// is the administrator's to change. Secure Client, the Linux and macOS
// layout and per-user keep the earlier text.
func TestShippedRulePacksOnManagedWindows(t *testing.T) {
	root := t.TempDir()
	defer config.SetWindowsShippedRulePacksRootForTest(root)()
	managedConfig := func(profile, configFile, pack string) *config.Config {
		cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, ConfigFilePath: configFile}
		cfg.Enterprise.Profile = profile
		cfg.Guardrail.RulePack = pack
		return cfg
	}
	load := func(cfg *config.Config) (*guardrail.RulePack, error) {
		return loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
	}
	const windowsConfig = `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`

	windows := managedConfig("standalone", windowsConfig, "strict")
	if _, err := load(windows); err == nil || !strings.Contains(err.Error(), "directory_not_found") || !strings.Contains(err.Error(), "/repair") {
		t.Fatalf("strict before Setup wrote its folder = %v, want directory_not_found with the repair named", err)
	}

	folder := writeShippedRulePacks(t, root)
	for _, pack := range []string{"strict", "permissive"} {
		windows.Guardrail.RulePack = pack
		loaded, err := load(windows)
		if err != nil {
			t.Fatalf("%s from the shipped folder: %v", pack, err)
		}
		if got := loaded.Posture(); got != pack {
			t.Errorf("%s loaded with posture %q", pack, got)
		}
	}
	windows.Guardrail.RulePack = "default"
	if _, err := load(windows); err != nil {
		t.Fatalf("default (embedded) on managed Windows: %v", err)
	}

	// A file changed in the shipped folder: refused, never loaded.
	windows.Guardrail.RulePack = "strict"
	suppressions := filepath.Join(folder, "strict", "suppressions.yaml")
	original, err := os.ReadFile(suppressions)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(suppressions, append(append([]byte{}, original...), []byte("\n# weakened\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(windows); err == nil || !strings.Contains(err.Error(), "are not the strict pack this release ships") ||
		!strings.Contains(err.Error(), "/repair") {
		t.Fatalf("an edited shipped strict pack = %v, want the refusal with the repair named", err)
	}
	if err := os.WriteFile(suppressions, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(windows); err != nil {
		t.Fatalf("the restored shipped folder: %v", err)
	}

	// An explicit policy_dir folder wins and is not held to the shipped
	// bytes: it is the administrator's pack.
	policyDir := t.TempDir()
	adminStrict := filepath.Join(policyDir, "guardrail", "strict")
	if err := os.CopyFS(adminStrict, os.DirFS(filepath.Join(folder, "strict"))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adminStrict, "suppressions.yaml"), append(append([]byte{}, original...), []byte("\n# admin copy\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	windows.PolicyDir = policyDir
	if got := windows.ResolveRulePackDir(config.RulePackRef{Name: "strict"}); got != adminStrict {
		t.Fatalf("strict with a policy_dir folder resolves to %q, want %q", got, adminStrict)
	}
	if _, err := load(windows); err != nil {
		t.Fatalf("the administrator's policy_dir strict pack: %v", err)
	}
	windows.PolicyDir = ""

	for name, cfg := range map[string]*config.Config{
		"secure client": managedConfig("secure_client", windowsConfig, "strict"),
		"linux layout":  managedConfig("standalone", "/etc/defenseclaw/config.yaml", "strict"),
		"per user":      {Guardrail: config.GuardrailConfig{RulePack: "strict"}},
	} {
		_, err := load(cfg)
		if err == nil || !strings.HasSuffix(err.Error(), `rule pack "strict": policy_dir is not set`) {
			t.Errorf("%s refusal = %v, want the earlier text", name, err)
		}
	}
}
