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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestBuiltinRulePackRefusalNamesTheProperty covers GAP-1041: a managed
// Windows standalone install ships only the default rule pack, so strict with
// no policy_dir is refused with the properties that fix it, and a policy_dir
// without the pack folder names itself. Secure Client and the Linux and macOS
// layout keep the earlier text.
func TestBuiltinRulePackRefusalNamesTheProperty(t *testing.T) {
	managedConfig := func(profile, configFile string) *config.Config {
		cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, ConfigFilePath: configFile}
		cfg.Enterprise.Profile = profile
		cfg.Guardrail.RulePack = "strict"
		return cfg
	}
	load := func(cfg *config.Config) error {
		_, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
		return err
	}

	windows := managedConfig("standalone", `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`)
	err := load(windows)
	if err == nil {
		t.Fatal("strict with no policy_dir loaded")
	}
	for _, want := range []string{"policy_dir is not set", "set policy_dir to", "guardrail.custom_packs", "rule_pack: default", `guardrail\strict`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("windows refusal %q does not contain %q", err, want)
		}
	}

	windows.PolicyDir = t.TempDir()
	err = load(windows)
	if err == nil || !strings.Contains(err.Error(), "directory_not_found") ||
		!strings.Contains(err.Error(), "policy_dir is") || !strings.Contains(err.Error(), "guardrail.custom_packs") {
		t.Errorf("windows policy_dir without the pack = %v, want the property named", err)
	}

	for name, cfg := range map[string]*config.Config{
		"secure client": managedConfig("secure_client", `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`),
		"linux layout":  managedConfig("standalone", "/etc/defenseclaw/config.yaml"),
		"per user":      {Guardrail: config.GuardrailConfig{RulePack: "strict"}},
	} {
		err := load(cfg)
		if err == nil || !strings.HasSuffix(err.Error(), `rule pack "strict": policy_dir is not set`) {
			t.Errorf("%s refusal = %v, want the earlier text", name, err)
		}
	}
}
