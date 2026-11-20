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

package setup

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// The callout's profiles take the profile's unattended_asks and
// actor_secrets, tightened over substrate.admin like
// config.TightenSandboxAdmin: deny wins, actor_secrets intersect, a profile
// without them takes the admin's.
func TestChartCalloutProfileKeys(t *testing.T) {
	helm := helmBinary(t)
	out := renderChart(t, helm, "profile-keys", "--show-only", "templates/callout-config.yaml")
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(out, &cm); err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Profiles []struct {
			Name           string   `yaml:"name"`
			UnattendedAsks string   `yaml:"unattended_asks"`
			ActorSecrets   []string `yaml:"actor_secrets"`
		} `yaml:"profiles"`
	}
	if err := yaml.Unmarshal([]byte(cm.Data["callout.yaml"]), &cfg); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		asks    string
		secrets []string
	}{
		"engineering": {"queue", []string{"db-password"}},
		"ci":          {"queue", nil},
		"data":        {"deny", []string{"db-password", "npm-token"}},
	}
	if len(cfg.Profiles) != len(want) {
		t.Fatalf("profiles = %+v", cfg.Profiles)
	}
	for _, p := range cfg.Profiles {
		w := want[p.Name]
		if p.UnattendedAsks != w.asks || !slices.Equal(p.ActorSecrets, w.secrets) {
			t.Errorf("%s: unattended_asks %q actor_secrets %v, want %q %v", p.Name, p.UnattendedAsks, p.ActorSecrets, w.asks, w.secrets)
		}
	}

	denied := renderChart(t, helm, "profile-keys", "--show-only", "templates/callout-config.yaml",
		"--set", "config.substrate.admin.unattended_asks=deny")
	if err := yaml.Unmarshal(denied, &cm); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(cm.Data["callout.yaml"]), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, p := range cfg.Profiles {
		if p.UnattendedAsks != "deny" {
			t.Errorf("%s: substrate.admin deny did not win: %q", p.Name, p.UnattendedAsks)
		}
	}
}
