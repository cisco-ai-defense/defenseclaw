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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// B5.4 S3: the sidecar's per-scan timeout is substrate.skills.scan.timeout,
// and gateway.skillScanner.enabled: false (the default, GAP-1103) turns the
// gateway's scan off in config.yaml (no sidecar, so the fail mode decides;
// managed refuses).
func TestChartSkillScanKeys(t *testing.T) {
	helm := helmBinary(t)
	for _, tc := range []struct {
		extra       []string
		wantTimeout string
		wantOff     bool
	}{
		{nil, "", true},
		{[]string{"--set", "gateway.skillScanner.enabled=true"}, "--timeout=20s", false},
		{[]string{"--set", "gateway.skillScanner.enabled=true", "--set", "config.substrate.skills.scan.timeout=45s"}, "--timeout=45s", false},
		{[]string{"--set", "gateway.skillScanner.enabled=false"}, "", true},
	} {
		out := renderChart(t, helm, "default", tc.extra...)
		var timeout string
		off := false
		for _, doc := range strings.Split(string(out), "\n---") {
			var o struct {
				Kind     string            `yaml:"kind"`
				Metadata map[string]any    `yaml:"metadata"`
				Data     map[string]string `yaml:"data"`
				Spec     struct {
					Template struct {
						Spec struct {
							Containers []struct {
								Name string   `yaml:"name"`
								Args []string `yaml:"args"`
							} `yaml:"containers"`
						} `yaml:"spec"`
					} `yaml:"template"`
				} `yaml:"spec"`
			}
			if yaml.Unmarshal([]byte(doc), &o) != nil {
				continue
			}
			if o.Kind == "Deployment" && o.Metadata["name"] == "defenseclaw-gateway" {
				for _, c := range o.Spec.Template.Spec.Containers {
					for _, a := range c.Args {
						if c.Name == "skill-scanner" && strings.HasPrefix(a, "--timeout=") {
							timeout = a
						}
					}
				}
			}
			if o.Kind == "ConfigMap" && o.Metadata["name"] == "defenseclaw-config" {
				var cfg struct {
					Substrate struct {
						Skills struct {
							Scan struct {
								Enabled *bool `yaml:"enabled"`
							} `yaml:"scan"`
						} `yaml:"skills"`
					} `yaml:"substrate"`
				}
				if err := yaml.Unmarshal([]byte(o.Data["config.yaml"]), &cfg); err != nil {
					t.Fatal(err)
				}
				off = cfg.Substrate.Skills.Scan.Enabled != nil && !*cfg.Substrate.Skills.Scan.Enabled
			}
		}
		if timeout != tc.wantTimeout || off != tc.wantOff {
			t.Fatalf("%v: sidecar %q (want %q), scan off=%v (want %v)", tc.extra, timeout, tc.wantTimeout, off, tc.wantOff)
		}
	}
}
