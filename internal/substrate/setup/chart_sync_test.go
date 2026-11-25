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
	"fmt"
	"os/exec"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// renderedSubstrate is config.substrate of the defenseclaw-config ConfigMap.
func renderedSubstrate(t *testing.T, out []byte) map[string]any {
	t.Helper()
	for _, o := range decodeObjects(t, out) {
		if o.Kind != "ConfigMap" || o.Metadata["name"] != "defenseclaw-config" {
			continue
		}
		var cfg map[string]any
		if err := yaml.Unmarshal([]byte(fmt.Sprint(o.Data["config.yaml"])), &cfg); err != nil {
			t.Fatalf("config.yaml: %v", err)
		}
		sub, _ := cfg["substrate"].(map[string]any)
		return sub
	}
	t.Fatal("no defenseclaw-config ConfigMap")
	return nil
}

// GAP-0732: the dedicated chart values fill the substrate.launcher, files
// and git config keys; config set by hand still works and wins.
func TestChartSubstrateSyncValues(t *testing.T) {
	helm := helmBinary(t)
	rewrite := []any{map[string]any{"from": "git@git.example.test:", "to": "https://git.example.test/"}}
	cases := []struct {
		name   string
		values string
		extra  []string
		want   map[string]any // section -> expected map
	}{
		{"dedicated values, config wins over the chart on lfs", "substrate-sync", nil, map[string]any{
			"launcher": map[string]any{"key_replay": "off"},
			"files":    map[string]any{"push": true, "sync": false},
			"git":      map[string]any{"https_rewrite": rewrite, "submodules": false, "lfs": false, "push_branch": "deny"},
		}},
		{"config alone (the raw passthrough)", "default", []string{
			"--set", "config.substrate.launcher.key_replay=on", "--set", "config.substrate.files.push=false",
			"--set", "config.substrate.git.submodules=false"}, map[string]any{
			"launcher": map[string]any{"key_replay": "on"},
			"files":    map[string]any{"push": false},
			"git":      map[string]any{"submodules": false},
		}},
		{"false is a value, not unset", "default", []string{"--set", "substrate.git.lfs=false", "--set", "substrate.files.push=false"}, map[string]any{
			"files": map[string]any{"push": false},
			"git":   map[string]any{"lfs": false},
		}},
		{"config beats a chart value on every key", "substrate-sync", []string{
			"--set", "config.substrate.launcher.key_replay=ask", "--set", "config.substrate.files.push=false",
			"--set", "config.substrate.files.sync=true", "--set", "config.substrate.git.submodules=true",
			"--set", "config.substrate.git.push_branch=allow", "--set-json", `config.substrate.git.https_rewrite=[]`}, map[string]any{
			"launcher": map[string]any{"key_replay": "ask"},
			"files":    map[string]any{"push": false, "sync": true},
			"git":      map[string]any{"https_rewrite": []any{}, "submodules": true, "lfs": false, "push_branch": "allow"},
		}},
		{"nothing set adds nothing", "default", nil, map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := renderedSubstrate(t, renderChart(t, helm, tc.values, tc.extra...))
			for _, sect := range []string{"launcher", "files", "git"} {
				got, has := sub[sect]
				want, wantHas := tc.want[sect]
				if has != wantHas || (has && !reflect.DeepEqual(got, want)) {
					t.Errorf("substrate.%s = %v (present %v), want %v (present %v)", sect, got, has, want, wantHas)
				}
			}
		})
	}
}

// GAP-0732: the schema refuses a bad dedicated value, and the same bad
// value written as config.
func TestChartSubstrateSyncValuesRefuseBad(t *testing.T) {
	helm := helmBinary(t)
	for name, set := range map[string][]string{
		"key replay":             {"--set", "substrate.launcher.keyReplay=maybe"},
		"files push not bool":    {"--set", "substrate.files.push=yes"},
		"files sync number":      {"--set", "substrate.files.sync=1"},
		"git lfs not bool":       {"--set", "substrate.git.lfs=sometimes"},
		"push branch":            {"--set", "substrate.git.pushBranch=force"},
		"unknown git key":        {"--set", "substrate.git.surprise=1"},
		"rewrite to http":        {"--set-json", `substrate.git.httpsRewrite=[{"from":"git@h:","to":"http://h/"}]`},
		"rewrite no slash":       {"--set-json", `substrate.git.httpsRewrite=[{"from":"git@h:","to":"https://h"}]`},
		"rewrite from open":      {"--set-json", `substrate.git.httpsRewrite=[{"from":"git@h","to":"https://h/"}]`},
		"rewrite missing to":     {"--set-json", `substrate.git.httpsRewrite=[{"from":"git@h:"}]`},
		"config key replay":      {"--set", "config.substrate.launcher.key_replay=maybe"},
		"config push not bool":   {"--set", "config.substrate.files.push=yes"},
		"config push branch":     {"--set", "config.substrate.git.push_branch=force"},
		"config rewrite to http": {"--set-json", `config.substrate.git.https_rewrite=[{"from":"git@h:","to":"http://h/"}]`},
	} {
		args := append([]string{"template", "dc", chartDir, "--kube-version", chartKubeVersion}, set...)
		if err := exec.Command(helm, args...).Run(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
