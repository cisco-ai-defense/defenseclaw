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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nonShellGuardrail(value string, set bool) *GuardrailConfig {
	g := &GuardrailConfig{}
	if set {
		g.Cascade.Lanes = map[string]string{NonShellLane: value}
	}
	return g
}

// GAP-0472: guardrail.cascade.lanes.nonshell is read in any case. Exactly on is
// live; shadow and off add nothing; every other value is refused at load.
func TestNonShellLaneValueSpellings(t *testing.T) {
	for _, c := range []struct {
		value, mode string
	}{
		{"on", "on"}, {"On", "on"}, {"ON", "on"}, {" on ", "on"},
		{"shadow", "shadow"}, {"Shadow", "shadow"}, {"SHADOW", "shadow"}, {"\tShadow\n", "shadow"},
		{"off", "off"}, {"Off", "off"}, {"OFF", "off"}, {" oFF ", "off"},
	} {
		g := nonShellGuardrail(c.value, true)
		if err := g.Validate(); err != nil {
			t.Errorf("%q: Validate() = %v, want it accepted", c.value, err)
		}
		if got := g.NonShellLaneMode(); got != c.mode {
			t.Errorf("%q: NonShellLaneMode() = %q, want %q", c.value, got, c.mode)
		}
	}
}

func TestNonShellLaneIsOnWithoutAValue(t *testing.T) {
	var nilConfig *GuardrailConfig
	if got := nilConfig.NonShellLaneMode(); got != "on" {
		t.Errorf("nil config = %q, want on", got)
	}
	if got := nonShellGuardrail("", false).NonShellLaneMode(); got != "on" {
		t.Errorf("no lanes = %q, want on", got)
	}
	g := &GuardrailConfig{}
	g.Cascade.Lanes = map[string]string{}
	if err := g.Validate(); err != nil {
		t.Errorf("empty lanes: %v", err)
	}
	if got := g.NonShellLaneMode(); got != "on" {
		t.Errorf("empty lanes = %q, want on", got)
	}
}

// A value that is none of on, shadow and off is refused with the key and the
// value set, and a config that skipped the loader never reads it as on.
func TestNonShellLaneRefusesOtherValues(t *testing.T) {
	for _, bad := range []string{"", " ", "true", "false", "enabled", "disabled", "onn", "of", "shadows", "on off", "1", "0", "live", "observe"} {
		g := nonShellGuardrail(bad, true)
		err := g.Validate()
		if err == nil {
			t.Errorf("%q: Validate() accepted it", bad)
			continue
		}
		for _, want := range []string{"guardrail.cascade.lanes.nonshell", "on, shadow or off"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: error %q does not name %q", bad, err, want)
			}
		}
		if got := g.NonShellLaneMode(); got == "on" {
			t.Errorf("%q: NonShellLaneMode() = on for a refused value", bad)
		}
	}
	g := &GuardrailConfig{}
	g.Cascade.Lanes = map[string]string{"nope": "on"}
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "guardrail.cascade.lanes.nope") {
		t.Errorf("unknown lane: %v", err)
	}
}

func TestNonShellLaneLoadFromFile(t *testing.T) {
	for _, c := range []struct {
		value, mode string
		refused     bool
	}{
		{"on", "on", false}, {"ON", "on", false}, {"Shadow", "shadow", false}, {"OFF", "off", false},
		{"disabled", "", true}, {"''", "", true}, {"true", "", true},
	} {
		dir := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", dir)
		path := filepath.Join(dir, "config.yaml")
		raw := "config_version: 8\nguardrail:\n  cascade:\n    lanes:\n      nonshell: " + c.value + "\n"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadFromFile(path)
		if c.refused {
			if err == nil || !strings.Contains(err.Error(), "guardrail.cascade.lanes.nonshell") {
				t.Errorf("%s: LoadFromFile = %v, want a refusal that names the key", c.value, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: LoadFromFile: %v", c.value, err)
			continue
		}
		if got := cfg.Guardrail.NonShellLaneMode(); got != c.mode {
			t.Errorf("%s: NonShellLaneMode() = %q, want %q", c.value, got, c.mode)
		}
	}
}
