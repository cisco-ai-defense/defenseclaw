// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nonShellCascade(value string, set bool) CascadeConfig {
	var c CascadeConfig
	if set {
		c.Lanes.NonShell = &value
	}
	return c
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
		cc := nonShellCascade(c.value, true)
		if err := cc.Validate(); err != nil {
			t.Errorf("%q: Validate() = %v, want it accepted", c.value, err)
		}
		g := &GuardrailConfig{Cascade: cc}
		if err := g.Validate(); err != nil {
			t.Errorf("%q: GuardrailConfig.Validate() = %v, want it accepted", c.value, err)
		}
		if got := cc.Lanes.NonShellMode(); got != c.mode {
			t.Errorf("%q: NonShellMode() = %q, want %q", c.value, got, c.mode)
		}
	}
}

func TestNonShellLaneIsOnWithoutAValue(t *testing.T) {
	var empty CascadeLanes
	if got := empty.NonShellMode(); got != "on" {
		t.Errorf("no lanes = %q, want on", got)
	}
	if err := (CascadeConfig{}).Validate(); err != nil {
		t.Errorf("empty lanes: %v", err)
	}
	if got := DefaultConfig().Guardrail.Cascade.Lanes.NonShellMode(); got != "on" {
		t.Errorf("default config = %q, want on", got)
	}
}

// A value that is none of on, shadow and off is refused with the key and the
// value set, and a config that skipped the loader never reads it as on.
func TestNonShellLaneRefusesOtherValues(t *testing.T) {
	for _, bad := range []string{"", " ", "true", "false", "enabled", "disabled", "onn", "of", "shadows", "on off", "1", "0", "live", "observe"} {
		cc := nonShellCascade(bad, true)
		err := cc.Validate()
		if err == nil {
			t.Errorf("%q: Validate() accepted it", bad)
			continue
		}
		for _, want := range []string{"guardrail.cascade.lanes.nonshell", "off, shadow, on"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q: error %q does not name %q", bad, err, want)
			}
		}
		if got := cc.Lanes.NonShellMode(); got == "on" {
			t.Errorf("%q: NonShellMode() = on for a refused value", bad)
		}
	}
	// An unknown lane is refused by the schema, with the key named.
	raw := []byte("config_version: 9\nguardrail:\n  cascade:\n    lanes:\n      nope: on\n")
	if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("unknown lane: %v", err)
	}
}

func TestNonShellLaneLoadFromFile(t *testing.T) {
	for _, c := range []struct {
		value, mode string
		refused     bool
	}{
		{"on", "on", false}, {"ON", "on", false}, {"Shadow", "shadow", false}, {"OFF", "off", false},
		{"' off '", "off", false}, {"-", "on", false},
		{"disabled", "", true}, {"''", "", true}, {"true", "", true}, {"onn", "", true},
	} {
		dir := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", dir)
		path := filepath.Join(dir, "config.yaml")
		raw := "config_version: 8\nguardrail:\n  cascade:\n    lanes:\n      nonshell: " + c.value + "\n"
		if c.value == "-" { // no key: an upgraded config
			raw = "config_version: 8\nguardrail:\n  mode: observe\n"
		}
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
		if got := cfg.Guardrail.Cascade.Lanes.NonShellMode(); got != c.mode {
			t.Errorf("%s: NonShellMode() = %q, want %q", c.value, got, c.mode)
		}
	}
}

// One parse for every lane: the shadow-only lanes read their values trimmed and
// in any case too, and still refuse on.
func TestNonShellLaneParseIsTheRegistryParse(t *testing.T) {
	for _, v := range []string{"Shadow", " OFF ", "shadow"} {
		c := CascadeConfig{Lanes: CascadeLanes{Effects: v, SecretFlow: v}}
		if err := c.Validate(); err != nil {
			t.Errorf("%q: %v", v, err)
		}
		if got, want := c.Lanes.EffectsMode(), normalizeCascadeLaneValue(v); got != want {
			t.Errorf("%q: EffectsMode() = %q, want %q", v, got, want)
		}
	}
	for _, v := range []string{"ON", " on"} {
		if err := (CascadeConfig{Lanes: CascadeLanes{Effects: v}}).Validate(); err == nil || !strings.Contains(err.Error(), "not available in 1.0.10") {
			t.Errorf("effects %q: %v, want not available", v, err)
		}
	}
}
