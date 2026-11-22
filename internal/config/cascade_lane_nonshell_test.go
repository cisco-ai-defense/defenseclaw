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
		c.Lanes = CascadeLaneValues{CascadeLaneNonShell: value}
	}
	return c
}

// validateCascade runs the loader's cascade check on a top-level cascade.
func (c CascadeConfig) validateCascade() error {
	cfg := &Config{}
	cfg.Guardrail.Cascade = c
	return cfg.ValidateCascade(false)
}

// GAP-0472: guardrail.cascade.lanes.nonshell is a registered lane. Exactly on
// is live; shadow and off add nothing. The loader takes exact values only
// (cascade.go: a typo never silently switches a lane); another case or a
// padded value is refused with the key named, and a config that skipped the
// loader reads it trimmed and in any case.
func TestNonShellLaneValueSpellings(t *testing.T) {
	for _, c := range []struct {
		value, mode string
		exact       bool
	}{
		{"on", "on", true}, {"On", "on", false}, {"ON", "on", false}, {" on ", "on", false},
		{"shadow", "shadow", true}, {"Shadow", "shadow", false}, {"SHADOW", "shadow", false}, {"\tShadow\n", "shadow", false},
		{"off", "off", true}, {"Off", "off", false}, {"OFF", "off", false}, {" oFF ", "off", false},
	} {
		cc := nonShellCascade(c.value, true)
		err := cc.validateCascade()
		if c.exact && err != nil {
			t.Errorf("%q: ValidateCascade() = %v, want it accepted", c.value, err)
		}
		if !c.exact && (err == nil || !strings.Contains(err.Error(), "guardrail.cascade.lanes.nonshell")) {
			t.Errorf("%q: ValidateCascade() = %v, want a refusal naming the key", c.value, err)
		}
		if got := cc.Lanes.NonShellMode(); got != c.mode {
			t.Errorf("%q: NonShellMode() = %q, want %q", c.value, got, c.mode)
		}
	}
	// The lane is process-wide: a connector or profile scope may not set it.
	cfg := &Config{}
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {Cascade: &CascadeScope{Lanes: CascadeLaneValues{CascadeLaneNonShell: "off"}}}}
	if err := cfg.ValidateCascade(false); err == nil || !strings.Contains(err.Error(), "process-wide") {
		t.Errorf("a connector scope set the nonshell lane: %v", err)
	}
}

func TestNonShellLaneIsOnWithoutAValue(t *testing.T) {
	var empty CascadeLaneValues
	if got := empty.NonShellMode(); got != "on" {
		t.Errorf("no lanes = %q, want on", got)
	}
	if err := (CascadeConfig{}).validateCascade(); err != nil {
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
		err := cc.validateCascade()
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
		{"on", "on", false}, {"shadow", "shadow", false}, {"off", "off", false}, {"'off'", "off", false},
		{"-", "on", false},
		{"ON", "", true}, {"Shadow", "", true}, {"OFF", "", true}, {"' off '", "", true},
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

// One check for every lane: the effects and secret_flow lanes take the same
// exact values and read the same way when the loader was skipped; the
// shadow-only secret_flow still refuses on with the not-available reason.
func TestNonShellLaneParseIsTheRegistryParse(t *testing.T) {
	for _, v := range []string{"Shadow", " OFF ", "shadow"} {
		c := CascadeConfig{Lanes: CascadeLaneValues{CascadeLaneEffects: v, CascadeLaneSecretFlow: v}}
		err := c.validateCascade()
		if exact := v == "shadow"; exact && err != nil {
			t.Errorf("%q: %v", v, err)
		} else if !exact && err == nil {
			t.Errorf("%q: accepted, want the exact-value refusal", v)
		}
		if got, want := c.Lanes.EffectsMode(), strings.ToLower(strings.TrimSpace(v)); got != want {
			t.Errorf("%q: EffectsMode() = %q, want %q", v, got, want)
		}
	}
	if err := (CascadeConfig{Lanes: CascadeLaneValues{CascadeLaneSecretFlow: "on"}}).validateCascade(); err == nil || !strings.Contains(err.Error(), "not available in 1.0.10") {
		t.Errorf("secret_flow on: %v, want not available", err)
	}
	if err := (CascadeConfig{Lanes: CascadeLaneValues{CascadeLaneEffects: "on"}}).validateCascade(); err != nil {
		t.Errorf("effects on: %v, want accepted (the lane ships on)", err)
	}
	for _, v := range []string{"ON", " on"} {
		if err := (CascadeConfig{Lanes: CascadeLaneValues{CascadeLaneEffects: v}}).validateCascade(); err == nil || !strings.Contains(err.Error(), "guardrail.cascade.lanes.effects") {
			t.Errorf("effects %q: %v, want a refusal naming the key", v, err)
		}
	}
}
