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

// TestLoadFromFileRefusesANullCascadeBlock (rel-1-0-10:GAP-0645): a guardrail,
// guardrail.cascade or guardrail.cascade.lanes block the source names without
// a value decodes as the defaults, but the gateway (LoadRuntimeV8File,
// ValidateCandidate) refuses it. LoadFromFile runs no schema pass, so it must
// refuse the same spellings, naming the key: one reading for every consumer.
func TestLoadFromFileRefusesANullCascadeBlock(t *testing.T) {
	cases := []struct{ name, guardrail, key string }{
		{"guardrail empty", "guardrail:\n", "guardrail has no value"},
		{"guardrail null", "guardrail: null\n", "guardrail has no value"},
		{"guardrail tilde", "guardrail: ~\n", "guardrail has no value"},
		{"cascade empty", "guardrail:\n  cascade:\n", "guardrail.cascade has no value"},
		{"cascade null", "guardrail:\n  cascade: null\n", "guardrail.cascade has no value"},
		{"lanes empty", "guardrail:\n  cascade:\n    lanes:\n", "guardrail.cascade.lanes has no value"},
		{"lanes null", "guardrail:\n  cascade:\n    lanes: null\n", "guardrail.cascade.lanes has no value"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", dir)
		path := filepath.Join(dir, DefaultConfigName)
		raw := "config_version: 8\ndata_dir: " + dir + "\n" + c.guardrail + "observability: {}\n"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFromFile(path); err == nil {
			t.Errorf("%s: LoadFromFile accepted it", c.name)
		} else if !strings.Contains(err.Error(), c.key) {
			t.Errorf("%s: LoadFromFile refusal %q does not say %q", c.name, err, c.key)
		}
		// The gateway's two loaders refuse the same source.
		if _, err := LoadRuntimeV8File(path); err == nil {
			t.Errorf("%s: LoadRuntimeV8File accepted it", c.name)
		}
		if err := ValidateCandidate(path, []byte(raw)); err == nil {
			t.Errorf("%s: ValidateCandidate accepted it", c.name)
		}
	}
}

// TestCascadeLaneRefusalOffersOnlyWhatTheLaneTakes (rel-1-0-10:GAP-0645): the
// refusal of a lane without a value, and of on for a shadow-only lane, lists
// the values CascadeLaneAllowed gives for that lane: secret_flow takes off
// and shadow, never on; effects takes off, shadow and on (DET111).
func TestCascadeLaneRefusalOffersOnlyWhatTheLaneTakes(t *testing.T) {
	load := func(lane, value string) error {
		dir := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", dir)
		path := filepath.Join(dir, DefaultConfigName)
		raw := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  cascade:\n    lanes:\n      " + lane + ": " + value + "\nobservability: {}\n"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadFromFile(path)
		return err
	}
	for _, c := range []struct {
		lane, allowed string
		refused       []string
	}{
		{CascadeLaneSecretFlow, "off, shadow", []string{"null", "on"}},
		{CascadeLaneEffects, "off, shadow, on", []string{"null"}},
	} {
		if allowed := strings.Join(CascadeLaneAllowed(c.lane), ", "); allowed != c.allowed {
			t.Fatalf("%s allowed = %q, want %s", c.lane, allowed, c.allowed)
		}
		for _, value := range c.refused {
			err := load(c.lane, value)
			if err == nil {
				t.Fatalf("%s: %s accepted", c.lane, value)
			}
			if c.allowed == "off, shadow" && strings.Contains(err.Error(), "off, shadow, on") || !strings.Contains(err.Error(), c.allowed) {
				t.Errorf("%s: %s refusal %q does not offer exactly %q", c.lane, value, err, c.allowed)
			}
		}
	}
	if err := load(CascadeLaneEffects, "on"); err != nil {
		t.Errorf("effects: on refused: %v", err)
	}
}
