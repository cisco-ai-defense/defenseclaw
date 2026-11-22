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

// TestCascadeLaneSpellingMatrix (s7-nscfg): every spelling of every lane
// value, written as YAML, through the three loaders (LoadFromFile, the
// gateway runtime load and the candidate check of a CLI save). A value is
// accepted with its mode or refused with the lane key named; effects and
// secret_flow are never on, and alert and block are the alignment lane's alone. Values are exact (cascade.go): another case or a
// padded value is refused, never read as the value. A null lane, or an empty string for a string lane,
// is refused by all three loaders: LoadFromFile runs no schema pass, so it
// checks the lane values itself (GAP-0545). The opt-in alignment lane is
// not in the schema: at gateway start a value it refuses invalidates the
// cascade (pack defaults, lane off), as its own test pins.
func TestCascadeLaneSpellingMatrix(t *testing.T) {
	spellings := []struct {
		yaml string
		want map[string]string // lane -> mode; missing lane = refused
	}{
		{"on", map[string]string{"nonshell": "on", "effects": "on"}},
		{"\"on\"", map[string]string{"nonshell": "on", "effects": "on"}},
		{"shadow", map[string]string{"nonshell": "shadow", "effects": "shadow", "secret_flow": "shadow", "alignment": "shadow"}},
		{"off", map[string]string{"nonshell": "off", "effects": "off", "secret_flow": "off", "alignment": "off"}},
		// The alignment lane's own values (GAP-0823): no other lane takes them.
		{"alert", map[string]string{"alignment": "alert"}},
		{"\"block\"", map[string]string{"alignment": "block"}},
		{"Alert", nil},
		{"\"alert \"", nil},
		{"BLOCK", nil},
		{"ON", nil},
		{"\"On\"", nil},
		{"\" shadow \"", nil},
		{"Shadow", nil},
		{"Off", nil},
		{"\"\"", nil},
		{"\" \"", nil},
		{"garbage", nil},
		{"1", nil},
		{"0", nil},
		{"true", nil},
		{"false", nil},
		{"yes", nil},
		{"no", nil},
		{"null", nil},
		{"~", nil},
		{"", nil}, // key with no value: YAML null
		{"[on]", nil},
		{"{on: on}", nil},
	}
	defaults := map[string]string{"nonshell": "on", "effects": "on", "secret_flow": "shadow", "alignment": "off"}
	// The shipped lanes (cascade_test.go registers test lanes the schema does not name).
	for _, lane := range []string{CascadeLaneEffects, CascadeLaneNonShell, CascadeLaneSecretFlow, CascadeLaneAlignment} {
		for _, s := range spellings {
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			path := filepath.Join(dir, DefaultConfigName)
			raw := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  cascade:\n    lanes:\n      " + lane + ": " + s.yaml + "\nobservability: {}\n"
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			wantMode, accept := s.want[lane]
			loaders := []struct {
				name string
				load func() (*Config, error)
			}{
				{"LoadFromFile", func() (*Config, error) { return LoadFromFile(path) }},
				{"LoadRuntimeV8File", func() (*Config, error) { return LoadRuntimeV8File(path) }},
				{"ValidateCandidate", func() (*Config, error) { return nil, ValidateCandidate(path, []byte(raw)) }},
			}
			for _, l := range loaders {
				cfg, err := l.load()
				label := lane + "=" + s.yaml + " via " + l.name
				if !accept {
					if err == nil && lane == CascadeLaneAlignment && l.name == "LoadRuntimeV8File" && cfg != nil &&
						cfg.Guardrail.Cascade.Invalid() != nil && cfg.ResolveCascade("").LaneMode(lane) == CascadeLaneOff {
						// The alignment lane's start rule (TestCascadeAlignmentLaneLoadsItsValues): the
						// schema takes any short string, the invalid cascade falls back and the lane is off.
						continue
					}
					if err == nil {
						got := ""
						if cfg != nil {
							got = cfg.Guardrail.Cascade.Lanes.mode(lane)
						}
						t.Errorf("%s: accepted (mode %q), want refused", label, got)
					} else if !strings.Contains(err.Error(), "cascade.lanes."+lane) {
						t.Errorf("%s: refusal %q does not name the key", label, err)
					}
					continue
				}
				if err != nil {
					t.Errorf("%s: refused: %v", label, err)
					continue
				}
				if cfg == nil {
					continue
				}
				got := cfg.Guardrail.Cascade.Lanes.mode(lane)
				if got != wantMode {
					t.Errorf("%s: mode %q, want %q", label, got, wantMode)
				}
				if lane == CascadeLaneSecretFlow && got == CascadeLaneOn {
					t.Errorf("%s: shadow-only lane is on", label)
				}
				for other, def := range defaults {
					if other != lane && cfg.Guardrail.Cascade.Lanes.mode(other) != def {
						t.Errorf("%s: lane %s = %q, want its default %q", label, other, cfg.Guardrail.Cascade.Lanes.mode(other), def)
					}
				}
			}
		}
	}
}

// TestCascadeLanesUpgradeWithoutTheKey (s7-nscfg): no release before 1.0.10
// has guardrail.cascade, so an upgraded config has no such key (or an empty
// block): it loads with nonshell and effects on and secret_flow shadow.
func TestCascadeLanesUpgradeWithoutTheKey(t *testing.T) {
	for _, guardrail := range []string{"  mode: observe\n", "  mode: action\n  cascade: {}\n", "  cascade:\n    lanes: {}\n"} {
		dir := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", dir)
		path := filepath.Join(dir, DefaultConfigName)
		raw := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n" + guardrail + "observability: {}\n"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		for name, load := range map[string]func(string) (*Config, error){"LoadFromFile": LoadFromFile, "LoadRuntimeV8File": LoadRuntimeV8File} {
			cfg, err := load(path)
			if err != nil {
				t.Fatalf("%q via %s: %v", guardrail, name, err)
			}
			l := cfg.Guardrail.Cascade.Lanes
			if l.NonShellMode() != CascadeLaneOn || l.EffectsMode() != CascadeLaneOn || l.SecretFlowMode() != CascadeLaneShadow {
				t.Errorf("%q via %s: nonshell %q effects %q secret_flow %q, want on on shadow", guardrail, name, l.NonShellMode(), l.EffectsMode(), l.SecretFlowMode())
			}
		}
	}
}

// TestLoadFromFileRefusesALaneWithoutAValue (GAP-0545): the CLI helpers read
// config.yaml with LoadFromFile, which runs no schema pass. A lane the source
// names without a value used to read there as the shipped default while the
// gateway refused the same file; LoadFromFile now refuses it with the key
// named, and a lane that is absent still loads as the default.
func TestLoadFromFileRefusesALaneWithoutAValue(t *testing.T) {
	for _, lane := range CascadeLaneNames() {
		for _, value := range []string{"null", "~", ""} {
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			path := filepath.Join(dir, DefaultConfigName)
			raw := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  cascade:\n    lanes:\n      " + lane + ": " + value + "\nobservability: {}\n"
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFromFile(path); err == nil {
				t.Errorf("%s: %q accepted by LoadFromFile", lane, value)
			} else if !strings.Contains(err.Error(), "guardrail.cascade.lanes."+lane) {
				t.Errorf("%s: %q refusal %q does not name the key", lane, value, err)
			}
		}
		// A source that does not name the lane loads (its default).
		dir := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", dir)
		path := filepath.Join(dir, DefaultConfigName)
		raw := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: observe\nobservability: {}\n"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFromFile(path); err != nil {
			t.Errorf("%s absent: %v", lane, err)
		}
	}
}
