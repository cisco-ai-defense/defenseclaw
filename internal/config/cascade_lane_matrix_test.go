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
// secret_flow are never on. LoadFromFile (CLI helpers only; the gateway
// start and hot reload use the runtime loaders) runs no schema check, so a
// null lane, or an empty string for a string lane, reads there as the
// lane's shipped default instead of a refusal; never as a weaker mode.
func TestCascadeLaneSpellingMatrix(t *testing.T) {
	spellings := []struct {
		yaml string
		want map[string]string // lane -> mode; missing lane = refused
	}{
		{"on", map[string]string{"nonshell": "on"}},
		{"ON", map[string]string{"nonshell": "on"}},
		{"\"On\"", map[string]string{"nonshell": "on"}},
		{"\" shadow \"", map[string]string{"nonshell": "shadow", "effects": "shadow", "secret_flow": "shadow"}},
		{"Shadow", map[string]string{"nonshell": "shadow", "effects": "shadow", "secret_flow": "shadow"}},
		{"Off", map[string]string{"nonshell": "off", "effects": "off", "secret_flow": "off"}},
		{"off", map[string]string{"nonshell": "off", "effects": "off", "secret_flow": "off"}},
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
	defaults := map[string]string{"nonshell": "on", "effects": "shadow", "secret_flow": "shadow"}
	for _, lane := range CascadeLaneNames() {
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
				lenient := l.name == "LoadFromFile" && (s.yaml == "null" || s.yaml == "~" || s.yaml == "" || (s.yaml == `""` && lane != "nonshell"))
				if !accept && lenient {
					if err != nil {
						t.Errorf("%s: %v (lenient loader)", label, err)
					} else if got := cfg.Guardrail.Cascade.Lanes.value(lane); got != defaults[lane] {
						t.Errorf("%s: mode %q, want the default %q", label, got, defaults[lane])
					}
					continue
				}
				if !accept {
					if err == nil {
						got := ""
						if cfg != nil {
							got = cfg.Guardrail.Cascade.Lanes.value(lane)
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
				got := cfg.Guardrail.Cascade.Lanes.value(lane)
				if got != wantMode {
					t.Errorf("%s: mode %q, want %q", label, got, wantMode)
				}
				if lane != "nonshell" && got == CascadeLaneOn {
					t.Errorf("%s: shadow-only lane is on", label)
				}
				for other, def := range defaults {
					if other != lane && cfg.Guardrail.Cascade.Lanes.value(other) != def {
						t.Errorf("%s: lane %s = %q, want its default %q", label, other, cfg.Guardrail.Cascade.Lanes.value(other), def)
					}
				}
			}
		}
	}
}

// TestCascadeLanesUpgradeWithoutTheKey (s7-nscfg): no release before 1.0.10
// has guardrail.cascade, so an upgraded config has no such key (or an empty
// block): it loads with nonshell on and the shadow-only lanes shadow.
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
			if l.NonShellMode() != CascadeLaneOn || l.EffectsMode() != CascadeLaneShadow || l.SecretFlowMode() != CascadeLaneShadow {
				t.Errorf("%q via %s: nonshell %q effects %q secret_flow %q, want on shadow shadow", guardrail, name, l.NonShellMode(), l.EffectsMode(), l.SecretFlowMode())
			}
		}
	}
}
