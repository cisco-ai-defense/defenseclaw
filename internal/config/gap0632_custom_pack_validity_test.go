// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useRulePackValidator stands in for the rule loader (guardrail registers the
// real one, and config cannot import it).
func useRulePackValidator(t *testing.T, validate RulePackValidator) {
	t.Helper()
	before := customRulePackValidator
	RegisterCustomRulePackValidator(validate)
	t.Cleanup(func() { RegisterCustomRulePackValidator(before) })
}

func filledPackDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pack")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "suppressions.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// GAP-0632: one entry has one verdict. The rule loader's refusal, a pin that
// does not match the files it loaded and a missing pin each are the entry's
// config error; a pack it accepts whose files hash to the pin is usable with
// the posture its manifest names.
func TestGAP0632ValidatorVerdictIsTheConfigError(t *testing.T) {
	dir := filledPackDir(t)
	const files = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	for _, row := range []struct {
		name, pin string
		validate  RulePackValidator
		wantErr   string
		stale     bool
	}{
		{name: "loader refuses the pack", pin: files, validate: func(string) (string, string, error) { return "", "", errors.New("bad component") }, wantErr: "not a valid rule pack"},
		{name: "pin does not match the files", pin: "sha256:" + strings.Repeat("2", 64), validate: func(string) (string, string, error) { return files, "strict", nil }, wantErr: "does not match guardrail.custom_packs.operator.digest", stale: true},
		{name: "no pin", pin: " ", validate: func(string) (string, string, error) { return files, "strict", nil }, wantErr: "does not match guardrail.custom_packs.operator.digest", stale: true},
		{name: "usable", pin: strings.ToUpper(files), validate: func(string) (string, string, error) { return files, "permissive", nil }},
	} {
		t.Run(row.name, func(t *testing.T) {
			useRulePackValidator(t, row.validate)
			cfg := &Config{}
			cfg.Guardrail.RulePack = "operator"
			cfg.Guardrail.CustomPacks = map[string]CustomRulePack{"operator": {Path: dir, Digest: row.pin}}
			err := cfg.CustomRulePackError("operator")
			if row.wantErr == "" {
				if err != nil {
					t.Fatalf("usable entry: %v", err)
				}
				if got := cfg.HookPolicyTierForConnector("codex"); got != HookPolicyTierPermissive {
					t.Errorf("tier = %q, want the validated manifest posture", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), row.wantErr) {
				t.Fatalf("config error = %v, want %q", err, row.wantErr)
			}
			// A stale or missing pin is an integrity refusal: the entry stays the
			// selected pack (the gateway refuses it) and nothing is enforced in
			// its place. Every other error loads the built-in fallback.
			wantFallback := "default"
			if row.stale {
				wantFallback = ""
				if !IsStalePinError(err) {
					t.Errorf("config error %v is not a stale pin", err)
				}
				if _, usable := cfg.UsableCustomRulePack("operator"); !usable {
					t.Error("a stale pin must keep the entry as the selected pack")
				}
			} else if IsStalePinError(err) {
				t.Errorf("config error %v must not be a stale pin", err)
			}
			if got := cfg.BuiltinRulePackFor("operator"); got != wantFallback {
				t.Errorf("fallback = %q, want %q", got, wantFallback)
			}
			if got := cfg.EffectiveHookOutageFailModeForConnector("codex"); got != "closed" {
				t.Errorf("outage mode = %q, want closed", got)
			}
		})
	}
}

// GAP-0632: a binary without the rule loader cannot prove a pinned pack, so
// its posture never sets an outage tier.
func TestGAP0632WithoutValidatorPinnedPostureStaysStrict(t *testing.T) {
	useRulePackValidator(t, nil)
	cfg := &Config{}
	cfg.Guardrail.RulePack = "operator"
	cfg.Guardrail.CustomPacks = map[string]CustomRulePack{"operator": {Path: filledPackDir(t), Digest: "sha256:" + strings.Repeat("3", 64)}}
	if got := cfg.HookPolicyTierForConnector("codex"); got != HookPolicyTierStrict {
		t.Errorf("tier = %q, want strict", got)
	}
}

// GAP-0632: a copy of the configuration (a derived guardrail profile) keeps
// the verdict of the load: a folder that goes away after the load does not
// turn the copy's entry into a config error while the source still uses it.
func TestGAP0632CopyKeepsTheLoadVerdict(t *testing.T) {
	dir := filledPackDir(t)
	const files = "sha256:" + "4444444444444444444444444444444444444444444444444444444444444444"
	useRulePackValidator(t, func(string) (string, string, error) { return files, "strict", nil })
	cfg := &Config{}
	cfg.Guardrail.RulePack = "operator"
	cfg.Guardrail.CustomPacks = map[string]CustomRulePack{"operator": {Path: dir, Digest: files}}
	cfg.CheckCustomRulePacks()
	if err := cfg.CustomRulePackError("operator"); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	clone, err := cfg.DeepCopy()
	if err != nil {
		t.Fatal(err)
	}
	for who, c := range map[string]*Config{"source": cfg, "copy": clone} {
		if err := c.CustomRulePackError("operator"); err != nil {
			t.Errorf("%s: loaded entry now a config error: %v", who, err)
		}
		if got := c.BuiltinRulePackFor("operator"); got != "" {
			t.Errorf("%s: fallback %q for a usable entry", who, got)
		}
		if got := c.Guardrail.CustomRulePackError("operator"); got != nil {
			t.Errorf("%s: guardrail block disagrees with the configuration: %v", who, got)
		}
	}
}

// GAP-0632: a relative custom_packs path is relative to the config file's
// directory, not the working directory, in the configuration and in the
// guardrail block alike.
func TestGAP0632RelativePathResolvesAgainstConfigDirectory(t *testing.T) {
	configDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(configDir, "pack"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "pack", "suppressions.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	useRulePackValidator(t, nil)
	pin := "sha256:" + strings.Repeat("5", 64)
	cfg := &Config{ConfigFilePath: filepath.Join(configDir, "config.yaml")}
	cfg.Guardrail.RulePack = "operator"
	cfg.Guardrail.CustomPacks = map[string]CustomRulePack{"operator": {Path: "pack", Digest: pin}}
	for _, recorded := range []bool{false, true} {
		if recorded {
			cfg.CheckCustomRulePacks()
		}
		if err := cfg.CustomRulePackError("operator"); err != nil {
			t.Errorf("recorded %v: %v", recorded, err)
		}
		want := filepath.Join(configDir, "pack")
		if got := cfg.ResolveRulePackDir(RulePackRef{Name: "operator"}); got != want {
			t.Errorf("recorded %v: dir = %q, want %q", recorded, got, want)
		}
		if got := cfg.Guardrail.CustomRulePackPath("operator"); recorded && got != want {
			t.Errorf("guardrail block path = %q, want %q", got, want)
		}
	}
	// The same relative path beside a different config is another folder.
	other := &Config{ConfigFilePath: filepath.Join(t.TempDir(), "config.yaml")}
	other.Guardrail.CustomPacks = cfg.Guardrail.CustomPacks
	if err := other.CustomRulePackError("operator"); err == nil {
		t.Error("a relative path resolved against the wrong directory")
	}
}
