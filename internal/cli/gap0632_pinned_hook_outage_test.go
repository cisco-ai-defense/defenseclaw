// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestGAP0632PinnedStandaloneHookOutageUsesValidatedPosture(t *testing.T) {
	isolateHookOutageAccount(t)
	for _, source := range []string{"strict", "default", "permissive"} {
		t.Run(source, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("HOME", home)
			dir := filepath.Join(t.TempDir(), "operator-pack")
			if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "policies", "guardrail", source))); err != nil {
				t.Fatal(err)
			}
			pin, err := guardrail.RulePackDigest(dir)
			if err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf("config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n  rule_pack: operator\n  custom_packs:\n    operator:\n      path: %q\n      digest: sha256:%s\n", dir, pin)
			writeOutageNowConfig(t, home, body)
			hooks := filepath.Join(home, "hooks")
			want := "open"
			if source == "strict" {
				want = "closed"
			}
			if got := hookOutageFailModeNow("codex", hooks); got != want {
				t.Fatalf("valid %s pack outage = %q, want %q", source, got, want)
			}
			if err := os.WriteFile(filepath.Join(dir, "operator-notes.txt"), []byte("local notes\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := hookOutageFailModeNow("codex", hooks); got != want {
				t.Fatalf("valid %s pack with notes outage = %q, want %q", source, got, want)
			}
			if source != "strict" {
				return
			}
			if err := os.WriteFile(filepath.Join(dir, guardrail.PackManifestFile), []byte(`{"posture":"default"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, _, err := loadHookRuntimeConfig(filepath.Join(home, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if got := loaded.HookPolicyTierForConnector("codex"); got != "strict" {
				t.Errorf("invalid pack pin tier = %q, want strict", got)
			}
			if got := hookOutageFailModeNow("codex", hooks); got != "closed" {
				t.Errorf("invalid pack pin outage = %q, want closed", got)
			}
		})
	}
}

// A matching content pin is only sufficient when the selected pack loads.
func TestGAP0632PinnedStandaloneHookOutageRejectsInvalidPack(t *testing.T) {
	isolateHookOutageAccount(t)
	for _, variant := range []string{"component directory", "invalid YAML with matching pin"} {
		t.Run(variant, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("HOME", home)
			dir := filepath.Join(t.TempDir(), "operator-pack")
			var pin string
			if variant == "component directory" {
				if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "policies", "guardrail", "default"))); err != nil {
					t.Fatal(err)
				}
				var err error
				pin, err = guardrail.RulePackDigest(dir)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o700); err != nil {
					t.Fatal(err)
				}
				manifest := []byte(`{"posture":"default"}`)
				rule := []byte("version: 1\ncategory: command\nrules: [\n")
				if err := os.WriteFile(filepath.Join(dir, guardrail.PackManifestFile), manifest, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "rules", "invalid.yaml"), rule, 0o600); err != nil {
					t.Fatal(err)
				}
				manifestSum, ruleSum := sha256.Sum256(manifest), sha256.Sum256(rule)
				hash := sha256.New()
				_, _ = fmt.Fprintf(hash, "%s\n%s\nrules/invalid.yaml\n%s\n", guardrail.PackManifestFile,
					hex.EncodeToString(manifestSum[:]), hex.EncodeToString(ruleSum[:]))
				pin = hex.EncodeToString(hash.Sum(nil))
			}
			body := fmt.Sprintf("config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n  rule_pack: operator\n  custom_packs:\n    operator:\n      path: %q\n      digest: sha256:%s\n", dir, pin)
			writeOutageNowConfig(t, home, body)
			hooks := filepath.Join(home, "hooks")
			if variant == "component directory" {
				if got := hookOutageFailModeNow("codex", hooks); got != "open" {
					t.Fatalf("valid default copy outage = %q, want open", got)
				}
				if err := os.Mkdir(filepath.Join(dir, "rules", "extra.yaml"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := guardrail.RulePackDigest(dir); err == nil {
				t.Fatal("invalid pack unexpectedly loadable")
			}
			if got := hookOutageFailModeNow("codex", hooks); got != "closed" {
				t.Errorf("invalid selected pack outage = %q, want closed", got)
			}
		})
	}
}

// A broken custom_packs entry is a config error, never outage evidence: the
// standalone hook stays closed whatever the entry's name, and the loaded
// config names the error. A usable default copy still opens.
func TestGAP0632BrokenCustomPackIsConfigErrorNotOutage(t *testing.T) {
	isolateHookOutageAccount(t)
	for _, variant := range []string{"whitespace path", "empty file set", "missing folder"} {
		for _, name := range []string{"operator", "default", "strict"} {
			t.Run(variant+"/"+name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("DEFENSECLAW_HOME", home)
				t.Setenv("HOME", home)
				dir := filepath.Join(t.TempDir(), "operator-pack")
				if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "..", "policies", "guardrail", "default"))); err != nil {
					t.Fatal(err)
				}
				pin, err := guardrail.RulePackDigest(dir)
				if err != nil {
					t.Fatal(err)
				}
				pin = "sha256:" + pin
				path := dir
				switch variant {
				case "whitespace path":
					path = "   "
				case "empty file set":
					pin = config.EmptyRulePackFilesDigest
				case "missing folder":
					path = filepath.Join(dir, "missing")
				}
				body := fmt.Sprintf("config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n  rule_pack: %s\n  custom_packs:\n    %s:\n      path: %q\n      digest: %s\n", name, name, path, pin)
				writeOutageNowConfig(t, home, body)
				loaded, _, err := loadHookRuntimeConfig(filepath.Join(home, "config.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				if errs := loaded.CustomRulePackErrors(); len(errs) != 1 {
					t.Fatalf("config errors = %v, want one", errs)
				}
				if got := loaded.HookPolicyTierForConnector("codex"); got != config.HookPolicyTierStrict {
					t.Errorf("tier = %q, want strict", got)
				}
				if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
					t.Errorf("outage = %q, want closed", got)
				}
			})
		}
	}
}
