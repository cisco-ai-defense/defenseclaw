// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestGAP0632PinnedStandaloneHookOutageUsesValidatedPosture(t *testing.T) {
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
