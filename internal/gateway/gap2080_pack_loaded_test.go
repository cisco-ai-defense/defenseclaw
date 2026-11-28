// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestPackTableFromDigestCheckedBytes pins the table of a pack loaded after
// the generation build. A later disk edit cannot replace the bytes that the
// loader checked against the configured digest.
func TestPackTableFromDigestCheckedBytes(t *testing.T) {
	root := guardrailPoliciesRoot(t)
	const custom = "version: 1\ntier: permissive\nrows:\n  - id: tiered-strict\n    per_user:\n      floor: allow\n    managed:\n      floor: allow\n"
	for _, route := range []string{"retry", "lazy"} {
		t.Run(route, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "operator-pack")
			if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, "default"))); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, decide.TiersFile), []byte(custom), 0o644); err != nil {
				t.Fatal(err)
			}
			pin, err := guardrail.RulePackDigest(dir)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{PolicyDir: filepath.Dir(root)}
			cfg.Guardrail.Enabled = true
			cfg.Guardrail.RulePack = "operator"
			cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
				"operator": {Path: dir, Digest: "sha256:" + pin},
			}
			scope := connectorRulePackScope(cfg, "codex")
			switch route {
			case "retry":
				r := &profileRulePackRetry{profile: "p", cfg: cfg, scope: scope}
				if r.rules(time.Now()) == nil {
					t.Fatal("profile retry did not load the pinned pack")
				}
			case "lazy":
				set := &guardrailProfileSet{}
				if entry := set.lazyScope("p", cfg, "codex", "unique"); entry.rules == nil {
					t.Fatal("lazy profile did not load the pinned pack")
				}
			}
			if err := os.WriteFile(filepath.Join(dir, decide.TiersFile), []byte("version: 1\ntier: default\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if !packTableHasTestColumn(packTable(dir)) {
				t.Fatal("late-loaded pack used unchecked disk table after edit")
			}
			t.Cleanup(func() { packTableFallback.Delete(dir) })
		})
	}
}
