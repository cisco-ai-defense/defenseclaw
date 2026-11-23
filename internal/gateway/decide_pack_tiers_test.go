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

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// TestPackTiersYAMLCellsDecide (DET111 D4 step 1): a custom pack's own
// tiers.yaml cells decide its verdicts, in the pack's own tier. A copy of
// the default pack whose state-write row floors at block blocks a proven
// DefenseClaw state write per-user; a copy of the permissive pack does the
// same through its permissive column. The unchanged copies keep the 1.0.10
// alert. At a64bfdb931 the gateway never read a pack's tiers.yaml (alert).
func TestPackTiersYAMLCellsDecide(t *testing.T) {
	root := guardrailPoliciesRoot(t)
	home := t.TempDir()
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Dir(state), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(state, []byte("guardrail: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const blockingStateRow = "  - id: state-write\n    per_user:\n      floor: block\n    managed:\n      floor: block\n"
	for _, tc := range []struct {
		name, source string
		column       string
		want         string
	}{
		{"default copy", "default", "", guardrailActionAlert},
		{"default copy, state-write floors at block", "default", "version: 1\ntier: default\nrows:\n" + blockingStateRow, guardrailActionBlock},
		{"permissive copy", "permissive", "", guardrailActionAlert},
		{"permissive copy, state-write floors at block", "permissive", "version: 1\ntier: permissive\nrows:\n" + blockingStateRow, guardrailActionBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "operator-pack")
			if err := os.CopyFS(dir, os.DirFS(filepath.Join(root, tc.source))); err != nil {
				t.Fatal(err)
			}
			if tc.column != "" {
				if err := os.WriteFile(filepath.Join(dir, "tiers.yaml"), []byte(tc.column), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			pin, err := guardrail.RulePackDigest(dir)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{PolicyDir: filepath.Dir(root)}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Enabled = true
			cfg.Guardrail.RulePack = "operator"
			cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"operator": {Path: dir, Digest: "sha256:" + pin}}
			t.Cleanup(func() {
				pendingPackPostures.Delete(dir)
				packPostures.Delete(dir)
				packTableFallback.Delete(dir)
			})
			pack, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cfg, "global")
			if err != nil {
				t.Fatal(err)
			}
			generation, err := compileRulePackCategories(pack)
			if err != nil {
				t.Fatal(err)
			}
			buildThresholdTable(cfg, nil)
			if got := cfg.HookPolicyTierForConnector("codex"); got != tc.source {
				t.Fatalf("hook policy tier %q, want %q", got, tc.source)
			}
			findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
				Input:     actionfacts.Input{Tool: "Bash", Command: "echo marker > " + posixShellOperand(state), CWD: project, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
				Connector: "codex", EnforcementCapable: true, generation: generation,
			})
			if got := singleProfileActionForFindings(cfg, "codex", findings, true, false); got != tc.want {
				t.Fatalf("state write: %s, want %s; findings=%v", got, tc.want, FindingStrings(findings))
			}
		})
	}
}
