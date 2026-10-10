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
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-0360: a custom pack copied from the 0.8.x default kept its pattern-only
// command rules, which 1.0 runs as candidate filters that never block: the
// operator's marker rule and the old built-in rules stopped enforcing, and
// doctor said PASS. The migration's rebase restores both. GAP-1225: the
// operator's own rule file of another category was left as it was, so its
// marker rule stopped blocking too and nothing said so.
func TestRebasedZeroEightPackKeepsTheOperatorRuleBlocking(t *testing.T) {
	old := t.TempDir()
	if err := os.MkdirAll(filepath.Join(old, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	// CMD-RM-RF keeps the shipped 0.8.x regex: an edited regex is the rule's
	// sole condition after the rebase (GAP-1004), so only an unedited copy
	// inherits the 1.0 expression.
	const rmRF08 = `'(?i)\brm\s+(?:-[a-zA-Z]*\s+)*(?:-[a-zA-Z]*)?(?:r[a-zA-Z]*f|f[a-zA-Z]*r)\b(?:\s+\S+)*\s+/` +
		`(?:$|["''\s,}\]]|(?:etc|bin|sbin|usr|var|home|root|opt|boot|lib(?:64)?|srv|mnt|dev|proc|sys)(?:$|/|["''\s,}\]]))'`
	commands := "version: 1\ncategory: command\nrules:\n" +
		"  - id: CMD-RM-RF\n    pattern: " + rmRF08 + "\n    title: \"Recursive delete\"\n    severity: CRITICAL\n    confidence: 0.9\n    tags: [destructive]\n" +
		"  - id: CMD-ACME-MARKER\n    pattern: acme-marker-7f3c\n    title: \"Acme marker\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [execution]\n" +
		"  - id: CMD-ACME-SPACED\n    pattern: 'acme\\s+spaced'\n    title: \"Acme spaced\"\n    severity: HIGH\n    confidence: 0.9\n    tags: [execution]\n"
	if err := os.WriteFile(filepath.Join(old, "rules", "commands.yaml"), []byte(commands), 0o644); err != nil {
		t.Fatal(err)
	}
	own := "version: 1\ncategory: acme-markers\nrules:\n" +
		"  - id: ACME-OWN-MARKER\n    pattern: 'acme\\.own-7f3c'\n    title: \"Own marker\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n" +
		"  - id: ACME-OWN-SPACED\n    pattern: 'acme\\s+own'\n    title: \"Own spaced\"\n    severity: HIGH\n    confidence: 0.9\n    tags: [marker]\n"
	if err := os.WriteFile(filepath.Join(old, "rules", "acme.yaml"), []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	blocks := func(pack *guardrail.RulePack, command string) bool {
		t.Helper()
		const connector = "rebase-0-8"
		if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
			t.Fatal(err)
		}
		defer RemoveConnectorRulePackOverrides(connector)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{
				Tool: "Bash", Command: command, CWD: "/home/alice/project",
				ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
			},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		return buildVerdict(findings, "tool_call").Action == guardrailActionBlock
	}
	const marker = "echo acme-marker-7f3c > /tmp/x.txt"
	const ownMarker = "echo acme.own-7f3c > /tmp/y.txt"

	before, err := guardrail.LoadRulePack(old)
	if err != nil {
		t.Fatal(err)
	}
	if summary := before.Summary(); blocks(before, marker) || blocks(before, ownMarker) ||
		summary.StaleRuleCount != 1 || summary.AlertOnlyRuleCount != 4 {
		t.Fatalf("the 0.8.x copy: summary %+v; want unblocked markers, 1 stale and 4 alert-only rules", summary)
	}

	plan, err := guardrail.PlanRulePackRebase(old)
	if err != nil || plan == nil {
		t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
	}
	if !slices.Equal(plan.Expressed, []string{"ACME-OWN-MARKER", "CMD-ACME-MARKER"}) ||
		!slices.Equal(plan.AlertOnly, []string{"ACME-OWN-SPACED", "CMD-ACME-SPACED"}) {
		t.Fatalf("expressed %v alert-only %v", plan.Expressed, plan.AlertOnly)
	}
	rebased := t.TempDir()
	for rel, data := range plan.Files {
		target := filepath.Join(rebased, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	after, err := guardrail.LoadRulePack(rebased)
	if err != nil {
		t.Fatal(err)
	}
	if after.FilesDigest() != plan.Digest {
		t.Fatalf("digest %s, plan %s", after.FilesDigest(), plan.Digest)
	}
	if summary := after.Summary(); !blocks(after, marker) || !blocks(after, ownMarker) || !blocks(after, "rm -rf /") ||
		summary.StaleRuleCount != 0 || summary.AlertOnlyRuleCount != 2 {
		t.Fatalf("the rebased pack: summary %+v; want both markers and rm -rf / blocked, 0 stale and 2 alert-only rules", summary)
	}

	// A gateway reload of the un-migrated v8 source must enforce the same
	// rebased rules without changing the operator's 0.8.x pack or config.
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + configDir +
		"\nguardrail:\n  rule_pack_dir: " + old + "\nobservability: {}\n")
	if err := os.WriteFile(configPath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeConfig, err := loadRuntimeConfigCandidate(configPath, source)
	if err != nil {
		t.Fatal(err)
	}
	runtimePack, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cloneConfig(runtimeConfig), "global")
	if err != nil {
		t.Fatal(err)
	}
	if !blocks(runtimePack, marker) || runtimePack.FilesDigest() != plan.Digest {
		t.Fatalf("read-only v8 load kept the original pack: digest %s", runtimePack.FilesDigest())
	}
	if current, err := os.ReadFile(filepath.Join(old, "rules", "commands.yaml")); err != nil || string(current) != commands {
		t.Fatalf("the v8 rule pack changed: %v", err)
	}
	if current, err := os.ReadFile(configPath); err != nil || string(current) != string(source) {
		t.Fatalf("the v8 config changed: %v", err)
	}
}
