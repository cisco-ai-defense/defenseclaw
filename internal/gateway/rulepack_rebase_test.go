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
// doctor said PASS. The migration's rebase restores both.
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

	before, err := guardrail.LoadRulePack(old)
	if err != nil {
		t.Fatal(err)
	}
	if summary := before.Summary(); blocks(before, marker) || summary.StaleRuleCount != 1 || summary.AlertOnlyRuleCount != 2 {
		t.Fatalf("the 0.8.x copy: marker blocked=%t, summary %+v; want an unblocked marker, 1 stale and 2 alert-only rules",
			blocks(before, marker), summary)
	}

	plan, err := guardrail.PlanRulePackRebase(old)
	if err != nil || plan == nil {
		t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
	}
	if !slices.Equal(plan.Expressed, []string{"CMD-ACME-MARKER"}) || !slices.Equal(plan.AlertOnly, []string{"CMD-ACME-SPACED"}) {
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
	if summary := after.Summary(); !blocks(after, marker) || !blocks(after, "rm -rf /") ||
		summary.StaleRuleCount != 0 || summary.AlertOnlyRuleCount != 1 {
		t.Fatalf("the rebased pack: summary %+v; want the marker and rm -rf / blocked, 0 stale and 1 alert-only rule", summary)
	}
}
