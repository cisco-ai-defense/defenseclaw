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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-1197: the first-guardrail walkthrough adds the test rule it prints to a
// copy of the default pack, and Claude Code's `echo defenseclaw-demo-marker`
// must then be blocked.
func TestFirstGuardrailDocsTestRuleBlocks(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "get-started", "first-guardrail.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout has CRLF line endings.
	_, rest, found := strings.Cut(strings.ReplaceAll(string(doc), "\r\n", "\n"), "<<'EOF'\n")
	rule, _, closed := strings.Cut(rest, "\nEOF\n")
	if !found || !closed {
		t.Fatal("first-guardrail.mdx has no test rule heredoc")
	}

	pack := t.TempDir()
	source := filepath.Join("..", "..", "policies", "guardrail", "default")
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		target := filepath.Join(pack, strings.TrimPrefix(path, source))
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack, "rules", "first-guardrail.yaml"), []byte(rule+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := guardrail.LoadRulePack(pack)
	if err != nil {
		t.Fatalf("load the documented pack: %v", err)
	}
	const connector = "first-guardrail-docs"
	if err := ApplyConnectorRulePackOverrides(connector, loaded); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { RemoveConnectorRulePackOverrides(connector) })

	for command, wantBlock := range map[string]bool{
		"echo defenseclaw-demo-marker": true,
		"echo hello":                   false,
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{
				Tool: "shell", Command: command, CWD: "/home/alice/project",
				ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
			},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		finding := findingWithID(findings, "DEMO-MARKER-BLOCK")
		blocked := buildVerdict(findings, "tool_call").Action == guardrailActionBlock
		if wantBlock != (finding != nil && finding.contributesToEnforcement() && blocked) {
			t.Errorf("%q: finding=%+v blocked=%t, want block=%t", command, finding, blocked, wantBlock)
		}
	}
}
