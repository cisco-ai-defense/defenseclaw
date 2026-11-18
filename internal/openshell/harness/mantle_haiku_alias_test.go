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

package harness

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// TestMantleHaikuAliasStaysHaiku45 pins the Claude Code Bedrock Mantle Haiku
// aliases to anthropic.claude-haiku-4-5 and requires the sandbox pages to say
// why: Mantle does not serve Claude Haiku 5.5 (anthropic.claude-haiku-5-5 is a
// 404 in us-east-1), so a sandbox cannot run it yet (rel-1-0-10:GAP-0169).
// Change the alias only when Mantle lists the model, and change the docs with
// it.
func TestMantleHaikuAliasStaysHaiku45(t *testing.T) {
	spec := ClaudeCode
	var env map[string]string
	for _, cp := range spec.CredentialProfiles("") {
		if cp.ProfileID == profiles.ClaudeBedrockMantleID {
			env = cp.Env
		}
	}
	if env == nil {
		t.Fatal("no Claude Code Bedrock Mantle credential profile")
	}
	for _, k := range []string{"ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_SMALL_FAST_MODEL"} {
		if got := env[k]; got != "anthropic.claude-haiku-4-5" {
			t.Errorf("%s = %q, want anthropic.claude-haiku-4-5 (Mantle does not serve Haiku 5.5, GAP-0169)", k, got)
		}
	}
	for _, page := range [][]string{
		{"docs-site", "content", "docs", "connectors", "claudecode.mdx"},
		{"docs", "SANDBOX.md"},
	} {
		text := docsFile(t, page...)
		if !strings.Contains(text, "does not serve Claude Haiku 5.5") {
			t.Errorf("%s does not say that Bedrock Mantle does not serve Claude Haiku 5.5", strings.Join(page, "/"))
		}
	}
}
