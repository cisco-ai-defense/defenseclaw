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

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestPolicyValidateRulePackHonorsRegexSource(t *testing.T) {
	contents := []byte("version: 1\ncategory: agent-control\nrules:\n  - id: SHARED-ID\n    pattern: central\n    title: Central\n    severity: HIGH\n    confidence: 1\n    tags: []\n")
	base := t.TempDir()
	baseRules := filepath.Join(base, "rules")
	if err := os.Mkdir(baseRules, 0o700); err != nil {
		t.Fatal(err)
	}
	localContents := []byte("version: 1\ncategory: local\nrules:\n  - id: SHARED-ID\n    pattern: local\n    title: Local\n    severity: HIGH\n    confidence: 1\n    tags: []\n")
	if err := os.WriteFile(filepath.Join(baseRules, "local.yaml"), localContents, 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := t.TempDir()
	overlayRules := filepath.Join(overlay, "rules")
	if err := os.Mkdir(overlayRules, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(overlayRules, "agent-control.yaml"), contents, 0o600); err != nil {
		t.Fatal(err)
	}

	savedBase, savedOverlay, savedSource := policyValidateRulePackBaseDir, policyValidateRulePackOverlayDir, policyValidateRulePackRegexSource
	defer func() {
		policyValidateRulePackBaseDir = savedBase
		policyValidateRulePackOverlayDir = savedOverlay
		policyValidateRulePackRegexSource = savedSource
	}()
	policyValidateRulePackBaseDir = base
	policyValidateRulePackOverlayDir = overlay

	policyValidateRulePackRegexSource = guardrail.RegexSourceAgentControl
	if err := policyValidateRulePackCmd.RunE(nil, nil); err != nil {
		t.Fatalf("managed-only validation rejected excluded local duplicate: %v", err)
	}
	policyValidateRulePackRegexSource = guardrail.RegexSourceHybrid
	if err := policyValidateRulePackCmd.RunE(nil, nil); err == nil {
		t.Fatal("hybrid validation accepted duplicate local/managed rule ID")
	}
}
