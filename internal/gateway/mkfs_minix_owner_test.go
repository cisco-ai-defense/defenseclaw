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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestMkfsMinixUsesDedicatedFormatterOwner(t *testing.T) {
	t.Parallel()

	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:    "exec",
		Command: "mkfs.minix /dev/sda",
		CWD:     "/workspace",
	})
	if !facts.Authoritative() {
		t.Fatalf("mkfs.minix facts are not authoritative: %#v", facts)
	}
	if !semanticReconImpactOwners["CMD-MKFS"].eligible(facts) {
		t.Fatalf("CMD-MKFS did not own mkfs.minix: %#v", facts)
	}
	if semanticReconImpactOwners["CMD-DEVICE-WIPE"].eligible(facts) {
		t.Fatalf("generic device owner stole mkfs.minix: %#v", facts)
	}

	findings := scanTrustedRules("mkfs.minix /dev/sda", "shell")
	if !hasMkfsMinixRule(findings, "CMD-MKFS") {
		t.Fatalf("generated catalog did not route mkfs.minix: %v", findingIDs(findings))
	}
	if hasMkfsMinixRule(findings, "CMD-DEVICE-WIPE") {
		t.Fatalf("generated catalog double-routed mkfs.minix: %v", findingIDs(findings))
	}
}

func TestMkfsMinixOwnerControls(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"mkfs.minix /tmp/minix.img",
		"mkfs.minix --help /dev/sda",
		"mkfs.minixx /dev/sda",
		"rg -n 'mkfs.minix /dev/sda' internal/gateway",
	} {
		facts := actionfacts.Analyze(actionfacts.Input{
			Tool:    "exec",
			Command: command,
			CWD:     "/workspace",
		})
		if semanticReconImpactOwners["CMD-MKFS"].eligible(facts) {
			t.Fatalf("control %q satisfied CMD-MKFS: %#v", command, facts)
		}
	}
}

func hasMkfsMinixRule(findings []RuleFinding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
