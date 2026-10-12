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

//go:build !windows

package gateway

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestSandboxRelayBlockNamesTheProfilePackRule pins GAP-0589 and GAP-0638: a
// relayed block by a rule only the caller's own profile rule pack defines
// (the contractors strict pack) tells the agent the rule, as the relayed
// audit record does, instead of the generic organization-policy text. The
// reason came from the host's rule catalog, which does not hold that rule.
func TestSandboxRelayBlockNamesTheProfilePackRule(t *testing.T) {
	resetConnectorRuleCategories(t)
	priorManaged := ManagedEnterpriseActive()
	setManagedEnterpriseRedactionPosture(false)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(priorManaged) })
	restoreFacts, restoreBlocking := identityFactsEnabled.Load(), identityLookupBlocking.Load()
	prevDirectory, prevRematched := managedHookPeerDirectory, sandboxRecordRematched
	identityFactsEnabled.Store(true)
	identityLookupBlocking.Store(true)
	managedHookPeerDirectory = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) {
		if uid != relayTestPeer.UID {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{
			Principal: "alice@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			Groups: []string{"dc-sbx-contractors"}, Source: "sssd", ResolvedAt: time.Now(),
		}, true
	}
	sandboxRecordRematched = func(*APIServer, sandboxreg.Registration, sandboxreg.Registration, []string, string) {}
	t.Cleanup(func() {
		identityFactsEnabled.Store(restoreFacts)
		identityLookupBlocking.Store(restoreBlocking)
		managedHookPeerDirectory, sandboxRecordRematched = prevDirectory, prevRematched
	})
	packDir := filepath.Join(t.TempDir(), "es-strict")
	writeRulePackFixtureFile(t, packDir, "rules/strict.yaml", `version: 1
category: command
rules:
  - id: ES-STRICT-ONLY
    pattern: "dccert-strict-marker"
    tool_call_only: true
    expression: "f.commands.exists(c, c.program == 'echo' && 'dccert-strict-marker' in c.argv)"
    title: Matrix marker strict
    severity: CRITICAL
    confidence: 0.99
    tags: [test]
`)
	f := newRelayFixture(t, func(c *config.Config) {
		c.Guardrail.Connector = "claudecode"
		c.Guardrail.Mode = "action"
		c.Guardrail.Profiles = map[string]config.GuardrailProfile{
			"contractors":   {Description: "Strict pack", Mode: "action", RulePackDir: packDir},
			"offline-floor": {Description: "Offline floor"},
		}
		c.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: "contractors", Match: config.ProfileMatch{Groups: []string{"dc-sbx-contractors"}}},
		}
		c.Guardrail.DefaultProfile = "offline-floor"
	})
	reg := f.register(t, "strictclaude", "claudecode", relayTestBindingID(0xa72), func(r *sandboxreg.Registration) {
		r.Profile, r.ProfileMatch = "contractors", "group"
	})
	resp, body := f.post(t, sandboxrelay.PathHookPrefix+"claudecode", reg.ID,
		`{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_use_id":"toolu_strict",`+
			`"tool_input":{"command":"echo dccert-strict-marker"},"cwd":"/work/app"}`)
	d, ok := relayTrailer(t, resp)
	if resp.StatusCode != http.StatusOK || !ok || d.Action != "block" {
		t.Fatalf("strict pack call: %d %s trailer %+v, want a block", resp.StatusCode, body, d)
	}
	want := "rule ES-STRICT-ONLY: Matrix marker strict"
	if !strings.Contains(d.Reason, want) || !strings.Contains(body, want) {
		t.Fatalf("block reason %q, body %s, want it to name %q", d.Reason, body, want)
	}
}
