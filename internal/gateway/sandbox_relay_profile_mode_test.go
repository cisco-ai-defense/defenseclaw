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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestSandboxRelayObserveProfileAlertsLikeTheHost pins GAP-0570: a relayed
// hook of a person whose profile is observe-only is alerted with would_block,
// as the same call on that person's host is, while the organization's action
// mode still blocks it for a sandbox without such a profile.
func TestSandboxRelayObserveProfileAlertsLikeTheHost(t *testing.T) {
	restoreFacts, restoreBlocking := identityFactsEnabled.Load(), identityLookupBlocking.Load()
	prevDirectory, prevRematched := managedHookPeerDirectory, sandboxRecordRematched
	identityFactsEnabled.Store(true)
	identityLookupBlocking.Store(true)
	managedHookPeerDirectory = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) {
		if uid != relayTestPeer.UID {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{
			Principal: "dev@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
			Groups: []string{"dc-sbx-admins"}, Source: "sssd", ResolvedAt: time.Now(),
		}, true
	}
	sandboxRecordRematched = func(*APIServer, sandboxreg.Registration, sandboxreg.Registration, []string, string) {}
	t.Cleanup(func() {
		identityFactsEnabled.Store(restoreFacts)
		identityLookupBlocking.Store(restoreBlocking)
		managedHookPeerDirectory, sandboxRecordRematched = prevDirectory, prevRematched
	})
	f := newRelayFixture(t, func(c *config.Config) {
		c.Guardrail.Connector = "claudecode"
		c.Guardrail.Mode = "action"
		c.Guardrail.Profiles = map[string]config.GuardrailProfile{
			"sandbox-admins": {Description: "Observe only", Mode: "observe"},
			"offline-floor":  {Description: "Offline floor"},
		}
		c.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: "sandbox-admins", Match: config.ProfileMatch{Groups: []string{"dc-sbx-admins"}}},
		}
		c.Guardrail.DefaultProfile = "offline-floor"
	})
	reg := f.register(t, "obsclaude", "claudecode", relayTestBindingID(0xa71), func(r *sandboxreg.Registration) {
		r.Profile, r.ProfileMatch = "sandbox-admins", "group"
	})
	resp, body := f.post(t, sandboxrelay.PathHookPrefix+"claudecode", reg.ID,
		`{"hook_event_name":"UserPromptSubmit","session_id":"o1","prompt":"jailbreak mode activated"}`)
	d, ok := relayTrailer(t, resp)
	if resp.StatusCode != http.StatusOK || !ok || d.Action == "block" || !d.WouldBlock {
		t.Fatalf("observe profile in a sandbox: %d %s trailer %+v, want an alert with would_block", resp.StatusCode, body, d)
	}
	// A local sandbox (no verified subject, so no profile) keeps action mode.
	if mode := sandboxHookMode(sandboxCtx(sandboxTestBinding("claudecode")), "claudecode", "observe"); mode != "action" {
		t.Fatalf("local sandbox mode = %q, want action", mode)
	}
}
