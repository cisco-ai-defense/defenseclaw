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
	"context"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0555: a contractor in enterprise.enrollment.exempt_users ran host
// Claude Code (the hook allowed it, require_sandbox=exempt) while its own
// `sandbox policy explain` said Claude Code runs only in a sandbox. The
// caller's explain now carries the exemption, and its host-run answer is the
// hook decision's for the same account; a non-exempt account's stays refused.
func TestSandboxExplainHostRunMatchesTheHookDecision(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{ExemptUsers: []string{sbxAlice.Name}}, nil)
	f.cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	f.cfg.Enterprise.Profile = managed.ProfileStandalone
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-contractors")
	authorizer := &managedHookAuthorizer{enrollment: f.cfg.Enterprise.Enrollment}
	for _, requiredFor := range [][]string{{"claudecode", "codex"}, {"codex"}, nil} {
		f.cfg.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Description: "Contractors",
			Sandbox: &config.OpenShellAdminConfig{RequiredFor: requiredFor}}
		// The organization and profile floors agree, so the test is about
		// the same caller and connector at both entry points.
		f.cfg.OpenShell.Admin.RequiredFor = requiredFor
		for _, tc := range []struct {
			peer   managedHookPeer
			exempt bool
		}{{sbxAlice, true}, {sbxBob, false}} {
			me := postureExplain(t, f, tc.peer, sandboxrelay.ExplainRequest{})
			if me.Profile != "contractors" {
				t.Fatalf("%s: explain profile %q, want contractors", tc.peer.Name, me.Profile)
			}
			// The hook as the hook socket hands it to the gate.
			ctx := withManagedHookPeer(context.Background(), tc.peer)
			ctx = attachVerifiedSubject(ctx, nil, strconv.Itoa(tc.peer.UID), tc.peer.Name, subjectSourcePeerCredentials)
			if authorizer.decide(tc.peer, "claudecode", "").Exempt {
				ctx = withEnterpriseExemptUser(ctx)
			}
			hook := f.api.requireSandboxDecision(ctx, "claudecode", "UserPromptSubmit", "/p", "")
			want := RequireSandboxHostGate(requiredFor, "claudecode", tc.exempt)
			if me.HostRunGate != requireSandboxHostGate(len(requiredFor) > 0, tc.exempt) ||
				me.EnrollmentExempt != (me.HostRunGate == requireSandboxExempt) ||
				hook.Outcome != want || hook.refuses() != me.HostRunRefused("claudecode") {
				t.Errorf("%s required_for=%v: hook %q, explain gate %q exempt=%t refused=%t, want %q",
					tc.peer.Name, requiredFor, hook.Outcome, me.HostRunGate, me.EnrollmentExempt, me.HostRunRefused("claudecode"), want)
			}
		}
	}
}
