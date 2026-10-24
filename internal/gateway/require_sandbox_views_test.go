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
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0555: the policy views took "a host run is refused" from required_for
// alone, while the hook allows an exempt_users account's host run. The views
// take the answer from the gate's own rule: the exported form the
// administrator's views use and the user's explain (ManagedExplain) agree
// with requireSandboxHostGate for every combination.
func TestRequireSandboxHostGateIsWhatTheViewsSay(t *testing.T) {
	for _, tc := range []struct {
		required, exempt bool
		want             string
	}{
		{false, false, ""},
		{false, true, ""},
		{true, true, requireSandboxExempt},
		{true, false, requireSandboxRefused},
	} {
		if got := requireSandboxHostGate(tc.required, tc.exempt); got != tc.want {
			t.Errorf("gate(required=%t, exempt=%t) = %q, want %q", tc.required, tc.exempt, got, tc.want)
		}
		var list []string
		if tc.required {
			list = []string{"codex", "claudecode"}
		}
		if got := RequireSandboxHostGate(list, "claudecode", tc.exempt); got != tc.want {
			t.Errorf("RequireSandboxHostGate(%v, exempt=%t) = %q, want %q", list, tc.exempt, got, tc.want)
		}
		m := &sandboxapi.ManagedExplain{RequiredFor: list, HostRunGate: tc.want, EnrollmentExempt: tc.exempt}
		if got := m.HostRunRefused("claudecode"); got != (tc.want == requireSandboxRefused) {
			t.Errorf("explain HostRunRefused(required=%t, exempt=%t) = %t", tc.required, tc.exempt, got)
		}
		if got := m.HostRunRefused("cursor"); got {
			t.Errorf("unlisted connector refused: required=%t exempt=%t", tc.required, tc.exempt)
		}
	}
	if (*sandboxapi.ManagedExplain)(nil).HostRunRefused("claudecode") {
		t.Error("no explain refuses a host run")
	}
}

// The Windows per-user credential matches the same SID, short name and
// DOMAIN\name that profile-explain shows. This matcher runs on every build,
// including Linux where the Windows policy UI cannot be executed.
func TestWindowsExemptMatcherAndHostRunGateViews(t *testing.T) {
	const sid = "S-1-5-21-1000-2000-3000-1105"
	subject := VerifiedSubject{UserID: sid, IDKind: useridentity.KindWindowsSID, UserName: "alice",
		Source: subjectSourceUserCredential, Directory: useridentity.DirectoryFacts{AccountDomain: "CORP"}}
	for _, tc := range []struct {
		entry string
		want  string
	}{
		{sid, requireSandboxExempt}, {"alice", requireSandboxExempt}, {`CORP\alice`, requireSandboxExempt},
		{`OTHER\alice`, requireSandboxRefused}, {"bob", requireSandboxRefused},
	} {
		cfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
		cfg.Enterprise.Profile = managed.ProfileStandalone
		cfg.Enterprise.Enrollment.ExemptUsers = []string{tc.entry}
		ctx := withVerifiedSubject(context.Background(), subject)
		exempt := requireSandboxExemptUser(ctx, cfg)
		gate := requireSandboxHostGate(true, exempt)
		view := explainEnrollmentExempt(cfg, &profileSubject{UserID: sid, IDKind: useridentity.KindWindowsSID,
			UserName: "alice", AccountDomain: "CORP"})
		if gate != tc.want || view != exempt || RequireSandboxHostGate([]string{"claudecode"}, "claudecode", view) != gate {
			t.Errorf("entry %q: hook gate %q, profile view exempt %t, want %q", tc.entry, gate, view, tc.want)
		}
	}
}

// The hook socket never marks root exempt (decide answers uid 0 by
// enrollment.root first), so neither the views' exemption nor
// profile-explain's may: a required agent's host run stays refused for root
// even when exempt_users names it.
func TestEnrollmentExemptionMatchesTheHookSocket(t *testing.T) {
	enrollment := config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"root", "0", "contractor", "1234"}}
	z := &managedHookAuthorizer{enrollment: enrollment}
	for _, tc := range []struct {
		peer managedHookPeer
		want bool
	}{
		{managedHookPeer{UID: 0, Name: "root"}, false},
		{managedHookPeer{UID: 2201, Name: "contractor"}, true},
		{managedHookPeer{UID: 1234, Name: "svc"}, true},
		{managedHookPeer{UID: 1001, Name: "alice"}, false},
	} {
		decision := z.decide(tc.peer, "claudecode", "")
		if decision.Exempt != tc.want || z.hostRunExempt(tc.peer) != tc.want ||
			EnrollmentExemptFromSandbox(enrollment, tc.peer.UID, tc.peer.Name) != tc.want {
			t.Errorf("%s (uid %d): decide.Exempt %t, hostRunExempt %t, views %t; want %t", tc.peer.Name, tc.peer.UID,
				decision.Exempt, z.hostRunExempt(tc.peer), EnrollmentExemptFromSandbox(enrollment, tc.peer.UID, tc.peer.Name), tc.want)
		}
	}

	cfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.Enrollment = enrollment
	root := &profileSubject{UserID: "0", IDKind: useridentity.KindPOSIXUID, UserName: "root"}
	if explainEnrollmentExempt(cfg, root) {
		t.Error("profile-explain calls root exempt; its hooks are never exempt")
	}
	ctr := &profileSubject{UserID: "2201", IDKind: useridentity.KindPOSIXUID, UserName: "contractor"}
	if !explainEnrollmentExempt(cfg, ctr) {
		t.Error("profile-explain misses the exempt account")
	}
}

// The Unix policy views use the hook socket's verified name forms. A bare
// local namesake never inherits a directory account's exemption.
func TestUnixDirectoryExemptionMatchesTheHookAndViews(t *testing.T) {
	previousEnabled := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previousEnabled) })
	now := time.Now()
	ad := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceSSSD,
		Assurance: useridentity.AssuranceVerified, Domain: "corp.example", AccountDomain: "CORP",
		Principal: "alice@corp.example", ResolvedAt: now}
	mac := ad
	mac.Source = useridentity.SourceMacOSOpenDirectory
	local := useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
		Assurance: useridentity.AssuranceVerified, ResolvedAt: now}
	facts := map[int]useridentity.DirectoryFacts{2202: ad, 2203: mac, 2500: local}
	previousFacts := managedHookExemptFacts
	managedHookExemptFacts = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) { f, ok := facts[uid]; return f, ok }
	t.Cleanup(func() { managedHookExemptFacts = previousFacts })
	enrollment := config.EnterpriseEnrollmentConfig{ExemptUsers: []string{`CORP\alice`}}
	z := &managedHookAuthorizer{enrollment: enrollment}
	cfg := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.Enrollment = enrollment
	for _, tc := range []struct {
		os   string
		peer managedHookPeer
		want bool
	}{
		{"linux", managedHookPeer{UID: 2202, Name: "alice@corp.example"}, true},
		{"darwin", managedHookPeer{UID: 2203, Name: "alice"}, true},
		{"local namesake", managedHookPeer{UID: 2500, Name: "alice"}, false},
	} {
		f := facts[tc.peer.UID]
		subject := profileSubjectFromVerified(VerifiedSubject{UserID: strconv.Itoa(tc.peer.UID),
			IDKind: useridentity.KindPOSIXUID, UserName: tc.peer.Name, Directory: f}, false)
		decision := z.decide(tc.peer, "claudecode", "")
		view := EnrollmentExemptFromSandbox(enrollment, tc.peer.UID, tc.peer.Name)
		profileView := explainEnrollmentExempt(cfg, &subject)
		gate := RequireSandboxHostGate([]string{"claudecode"}, "claudecode", view)
		if decision.Exempt != tc.want || view != tc.want || profileView != tc.want ||
			(gate == RequireSandboxHostRunExempt) != tc.want {
			t.Errorf("%s: hook exempt=%t, policy exempt=%t, profile exempt=%t, gate=%q; want exempt=%t",
				tc.os, decision.Exempt, view, profileView, gate, tc.want)
		}
	}
}
