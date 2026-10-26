// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestExplainCacheAgreesWithTheHookOnAnUnconfirmedNumericGroup is GAP-1685:
// a local account whose unnamed primary gid the gateway cannot confirm, a
// numeric group assignment, and a default that enforces as the assigned
// profile does on the hook path. The hook decides on its path and allows;
// explain's cache view decided pathless and reported a refusal. Where the
// assigned profile enforces differently on the hook path, the refusal stays
// (MUST NOT CHANGE: refusals for genuinely unconfirmed identities).
func TestExplainCacheAgreesWithTheHookOnAnUnconfirmedNumericGroup(t *testing.T) {
	previousBlocking := identityLookupBlocking.Load()
	setIdentityLookupBlocking(true)
	t.Cleanup(func() { setIdentityLookupBlocking(previousBlocking) })
	now := time.Now()
	cached := useridentity.DirectoryFacts{
		Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal,
		Groups: []string{"49202"}, UnconfirmedGroups: []string{"49202"},
		Assurance: useridentity.AssuranceVerified, ResolvedAt: now.Add(-6 * time.Second),
	}
	prevFacts, prevRefresh := cachedDirectoryFacts, cachedDirectoryRefreshFailure
	t.Cleanup(func() { cachedDirectoryFacts, cachedDirectoryRefreshFailure = prevFacts, prevRefresh })
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) { return cached, cached.ResolvedAt, true }
	cachedDirectoryRefreshFailure = func(string) (time.Time, string, bool) { return time.Time{}, "", false }
	explained := profileSubject{
		UserID: "49201", IDKind: useridentity.KindPOSIXUID, UserName: "fcb3r3num",
		Groups: []string{"49202"}, Directory: useridentity.DirectoryLocal, localAccount: true,
	}
	hookSubject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "49201", IDKind: useridentity.KindPOSIXUID, UserName: "fcb3r3num", Directory: cached,
	}, true)
	for _, tc := range []struct {
		name, assignedMode string
		refused            bool
	}{
		{"assigned profile enforces as the default on the hook", "observe", false},
		{"assigned profile enforces more than the default", "action", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Connector = "codex"
			cfg.Codex.Mode = "observe"
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"watch": {Mode: "observe"}, "numeric": {Mode: tc.assignedMode},
			}
			cfg.Guardrail.DefaultProfile = "watch"
			cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
				{Profile: "numeric", Match: config.ProfileMatch{Groups: []string{"49202"}}},
			}
			set := newGuardrailProfileSetFor(t, cfg)
			hook := set.selectProfile(&hookSubject, resolveIdentity(&hookSubject, nil), profileSubjectVerified, "codex", nil, profilePathHook, "")
			if (hook.Refused != "") != tc.refused {
				t.Fatalf("fixture: hook decision %+v; want refused=%v", hook, tc.refused)
			}
			decision := set.match(&explained, profileSubjectLookup, "codex", "")
			view, warning := explainCacheView(set, &explained, decision, "codex", "", now)
			if view == nil {
				t.Fatal("no cache view")
			}
			if view["refused"] != tc.refused || strings.Contains(warning, "are refused") != tc.refused {
				t.Fatalf("cache view %v, warning %q; want refused=%v as the hook decides", view, warning, tc.refused)
			}
		})
	}
}
