// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// TestExplainNamesTheSandboxRefusalTheHookDoesNotMake is GAP-1789: the
// GAP-1685 fixture, where the hook path allows the account but a sandbox
// run, which decides on any path, is still refused. Explain shows the hook
// decision and names the sandbox refusal, in the cache view as well; the
// sandbox decision itself does not change.
func TestExplainNamesTheSandboxRefusalTheHookDoesNotMake(t *testing.T) {
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
	verified := profileSubjectFromVerified(VerifiedSubject{
		UserID: "49201", IDKind: useridentity.KindPOSIXUID, UserName: "fcb3r3num", Directory: cached,
	}, true)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "codex"
	cfg.Codex.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"watch": {Mode: "observe"}, "numeric": {Mode: "observe"}}
	cfg.Guardrail.DefaultProfile = "watch"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "numeric", Match: config.ProfileMatch{Groups: []string{"49202"}}},
	}
	set := newGuardrailProfileSetFor(t, cfg)
	resolved := resolveIdentity(&verified, nil)
	if hook := set.selectProfile(&verified, resolved, profileSubjectVerified, "codex", nil, profilePathHook, ""); hook.Refused != "" {
		t.Fatalf("fixture: hook decision %+v; want allowed", hook)
	}
	sandbox := set.matchResolved(&verified, resolved, profileSubjectVerified, "codex", nil, profilePathAny, "")
	if sandbox.Refused == "" {
		t.Fatalf("fixture: sandbox decision %+v; want the pathless refusal", sandbox)
	}
	decision := set.match(&explained, profileSubjectLookup, "codex", "")
	view, _ := explainCacheView(set, &explained, decision, "codex", "", now)
	if view == nil {
		t.Fatal("no cache view")
	}
	if view["refused"] != false {
		t.Fatalf("cache view %v; want the hook decision (not refused)", view)
	}
	if view["sandbox_refused"] != true || !strings.Contains(explainViewString(view["sandbox_refused_reason"]), "unconfirmed") {
		t.Fatalf("cache view %v; want the sandbox refusal named with its reason", view)
	}
}

func explainViewString(v any) string {
	s, _ := v.(string)
	return s
}

// TestExplainHandlerNamesTheSandboxRefusal is GAP-1868 (review of GAP-1789):
// the profile-explain answer itself, not only its cache view, keeps the hook
// decision (not refused) and names the pathless refusal a sandbox run makes:
// refused_paths ["sandbox"], sandbox_refused_reason and a warning.
func TestExplainHandlerNamesTheSandboxRefusal(t *testing.T) {
	previousBlocking := identityLookupBlocking.Load()
	setIdentityLookupBlocking(true)
	t.Cleanup(func() { setIdentityLookupBlocking(previousBlocking) })
	now := time.Now()
	cached := useridentity.DirectoryFacts{
		Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal,
		Groups: []string{"49202"}, UnconfirmedGroups: []string{"49202"},
		Assurance: useridentity.AssuranceVerified, ResolvedAt: now.Add(-6 * time.Second),
	}
	prevFacts, prevRefresh, prevLookup := cachedDirectoryFacts, cachedDirectoryRefreshFailure, profileExplainSubjectLookup
	t.Cleanup(func() {
		cachedDirectoryFacts, cachedDirectoryRefreshFailure, profileExplainSubjectLookup = prevFacts, prevRefresh, prevLookup
		liveGuardrailProfiles.Store(nil)
	})
	cachedDirectoryFacts = func(string) (useridentity.DirectoryFacts, time.Time, bool) { return cached, cached.ResolvedAt, true }
	cachedDirectoryRefreshFailure = func(string) (time.Time, string, bool) { return time.Time{}, "", false }
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "49201", IDKind: useridentity.KindPOSIXUID, UserName: "fcb3r3num", Directory: cached,
	}, true)
	profileExplainSubjectLookup = func(string) (profileSubject, error) { return subject, nil }
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "codex"
	cfg.Codex.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"watch": {Mode: "observe"}, "numeric": {Mode: "observe"}}
	cfg.Guardrail.DefaultProfile = "watch"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "numeric", Match: config.ProfileMatch{Groups: []string{"49202"}}},
	}
	liveGuardrailProfiles.Store(nil)
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user=49201&connector=codex", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(rec, req)
	var out struct {
		Refused       bool     `json:"refused"`
		RefusedPaths  []string `json:"refused_paths"`
		SandboxReason string   `json:"sandbox_refused_reason"`
		Warnings      []string `json:"warnings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	if out.Refused || len(out.RefusedPaths) != 1 || out.RefusedPaths[0] != "sandbox" || !strings.Contains(out.SandboxReason, "unconfirmed") {
		t.Fatalf("explain = %s; want the hook decision with the sandbox refusal named", rec.Body.String())
	}
	if !strings.Contains(strings.Join(out.Warnings, "\n"), out.SandboxReason) && !strings.Contains(strings.Join(out.Warnings, "\n"), "sandbox") {
		t.Fatalf("explain warnings %q name no sandbox refusal", out.Warnings)
	}
}
