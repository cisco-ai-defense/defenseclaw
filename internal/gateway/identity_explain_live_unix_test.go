// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0663: a managed explain and a hook must select from the same live
// directory facts. The administrator's caller facts can omit fields that
// DirectoryFacts does not expose in JSON, including the confirmed flat
// account domain; they are useful only when the gateway lookup fails.
func TestGAP0663ProfileExplainUsesLiveHookFactsForAssignmentForms(t *testing.T) {
	managedExplainView(t)
	previousFacts := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previousFacts) })
	previousLookup := profileExplainSubjectLookup
	t.Cleanup(func() { profileExplainSubjectLookup = previousLookup })
	previousProfiles := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previousProfiles) })

	const uid = "49201"
	const name = "alice@dclab.test"
	facts := useridentity.DirectoryFacts{
		Source: useridentity.SourceSSSD, Directory: useridentity.DirectoryActiveDirectory,
		Domain: "dclab.test", AccountDomain: "DCLAB", Realm: "DCLAB.TEST",
		UPN: name, Principal: name, Assurance: useridentity.AssuranceVerified,
		Groups: []string{"engineering"}, ResolvedAt: time.Now(),
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: uid, IDKind: useridentity.KindPOSIXUID, UserName: name, Directory: facts,
	}, true)
	localFacts := useridentity.DirectoryFacts{
		Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal,
		Groups: []string{"users"}, ResolvedAt: time.Now(),
	}
	localSubject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "49202", IDKind: useridentity.KindPOSIXUID, UserName: "alice", Directory: localFacts,
	}, true)
	otherFacts := useridentity.DirectoryFacts{
		Source: useridentity.SourceSSSD, Directory: useridentity.DirectoryActiveDirectory,
		Domain: "other.test", AccountDomain: "OTHER", UPN: "alice@other.test",
		Groups: []string{"engineering"}, ResolvedAt: time.Now(),
	}
	otherSubject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "49203", IDKind: useridentity.KindPOSIXUID, UserName: "alice@other.test", Directory: otherFacts,
	}, true)

	for _, tc := range []struct {
		name, user, assignment string
		uid                    int
		live                   profileSubject
		callerFacts            useridentity.DirectoryFacts
	}{
		{"flat domain", name, `DCLAB\alice`, 49201, subject, facts},
		{"UPN", name, name, 49201, subject, facts},
		{"uid", uid, uid, 49201, subject, facts},
		{"local namesake", "alice", `DCLAB\alice`, 49202, localSubject, localFacts},
		{"other domain", "alice@other.test", `DCLAB\alice`, 49203, otherSubject, otherFacts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
				"e3-open": {Mode: "observe"}, "e3-strict": {Mode: "action"},
			}
			cfg.Guardrail.DefaultProfile = "e3-strict"
			cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{
				Profile: "e3-open", Match: config.ProfileMatch{Users: []string{tc.assignment}},
			}}
			api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
			t.Cleanup(func() { api.setGuardrailProfiles(nil) })
			profileExplainSubjectLookup = func(string) (profileSubject, error) { return tc.live, nil }
			hook := api.guardrailProfileSet().match(&tc.live, profileSubjectVerified, "claudecode", "")
			if tc.name == "flat domain" && (hook.Name != "e3-open" || hook.Match != profileMatchUser) {
				t.Fatalf("fixture: live hook decision = %+v", hook)
			}
			if (tc.name == "local namesake" || tc.name == "other domain") && hook.Name != "e3-strict" {
				t.Fatalf("fixture: unrelated account decision = %+v", hook)
			}
			callerName := tc.user
			if tc.user == uid {
				callerName = name
			}
			raw, err := EncodeProfileExplainCallerFacts(ProfileExplainCallerFacts{
				UID: tc.uid, Name: callerName, Facts: tc.callerFacts,
			})
			if err != nil {
				t.Fatal(err)
			}
			query := url.Values{"user": {tc.user}, "connector": {"claudecode"}, "caller_facts": {raw}}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?"+query.Encode(), nil)
			req.RemoteAddr = "127.0.0.1:40000"
			rec := httptest.NewRecorder()
			api.handleGuardrailProfileResolve(rec, req)
			var out struct {
				Profile     string `json:"profile"`
				Match       string `json:"match"`
				Assignment  int    `json:"assignment"`
				FactsSource string `json:"facts_source"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
				t.Fatalf("explain status %d, decode %v: %s", rec.Code, err, rec.Body.String())
			}
			if out.Profile != hook.Name || out.Match != hook.Match || out.Assignment != hook.Assignment || out.FactsSource == "caller" {
				t.Fatalf("explain = %+v, hook = %+v; want the live resolver's decision", out, hook)
			}
		})
	}
}
