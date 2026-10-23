// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0500: on RHEL the managed gateway, a service account, cannot run the
// root-only SSSD checks, so explain of a fresh local account stopped at
// default_lookup_failed. profile-explain now resolves the account as its
// caller, root, through NSS, and the gateway explains those facts; its own
// lookup is the fallback.
func TestProfileExplainUsesTheCallersNSSFacts(t *testing.T) {
	facts := useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal,
		Groups: []string{"49202", "t6-numeric"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}
	raw, err := EncodeProfileExplainCallerFacts(ProfileExplainCallerFacts{UID: 49201, Name: "t6b4r2num", Facts: facts})
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"t6b4r2num", "49201"} {
		subject, ok := profileExplainCallerSubject(raw, user)
		if !ok || subject.UserID != "49201" || subject.LookupFailed || len(subject.Groups) != 2 {
			t.Fatalf("user %s: subject %+v, %v; want uid 49201 with its groups", user, subject, ok)
		}
	}
	for _, tc := range []struct{ raw, user string }{{raw, "someone-else"}, {raw, "49202"}, {"not-base64!", "49201"}, {"", "49201"}} {
		if _, ok := profileExplainCallerSubject(tc.raw, tc.user); ok {
			t.Fatalf("caller facts %q for %q were taken", tc.raw, tc.user)
		}
	}

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"numeric": {Mode: "observe"}, "strict": {Mode: "action", BlockAt: "LOW"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "numeric", Match: config.ProfileMatch{Groups: []string{"t6-numeric"}}}}
	cfg.Guardrail.DefaultProfile = "strict"
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	previous := profileExplainSubjectLookup
	t.Cleanup(func() { profileExplainSubjectLookup = previous })
	profileExplainSubjectLookup = func(name string) (profileSubject, error) {
		return profileSubject{UserName: name, LookupFailed: true},
			errors.New("sssctl domain-list failed (it needs root)")
	}
	explain := func(query url.Values) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?"+query.Encode(), nil)
		req.RemoteAddr = "127.0.0.1:40000"
		rec := httptest.NewRecorder()
		api.handleGuardrailProfileResolve(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("explain answered %d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	out := explain(url.Values{"user": {"t6b4r2num"}, "connector": {"codex"}, "caller_facts": {raw}})
	if out["profile"] != "numeric" || out["match"] != profileMatchGroup || out["facts_source"] != "caller" {
		t.Fatalf("explain with the caller's facts: %v; want numeric by group", out)
	}
	out = explain(url.Values{"user": {"t6b4r2num"}, "connector": {"codex"}})
	if out["profile"] != "strict" || out["facts_source"] != nil {
		t.Fatalf("explain without them (the gateway's lookup): %v; want the strict default", out)
	}
}
