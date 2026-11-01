// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0431, GAP-0422: a standard user of a managed computer reads their own
// guardrail profile on the hook socket. The subject is the kernel-verified
// caller; another account, or administrator caller_facts, are not taken,
// and the answer leaves out the other profiles (users see only their own).
func TestOwnProfileExplainAnswersOnlyTheCaller(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"engineering": {Mode: "observe"}, "strict": {Mode: "action", BlockAt: "LOW"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{"engineering"}}}}
	cfg.Guardrail.DefaultProfile = "strict"
	live := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(live) })
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	previous := profileExplainSubjectLookup
	t.Cleanup(func() { profileExplainSubjectLookup = previous })
	var looked []string
	profileExplainSubjectLookup = func(name string) (profileSubject, error) {
		looked = append(looked, name)
		return profileSubjectFromVerified(VerifiedSubject{UserID: name, IDKind: useridentity.KindPOSIXUID, UserName: "alice",
			Directory: useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal,
				Groups: []string{"engineering"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}}, false), nil
	}
	explain := func(query string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, managed.OwnProfileExplainPath+query, nil)
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{UID: 5001, Name: "alice"}))
		rec := httptest.NewRecorder()
		api.handleOwnProfileExplain(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("explain answered %d %s", rec.Code, rec.Body.String())
		}
		return rec.Code, out
	}
	for _, query := range []string{"?connector=codex", "?user=alice&connector=codex", "?user=5001&connector=codex&caller_facts=forged"} {
		code, out := explain(query)
		subject, _ := out["subject"].(map[string]any)
		if code != http.StatusOK || out["own"] != true || out["profile"] != "engineering" || subject["user_id"] != "5001" ||
			out["profiles"] != nil || out["facts_source"] != nil {
			t.Fatalf("own explain %s = %d %v; want the caller's engineering profile and no other profiles", query, code, out)
		}
	}
	looked = nil
	if code, out := explain("?user=bob&connector=codex"); code != http.StatusForbidden || out["error"] != "own_profile_only" || out["profile"] != nil {
		t.Fatalf("explain of another account = %d %v; want own_profile_only", code, out)
	}
	if slices.Contains(looked, "bob") || len(looked) != 0 {
		t.Fatalf("the refused explain looked up %v", looked)
	}
	req := httptest.NewRequest(http.MethodGet, managed.OwnProfileExplainPath, nil)
	rec := httptest.NewRecorder()
	api.handleOwnProfileExplain(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("explain without a verified peer = %d; want 403", rec.Code)
	}
}
