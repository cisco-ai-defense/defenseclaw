// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/user"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// gatewayOwnerOfThisBuild is the production profileExplainGatewayOwner.
// The package's explain tests model the administrator view of a managed
// gateway with made-up accounts, so the package default is that view; the
// tests below put the per-user rule back.
var gatewayOwnerOfThisBuild = profileExplainGatewayOwner

func init() { profileExplainGatewayOwner = func() (string, bool) { return "", false } }

func explainAs(t *testing.T, owner string, perUser bool, subject profileSubject, user string) (int, map[string]any) {
	t.Helper()
	stubProfileSources(t)
	prevLookup, prevOwner := profileExplainSubjectLookup, profileExplainGatewayOwner
	t.Cleanup(func() { profileExplainSubjectLookup, profileExplainGatewayOwner = prevLookup, prevOwner })
	profileExplainSubjectLookup = func(string) (profileSubject, error) { return subject, nil }
	profileExplainGatewayOwner = func() (string, bool) { return owner, perUser }
	cfg := profileSecurityConfig()
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user="+url.QueryEscape(user)+"&connector=codex", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	return rec.Code, out
}

// rel-1-0-6:GAP-0328: a per-user gateway explains only the account it runs
// as. Another account (by name or uid) is answered as an account the lookup
// cannot name: lookup_error, no user id, no groups, so the CLI exits 1 as on
// Linux, and none of the account's facts or its profile leave the gateway.
// The own account still resolves (GAP-0269), and a managed gateway's
// administrator view still explains every account.
func TestPerUserProfileExplainRefusesAnotherAccount(t *testing.T) {
	other := profileSubject{UserID: "517", IDKind: useridentity.KindPOSIXUID, UserName: "dcm-other", Groups: []string{"staff", "dcm-secret-group"}}
	for _, user := range []string{"dcm-other", "517"} {
		code, out := explainAs(t, "511", true, other, user)
		subject, _ := out["subject"].(map[string]any)
		if code != http.StatusOK || !strings.Contains(out["lookup_error"].(string), "only your own account") ||
			subject["user_id"] != "" || subject["group_count"] != float64(0) || subject["user_name"] != user {
			t.Fatalf("--user %s on another account's per-user gateway: HTTP %d %v", user, code, out)
		}
		body, _ := json.Marshal(out)
		leaks := []string{"dcm-secret-group"}
		if user == "dcm-other" {
			leaks = append(leaks, "517")
		} else {
			leaks = append(leaks, "dcm-other")
		}
		for _, fact := range leaks {
			if strings.Contains(string(body), fact) {
				t.Errorf("--user %s: the answer carries %s: %s", user, fact, body)
			}
		}
	}
	own := profileSubject{UserID: "511", IDKind: useridentity.KindPOSIXUID, UserName: "dcm-own", Groups: []string{"staff"}}
	for _, user := range []string{"dcm-own", "511"} {
		_, out := explainAs(t, "511", true, own, user)
		subject, _ := out["subject"].(map[string]any)
		if out["lookup_error"] != nil || subject["user_id"] != "511" {
			t.Fatalf("own account --user %s: %v", user, out)
		}
	}
	// A per-user gateway that cannot name its own account explains none.
	if _, out := explainAs(t, "", true, own, "dcm-own"); out["lookup_error"] == nil {
		t.Fatalf("no gateway owner: %v", out)
	}
	// The managed administrator view explains every account.
	if _, out := explainAs(t, "", false, other, "dcm-other"); out["lookup_error"] != nil {
		t.Fatalf("managed administrator view: %v", out)
	}
}

// The production owner is the per-user gateway's process account, and a
// managed gateway has none.
func TestProfileExplainGatewayOwnerIsTheProcessAccount(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	prev := managedServiceHosted.Load()
	t.Cleanup(func() { setManagedServiceHosted(prev) })
	setManagedServiceHosted(false)
	if id, perUser := gatewayOwnerOfThisBuild(); !perUser || id != sanitizeLLMEventUser(current.Uid) {
		t.Fatalf("per-user owner %q, %v; want %q", id, perUser, current.Uid)
	}
	setManagedServiceHosted(true)
	if _, perUser := gatewayOwnerOfThisBuild(); perUser {
		t.Fatal("a managed gateway reported a per-user owner")
	}
	_ = config.Config{}
}
