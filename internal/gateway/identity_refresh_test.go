// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// identityRefreshTestAPI is a standalone managed gateway that serves
// contractors to dc-sbx-contractors and engineering to dc-sbx-devs, with the
// memo hook calls use.
func identityRefreshTestAPI(t *testing.T) (*APIServer, *guardrailProfileSet) {
	t.Helper()
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"contractors": {Mode: "action"}, "engineering": {Mode: "observe"}}
	if !cfg.StandaloneEnterprise() {
		t.Skip("standalone profile name changed")
	}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	set := &guardrailProfileSet{base: cfg, profiles: map[string]config.DerivedGuardrailProfile{
		"contractors": {Digest: "c"}, "engineering": {Digest: "e"}},
		assignments: []config.ProfileAssignment{
			{Profile: "contractors", Match: config.ProfileMatch{Groups: []string{"dc-sbx-contractors"}}},
			{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{"dc-sbx-devs"}}},
		},
		matches: newProfileMatchCache(), provenProfiles: &provenProfileStore{}}
	api.setGuardrailProfiles(set)
	t.Cleanup(func() { api.setGuardrailProfiles(nil) })
	return api, set
}

func identityRefreshCall(t *testing.T, api *APIServer, body string) (int, identityRefreshAnswer, map[string]string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, identityRefreshPath, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:40000"
	response := httptest.NewRecorder()
	api.handleIdentityRefresh(response, req)
	var answer identityRefreshAnswer
	var refusal map[string]string
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &answer); err != nil {
			t.Fatalf("answer %s: %v", response.Body.String(), err)
		}
	} else if err := json.Unmarshal(response.Body.Bytes(), &refusal); err != nil {
		t.Fatalf("refusal %s: %v", response.Body.String(), err)
	}
	return response.Code, answer, refusal
}

// hookProfileOf is the profile the next hook call of id gets: the facts the
// hook path reads (get, blocking) decided as a verified request.
func hookProfileOf(t *testing.T, set *guardrailProfileSet, cache *identityDirectoryCache, id, name string) string {
	t.Helper()
	facts, ok := cache.get(id, true)
	if !ok {
		t.Fatalf("the hook cache serves no facts of %s", id)
	}
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: id, IDKind: useridentity.KindForID(id), UserName: name, Directory: facts}, false)
	return set.match(&subject, profileSubjectVerified, "", "").Name
}

func identityRefreshTestCache(t *testing.T, groups *[]string) (*identityDirectoryCache, *time.Time) {
	t.Helper()
	clock := time.Now().Add(-5 * time.Minute)
	cache := newIdentityCache(func(string) (useridentity.DirectoryFacts, error) {
		return useridentity.DirectoryFacts{Groups: append([]string(nil), (*groups)...), ResolvedAt: clock}, nil
	})
	cache.now = func() time.Time { return clock }
	saved := identityRefreshAccounts
	identityRefreshAccounts = cache.accounts
	t.Cleanup(func() { identityRefreshAccounts = saved })
	return cache, &clock
}

// The refresh re-reads every cached account, lists the one whose
// group changed with its old and new profile, and the next hook call of that
// account gets the new profile, inside the 15-minute TTL of its old facts.
func TestIdentityRefreshAppliesAGroupChangeToTheNextHookCall(t *testing.T) {
	groups := []string{"dc-sbx-devs"}
	cache, clock := identityRefreshTestCache(t, &groups)
	api, set := identityRefreshTestAPI(t)
	if _, ok := cache.get("1201", true); !ok {
		t.Fatal("seeding the cache failed")
	}
	explainProfileFromCache(t, cache, "1201", "eng2")
	if got := hookProfileOf(t, set, cache, "1201", "eng2"); got != "engineering" {
		t.Fatalf("hook profile before the change = %q, want engineering", got)
	}
	if set.matches.forgetUser("") != 0 {
		t.Fatal("forgetUser of no account dropped decisions")
	}
	// eng2 leaves dc-sbx-devs and joins dc-sbx-contractors; the cached facts
	// are 0 minutes old, so without the refresh hooks keep engineering.
	groups = []string{"dc-sbx-contractors"}
	*clock = time.Now()
	if got := hookProfileOf(t, set, cache, "1201", "eng2"); got != "engineering" {
		t.Fatalf("hook profile inside the TTL = %q, want the cached engineering", got)
	}
	status, answer, refusal := identityRefreshCall(t, api, `{}`)
	if status != http.StatusOK {
		t.Fatalf("refresh status %d %v", status, refusal)
	}
	if answer.Scope != "all" || answer.Refreshed != 1 || answer.Changed != 1 || answer.Failed != 0 || len(answer.Changes) != 1 {
		t.Fatalf("answer %+v: want one refreshed and changed account", answer)
	}
	change := answer.Changes[0]
	if change.UserID != "1201" || change.UserName != "eng2" || change.PreviousProfile != "engineering" || change.Profile != "contractors" ||
		change.Match != profileMatchGroup || change.Connector != "" {
		t.Fatalf("change %+v: want eng2 engineering -> contractors by group", change)
	}
	for _, entry := range set.matches.entries {
		if entry.userID == "1201" {
			t.Fatal("the memoised decisions of the changed account were kept")
		}
	}
	if got := hookProfileOf(t, set, cache, "1201", "eng2"); got != "contractors" {
		t.Fatalf("hook profile after the refresh = %q, want contractors", got)
	}
	// A second run finds nothing new.
	*clock = time.Now().Add(10 * time.Second)
	if _, again, _ := identityRefreshCall(t, api, `{"user":"1201"}`); again.Scope != "user" || again.Changed != 0 || again.Refreshed != 1 {
		t.Fatalf("second refresh %+v: want one account re-read and no change", again)
	}
}

// An account the refresh is told about but the cache held nothing for gets
// its facts at its first hook call: it is re-read and reported as no change.
func TestIdentityRefreshOfAnUncachedAccountIsNoChange(t *testing.T) {
	groups := []string{"dc-sbx-contractors"}
	cache, _ := identityRefreshTestCache(t, &groups)
	api, _ := identityRefreshTestAPI(t)
	explainProfileFromCache(t, cache, "1305", "eng5")
	_, answer, refusal := identityRefreshCall(t, api, `{"user":"1305"}`)
	if refusal != nil || answer.Refreshed != 1 || answer.Changed != 0 {
		t.Fatalf("answer %+v %v", answer, refusal)
	}
}

func TestIdentityRefreshRefusals(t *testing.T) {
	groups := []string{"dc-sbx-devs"}
	identityRefreshTestCache(t, &groups)
	api, _ := identityRefreshTestAPI(t)
	for _, tc := range []struct{ name, body, code string }{
		{"name instead of an id", `{"user":"eng2"}`, "invalid_arguments"},
		{"unknown member", `{"principal":"eng2"}`, "invalid_arguments"},
		{"max_users over the cap", `{"max_users":5000}`, "invalid_arguments"},
	} {
		if status, _, refusal := identityRefreshCall(t, api, tc.body); status != http.StatusBadRequest || refusal["code"] != tc.code {
			t.Fatalf("%s: status %d %v", tc.name, status, refusal)
		}
	}
	get := httptest.NewRequest(http.MethodGet, identityRefreshPath, nil)
	get.RemoteAddr = "127.0.0.1:40000"
	response := httptest.NewRecorder()
	api.handleIdentityRefresh(response, get)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", response.Code)
	}
	remote := httptest.NewRequest(http.MethodPost, identityRefreshPath, strings.NewReader(`{}`))
	remote.RemoteAddr = "192.0.2.10:40000"
	response = httptest.NewRecorder()
	api.handleIdentityRefresh(response, remote)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-loopback: %d", response.Code)
	}
	identityRefreshRunning.Store(true)
	status, _, refusal := identityRefreshCall(t, api, `{}`)
	identityRefreshRunning.Store(false)
	if status != http.StatusConflict || refusal["code"] != "refresh_busy" {
		t.Fatalf("busy: %d %v", status, refusal)
	}
	// A per-user (OSS) gateway has no such verb.
	oss := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, &config.Config{})
	if status, _, refusal := identityRefreshCall(t, oss, `{}`); status != http.StatusNotFound || refusal["code"] != "not_managed" {
		t.Fatalf("per-user gateway: %d %v", status, refusal)
	}
}

// The audit row (and the telemetry built from it) carries counts only: no
// account name and no uid or SID.
func TestIdentityRefreshAuditRowCarriesCountsOnly(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	api := &APIServer{logger: logger}
	answer := identityRefreshAnswer{Scope: "all", Refreshed: 2, Changed: 1, Failed: 1, DurationMS: 7,
		Changes:                   []identityRefreshChange{{UserID: "1916801105", UserName: "eng2@corp.example.com", PreviousProfile: "engineering", Profile: "contractors"}},
		Failures:                  []identityRefreshFailure{{UserID: "1916801106", UserName: "eng3@corp.example.com", Code: identityRefreshLookupFailed}},
		WindowsTokenGroupsPending: []identityRefreshAccount{{UserID: "S-1-5-21-1-2-3-1105", UserName: "CORP-eng4"}}}
	api.auditIdentityRefresh(answer, identityRefreshRequest{OSCacheFlushed: "all"})
	events, err := fixture.store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, ev := range events {
		if ev.Action != string(audit.ActionIdentityRefreshCompleted) {
			continue
		}
		rows++
		row := ev.Target + " " + ev.Details
		for _, leak := range []string{"eng2", "eng3", "eng4", "1916801105", "1916801106", "S-1-5-21", "engineering", "contractors"} {
			if strings.Contains(row, leak) {
				t.Fatalf("audit row names %q: %q", leak, row)
			}
		}
		if !strings.Contains(ev.Details, "refreshed=2 changed=1 failed=1") || !strings.Contains(ev.Details, "token_groups_pending=1") ||
			!strings.Contains(ev.Details, "os_cache_flushed=all") {
			t.Fatalf("audit row details %q: want the counts", ev.Details)
		}
	}
	if rows != 1 {
		t.Fatalf("%d identity-refresh-completed rows, want 1", rows)
	}
}

// Windows: an account whose groups come from its sign-in token is listed as
// pending its next sign-in.
func TestIdentityRefreshListsTokenGroupsPending(t *testing.T) {
	groups := []string{"dc-sbx-devs"}
	cache, _ := identityRefreshTestCache(t, &groups)
	api, _ := identityRefreshTestAPI(t)
	saved := identityRefreshTokenGroupsPending
	identityRefreshTokenGroupsPending = func(useridentity.DirectoryFacts) bool { return true }
	t.Cleanup(func() { identityRefreshTokenGroupsPending = saved })
	explainProfileFromCache(t, cache, "1201", "eng2")
	_, answer, _ := identityRefreshCall(t, api, `{"user":"1201"}`)
	if len(answer.WindowsTokenGroupsPending) != 1 || answer.WindowsTokenGroupsPending[0].UserID != "1201" {
		t.Fatalf("pending %+v", answer.WindowsTokenGroupsPending)
	}
}

func TestProfileMatchCacheForgetUser(t *testing.T) {
	c := newProfileMatchCache()
	c.put([32]byte{1}, "1201", profileDecision{Name: "a"})
	c.put([32]byte{2}, "1202", profileDecision{Name: "b"})
	c.put([32]byte{3}, "1201", profileDecision{Name: "c"})
	if dropped := c.forgetUser("1201"); dropped != 2 {
		t.Fatalf("dropped %d, want 2", dropped)
	}
	if _, ok := c.get([32]byte{2}); !ok {
		t.Fatal("another account lost its decision")
	}
	if _, ok := c.get([32]byte{1}); ok {
		t.Fatal("the account kept a decision")
	}
	var none *profileMatchCache
	if none.forgetUser("1201") != 0 {
		t.Fatal("nil cache")
	}
}
