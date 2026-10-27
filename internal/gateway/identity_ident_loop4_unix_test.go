// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// Review of GAP-0947 (loop 4): a SID showed continuity with the account an
// older build saw whenever uid - 200000 matched its RID modulo the range
// size, so an RFC 2307 uid 201105 with RID 1105 (ldap_id_mapping off) was
// taken for an id-mapped one, and an account that replaced the former
// holder kept its agent IDs. Only the uid of the SID's own slice counts:
// SSSD picks it with murmurhash3 of the domain SID.
func TestLegacyContinuityNeedsTheUIDOfTheSIDsOwnSlice(t *testing.T) {
	if got := murmurHash3x86_32(nil, 0); got != 0 {
		t.Fatalf("murmurhash3 of nothing = %d", got)
	}
	if got := murmurHash3x86_32([]byte("hello"), 0); got != 613153351 {
		t.Fatalf("murmurhash3(hello) = %d, want 613153351", got)
	}
	for _, tc := range []struct {
		name  string
		uid   int
		token string
		want  bool
	}{
		// dc-ent-rhel: dcad-r103-eng1@dclab.test is uid 94404135, RID 4135.
		{"an id-mapped account of the lab domain", 94404135, "sid:S-1-5-21-602989718-809138714-1982218064-4135", true},
		{"an id-mapped account (slice 1488)", 297801105, "sid:S-1-5-21-7-7-7-1105", true},
		{"RFC 2307 uid matching the RID modulo the range", 201105, "sid:S-1-5-21-7-7-7-1105", false},
		{"another slice's uid of the RID", 1234801105, "sid:S-1-5-21-7-7-7-1105", false},
		{"a RID past the primary slice", 200000 + 1488*200000 + 199999 + 1, "sid:S-1-5-21-7-7-7-200000", false},
		{"not a domain account SID", 201105, "sid:S-1-5-32-1105", false},
		{"no RID", 201105, "sid:S", false},
		{"a local account", 1001, "files", true},
		{"an SSSD account without a SID", 41501, "sss", true},
		{"a macOS record", 501, "record:ABC", false},
		{"a home newer than the older build's sighting (GAP-2086)", 1001, "files|home:3000:1793052449571507240", false},
	} {
		if got := legacyContinuity(tc.uid, tc.token); got != tc.want {
			t.Errorf("%s: legacyContinuity(%d, %q) = %v, want %v", tc.name, tc.uid, tc.token, got, tc.want)
		}
	}
}

// Review of GAP-1087 (loop 4): explain refused a bare name only for an
// ambiguous name or unknown namesakes. A uid that two accounts hold (the
// hook path gives it no facts) and an NSS answer for another account fell
// back to the OS account database, which named a local account of the name,
// and explain printed its profile. Both now refuse the name, and the
// fallback takes an account only when NSS shows it is the local account
// that holds its uid, alone.
func TestProfileExplainRefusesAnAccountItsLookupRefused(t *testing.T) {
	prevAccount, prevCached, prevLocal := profileExplainAccount, profileExplainCachedSubject, profileExplainLocalAccount
	prevBlocking := identityLookupBlocking.Load()
	t.Cleanup(func() {
		profileExplainAccount, profileExplainCachedSubject, profileExplainLocalAccount = prevAccount, prevCached, prevLocal
		setIdentityLookupBlocking(prevBlocking)
		liveGuardrailProfiles.Store(nil)
	})
	profileExplainCachedSubject = func(string, time.Time) (profileSubject, error) { return profileSubject{}, errNoCachedHolder }
	setIdentityLookupBlocking(true)

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"root-team": {Mode: "action", BlockAt: "CRITICAL"},
		"floor":     {Mode: "action", BlockAt: "MEDIUM"},
	}
	// root is uid 0 in every Unix account database os/user reads.
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "root-team", Match: config.ProfileMatch{Users: []string{"0"}}}}
	cfg.Guardrail.DefaultProfile = "floor"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	api.setGuardrailProfiles(set)
	type answer struct {
		Profile     string `json:"profile"`
		Match       string `json:"match"`
		LookupError string `json:"lookup_error"`
		Subject     struct {
			UserID string `json:"user_id"`
		} `json:"subject"`
	}
	explain := func(user string) answer {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?connector=codex&user="+url.QueryEscape(user), nil)
		req.RemoteAddr = "127.0.0.1:40000"
		rec := httptest.NewRecorder()
		api.handleGuardrailProfileResolve(rec, req)
		var out answer
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("explain %s: %v: %s", user, err, rec.Body.String())
		}
		return out
	}
	refused := func(t *testing.T, got answer, reason string) {
		t.Helper()
		if got.Subject.UserID != "" || got.Profile != "floor" || got.Match != profileMatchDefaultLookupFailed ||
			!strings.Contains(got.LookupError, reason) {
			t.Fatalf("explain = %+v; want root refused (%q) with default_lookup_failed", got, reason)
		}
	}
	proven := 0
	profileExplainLocalAccount = func(uid int, name string) error {
		proven++
		if uid != 0 || name != "root" {
			return errors.New("not the account asked")
		}
		return nil
	}

	profileExplainAccount = func(string) (string, string, error) {
		return "", "", &unixidentity.SharedUIDError{UID: 0, Accounts: []string{"root (files)", "root (sss)"}}
	}
	refused(t, explain("root"), "more than one account")

	profileExplainAccount = func(name string) (string, string, error) {
		return "", "", &unixidentity.NameMismatchError{Key: name, Answered: unixidentity.Account{Name: "root@other.example", UID: 0}}
	}
	refused(t, explain("root"), "not confirmed to be the same account")
	if proven != 0 {
		t.Fatalf("a refused lookup asked for the local account %d times", proven)
	}

	// Any other failure: the local account os/user names is taken only
	// when NSS shows it holds its uid alone.
	profileExplainAccount = func(string) (string, string, error) { return "", "", errors.New("getent timed out") }
	profileExplainLocalAccount = func(int, string) error { return errors.New("nslcd did not complete the search") }
	refused(t, explain("root"), "getent timed out")
	profileExplainLocalAccount = func(int, string) error { return nil }
	if got := explain("root"); got.Subject.UserID != "0" || got.Profile != "root-team" || got.Match != profileMatchUser {
		t.Fatalf("explain of a proven local account = %+v; want root-team by user", got)
	}
}
