//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// outageAccounts is an SSSD-backed account database whose responder can be
// stopped: it then names no account at all.
type outageAccounts struct {
	unixidentity.Resolver
	down     *atomic.Bool
	accounts map[int]unixidentity.Account
}

var errOutageResponder = errors.New("sssd: the NSS responder is not running")

func (r outageAccounts) LookupUID(uid int) (unixidentity.Account, error) {
	if r.down.Load() {
		return unixidentity.Account{}, errOutageResponder
	}
	if account, ok := r.accounts[uid]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

// GAP-0529: an administrator explained eng1 before a directory outage, and no
// hook of eng1 had run yet. During the outage (SSSD stopped) eng1's hooks
// kept the cached facts and the engineering profile, while explain by name
// reported offline-floor with default_lookup_failed: the live decision was
// looser than the one explain showed. Explain, the hooks and the hour the
// facts are kept now agree; an account with no cached facts gets the
// provisional default from both, and so do both once the hour is over.
func TestProfileExplainDuringOutageAgreesWithTheHooksOfAnExplainedAccount(t *testing.T) {
	const engUID, eng2UID = 94404116, 94404117
	eng := unixidentity.Account{Name: "dcad-r102-eng1@dclab.test", UID: engUID, Home: "/home/dcad-r102-eng1@dclab.test"}
	eng2 := unixidentity.Account{Name: "dcad-r102-eng2@dclab.test", UID: eng2UID, Home: "/home/dcad-r102-eng2@dclab.test"}
	accounts := map[int]unixidentity.Account{engUID: eng, eng2UID: eng2}
	var down atomic.Bool
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }

	prevHomes, prevAccount := managedHookPeerHomes, profileExplainAccount
	prevFacts, prevBlocking := identityFactsEnabled.Load(), identityLookupBlocking.Load()
	t.Cleanup(func() {
		managedHookPeerHomes, profileExplainAccount = prevHomes, prevAccount
		setIdentityFactsEnabled(prevFacts)
		setIdentityLookupBlocking(prevBlocking)
		liveGuardrailProfiles.Store(nil)
	})
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return outageAccounts{down: &down, accounts: accounts} },
		now:         time.Now,
	}
	managedHookPeerHomes.directoriesOnce.Do(func() {
		cache := newIdentityDirectoryCache(func(key string) (useridentity.DirectoryFacts, error) {
			if down.Load() {
				return useridentity.DirectoryFacts{}, errOutageResponder
			}
			uid, _ := strconv.Atoi(key)
			name := accounts[uid].Name
			return useridentity.DirectoryFacts{
				Source: useridentity.SourceSSSD, Directory: useridentity.DirectoryActiveDirectory, Domain: "dclab.test",
				Principal: name, UPN: name, Groups: []string{"dc-r102-devs@dclab.test"}, ResolvedAt: now(),
			}, nil
		})
		cache.logf = nil
		cache.now = now
		managedHookPeerHomes.directories = cache
	})
	// Explain names an account through NSS, which names no directory
	// account while SSSD is stopped.
	profileExplainAccount = func(name string) (string, string, error) {
		if down.Load() {
			return "", "", unixidentity.ErrNotFound
		}
		for uid, account := range accounts {
			if useridentity.EqualFold(account.Name, name) || strconv.Itoa(uid) == name {
				return strconv.Itoa(uid), account.Name, nil
			}
		}
		return "", "", unixidentity.ErrNotFound
	}
	setIdentityFactsEnabled(true)
	setIdentityLookupBlocking(true)

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"engineering":   {Mode: "action", BlockAt: "CRITICAL"},
		"offline-floor": {Mode: "action", BlockAt: "MEDIUM"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "engineering", Match: config.ProfileMatch{Users: []string{eng.Name, eng2.Name}}},
	}
	cfg.Guardrail.DefaultProfile = "offline-floor"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, cfg)
	api.setGuardrailProfiles(set)

	explain := func(user string) profileDecision {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?connector=opencode&user="+url.QueryEscape(user), nil)
		req.RemoteAddr = "127.0.0.1:40000"
		rec := httptest.NewRecorder()
		api.handleGuardrailProfileResolve(rec, req)
		var out struct {
			Profile string `json:"profile"`
			Match   string `json:"match"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("explain %s: %v: %s", user, err, rec.Body.String())
		}
		return profileDecision{Name: out.Profile, Match: out.Match}
	}
	hook := func(uid int) profileDecision {
		facts, _ := managedHookPeerHomes.directory(uid, true)
		subject := profileSubjectFromVerified(VerifiedSubject{
			UserID: strconv.Itoa(uid), IDKind: useridentity.KindPOSIXUID, Directory: facts, Source: subjectSourcePeerCredentials,
		}, true)
		return set.match(&subject, profileSubjectVerified, "opencode", "")
	}
	same := func(a, b profileDecision) bool { return a.Name == b.Name && a.Match == b.Match }

	if got := explain(eng.Name); got.Name != "engineering" || got.Match != profileMatchUser {
		t.Fatalf("explain before the outage = %+v; want engineering by user", got)
	}
	down.Store(true)
	live := hook(engUID)
	if live.Name != "engineering" || live.Match != profileMatchUser {
		t.Fatalf("hook during the outage = %+v; want engineering from the cached facts", live)
	}
	for _, spelled := range []string{eng.Name, "DCAD-R102-ENG1@DCLAB.TEST", strconv.Itoa(engUID)} {
		if got := explain(spelled); !same(got, live) {
			t.Fatalf("explain %s during the outage = %+v; its hooks decide %+v", spelled, got, live)
		}
	}
	// No facts were ever cached for eng2: both get the provisional default.
	other := hook(eng2UID)
	if other.Name != "offline-floor" || other.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("hook of an account without cached facts = %+v; want offline-floor by default_lookup_failed", other)
	}
	if got := explain(eng2.Name); !same(got, other) {
		t.Fatalf("explain of an account without cached facts = %+v; its hooks decide %+v", got, other)
	}
	// After the hour the facts are kept, both use the provisional default.
	clock.Add(int64(identityDirectoryMaxAge + time.Minute))
	expired := hook(engUID)
	if expired.Name != "offline-floor" || expired.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("hook an hour into the outage = %+v; want offline-floor by default_lookup_failed", expired)
	}
	if got := explain(eng.Name); !same(got, expired) {
		t.Fatalf("explain an hour into the outage = %+v; its hooks decide %+v", got, expired)
	}
}
