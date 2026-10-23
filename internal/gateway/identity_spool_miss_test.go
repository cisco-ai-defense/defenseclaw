// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A guardian identity record that is there but cannot be read now (a
// sharing violation while the enumerator replaces it, a torn or foreign
// file, a timestamp outside its trust window) withdraws nothing. The facts it
// proved keep selecting their strict group or UPN assignment; dropping them
// let the next request resolve without the record and select a weaker
// default_profile. Only a withdrawn record (removed by the guardian) ends
// them, and then the request takes the outage path, never a plain default.
func TestUnreadableSpoolRecordKeepsCachedStrictFacts(t *testing.T) {
	const (
		sid = "S-1-5-21-1-2-3-1201"
		uid = "5201"
	)
	dir := t.TempDir()
	oldValidate, previousDir := validateManagedGuardianAuthorization, currentIdentitySpoolDir()
	trustErr := error(nil)
	validateManagedGuardianAuthorization = func(string, string) error { return trustErr }
	setIdentitySpoolDir(dir)
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate; setIdentitySpoolDir(previousDir) })
	path := func(key string) string { return filepath.Join(dir, key+".json") }
	write := func(key string, updated time.Time) {
		t.Helper()
		_ = os.RemoveAll(path(key))
		data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
			Key: key, User: `DCLAB\dcad-strict`, AccountSID: "S-1-5-21-9-9-9-5201", UpdatedAt: updated.UTC(),
			Facts: useridentity.DirectoryFacts{Groups: []string{`DCLAB\dc-strict`}, UPN: "dcad-strict@dclab.test"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path(key), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newCache := func(key string) *identityDirectoryCache {
		return newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			record, _ := readIdentitySpoolFacts(key, time.Now())
			facts := record.Facts
			facts.AccountSID = record.AccountSID
			facts.ResolvedAt = time.Now()
			return facts, nil
		})
	}

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Mode: "action", BlockAt: "LOW"}, "watch": {Mode: "observe"}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "strict", Match: config.ProfileMatch{Groups: []string{`DCLAB\dc-strict`}}},
		{Profile: "strict", Match: config.ProfileMatch{Users: []string{"dcad-strict@dclab.test"}}},
	}
	cfg.Guardrail.DefaultProfile = "watch"
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	decide := func(key, kind string, facts useridentity.DirectoryFacts) profileDecision {
		subject := profileSubjectFromVerified(VerifiedSubject{UserID: key, IDKind: kind, UserName: "dcad-strict", Directory: facts}, true)
		return set.match(&subject, profileSubjectVerified, "codex", "")
	}

	misses := []struct {
		name  string
		apply func(key string)
	}{
		{"torn record", func(key string) {
			if err := os.WriteFile(path(key), []byte(`{"version":`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"untrusted record", func(string) { trustErr = errors.New("record owner is not the guardian") }},
		{"not a regular file", func(key string) {
			if err := os.Remove(path(key)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path(key), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"future-dated record", func(key string) { write(key, time.Now().Add(time.Hour)) }},
		{"record past its trust window", func(key string) { write(key, time.Now().Add(-2*identitySpoolMaxAge)) }},
	}
	for _, platform := range []struct {
		name, key, kind string
		check           func(*identityDirectoryCache, string)
	}{
		{"windows token groups", sid, useridentity.KindWindowsSID, func(c *identityDirectoryCache, key string) { forgetOnSpoolGroupChange(c, key, time.Now()) }},
		{"unix guardian UPN", uid, useridentity.KindPOSIXUID, func(c *identityDirectoryCache, key string) { forgetOnSpoolChange(c, key, time.Now(), false) }},
	} {
		for _, miss := range misses {
			t.Run(platform.name+"/"+miss.name, func(t *testing.T) {
				trustErr = nil
				write(platform.key, time.Now())
				cache := newCache(platform.key)
				facts, ok := cache.get(platform.key, true)
				if !ok || len(facts.Groups) != 1 || facts.UPN == "" {
					t.Fatalf("first lookup = %+v, %v", facts, ok)
				}
				if got := decide(platform.key, platform.kind, facts); got.Name != "strict" {
					t.Fatalf("cached facts select %+v; want strict", got)
				}
				miss.apply(platform.key)
				platform.check(cache, platform.key)
				trustErr = nil
				cached, _, ok := cache.peek(platform.key)
				if !ok || len(cached.Groups) != 1 || cached.UPN != "dcad-strict@dclab.test" {
					t.Fatalf("a spool miss dropped the strict facts: %+v, %v", cached, ok)
				}
				if got := decide(platform.key, platform.kind, cached); got.Name != "strict" {
					t.Errorf("after a spool miss the request selects %+v; want strict, not the weaker default", got)
				}
			})
		}
	}

	// A withdrawn Windows record ends the token groups. The next lookup has
	// none, and the request takes the outage path (default_lookup_failed),
	// not a plain default as if the account were in no group.
	trustErr = nil
	write(sid, time.Now())
	cache := newCache(sid)
	if facts, ok := cache.get(sid, true); !ok || len(facts.Groups) != 1 {
		t.Fatalf("first lookup = %+v, %v", facts, ok)
	}
	if err := os.Remove(path(sid)); err != nil {
		t.Fatal(err)
	}
	forgetOnSpoolGroupChange(cache, sid, time.Now())
	if _, _, ok := cache.peek(sid); ok {
		t.Fatal("a withdrawn record left its token groups cached")
	}
	withdrawn := useridentity.DirectoryFacts{Source: useridentity.SourceWindowsLSA, ResolvedAt: time.Now()}
	if got := decide(sid, useridentity.KindWindowsSID, withdrawn); got.Match != profileMatchDefaultLookupFailed {
		t.Errorf("withdrawn token groups select %+v; want the outage path %s", got, profileMatchDefaultLookupFailed)
	}
}
