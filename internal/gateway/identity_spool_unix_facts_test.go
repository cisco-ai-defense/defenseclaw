// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

const (
	unixFactsUID = "6001"
	unixFactsSID = "S-1-5-21-9-9-9-6001"
)

// unixFactsSpool points the gateway at a fresh identity spool and returns
// writers for a record and for the guardian's withdrawal of uid 6001.
func unixFactsSpool(t *testing.T) (writeRecord func(enterprisehooks.IdentitySpoolRecord), withdraw func(time.Time)) {
	t.Helper()
	dir := t.TempDir()
	oldValidate, previousDir := validateManagedGuardianAuthorization, currentIdentitySpoolDir()
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	setIdentitySpoolDir(dir)
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate; setIdentitySpoolDir(previousDir) })
	write := func(name string, record enterprisehooks.IdentitySpoolRecord) {
		t.Helper()
		record.Key = unixFactsUID
		data, err := enterprisehooks.MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return func(record enterprisehooks.IdentitySpoolRecord) {
			if record.UpdatedAt.IsZero() {
				record.UpdatedAt = time.Now().UTC()
			}
			write(unixFactsUID+".json", record)
		}, func(at time.Time) {
			// The literal file name, so this test also runs against a build
			// that does not know the withdrawal.
			write(unixFactsUID+".withdrawn", enterprisehooks.IdentitySpoolRecord{UpdatedAt: at.UTC()})
		}
}

// unixFactsProfiles is a strict group and UPN assignment over a weaker
// default profile.
func unixFactsProfiles(t *testing.T) func(facts useridentity.DirectoryFacts, ok bool) profileDecision {
	t.Helper()
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
	return func(facts useridentity.DirectoryFacts, ok bool) profileDecision {
		if !ok {
			// What a hook request gets when the lookup has no answer.
			facts = useridentity.DirectoryFacts{}
		}
		subject := profileSubjectFromVerified(VerifiedSubject{UserID: unixFactsUID, IDKind: useridentity.KindPOSIXUID,
			UserName: "dcad-strict", Directory: facts}, true)
		return set.match(&subject, profileSubjectVerified, "codex", "")
	}
}

// unixNSSFacts is what NSS (SSSD) verified for uid 6001: its strict group
// and the SID SSSD holds for it.
func unixNSSFacts() useridentity.DirectoryFacts {
	return useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Groups: []string{`DCLAB\dc-strict`}, AccountSID: unixFactsSID,
		Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}
}

// Loop round 3, finding 1: on a Linux (or macOS) gateway the guardian's
// record only adds the UPN to the facts NSS verified. A missing record, or
// one that lacks a fact the cached facts have (the account SID), dropped the
// cached facts at every hook request, and while NSS was slow the request
// selected the weaker default as default_lookup_failed. Those facts now
// stay; a record that adds the UPN refreshes them in place, keeping them
// when the refresh fails. Only a record that names another SID or UPN, or
// the guardian's explicit withdrawal, drops them.
func TestAbsentOrIncompleteSpoolRecordKeepsVerifiedUnixFacts(t *testing.T) {
	for _, tc := range []struct {
		name string
		// before is the record the first lookup reads (nil: none).
		before *enterprisehooks.IdentitySpoolRecord
		// after changes the spool once the facts are cached.
		after    func(writeRecord func(enterprisehooks.IdentitySpoolRecord), withdraw func(time.Time))
		wantKept bool
	}{
		{name: "no record yet", wantKept: true},
		{name: "a record without the account SID", wantKept: true,
			before: &enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", Facts: useridentity.DirectoryFacts{Realm: "DCLAB.TEST"}}},
		{name: "a record without the account SID written later", wantKept: true,
			after: func(write func(enterprisehooks.IdentitySpoolRecord), _ func(time.Time)) {
				write(enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", Facts: useridentity.DirectoryFacts{Realm: "DCLAB.TEST"}})
			}},
		{name: "a first record that adds the UPN", wantKept: true,
			after: func(write func(enterprisehooks.IdentitySpoolRecord), _ func(time.Time)) {
				write(enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", AccountSID: unixFactsSID,
					Facts: useridentity.DirectoryFacts{UPN: "dcad-strict@dclab.test"}})
			}},
		{name: "the record is removed", wantKept: true,
			before: &enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", AccountSID: unixFactsSID},
			after: func(write func(enterprisehooks.IdentitySpoolRecord), _ func(time.Time)) {
				if err := os.Remove(filepath.Join(currentIdentitySpoolDir(), unixFactsUID+".json")); err != nil {
					panic(err)
				}
			}},
		{name: "a record that names another SID",
			after: func(write func(enterprisehooks.IdentitySpoolRecord), _ func(time.Time)) {
				write(enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", AccountSID: "S-1-5-21-9-9-9-7002"})
			}},
		{name: "the guardian withdraws the identity",
			after: func(_ func(enterprisehooks.IdentitySpoolRecord), withdraw func(time.Time)) { withdraw(time.Now()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeRecord, withdraw := unixFactsSpool(t)
			decide := unixFactsProfiles(t)
			if tc.before != nil {
				writeRecord(*tc.before)
			}
			var nssDown atomic.Bool
			cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
				if nssDown.Load() {
					return useridentity.DirectoryFacts{}, errors.New("sssd: the NSS lookup did not answer in time")
				}
				facts := unixNSSFacts()
				if record, ok := readIdentitySpoolFacts(unixFactsUID, time.Now()); ok {
					facts = mergeSpoolFacts(facts, record)
				}
				return facts, nil
			})
			facts, ok := cache.get(unixFactsUID, true)
			if got := decide(facts, ok); got.Name != "strict" {
				t.Fatalf("first request selects %+v (facts %+v, %v); want strict", got, facts, ok)
			}
			if tc.after != nil {
				time.Sleep(time.Millisecond) // a record written after the lookup
				tc.after(writeRecord, withdraw)
			}
			nssDown.Store(true)
			for request := 1; request <= 3; request++ {
				forgetOnSpoolChange(cache, unixFactsUID, time.Now(), false)
				facts, ok = cache.get(unixFactsUID, true)
				got := decide(facts, ok)
				if tc.wantKept && got.Name != "strict" {
					t.Fatalf("request %d while NSS is slow selects %+v (facts %+v, %v); want the verified strict facts kept",
						request, got, facts, ok)
				}
				if !tc.wantKept && (ok || got.Match != profileMatchDefaultLookupFailed) {
					t.Fatalf("request %d: the facts of a replaced or withdrawn identity stayed: %+v, %v (%+v)", request, facts, ok, got)
				}
			}
		})
	}
}

// Each guardian record and withdrawal is acted on once. A record the lookup
// already read (one without a SID, or one it refused) no longer starts a
// lookup at every request; a withdrawal drops the facts once, and the
// facts resolved after it stay; a record that adds the UPN merges it.
func TestUnixSpoolRecordsAndWithdrawalsAreActedOnOnce(t *testing.T) {
	writeRecord, withdraw := unixFactsSpool(t)
	decide := unixFactsProfiles(t)
	writeRecord(enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", Facts: useridentity.DirectoryFacts{Realm: "DCLAB.TEST"}})
	var lookups atomic.Int32
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		lookups.Add(1)
		facts := unixNSSFacts()
		facts.SpoolSeenAt = identitySpoolSeenAt(unixFactsUID, time.Now())
		if record, ok := readIdentitySpoolFacts(unixFactsUID, time.Now()); ok {
			facts = mergeSpoolFacts(facts, record)
		}
		return facts, nil
	})
	request := func() (useridentity.DirectoryFacts, bool) {
		forgetOnSpoolChange(cache, unixFactsUID, time.Now(), false)
		return cache.get(unixFactsUID, true)
	}
	for range 5 {
		if facts, ok := request(); decide(facts, ok).Name != "strict" {
			t.Fatalf("facts %+v, %v do not select strict", facts, ok)
		}
	}
	if n := lookups.Load(); n != 1 {
		t.Fatalf("a record without a SID started %d lookups for 5 requests; want 1", n)
	}
	time.Sleep(time.Millisecond)
	// The guardian rewrites the same facts at its next pass.
	writeRecord(enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", Facts: useridentity.DirectoryFacts{Realm: "DCLAB.TEST"}})
	request()
	if n := lookups.Load(); n != 1 {
		t.Fatalf("a rewritten record that adds nothing started a lookup (%d)", n)
	}
	time.Sleep(time.Millisecond)
	withdraw(time.Now())
	for range 3 {
		if facts, ok := request(); decide(facts, ok).Name != "strict" {
			t.Fatalf("after the withdrawal the NSS facts %+v, %v do not select strict", facts, ok)
		}
	}
	if n := lookups.Load(); n != 2 {
		t.Fatalf("the withdrawal started %d lookups in all; want one more", n)
	}
	time.Sleep(time.Millisecond)
	writeRecord(enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", AccountSID: unixFactsSID,
		Facts: useridentity.DirectoryFacts{UPN: "dcad-strict@dclab.test"}})
	facts, ok := request()
	if !ok || facts.UPN != "dcad-strict@dclab.test" || lookups.Load() != 3 {
		t.Fatalf("a record that adds the UPN gave %+v, %v after %d lookups; want it merged by one refresh", facts, ok, lookups.Load())
	}
}
