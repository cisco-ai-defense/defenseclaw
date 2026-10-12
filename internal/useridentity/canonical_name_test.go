// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0382, GAP-0533: a UPN the LSA answers for a signed-in AD account
// becomes the account's bare sAMAccountName; a literal @ in an account's own
// name, or a UPN of another account, stays as the LSA gave it. The
// directory translation gives the sAMAccountName in its own case; where it
// does not answer (the gateway's restricted service account), the LSA alone
// confirms it (DOMAIN\<prefix> and the UPN both name the SID).
func TestCanonicalSIDAccountNameMapsSignInUPNToSAMName(t *testing.T) {
	const bob = "S-1-5-21-602989718-809138714-1982218064-4077"
	const erin = "S-1-5-21-602989718-809138714-1982218064-4089"
	const literal = "S-1-5-21-602989718-809138714-1982218064-4090" // sAMAccountName ent-bob@dclab.test
	const smith = "S-1-5-21-602989718-809138714-1982218064-4091"   // UPN bob.smith@dclab.test, sAM bsmith
	sams := map[string]string{"ENT-BOB@DCLAB.TEST": `DCLAB\ent-bob`, "ent-erin@dclab.test": `DCLAB\ent-erin`,
		"bob.smith@dclab.test": `DCLAB\bsmith`}
	sids := map[string]string{
		`DCLAB\ent-bob`: bob, "ENT-BOB@DCLAB.TEST": bob, "ent-bob@dclab.test": bob,
		`DCLAB\ent-erin`: erin, "ent-erin@dclab.test": erin,
		`DCLAB\ent-bob@dclab.test`: literal,
		`DCLAB\bsmith`:             smith, "bob.smith@dclab.test": smith,
	}
	translate := func(upn string) string { return sams[upn] }
	noTranslate := func(string) string { return "" }
	sidOf := func(name string) string { // the LSA compares names without regard to case
		for account, sid := range sids {
			if EqualFold(account, name) {
				return sid
			}
		}
		return ""
	}
	for _, tc := range []struct {
		name, sid, domain, lsa string
		samForUPN              func(string) string
		want                   string
	}{
		{"UPN sign-in, translated", bob, "DCLAB", "ENT-BOB@DCLAB.TEST", translate, "ent-bob"},
		{"UPN sign-in, LSA only", bob, "DCLAB", "ENT-BOB@DCLAB.TEST", noTranslate, "ENT-BOB"},
		{"UPN sign-in, no translator", bob, "DCLAB", "ent-bob@dclab.test", nil, "ent-bob"},
		{"DOMAIN sign-in", bob, "DCLAB", "ent-bob", noTranslate, "ent-bob"},
		{"unknown name", bob, "DCLAB", "alex@corp.example.com", translate, "alex@corp.example.com"},
		{"another account's UPN", bob, "DCLAB", "ent-erin@dclab.test", translate, "ent-erin@dclab.test"},
		{"SID mismatch", "S-1-5-21-1-2-3-1107", "DCLAB", "ENT-BOB@DCLAB.TEST", translate, "ENT-BOB@DCLAB.TEST"},
		{"literal @ account", literal, "DCLAB", "ent-bob@dclab.test", noTranslate, "ent-bob@dclab.test"},
		{"UPN prefix is not the sAM", smith, "DCLAB", "bob.smith@dclab.test", translate, "bsmith"},
		{"UPN prefix is not the sAM, untranslated", smith, "DCLAB", "bob.smith@dclab.test", noTranslate, "bob.smith@dclab.test"},
		{"no domain", bob, "", "ENT-BOB@DCLAB.TEST", noTranslate, "ENT-BOB@DCLAB.TEST"},
	} {
		if got, _ := canonicalSIDAccountName(tc.sid, tc.domain, tc.lsa, tc.samForUPN, nil, sidOf); got != tc.want {
			t.Errorf("%s: canonical(%s, %q) = %q, want %q", tc.name, tc.sid, tc.lsa, got, tc.want)
		}
	}
}

// GAP-0382: where the translation does not answer (the gateway's service
// account), the sAMAccountName is spelt as the SYSTEM enumerator recorded it,
// so a UPN sign-in typed ENT-CAROL@DCLAB.TEST is named ent-carol, as a
// DCLAB\ent-carol sign-in is. A record is used only when it and the sign-in
// name both resolve to the SID; the LSA's typed prefix is not settled.
func TestCanonicalSIDAccountNameTakesTheRecordedSpelling(t *testing.T) {
	const carol = "S-1-5-21-602989718-809138714-1982218064-4078"
	const bob = "S-1-5-21-602989718-809138714-1982218064-4077"
	sids := map[string]string{`DCLAB\ent-carol`: carol, "ent-carol@dclab.test": carol, `DCLAB\ent-bob`: bob}
	sidOf := func(name string) string {
		for account, sid := range sids {
			if EqualFold(account, name) {
				return sid
			}
		}
		return ""
	}
	noTranslate := func(string) string { return "" }
	for _, tc := range []struct {
		name, recorded, want string
		settled              bool
	}{
		{"recorded", `DCLAB\ent-carol`, "ent-carol", true},
		{"no record", "", "ENT-CAROL", false},
		{"another account's record", `DCLAB\ent-bob`, "ENT-CAROL", false},
		{"record names a UPN", `DCLAB\ENT-CAROL@DCLAB.TEST`, "ENT-CAROL", false},
		{"record does not resolve", `DCLAB\ent-carol-old`, "ENT-CAROL", false},
	} {
		known := func(sid string) string {
			if sid != carol {
				return ""
			}
			return tc.recorded
		}
		got, settled := canonicalSIDAccountName(carol, "DCLAB", "ENT-CAROL@DCLAB.TEST", noTranslate, known, sidOf)
		if got != tc.want || settled != tc.settled {
			t.Errorf("%s: canonical = %q, %t; want %q, %t", tc.name, got, settled, tc.want, tc.settled)
		}
	}

	// The installed lookup is the one the gateway's names use.
	SetKnownAccountNameLookup(func(sid string) string { return `DCLAB\ent-carol` })
	t.Cleanup(func() { SetKnownAccountNameLookup(nil) })
	if got := knownAccountName(carol); got != `DCLAB\ent-carol` {
		t.Fatalf("knownAccountName = %q", got)
	}
	SetKnownAccountNameLookup(nil)
	if got := knownAccountName(carol); got != "" {
		t.Fatalf("knownAccountName after removal = %q", got)
	}
}

// The directory is asked once per account and spelling, a slow answer never
// holds a request past the wait, and an answer that kept the LSA name is
// asked again later.
func TestCanonicalNameCacheAsksOnceAndBoundsTheWait(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	cache := &canonicalNameCache{wait: 50 * time.Millisecond, resolve: func(_, name, _ string) (string, bool) {
		calls.Add(1)
		<-release
		return "ent-bob", true
	}}
	if got := cache.get("S-1-5-21-1", "ENT-BOB@DCLAB.TEST"); got != "ENT-BOB@DCLAB.TEST" {
		t.Fatalf("timed-out lookup = %q, want the LSA name", got)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for cache.get("S-1-5-21-1", "ENT-BOB@DCLAB.TEST") != "ent-bob" {
		if time.Now().After(deadline) {
			t.Fatal("late answer was not cached")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := calls.Load(); n > 2 {
		t.Fatalf("directory asked %d times, want at most 2", n)
	}

	// An answer the directory did not spell (the LSA's typed prefix) is asked
	// again after the retry window, so a record written later settles it.
	clock := time.Unix(1_800_000_000, 0)
	spelt := "ENT-CAROL"
	typed := &canonicalNameCache{wait: time.Second, now: func() time.Time { return clock },
		resolve: func(string, string, string) (string, bool) { return spelt, spelt == "ent-carol" }}
	if got := typed.get("S-1-5-21-3", "ENT-CAROL@DCLAB.TEST"); got != "ENT-CAROL" {
		t.Fatalf("typed answer = %q", got)
	}
	spelt = "ent-carol"
	if got := typed.get("S-1-5-21-3", "ENT-CAROL@DCLAB.TEST"); got != "ENT-CAROL" {
		t.Fatalf("typed answer within the retry window = %q, want the cached ENT-CAROL", got)
	}
	clock = clock.Add(canonicalSIDNameRetry + time.Second)
	if got := typed.get("S-1-5-21-3", "ENT-CAROL@DCLAB.TEST"); got != "ent-carol" {
		t.Fatalf("answer after the retry window = %q, want ent-carol", got)
	}

	now := time.Unix(1_800_000_000, 0)
	var misses atomic.Int32
	unmapped := &canonicalNameCache{wait: time.Second, now: func() time.Time { return now },
		resolve: func(_, name, _ string) (string, bool) { misses.Add(1); return name, false }}
	unmapped.get("S-1-5-21-2", "ENT-DAVE@DCLAB.TEST")
	unmapped.get("S-1-5-21-2", "ENT-DAVE@DCLAB.TEST")
	if n := misses.Load(); n != 1 {
		t.Fatalf("unmapped name asked %d times within the retry window, want 1", n)
	}
	now = now.Add(canonicalSIDNameRetry + time.Second)
	unmapped.get("S-1-5-21-2", "ENT-DAVE@DCLAB.TEST")
	if n := misses.Load(); n != 2 {
		t.Fatalf("unmapped name asked %d times after the retry window, want 2", n)
	}
}

// GAP-0382: the SYSTEM enumerator's identity record takes only a spelling
// the directory settled: the translation of the sign-in UPN, never the typed
// prefix (ENT-CAROL), which the gateway would read as settled.
func TestSettledWindowsAccountNameTakesOnlyTheDirectorySpelling(t *testing.T) {
	const carol = "S-1-5-21-602989718-809138714-1982218064-4078"
	prev := canonicalSIDNames
	t.Cleanup(func() { canonicalSIDNames = prev })
	translated := true
	canonicalSIDNames = &canonicalNameCache{wait: time.Second, resolve: func(_, name, _ string) (string, bool) {
		if translated {
			return "ent-carol", true
		}
		return "ENT-CAROL", false
	}}
	if got := SettledWindowsAccountName(carol, "ENT-CAROL@DCLAB.TEST", "DCLAB"); got != "ent-carol" {
		t.Fatalf("translated UPN = %q, want ent-carol", got)
	}
	translated = false
	if got := SettledWindowsAccountName(carol, "ent-carol@dclab.test", "DCLAB"); got != "" {
		t.Fatalf("typed spelling = %q, want none", got)
	}
	if got := SettledWindowsAccountName(carol, "ent-carol", "DCLAB"); got != "" {
		t.Fatalf("a sAMAccountName = %q, want none (nothing to settle)", got)
	}
}
