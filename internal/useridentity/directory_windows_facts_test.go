// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"testing"
	"time"
)

type fakeWindowsReader struct {
	values    map[string]string // path|name -> value
	subkeys   map[string][]string
	accounts  map[string][2]string
	computer  string
	adDomain  string
	dnsName   string
	adDNSName string
}

func (f fakeWindowsReader) StringValue(path, name string) (string, bool) {
	v, ok := f.values[path+"|"+name]
	return v, ok
}
func (f fakeWindowsReader) SubKeys(path string) []string { return f.subkeys[path] }
func (f fakeWindowsReader) LookupAccount(sid string) (string, string, bool) {
	a, ok := f.accounts[sid]
	return a[0], a[1], ok
}
func (f fakeWindowsReader) ComputerName() string { return f.computer }
func (f fakeWindowsReader) DomainJoin() (string, string, bool) {
	return f.adDomain, f.adDNSName, f.adDomain != ""
}

func TestResolveWindowsDirectoryFacts(t *testing.T) {
	const tenant = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	entraSID := "S-1-12-1-111-222-333-444"
	adSID := "S-1-5-21-1-2-3-1105"
	localSID := "S-1-5-21-9-9-9-1001"
	store := func(sid string) string { return identityStoreCacheKey + `\` + sid + `\IdentityCache\` + sid }
	reader := fakeWindowsReader{
		values: map[string]string{
			cloudJoinInfoKey + `\ABCD|TenantId`: tenant,
			store(entraSID) + "|UserName":       "Alice@Contoso.com",
			store(entraSID) + "|ProviderName":   "AzureAD",
			store(adSID) + "|UserName":          "bob@corp.example.com",
			store(adSID) + "|ProviderName":      "AzureAD",
		},
		subkeys:  map[string][]string{cloudJoinInfoKey: {"ABCD"}},
		accounts: map[string][2]string{adSID: {"bob", "CORP"}, localSID: {"carol", "WS01"}},
		computer: "WS01", adDomain: "CORP", adDNSName: "corp.example.com",
	}
	now := time.Unix(1_800_000_000, 0)

	entra := resolveWindowsDirectoryFacts(reader, entraSID, nil, now)
	if entra.Directory != DirectoryEntraID || entra.UPN != "alice@contoso.com" || entra.TenantID != tenant ||
		entra.Source != SourceWindowsIdentityStore || entra.Assurance != AssuranceVerified || entra.AccountDomain != "AzureAD" {
		t.Fatalf("entra facts = %+v", entra)
	}
	hybrid := resolveWindowsDirectoryFacts(reader, adSID, func(string, string) string { return "ignored@corp.example.com" }, now)
	if hybrid.Directory != DirectoryActiveDirectory || hybrid.Domain != "corp.example.com" || hybrid.Realm != "CORP.EXAMPLE.COM" ||
		hybrid.Principal != "bob@corp.example.com" || hybrid.TenantID != tenant || hybrid.AccountDomain != "CORP" {
		t.Fatalf("hybrid AD facts = %+v", hybrid)
	}
	local := resolveWindowsDirectoryFacts(reader, localSID, nil, now)
	if local.Directory != DirectoryLocal || local.Principal != "" || local.UPN != "" || local.AccountDomain != "WS01" {
		t.Fatalf("local facts = %+v", local)
	}
	// GAP-0417: after a UPN sign-in the LSA names the account in UPN form;
	// the principal is that UPN, not the UPN with the realm appended again.
	upnSID := "S-1-5-21-1-2-3-1106"
	reader.accounts[upnSID] = [2]string{"Dave@corp.example.com", "CORP"}
	upnForm := resolveWindowsDirectoryFacts(reader, upnSID, func(string, string) string { return "" }, now)
	if upnForm.Directory != DirectoryActiveDirectory || upnForm.UPN != "dave@corp.example.com" ||
		upnForm.Principal != "dave@corp.example.com" {
		t.Fatalf("UPN-form LSA account facts = %+v", upnForm)
	}
}

// A disjoint computer DNS suffix must not become a verified account domain or realm.
func TestWindowsADDomainIgnoresComputerDNSSuffix(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1105"
	reader := fakeWindowsReader{
		accounts: map[string][2]string{sid: {"alice", "CORP"}},
		computer: "WS01", adDomain: "CORP", dnsName: "workstations.example.net",
		adDNSName: "corp.example.com",
	}
	facts := resolveWindowsDirectoryFacts(reader, sid, nil, time.Unix(1_800_000_000, 0))
	if facts.Domain != "corp.example.com" || facts.Domain == reader.dnsName || facts.Realm != "CORP.EXAMPLE.COM" ||
		facts.Principal != "alice@corp.example.com" || facts.AccountDomain != "CORP" {
		t.Fatalf("disjoint-namespace AD facts = %+v", facts)
	}
}

// TestADUPNCacheWaitsAndRetriesFailures pins GAP-0129: a lookup answers within
// the wait it is given, and a failed lookup (no domain controller) is retried
// after minutes while the last good answer is kept, not forgotten for a day.
func TestADUPNCacheWaitsAndRetriesFailures(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	answers := []string{"", "alice@corp.example.com", ""}
	calls := 0
	cache := newADUPNCache(func(string) string { calls++; return answers[calls-1] })
	cache.now = func() time.Time { return now }
	const name = `CORP\alice`

	if got := cache.lookup("S-1-5-21-1-2-3-1105", name, time.Second); got != "" || calls != 1 {
		t.Fatalf("failed lookup = %q after %d calls; want empty after 1", got, calls)
	}
	now = now.Add(adUPNFailureTTL - time.Second)
	if got := cache.lookup("S-1-5-21-1-2-3-1105", name, time.Second); got != "" || calls != 1 {
		t.Fatalf("lookup inside the failure lifetime = %q after %d calls; want the cached failure", got, calls)
	}
	now = now.Add(2 * time.Second)
	if got := cache.lookup("S-1-5-21-1-2-3-1105", name, time.Second); got != "alice@corp.example.com" || calls != 2 {
		t.Fatalf("retried lookup = %q after %d calls; want the UPN after 2", got, calls)
	}
	now = now.Add(adUPNTTL)
	if got := cache.lookup("S-1-5-21-1-2-3-1105", name, time.Second); got != "alice@corp.example.com" || calls != 3 {
		t.Fatalf("lookup after a failure = %q after %d calls; want the last good UPN kept", got, calls)
	}
}

// A UPN-only rename leaves the SID and sAMAccountName unchanged. The next
// directory refresh must retranslate instead of selecting the old user profile.
func TestADUPNCacheRetranslatesBeforeDirectoryRefresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	upn := "old@corp.example.com"
	calls := 0
	cache := newADUPNCache(func(string) string { calls++; return upn })
	cache.now = func() time.Time { return now }
	const sid = "S-1-5-21-1-2-3-1105"
	const sam = `CORP\alice`
	if got := cache.lookup(sid, sam, time.Second); got != upn {
		t.Fatalf("initial UPN = %q", got)
	}
	upn = "new@corp.example.com"
	now = now.Add(15 * time.Minute)
	if got := cache.lookup(sid, sam, time.Second); got != upn || calls != 2 {
		t.Fatalf("UPN after directory refresh = %q after %d translations; want %q after 2", got, calls, upn)
	}
}

func TestWindowsBuiltInAndServiceSIDsAreLocal(t *testing.T) {
	reader := fakeWindowsReader{
		accounts: map[string][2]string{
			"S-1-5-18":     {"SYSTEM", "NT AUTHORITY"},
			"S-1-5-80-123": {"agent", "NT SERVICE"},
		},
		computer: "WS01",
	}
	lookups := 0
	for _, sid := range []string{"S-1-5-18", "S-1-5-80-123"} {
		facts := resolveWindowsDirectoryFacts(reader, sid, func(string, string) string {
			lookups++
			return ""
		}, time.Unix(1_800_000_000, 0))
		if facts.Directory != DirectoryLocal || facts.Domain != "" {
			t.Fatalf("%s resolved as %+v", sid, facts)
		}
	}
	if lookups != 0 {
		t.Fatalf("service accounts triggered %d AD UPN lookups", lookups)
	}
}

func TestADUPNCacheDoesNotReuseAccountNameAcrossSIDs(t *testing.T) {
	const name = `CORP\alice`
	calls := 0
	cache := newADUPNCache(func(string) string {
		calls++
		if calls == 1 {
			return "former@corp.example.com"
		}
		return "current@corp.example.com"
	})
	if got := cache.lookup("S-1-5-21-1-2-3-1105", name, time.Second); got != "former@corp.example.com" {
		t.Fatalf("former SID UPN = %q", got)
	}
	if got := cache.lookup("S-1-5-21-1-2-3-1106", name, time.Second); got != "current@corp.example.com" || calls != 2 {
		t.Fatalf("new SID UPN = %q after %d translations", got, calls)
	}
}

func TestWindowsGroupNamesLookupHonorsBudget(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	sids := []string{"S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3-1106"}
	start := time.Now()
	got := windowsGroupNamesWithLookup(sids, 2, 20*time.Millisecond, func(string) (string, string, bool) {
		<-blocked
		return "group", "CORP", true
	})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("group lookup took %s after its budget", elapsed)
	}
	for i, sid := range sids {
		if got[i] != sid {
			t.Fatalf("group %d = %q; want SID %q after timeout", i, got[i], sid)
		}
	}
}
