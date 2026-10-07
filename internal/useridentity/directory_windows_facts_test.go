// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"testing"
	"time"
)

type fakeWindowsReader struct {
	values   map[string]string // path|name -> value
	subkeys  map[string][]string
	accounts map[string][2]string
	computer string
	adDomain string
	dnsName  string
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
func (f fakeWindowsReader) ComputerName() string       { return f.computer }
func (f fakeWindowsReader) DomainJoin() (string, bool) { return f.adDomain, f.adDomain != "" }
func (f fakeWindowsReader) DNSDomain() string          { return f.dnsName }

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
		computer: "WS01", adDomain: "CORP", dnsName: "corp.example.com",
	}
	now := time.Unix(1_800_000_000, 0)

	entra := resolveWindowsDirectoryFacts(reader, entraSID, nil, now)
	if entra.Directory != DirectoryEntraID || entra.UPN != "alice@contoso.com" || entra.TenantID != tenant ||
		entra.Source != SourceWindowsIdentityStore || entra.Assurance != AssuranceVerified {
		t.Fatalf("entra facts = %+v", entra)
	}
	hybrid := resolveWindowsDirectoryFacts(reader, adSID, func(string) string { return "ignored@corp.example.com" }, now)
	if hybrid.Directory != DirectoryActiveDirectory || hybrid.Domain != "corp.example.com" || hybrid.Realm != "CORP.EXAMPLE.COM" ||
		hybrid.Principal != "bob@corp.example.com" || hybrid.TenantID != tenant {
		t.Fatalf("hybrid AD facts = %+v", hybrid)
	}
	local := resolveWindowsDirectoryFacts(reader, localSID, nil, now)
	if local.Directory != DirectoryLocal || local.Principal != "" || local.UPN != "" {
		t.Fatalf("local facts = %+v", local)
	}
	// GAP-0417: after a UPN sign-in the LSA names the account in UPN form;
	// the principal is that UPN, not the UPN with the realm appended again.
	upnSID := "S-1-5-21-1-2-3-1106"
	reader.accounts[upnSID] = [2]string{"Dave@corp.example.com", "CORP"}
	upnForm := resolveWindowsDirectoryFacts(reader, upnSID, func(string) string { return "" }, now)
	if upnForm.Directory != DirectoryActiveDirectory || upnForm.UPN != "dave@corp.example.com" ||
		upnForm.Principal != "dave@corp.example.com" {
		t.Fatalf("UPN-form LSA account facts = %+v", upnForm)
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

	if got := cache.lookup(name, time.Second); got != "" || calls != 1 {
		t.Fatalf("failed lookup = %q after %d calls; want empty after 1", got, calls)
	}
	now = now.Add(adUPNFailureTTL - time.Second)
	if got := cache.lookup(name, time.Second); got != "" || calls != 1 {
		t.Fatalf("lookup inside the failure lifetime = %q after %d calls; want the cached failure", got, calls)
	}
	now = now.Add(2 * time.Second)
	if got := cache.lookup(name, time.Second); got != "alice@corp.example.com" || calls != 2 {
		t.Fatalf("retried lookup = %q after %d calls; want the UPN after 2", got, calls)
	}
	now = now.Add(adUPNTTL)
	if got := cache.lookup(name, time.Second); got != "alice@corp.example.com" || calls != 3 {
		t.Fatalf("lookup after a failure = %q after %d calls; want the last good UPN kept", got, calls)
	}
}
