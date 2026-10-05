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
		entra.JoinType != JoinTypeHybrid || entra.Source != SourceWindowsIdentityStore || entra.Assurance != AssuranceVerified {
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
}
