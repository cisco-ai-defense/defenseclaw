// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// rel-1-0-6:GAP-0275: the macOS guardian records the SID of an Active
// Directory account from its domain node only, when that record is the
// uid's and names exactly one domain account SID.
func TestMacOSAccountSIDComesFromTheDomainNode(t *testing.T) {
	ad := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory}
	const sid = "S-1-5-21-1004336348-1177238915-682003330-1105"
	mobile := "UniqueID: 1105 1105\nAppleMetaNodeLocation:\n /Local/Default\n /Active Directory/CORP/All Domains\nOriginalNodeName:\n /Active Directory/CORP/All Domains\n"
	network := "UniqueID: 1105\nAppleMetaNodeLocation:\n /Active Directory/CORP/All Domains\n"
	node := func(out string) func(string) string {
		return func(n string) string {
			if n != "/Active Directory/CORP/All Domains" {
				t.Errorf("read node %q", n)
			}
			return out
		}
	}
	for _, tc := range []struct {
		name   string
		facts  useridentity.DirectoryFacts
		search string
		read   func(string) string
		want   string
	}{
		{"mobile account", ad, mobile, node("UniqueID: 1105\nSMBSID: " + sid + "\n"), sid},
		{"network account", ad, network, node("UniqueID: 1105\nSMBSID: " + sid + "\n"), sid},
		{"the domain record is another uid's", ad, mobile, node("UniqueID: 1200\nSMBSID: " + sid + "\n"), ""},
		{"the domain does not answer", ad, mobile, node(""), ""},
		{"two SIDs", ad, mobile, node("UniqueID: 1105\nSMBSID: " + sid + " S-1-5-21-1-2-3-1106\n"), ""},
		{"no SID", ad, network, node("UniqueID: 1105\n"), ""},
		{"local account with a local SMBSID", useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}, "UniqueID: 501\nAppleMetaNodeLocation: /Local/Default\nSMBSID: S-1-5-21-9-9-9-1001\n",
			func(string) string { t.Error("a local account read a node"); return "" }, ""},
		{"Active Directory facts without an Active Directory node", ad, "UniqueID: 1105\nAppleMetaNodeLocation: /Local/Default\n",
			func(string) string { t.Error("read a node"); return "" }, ""},
	} {
		if got := macOSAccountSID(tc.facts, tc.search, 1105, tc.read); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The SID travels in the record extension, which a 1.0.3 or older gateway
// does not read, and comes back on parse.
func TestMacOSAccountSIDRoundTripsInTheRecordExtension(t *testing.T) {
	record := IdentitySpoolRecord{Key: "1105", User: "alice", AccountSID: "S-1-5-21-1-2-3-1105",
		Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory}}
	data, err := MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIdentitySpoolRecord(data, "1105")
	if err != nil || got.AccountSID != record.AccountSID {
		t.Fatalf("parsed %+v, %v", got, err)
	}
}
