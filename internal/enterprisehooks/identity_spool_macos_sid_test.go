// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

const testMacOSSID = "S-1-5-21-1004336348-1177238915-682003330-1105"

// rel-1-0-6:GAP-0275: the macOS guardian records the SID of an Active
// Directory account from its domain node only, when that record is the
// uid's, carries the GeneratedUID the /Search answer names, and names
// exactly one domain account SID.
func TestMacOSAccountSIDComesFromTheDomainNode(t *testing.T) {
	ad := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory}
	mobile := "UniqueID: 1105 1105\nGeneratedUID: 7F3A0000-0000-0000-0000-000000001105 7F3A0000-0000-0000-0000-000000001105\nAppleMetaNodeLocation:\n /Local/Default\n /Active Directory/CORP/All Domains\nOriginalNodeName:\n /Active Directory/CORP/All Domains\n"
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
		name       string
		facts      useridentity.DirectoryFacts
		search     string
		read       func(string) string
		want       string
		unanswered bool
	}{
		{"mobile account", ad, mobile, node("UniqueID: 1105\nGeneratedUID: 7F3A0000-0000-0000-0000-000000001105\nSMBSID: " + testMacOSSID + "\n"), testMacOSSID, false},
		{"network account", ad, network, node("UniqueID: 1105\nSMBSID: " + testMacOSSID + "\n"), testMacOSSID, false},
		{"the domain record is another uid's", ad, mobile, node("UniqueID: 1200\nSMBSID: " + testMacOSSID + "\n"), "", false},
		{"the domain record is another GeneratedUID's", ad, mobile, node("UniqueID: 1105\nGeneratedUID: 7F3A0000-0000-0000-0000-000000009999\nSMBSID: " + testMacOSSID + "\n"), "", false},
		{"the domain does not answer", ad, mobile, node(""), "", true},
		{"two SIDs", ad, mobile, node("UniqueID: 1105\nSMBSID: " + testMacOSSID + " S-1-5-21-1-2-3-1106\n"), "", false},
		{"no SID", ad, network, node("UniqueID: 1105\n"), "", false},
		{"local account with a local SMBSID", useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}, "UniqueID: 501\nAppleMetaNodeLocation: /Local/Default\nSMBSID: S-1-5-21-9-9-9-1001\n",
			func(string) string { t.Error("a local account read a node"); return "" }, "", false},
		{"Active Directory facts without an Active Directory node", ad, "UniqueID: 1105\nAppleMetaNodeLocation: /Local/Default\n",
			func(string) string { t.Error("read a node"); return "" }, "", false},
	} {
		got, unanswered := macOSAccountSID(tc.facts, tc.search, 1105, tc.read)
		if got != tc.want || unanswered != tc.unanswered {
			t.Errorf("%s: %q, unanswered %v; want %q, %v", tc.name, got, unanswered, tc.want, tc.unanswered)
		}
	}
}

// The darwin collector asks /Search for the node attributes and reads the
// domain node with its own short timeout; the record carries the SID.
func TestCollectMacOSIdentityRecordReadsTheDomainNode(t *testing.T) {
	var calls []string
	run := func(_ context.Context, timeout time.Duration, tool string, args ...string) string {
		calls = append(calls, timeout.String()+" "+tool+" "+strings.Join(args, " "))
		switch {
		case tool == "/usr/bin/dscl" && args[0] == "/Search":
			if !slices.Contains(args, "AppleMetaNodeLocation") || !slices.Contains(args, "OriginalNodeName") {
				t.Errorf("/Search read lacks the node attributes: %v", args)
			}
			return "UniqueID: 1105\nAuthenticationAuthority: ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM; ;NetLogon;alice;CORP\nAppleMetaNodeLocation:\n /Active Directory/CORP/All Domains\n"
		case tool == "/usr/bin/dscl":
			return "UniqueID: 1105\nSMBSID: " + testMacOSSID + "\n"
		case tool == "/usr/sbin/dsconfigad":
			return "Active Directory Domain          = corp.example.com\n"
		}
		return ""
	}
	record, err := collectMacOSIdentityRecord(context.Background(), run, IdentitySpoolAccount{UID: 1105, User: "alice"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if record.AccountSID != testMacOSSID || record.Facts.Directory != useridentity.DirectoryActiveDirectory || record.macOSSIDUnanswered {
		t.Fatalf("record %+v", record)
	}
	want := macOSDirectoryNodeReadTimeout.String() + " /usr/bin/dscl /Active Directory/CORP/All Domains -read /Users/alice UniqueID GeneratedUID SMBSID"
	if !slices.Contains(calls, want) {
		t.Fatalf("calls %q lack %q", calls, want)
	}
}

// A pass that cannot reach the domain keeps the SID of the account's
// previous record, while it still names the same account in the same
// domain; nothing else is carried.
func TestCarryMacOSAccountSID(t *testing.T) {
	ad := func(user, domain string) useridentity.DirectoryFacts {
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Domain: domain}
	}
	previous := IdentitySpoolRecord{User: "alice", AccountSID: testMacOSSID, Facts: ad("alice", "corp.example.com")}
	away := IdentitySpoolRecord{User: "alice", Facts: ad("alice", "corp.example.com"), macOSSIDUnanswered: true}
	if got := carryMacOSAccountSID(away, previous); got.AccountSID != testMacOSSID {
		t.Fatalf("domain away: %q, want the previous SID", got.AccountSID)
	}
	for name, record := range map[string]IdentitySpoolRecord{
		"answered without a SID": {User: "alice", Facts: ad("alice", "corp.example.com")},
		"another name":           {User: "bob", Facts: ad("bob", "corp.example.com"), macOSSIDUnanswered: true},
		"another domain":         {User: "alice", Facts: ad("alice", "other.example.com"), macOSSIDUnanswered: true},
		"now a local account":    {User: "alice", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}, macOSSIDUnanswered: true},
	} {
		if got := carryMacOSAccountSID(record, previous); got.AccountSID != "" {
			t.Errorf("%s: carried %q", name, got.AccountSID)
		}
	}
	// The mark is never written.
	data, err := MarshalIdentitySpoolRecord(away)
	if err != nil || strings.Contains(string(data), "unanswered") {
		t.Fatalf("marshal %s, %v", data, err)
	}
}

// On macOS a record without a SID (1.0.6 and older, or written while the
// domain was away) is not another identity because the fresh lookup has
// one; differing SIDs still are.
func TestMacOSMissingSIDIsNoAnswer(t *testing.T) {
	previous := identitySpoolMissingSIDIsAnotherIdentity
	identitySpoolMissingSIDIsAnotherIdentity = false
	t.Cleanup(func() { identitySpoolMissingSIDIsAnotherIdentity = previous })
	facts := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example.com", Source: useridentity.SourceMacOSOpenDirectory}
	old := IdentitySpoolRecord{Key: "1105", User: "alice", Facts: facts}
	fresh := IdentitySpoolRecord{Key: "1105", User: "alice", AccountSID: testMacOSSID, Facts: facts}
	if got := identitySpoolSameIdentity(old, fresh, true); got == identitySpoolDepartureOther {
		t.Fatal("a record without a SID counted as another identity on macOS")
	}
	old.AccountSID = "S-1-5-21-1-2-3-1105"
	if got := identitySpoolSameIdentity(old, fresh, true); got != identitySpoolDepartureOther {
		t.Fatalf("another SID: %v, want another identity", got)
	}
}

// The SID travels in the record extension, which a 1.0.3 or older gateway
// does not read, and comes back on parse.
func TestMacOSAccountSIDRoundTripsInTheRecordExtension(t *testing.T) {
	record := IdentitySpoolRecord{Key: "1105", User: "alice", AccountSID: testMacOSSID,
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
