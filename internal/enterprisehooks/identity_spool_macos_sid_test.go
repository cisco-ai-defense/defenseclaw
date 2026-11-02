// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"slices"
	"strconv"
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
	answer := func(result macOSToolResult) func(string) macOSToolResult {
		return func(n string) macOSToolResult {
			if n != "/Active Directory/CORP/All Domains" {
				t.Errorf("read node %q", n)
			}
			return result
		}
	}
	node := func(stdout string) func(string) macOSToolResult { return answer(macOSToolResult{Stdout: stdout}) }
	for _, tc := range []struct {
		name       string
		facts      useridentity.DirectoryFacts
		search     string
		read       func(string) macOSToolResult
		want       string
		unanswered bool
	}{
		{"mobile account", ad, mobile, node("UniqueID: 1105\nGeneratedUID: 7F3A0000-0000-0000-0000-000000001105\nSMBSID: " + testMacOSSID + "\n"), testMacOSSID, false},
		{"network account", ad, network, node("UniqueID: 1105\nSMBSID: " + testMacOSSID + "\n"), testMacOSSID, false},
		{"the domain record is another uid's", ad, mobile, node("UniqueID: 1200\nSMBSID: " + testMacOSSID + "\n"), "", false},
		{"the domain record is another GeneratedUID's", ad, mobile, node("UniqueID: 1105\nGeneratedUID: 7F3A0000-0000-0000-0000-000000009999\nSMBSID: " + testMacOSSID + "\n"), "", false},
		{"the domain does not answer (timeout)", ad, mobile, answer(macOSToolResult{Code: -1}), "", true},
		// rel-1-0-6:GAP-0447, the streams and exit codes of the real dscl:
		// while the domain controller is unreachable the node read answers
		// at once on stdout, exit 69; that is no answer.
		{"the domain node is not valid", ad, mobile, answer(macOSToolResult{Stdout: "Data source (/Active Directory/CORP/All Domains) is not valid.\n", Code: dsclExitNodeNotValid}), "", true},
		{"exit 69 alone", ad, mobile, answer(macOSToolResult{Code: dsclExitNodeNotValid}), "", true},
		{"the domain node is not found", ad, mobile, answer(macOSToolResult{Stderr: "<main> attribute status: eDSNodeNotFound\n<dscl_cmd> DS Error: -14008 (eDSNodeNotFound)\n", Code: 1}), "", true},
		// An account gone from the domain: nothing on stdout, the
		// eDSRecordNotFound text on stderr, exit 56. That is a definitive
		// answer: the SID is not carried.
		{"the account is gone from the domain", ad, mobile, answer(macOSToolResult{Stderr: "<main> attribute status: eDSRecordNotFound\n<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n", Code: dsclExitRecordNotFound}), "", false},
		{"exit 56 alone", ad, mobile, answer(macOSToolResult{Code: dsclExitRecordNotFound}), "", false},
		// Any other output is an answer, read as before: a record without
		// a UniqueID line (each missing key is a "No such key" line on
		// stderr) or text that is not dscl's not-valid line gives no SID
		// and carries none.
		{"a record without a UniqueID", ad, mobile, answer(macOSToolResult{Stdout: "GeneratedUID: 7F3A0000-0000-0000-0000-000000001105\nSMBSID: " + testMacOSSID + "\n", Stderr: "No such key: UniqueID\n"}), "", false},
		{"other output", ad, mobile, answer(macOSToolResult{Stdout: "unexpected text\n", Code: 1}), "", false},
		{"a not-valid text inside an attribute value", ad, mobile, node("UniqueID: 1105\nGeneratedUID:\n Data source (/Active Directory/CORP/All Domains) is not valid.\n"), "", false},
		{"two SIDs", ad, mobile, node("UniqueID: 1105\nSMBSID: " + testMacOSSID + " S-1-5-21-1-2-3-1106\n"), "", false},
		{"no SID", ad, network, node("UniqueID: 1105\n"), "", false},
		{"local account with a local SMBSID", useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}, "UniqueID: 501\nAppleMetaNodeLocation: /Local/Default\nSMBSID: S-1-5-21-9-9-9-1001\n",
			func(string) macOSToolResult { t.Error("a local account read a node"); return macOSToolResult{} }, "", false},
		{"Active Directory facts without an Active Directory node", ad, "UniqueID: 1105\nAppleMetaNodeLocation: /Local/Default\n",
			func(string) macOSToolResult { t.Error("read a node"); return macOSToolResult{} }, "", false},
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
	run := func(_ context.Context, timeout time.Duration, tool string, args ...string) macOSToolResult {
		calls = append(calls, timeout.String()+" "+tool+" "+strings.Join(args, " "))
		out := func(stdout string) macOSToolResult { return macOSToolResult{Stdout: stdout} }
		switch {
		case tool == "/usr/bin/dscl" && args[0] == "/Search":
			if !slices.Contains(args, "AppleMetaNodeLocation") || !slices.Contains(args, "OriginalNodeName") {
				t.Errorf("/Search read lacks the node attributes: %v", args)
			}
			return out("UniqueID: 1105\nAuthenticationAuthority: ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM; ;NetLogon;alice;CORP\nAppleMetaNodeLocation:\n /Active Directory/CORP/All Domains\n")
		case tool == "/usr/bin/dscl":
			return out("UniqueID: 1105\nSMBSID: " + testMacOSSID + "\n")
		case tool == "/usr/sbin/dsconfigad":
			return out("Active Directory Domain          = corp.example.com\n")
		}
		return macOSToolResult{Code: -1}
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
	other := away
	other.Facts.Principal = "bob@CORP.EXAMPLE.COM"
	withPrincipal := previous
	withPrincipal.Facts.Principal = "alice@CORP.EXAMPLE.COM"
	if got := carryMacOSAccountSID(other, withPrincipal); got.AccountSID != "" {
		t.Errorf("another principal: carried %q", got.AccountSID)
	}
	// The mark is never written.
	data, err := MarshalIdentitySpoolRecord(away)
	if err != nil || strings.Contains(string(data), "unanswered") {
		t.Fatalf("marshal %s, %v", data, err)
	}
}

// The guardian pass writes the carried SID: a pass that cannot reach the
// domain keeps the account's SID in its record.
func TestIdentitySpoolPassKeepsTheMacOSSIDWhileTheDomainIsAway(t *testing.T) {
	const uid = 94401471
	dir := t.TempDir()
	old := testDirectoryRecord(uid, "dcad-alice", "dclab.test")
	old.Facts.Directory = useridentity.DirectoryActiveDirectory
	old.AccountSID = testMacOSSID
	writeTestSpoolRecord(t, dir, old)
	previous := identitySpoolCollect
	t.Cleanup(func() { identitySpoolCollect = previous })
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, _ time.Time) (IdentitySpoolRecord, error) {
		fresh := testDirectoryRecord(account.UID, account.User, "dclab.test")
		fresh.Facts.Directory = useridentity.DirectoryActiveDirectory
		fresh.macOSSIDUnanswered = true
		return fresh, nil
	}
	if err := WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: uid, User: old.User}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	got, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(uid), nil)
	if err != nil || got.AccountSID != testMacOSSID {
		t.Fatalf("record after a pass away from the domain: %+v (%v)", got, err)
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

// rel-1-0-6:GAP-0447, end to end with a fake Open Directory: with the domain
// controller unreachable, /Search still answers from the mobile account's
// local copy and the domain node answers "Data source (...) is not valid."
// at once. Five Active Directory accounts kept their SIDs (so their account
// join keys) on the managed Mac lane only if the pass carries them; it now
// does, over three passes away, and the same SID is read when the domain is
// back. A definitive eDSRecordNotFound from the node (stderr, exit 56, as
// the real dscl gives it) clears the SID.
func TestIdentitySpoolPassKeepsTheMacOSSIDWhenTheDomainNodeIsNotValid(t *testing.T) {
	const domainNode = "/Active Directory/DCLAB/dclab.test"
	users := map[int]string{94401471: "dcad-eng1", 94401472: "dcad-eng2", 94401473: "dcad-eng3", 94401474: "dcad-ctr1", 94401475: "dcad-admin"}
	sidOf := func(uid int) string { return "S-1-5-21-602989718-809138714-1982218064-" + strconv.Itoa(uid%10000) }
	node := "answers"
	run := func(_ context.Context, _ time.Duration, tool string, args ...string) macOSToolResult {
		if tool == "/usr/sbin/dsconfigad" {
			return macOSToolResult{Stdout: "Active Directory Domain          = dclab.test\n"}
		}
		if tool != "/usr/bin/dscl" {
			return macOSToolResult{Code: -1}
		}
		name := strings.TrimPrefix(args[2], "/Users/")
		uid := 0
		for id, user := range users {
			if user == name {
				uid = id
			}
		}
		if args[0] == "/Search" {
			return macOSToolResult{Stdout: "UniqueID: " + strconv.Itoa(uid) + "\nAuthenticationAuthority: ;Kerberosv5;;" + name + "@DCLAB.TEST;DCLAB.TEST; ;NetLogon;" + name + ";DCLAB\nOriginalNodeName:\n " + domainNode + "\n"}
		}
		if args[0] != domainNode {
			t.Errorf("read node %q", args[0])
		}
		switch node {
		case "not valid":
			return macOSToolResult{Stdout: "Data source (" + domainNode + ") is not valid.\n", Code: dsclExitNodeNotValid}
		case "gone":
			return macOSToolResult{Stderr: "<main> attribute status: eDSRecordNotFound\n<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n", Code: dsclExitRecordNotFound}
		}
		return macOSToolResult{Stdout: "UniqueID: " + strconv.Itoa(uid) + "\nSMBSID: " + sidOf(uid) + "\n"}
	}
	previous := identitySpoolCollect
	t.Cleanup(func() { identitySpoolCollect = previous })
	identitySpoolCollect = func(ctx context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
		return collectMacOSIdentityRecord(ctx, run, account, now)
	}
	dir := t.TempDir()
	var accounts []IdentitySpoolAccount
	for uid, user := range users {
		accounts = append(accounts, IdentitySpoolAccount{UID: uid, User: user})
	}
	pass := func(label string) map[int]string {
		t.Helper()
		if err := WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, nil); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		got := map[int]string{}
		for uid := range users {
			record, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(uid), nil)
			if err != nil {
				t.Fatalf("%s: read %d: %v", label, uid, err)
			}
			got[uid] = record.AccountSID
		}
		return got
	}
	for uid, sid := range pass("domain reachable") {
		if sid != sidOf(uid) {
			t.Fatalf("domain reachable: uid %d SID %q, want %q", uid, sid, sidOf(uid))
		}
	}
	node = "not valid"
	for rep := 1; rep <= 3; rep++ {
		for uid, sid := range pass("domain away") {
			if sid != sidOf(uid) {
				t.Fatalf("domain away, pass %d: uid %d SID %q, want the previous %q kept", rep, uid, sid, sidOf(uid))
			}
		}
	}
	node = "answers"
	for uid, sid := range pass("domain back") {
		if sid != sidOf(uid) {
			t.Fatalf("domain back: uid %d SID %q, want %q", uid, sid, sidOf(uid))
		}
	}
	node = "gone"
	for uid, sid := range pass("accounts gone from the domain") {
		if sid != "" {
			t.Fatalf("a definitive eDSRecordNotFound must not carry the SID: uid %d kept %q", uid, sid)
		}
	}
}
