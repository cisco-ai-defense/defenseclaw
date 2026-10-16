// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"testing"
	"time"
)

// macOSMobileADRead is the shape of `dscl /Search -read /Users/<name>
// UniqueID AuthenticationAuthority OriginalNodeName AltSecurityIdentities
// dsAttrTypeNative:userPrincipalName` for a mobile Active Directory account:
// the local copy's attributes, then the domain record's (the lab Mac printed
// RecordName twice, with OriginalNodeName from the copy and the native
// userPrincipalName from the domain). Names replaced.
const macOSMobileADRead = "AuthenticationAuthority:\n" +
	" ;LocalCachedUser;/Active Directory/CORP/All Domains:alice:E9F6E0ED-138E-40C9-B9E7-A7F3F661DB14\n" +
	" ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM;\n" +
	"No such key: AltSecurityIdentities\n" +
	"OriginalNodeName:\n /Active Directory/CORP/corp.example.com\n" +
	"RecordName: alice\n" +
	"UniqueID: 1404012345\n" +
	"AuthenticationAuthority: ;Kerberosv5;;alice@CORP.EXAMPLE.COM;CORP.EXAMPLE.COM; ;NetLogon;alice;CORP\n" +
	"dsAttrTypeNative:userPrincipalName: Alice.Smith@Example.COM\n" +
	"RecordName: alice\n" +
	"UniqueID: 1404012345\n"

// GAP-0534 (GAP-0538): the guardian refused the record of every mobile AD
// account (no single UniqueID), so a users entry naming its UPN selected
// nobody and its cached facts were dropped minutes into an outage. A
// repeated identical UniqueID is the account's; two different ones are not.
// The domain record's userPrincipalName is the account's UPN.
func TestMacOSMobileADRecordKeepsItsUIDAndUPN(t *testing.T) {
	if uid, ok := MacOSDSCLRecordUID(macOSMobileADRead); !ok || uid != 1404012345 {
		t.Fatalf("MacOSDSCLRecordUID(mobile AD read) = %d, %v; want 1404012345, true", uid, ok)
	}
	for _, output := range []string{
		"UniqueID: 1404012345\nRecordName: alice\nUniqueID: 501\n",
		"UniqueID: 501 501 502\n",
		"UniqueID: 501\nUniqueID: x\n",
	} {
		if uid, ok := MacOSDSCLRecordUID(output); ok {
			t.Errorf("MacOSDSCLRecordUID(%q) = %d, true; want two accounts refused", output, uid)
		}
	}
	if uid, ok := MacOSDSCLRecordUID("UniqueID: 501 501\n"); !ok || uid != 501 {
		t.Errorf("a repeated value = %d, %v; want 501, true", uid, ok)
	}
	facts := ParseMacOSDirectoryFacts(MacOSDirectoryInputs{
		DSCL: macOSMobileADRead, DSConfigAD: "Active Directory Domain          = corp.example.com\n",
	}, time.Unix(1_800_000_000, 0))
	if facts.Directory != DirectoryActiveDirectory || facts.UPN != "alice.smith@example.com" ||
		facts.Principal != "alice@corp.example.com" || facts.Domain != "corp.example.com" || facts.AccountDomain != "CORP" {
		t.Fatalf("facts = %+v; want the AD account with its UPN, principal, domain and NetBIOS domain", facts)
	}
	local := ParseMacOSDirectoryFacts(MacOSDirectoryInputs{
		DSCL: "AuthenticationAuthority: ;ShadowHash;\ndsAttrTypeNative:userPrincipalName: carol@example.com\nUniqueID: 501\n",
	}, time.Unix(1_800_000_000, 0))
	if local.Directory != DirectoryLocal || local.UPN != "" {
		t.Fatalf("local facts = %+v; a local record's native attribute is no UPN", local)
	}
}
