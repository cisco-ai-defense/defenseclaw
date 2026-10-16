//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"
)

// GAP-0534: a mobile AD account's /Search read names its UniqueID once per
// record (the local copy and the domain's); the guardian refused it and
// wrote no identity record for any AD account of a bound Mac. The same uid
// twice is the account's; another account's uid is still refused.
func TestMacOSMobileAccountRecordIsTheAccounts(t *testing.T) {
	read := "OriginalNodeName:\n /Active Directory/CORP/corp.example.com\nRecordName: alice\nUniqueID: 1404012345\n" +
		"dsAttrTypeNative:userPrincipalName: alice@corp.example.com\nRecordName: alice\nUniqueID: 1404012345\n"
	if err := checkMacOSRecordUID(read, 1404012345); err != nil {
		t.Fatalf("the mobile account's own record was refused: %v", err)
	}
	if err := checkMacOSRecordUID(read, 501); err == nil || !strings.Contains(err.Error(), "record belongs to another account") {
		t.Fatalf("the record was accepted for another uid: %v", err)
	}
	twoAccounts := "UniqueID: 1404012345\nRecordName: alice\nUniqueID: 501\n"
	if err := checkMacOSRecordUID(twoAccounts, 1404012345); err == nil {
		t.Fatal("a read naming two accounts was accepted")
	}
}
