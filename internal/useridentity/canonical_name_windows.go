// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package useridentity

import (
	"time"

	"golang.org/x/sys/windows"
)

// platformSAMNameForUPN translates a UPN to DOMAIN\sAMAccountName through
// TranslateNameW, or "" when the directory does not know it as a UPN or
// does not answer within canonicalSAMTranslateWait; the LSA then decides
// (canonicalSIDAccountName).
func platformSAMNameForUPN(upn string) string {
	return SAMNameForUPN(upn, canonicalSAMTranslateWait)
}

// canonicalSAMTranslateWait bounds the directory translation of a sign-in
// UPN, so a translation that never answers leaves the LSA time to name the
// account within canonicalSIDNameWait.
const canonicalSAMTranslateWait = 500 * time.Millisecond

// platformSIDForAccountName is the SID an account name resolves to
// (LookupAccountName), or "". A name that resolves to a group or another
// kind of account is not an account name here.
func platformSIDForAccountName(name string) string {
	sid, _, kind, err := windows.LookupSID("", name)
	if err != nil || sid == nil || kind != windows.SidTypeUser {
		return ""
	}
	return sid.String()
}

// platformDomainForSID is the domain LookupAccountSid names for sid, or "".
func platformDomainForSID(sid string) string {
	_, domain, ok := (osWindowsDirectoryReader{}).LookupAccount(sid)
	if !ok {
		return ""
	}
	return domain
}
