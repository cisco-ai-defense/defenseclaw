// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Principal and UPN rules.
//
// Directories disagree on case: SSSD reports a UPN with the realm in upper
// case (alice@CORP.EXAMPLE.COM) while Active Directory stores it as typed
// (alice@corp.example.com), and Kerberos realms are upper case by
// convention. Principals and UPNs therefore always compare
// case-insensitively (PrincipalsEqual), and DefenseClaw renders them in one
// canonical form:
//
//   - a Kerberos principal (NormalizePrincipal) keeps the user part as
//     reported and upper-cases the realm: alice@CORP.EXAMPLE.COM;
//   - a UPN (NormalizeUPN) is lower-cased as a whole, the form directory
//     consoles display: alice@corp.example.com.
//
// DirectoryFacts.Principal, the account's defenseclaw.user.principal, is
// always in the UPN form: the UPN when a UPN is known, else the account's
// Kerberos principal rendered like one (AccountPrincipal). One account
// therefore shows one principal whether its UPN resolved or not, on a
// per-user or a managed gateway and on every OS (GAP-0259, GAP-0284).
// DirectoryFacts.Realm and the session's Kerberos principal keep the
// upper-case realm.

// maxPrincipalLength bounds a principal before it is used; the v8 registry
// accepts at most 512 bytes.
const maxPrincipalLength = 512

// NormalizePrincipal renders a Kerberos principal as user@REALM with the
// realm upper-cased. A value without a realm, or with control characters or
// spaces, is returned empty: it is not a principal DefenseClaw can report.
func NormalizePrincipal(principal string) string {
	principal = strings.TrimSpace(principal)
	if !plausiblePrincipal(principal) {
		return ""
	}
	at := strings.LastIndexByte(principal, '@')
	if at <= 0 || at == len(principal)-1 {
		return ""
	}
	return principal[:at] + "@" + strings.ToUpper(principal[at+1:])
}

// AccountPrincipal is the principal of an account known by its account name
// and Kerberos realm when no UPN resolved, in the UPN form:
// alice@corp.example.com. It returns empty when either part is missing.
func AccountPrincipal(account, realm string) string {
	account, realm = strings.TrimSpace(account), strings.TrimSpace(realm)
	if account == "" || realm == "" {
		return ""
	}
	return NormalizeUPN(account + "@" + realm)
}

// NormalizeUPN renders a userPrincipalName lower-cased. It returns empty for
// a value that is not user@suffix.
func NormalizeUPN(upn string) string {
	upn = strings.TrimSpace(upn)
	if !plausiblePrincipal(upn) {
		return ""
	}
	at := strings.LastIndexByte(upn, '@')
	if at <= 0 || at == len(upn)-1 {
		return ""
	}
	return strings.ToLower(upn)
}

// PrincipalsEqual compares two principals or UPNs case-insensitively and
// without regard to Unicode normalization form (EqualFold).
func PrincipalsEqual(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && EqualFold(a, b)
}

// EqualFold reports whether a and b are equal without regard to case or
// Unicode normalization form. A name typed or pasted with a combining accent
// (e plus U+0301) is the name a directory holds precomposed (U+00E9), and an
// assignment spelled either way must match it (GAP-0154). Plain ASCII names
// take the allocation-free path.
func EqualFold(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	if isASCII(a) && isASCII(b) {
		return false
	}
	return strings.EqualFold(norm.NFC.String(a), norm.NFC.String(b))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// RealmOf returns the upper-cased realm of a principal, or "".
func RealmOf(principal string) string {
	principal = strings.TrimSpace(principal)
	at := strings.LastIndexByte(principal, '@')
	if at < 0 || at == len(principal)-1 {
		return ""
	}
	return strings.ToUpper(principal[at+1:])
}

// SplitQualifiedName splits an NSS account name into its bare account and
// domain: "alice@corp.example.com" (SSSD fully-qualified names) and
// "CORP\alice" (winbind) both give ("alice", "corp.example.com"/"CORP"). An
// unqualified name returns an empty domain.
func SplitQualifiedName(name string) (account, domain string) {
	name = strings.TrimSpace(name)
	if i := strings.IndexByte(name, '\\'); i > 0 && i < len(name)-1 {
		return name[i+1:], name[:i]
	}
	if i := strings.LastIndexByte(name, '@'); i > 0 && i < len(name)-1 {
		return name[:i], name[i+1:]
	}
	return name, ""
}

// BareAccountName is the account part of an NSS or Windows account name,
// the value defenseclaw.user.name carries: "alice@corp.example.com" and
// "CORP\alice" both give "alice". The qualified form is the principal,
// reported separately, and it fails the field's identifier syntax.
func BareAccountName(name string) string {
	account, _ := SplitQualifiedName(name)
	return account
}

// AccountFilterMatches reports whether a --user filter selects an account
// row: its id (uid or SID), its name, or its bare account, compared
// case-insensitively as Windows compares account names. The admin views share
// it (GAP-0051, GAP-0079). A bare filter selects the account of that name in
// every domain. A qualified filter (DOMAIN\name, user@domain) selects only a
// row of exactly that domain: CORP\alice is not OTHER\alice, and
// alice@corp.example.com is not a local alice (GAP-0366). A row that names
// its account bare is matched by a qualified filter only when its id is a SID:
// Windows rows keep the bare name next to the SID, while a bare Unix row is a
// local or short-name account of no known domain.
func AccountFilterMatches(filter, id, name string) bool {
	if filter == "" || strings.EqualFold(filter, id) || strings.EqualFold(filter, name) {
		return true
	}
	if name == "" {
		return false
	}
	filterAccount, filterDomain := SplitQualifiedName(filter)
	rowAccount, rowDomain := SplitQualifiedName(name)
	switch {
	case !EqualFold(filterAccount, rowAccount):
		return false
	case filterDomain == "":
		return true
	case rowDomain != "":
		return EqualFold(filterDomain, rowDomain)
	default:
		return KindForID(id) == KindWindowsSID
	}
}

func plausiblePrincipal(value string) bool {
	if value == "" || len(value) > maxPrincipalLength {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
