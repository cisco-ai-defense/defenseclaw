// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import "strings"

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
// DirectoryFacts.Principal holds the UPN form when a UPN is known and the
// Kerberos form otherwise.

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

// PrincipalsEqual compares two principals or UPNs case-insensitively.
func PrincipalsEqual(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && strings.EqualFold(a, b)
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
