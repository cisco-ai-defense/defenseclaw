// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"fmt"
	"slices"
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

// AccountFilter is a compiled --user filter of the admin views. AI
// Discovery, agent identities and IDE plugins share it, so one spelling
// selects the same accounts in each (GAP-0051, GAP-0079, GAP-1080). It
// selects a row by its id (uid or SID), by the name the row was recorded
// with, compared case-insensitively as Windows and SSSD compare account
// names, or by the account the operating system resolves a qualified filter
// to:
//
//   - a bare name selects the account of that name in every domain, so it
//     selects both accounts when a local and a directory account share it;
//   - a qualified filter (DOMAIN\name, .\name, user@domain) selects a row
//     recorded with exactly that domain, or the account the OS resolves the
//     filter to, by its id. A row recorded with its bare name is never
//     selected by a qualified filter on its name alone: CORP\alice is not
//     OTHER\alice, alice@corp.example.com is not a local alice, and a
//     Windows row that carries the bare name next to its SID is selected by
//     DOMAIN\name only when that SID is the account the LSA names so
//     (GAP-0366).
type AccountFilter struct {
	raw, account, domain string
	ids                  []string
	removed              func(id string) bool
}

// NewAccountFilter compiles filter. ids are the ids (uid or SID) of the
// account the OS resolves a qualified filter to, which the caller looks up
// the way profile-explain does (NSS and the verified directory facts on
// Linux and macOS, the LSA on Windows); none for a bare filter or one that
// does not resolve.
func NewAccountFilter(filter string, ids ...string) AccountFilter {
	f := AccountFilter{raw: strings.TrimSpace(filter)}
	f.account, f.domain = SplitQualifiedName(f.raw)
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			f.ids = append(f.ids, id)
		}
	}
	return f
}

// WithRemovedAccounts lets a qualified filter that resolves to no account,
// as a deleted account's name does, also select a row recorded with the bare
// name of its account whose id removed reports: Windows rows keep the bare
// name next to the SID, as do SSSD rows where names are not fully qualified,
// and the deleted account is still read by the name it was known by
// (GAP-1221). removed must report only an id no account holds now (and that
// the filter's domain could have held), so a live twin is never selected
// (GAP-0366).
func (f AccountFilter) WithRemovedAccounts(removed func(id string) bool) AccountFilter {
	f.removed = removed
	return f
}

// QualifiedAccountName reports whether name names its domain (DOMAIN\name,
// .\name or user@domain), the filters a caller resolves to an account id.
func QualifiedAccountName(name string) bool {
	_, domain := SplitQualifiedName(name)
	return domain != ""
}

// Matches reports whether the filter selects the row of account id recorded
// as name. An empty filter selects every row.
func (f AccountFilter) Matches(id, name string) bool {
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	switch {
	case f.raw == "":
		return true
	case id != "" && (strings.EqualFold(f.raw, id) || slices.ContainsFunc(f.ids, func(resolved string) bool {
		return strings.EqualFold(resolved, id)
	})):
		return true
	case name == "":
		return false
	case EqualFold(f.raw, name):
		return true
	}
	rowAccount, rowDomain := SplitQualifiedName(name)
	switch {
	case !EqualFold(f.account, rowAccount):
		return false
	case f.domain == "":
		return true
	case rowDomain != "":
		return EqualFold(f.domain, rowDomain)
	}
	return len(f.ids) == 0 && id != "" && f.removed != nil && f.removed(id)
}

// AccountRef names one account of an AmbiguousAccountError.
type AccountRef struct {
	ID   string `json:"user_id"`
	Name string `json:"user_name"`
}

// AmbiguousAccountError refuses a bare account name that names more than one
// account on the host, a local account and a directory account of the same
// name: profile-explain and policy show explain one account, so the
// administrator names it by its qualified name or its id (GAP-1087).
type AmbiguousAccountError struct {
	Name     string
	Accounts []AccountRef
}

func (e *AmbiguousAccountError) Error() string {
	named := make([]string, 0, len(e.Accounts))
	for _, account := range e.Accounts {
		kind := "uid"
		if KindForID(account.ID) == KindWindowsSID {
			kind = "SID"
		}
		named = append(named, fmt.Sprintf("%s (%s %s)", account.Name, kind, account.ID))
	}
	return fmt.Sprintf("%d accounts are named %q on this host: %s; name the one you mean by its qualified name "+
		"(user@domain or DOMAIN\\name) or its uid", len(e.Accounts), e.Name, strings.Join(named, ", "))
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
