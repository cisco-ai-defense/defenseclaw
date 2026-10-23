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
	accountDomains       []string
	// incarnation is the account token of the account ids name, and
	// holderChanged reports that another account is known to have held its
	// uid (WithAccountIncarnation).
	incarnation   string
	holderChanged bool
	removed       func(id string) bool
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
// as name, a row that keeps no provenance of its account (an IDE plugin or
// discovery row): a qualified filter selects it by the id it resolves to.
// An empty filter selects every row.
func (f AccountFilter) Matches(id, name string) bool {
	return f.matches(id, name, "", func() bool { return true }, nil)
}

// MatchesIn is Matches for an agent identity row, which also keeps the
// AccountDomains and the account token (incarnation) of the account it was
// recorded for. A qualified filter selects such a row by the uid it
// resolves to only when the row was recorded for that account: a uid handed
// from CORP\alice to OTHER\alice kept CORP's rows, recorded with the bare
// name alice, under alice@OTHER (review of GAP-1263). The account token
// decides where both sides name one: domains alone may overlap (two
// accounts with UPNs under one suffix). A row that names no token (written
// before v8, or while none was known) is selected by its uid only while no
// other account is known to have held the uid, and then only when its
// owning domains, if it names any, are the account's (review of GAP-1263,
// loop 3). Its recorded name does not select a row recorded for another
// account than the one the filter resolves to (recordedForAnother).
func (f AccountFilter) MatchesIn(id, name, domains, incarnation string) bool {
	if f.domain != "" && f.incarnation == "" && f.holderChanged && slices.ContainsFunc(f.ids, func(resolved string) bool {
		return KindForID(resolved) == KindPOSIXUID
	}) {
		// The resolved uid's current holder is unproven. Even a row with
		// another uid and the same qualified name has no ownership proof.
		return false
	}
	return f.matches(id, name, domains, func() bool { return f.ownRow(id, domains, incarnation) },
		func() bool { return f.recordedForAnother(id, incarnation) })
}

func (f AccountFilter) matches(id, name, domains string, own, another func() bool) bool {
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	switch {
	case f.raw == "":
		return true
	case id != "" && strings.EqualFold(f.raw, id):
		return true
	case id != "" && slices.ContainsFunc(f.ids, func(resolved string) bool {
		return strings.EqualFold(resolved, id)
	}) && own():
		return true
	case f.domain != "" && len(f.ids) > 0:
		// A resolved qualified name belongs to its live UID/SID. A prior
		// holder's row can retain the exact spelling without an account
		// token, but that spelling cannot overrule the resolved identity.
		return false
	case name == "":
		return false
	case another != nil && another():
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
	return len(f.ids) == 0 && id != "" && f.removed != nil && f.recordedIn(domains) && f.removed(id)
}

// ownRow reports whether a row of id recorded for an account of domains and
// incarnation was recorded for the account the filter resolves to. A SID is
// never handed on, so its domains alone decide (recordedIn).
func (f AccountFilter) ownRow(id, domains, incarnation string) bool {
	incarnation = strings.TrimSpace(incarnation)
	if f.domain == "" || KindForID(strings.TrimSpace(id)) != KindPOSIXUID {
		return f.recordedIn(domains)
	}
	switch {
	case incarnation != "" && f.incarnation != "":
		return incarnation == f.incarnation
	case f.holderChanged:
		return false
	}
	return f.recordedIn(domains)
}

// recordedForAnother reports whether a row was recorded for another account
// than the one a qualified filter resolves to: the row and the account name
// account tokens and they differ, or the row names none, is of the resolved
// uid, and another account is known to have held that uid. A qualified
// name is handed on with the uid (an account deleted and created again
// with a new SID, its RFC 2307 uid and CORP\alice), so the recorded name
// selected the former holder's rows, and their history, for the new account
// (review of GAP-1263, loop 4). A bare filter names every account of the
// name.
func (f AccountFilter) recordedForAnother(id, incarnation string) bool {
	if f.domain == "" {
		return false
	}
	incarnation = strings.TrimSpace(incarnation)
	switch {
	case incarnation != "" && f.incarnation != "":
		return incarnation != f.incarnation
	case f.holderChanged:
		return slices.ContainsFunc(f.ids, func(resolved string) bool { return strings.EqualFold(resolved, strings.TrimSpace(id)) })
	}
	return false
}

// WithAccountIncarnation gives the account token of the account a qualified
// filter resolves to, and whether another account is known to have held its
// uid (or its first holder is not proved to be the one older builds saw).
func (f AccountFilter) WithAccountIncarnation(incarnation string, holderChanged bool) AccountFilter {
	f.incarnation, f.holderChanged = strings.TrimSpace(incarnation), holderChanged
	return f
}

// WithAccountDomains gives the AccountDomains of the account a qualified
// filter resolves to (its ids), so a row recorded for that account is
// selected by its uid also when the filter spells the domain another way
// than its facts do (CORP\alice for an account whose facts name only
// corp.example.com).
func (f AccountFilter) WithAccountDomains(domains string) AccountFilter {
	f.accountDomains = strings.Fields(domains)
	return f
}

// recordedIn reports whether a row recorded for an account of domains (its
// AccountDomains) may be an account of the filter's domain: it names that
// domain or a domain of the account the filter resolves to, or names none.
func (f AccountFilter) recordedIn(domains string) bool {
	recorded := strings.Fields(domains)
	if f.domain == "" || len(recorded) == 0 {
		return true
	}
	return slices.ContainsFunc(recorded, func(domain string) bool {
		return strings.EqualFold(domain, f.domain) || slices.ContainsFunc(f.accountDomains, func(own string) bool {
			return strings.EqualFold(own, domain)
		})
	})
}

// AccountDomains is the provenance an admin-view row keeps of the account
// it was recorded for: the domains that own its verified directory facts
// (DNS domain, NetBIOS domain, realm), lower case and space separated, after
// "." for a local account. A removed account's uid is handed to the next
// account, of the same bare name in another domain too, and the provenance
// tells their rows apart where the uid and the name cannot. The suffixes of
// a UPN or principal are aliases, not the owner: two domains' accounts may
// have UPNs under one suffix, and their rows read as one account's (review
// of GAP-1263, loop 3). "" when the facts name none.
func AccountDomains(facts DirectoryFacts) string {
	var out []string
	add := func(domain string) {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" && !strings.ContainsAny(domain, " \t\r\n") && !slices.Contains(out, domain) {
			out = append(out, domain)
		}
	}
	if facts.Directory == DirectoryLocal {
		add(".")
	}
	for _, domain := range []string{facts.Domain, facts.AccountDomain, facts.Realm} {
		add(domain)
	}
	return strings.Join(out, " ")
}

// NamesakesUnknownError refuses a bare account name while the host cannot
// tell whether a directory account shares it: realmd did not answer and no
// other source names the joined domains, so the directory twin of a local
// account cannot be looked up (GAP-1131). The administrator names the
// account by its qualified name or its uid.
type NamesakesUnknownError struct {
	Name string
	Err  error
}

func (e *NamesakesUnknownError) Error() string {
	return fmt.Sprintf("cannot tell whether a directory account is also named %q: the joined domains are unknown (%v); "+
		"name the account by its qualified name (user@domain or DOMAIN\\name) or its uid", e.Name, e.Err)
}

func (e *NamesakesUnknownError) Unwrap() error { return e.Err }

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
