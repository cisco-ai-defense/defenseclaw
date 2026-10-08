//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// LookupAccountSpelling resolves the account an administrator names to
// profile-explain or enterprise policy show|verify --user in any spelling
// the host's NSS accepts for it: name, name@domain or DOMAIN\name, the forms
// winbind, SSSD with fully qualified names and the Okta LDAP setups print
// (GAP-0711, GAP-0740). An answer whose name is not the one asked is taken
// only when it is the same account spelled another way:
//
//   - the same bare account name, and the domain written is the answer's
//     own, or none was written;
//   - DOMAIN\name answered by a bare name: winbind and SSSD look a
//     backslash name up in that domain only;
//   - otherwise the account's verified directory facts (facts, may be nil)
//     must name it: its UPN or principal is the name, or, for the same bare
//     name, its domain or realm is the domain written. SSSD may answer
//     user@domain by a UPN or e-mail search across domains, so such an
//     answer is never taken on its name alone.
func LookupAccountSpelling(r Resolver, name string, facts func(uid int) (useridentity.DirectoryFacts, bool)) (Account, error) {
	account, err := r.LookupUser(name)
	var mismatch *NameMismatchError
	if err == nil || !errors.As(err, &mismatch) {
		return account, err
	}
	answered := mismatch.Answered
	if canonical, uidErr := r.LookupUID(answered.UID); uidErr != nil || canonical.Name != answered.Name {
		return Account{}, err
	}
	bare, domain := useridentity.SplitQualifiedName(name)
	answeredBare, answeredDomain := useridentity.SplitQualifiedName(answered.Name)
	sameBare := useridentity.EqualFold(bare, answeredBare)
	switch {
	case sameBare && (domain == "" || useridentity.EqualFold(domain, answeredDomain)):
		return answered, nil
	case sameBare && answeredDomain == "" && strings.Contains(name, `\`):
		return answered, nil
	}
	if facts != nil {
		if f, ok := facts(answered.UID); ok {
			if useridentity.PrincipalsEqual(f.UPN, name) || useridentity.PrincipalsEqual(f.Principal, name) ||
				sameBare && domain != "" && (useridentity.EqualFold(domain, f.Domain) || useridentity.EqualFold(domain, f.Realm)) {
				return answered, nil
			}
		}
	}
	return Account{}, err
}
