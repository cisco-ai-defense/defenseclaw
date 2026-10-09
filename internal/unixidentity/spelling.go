//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"errors"
	"fmt"
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
//     name, its domain, realm or verified NetBIOS account domain is the
//     domain written, so DCLAB\alice, the spelling a users entry uses,
//     takes the alice@dclab.test SSSD answers for it (GAP-1089). SSSD may
//     answer user@domain by a UPN or e-mail search across domains, so such
//     an answer is never taken on its name alone.
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
				sameBare && domain != "" && (useridentity.EqualFold(domain, f.Domain) || useridentity.EqualFold(domain, f.Realm) ||
					useridentity.EqualFold(domain, f.AccountDomain)) {
				return answered, nil
			}
		}
	}
	return Account{}, err
}

// AccountLookupError is the sentence an administrator reads when the
// account named to profile-explain or policy show|verify --user does not
// resolve: what getent answered, the spelling NSS knows a short name by
// (qualified, from QualifiedUserName; "" for none), or how to check it. It
// carries no package prefix (GAP-1089).
func AccountLookupError(name, qualified string, err error) error {
	var mismatch *NameMismatchError
	switch {
	case errors.As(err, &mismatch):
		return fmt.Errorf("no account named %q on this host: getent passwd answers it with the account %q, which is not "+
			"confirmed to be the same account; name that account %q or by its uid if it is the one you mean",
			name, mismatch.Answered.Name, mismatch.Answered.Name)
	case err != nil && !IsNotFound(err):
		return fmt.Errorf("could not look up %q in the account database (%s); try again, or name the account by its uid",
			name, strings.TrimPrefix(err.Error(), "unixidentity: "))
	case name != "" && strings.Trim(name, "0123456789") == "":
		return fmt.Errorf("no account has uid %s on this host", name)
	case qualified != "":
		return fmt.Errorf("no account named %q on this host; getent passwd knows %q: use that spelling or its uid", name, qualified)
	}
	return fmt.Errorf("no account named %q on this host; check the current spelling with getent passwd or use the account uid", name)
}
