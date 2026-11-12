// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// localSpellingResolver answers accounts by exact name and by uid, as NSS
// answers a lookup it can name.
type localSpellingResolver struct {
	unixidentity.Resolver
	accounts []unixidentity.Account
}

func (r localSpellingResolver) LookupUser(name string) (unixidentity.Account, error) {
	for _, a := range r.accounts {
		if a.Name == name {
			return a, nil
		}
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (r localSpellingResolver) LookupUID(uid int) (unixidentity.Account, error) {
	for _, a := range r.accounts {
		if a.UID == uid {
			return a, nil
		}
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

// GAP-0759: profile explain resolved the dot-backslash spelling of a local
// account (.\short) differently from the uid: NSS does not take it, so a
// per-user gateway refused the spelling of its own account and the strict
// profile of an unconfirmed holder printed a refusal the uid and the live
// prompt did not. Every spelling of the local account now resolves to its
// uid, a directory namesake never answers for it, and a spelling no local
// account has says so plainly.
func TestGAP0759LocalSpellingExplainsTheSamePrincipalAsTheUID(t *testing.T) {
	local := unixidentity.Account{Name: "short", UID: 1059}
	directory := unixidentity.Account{Name: "short@dclab.test", UID: 94408157}
	cases := []struct {
		name     string
		accounts []unixidentity.Account
		locals   map[string]int
		user     string
		wantID   string
		wantErr  string
	}{
		{"local only, dot-backslash", []unixidentity.Account{local}, map[string]int{"short": 1059}, `.\short`, "1059", ""},
		{"local only, uid", []unixidentity.Account{local}, map[string]int{"short": 1059}, "1059", "1059", ""},
		{"local only, bare name", []unixidentity.Account{local}, map[string]int{"short": 1059}, "short", "1059", ""},
		{"local namesake of AD, dot-backslash", []unixidentity.Account{local, directory}, map[string]int{"short": 1059}, `.\short`, "1059", ""},
		{"local namesake of AD, dot-backslash case variant", []unixidentity.Account{local, directory}, map[string]int{"short": 1059}, `.\SHORT`, "1059", ""},
		{"local namesake of AD, uid", []unixidentity.Account{local, directory}, map[string]int{"short": 1059}, "1059", "1059", ""},
		{"local namesake of AD, UPN", []unixidentity.Account{local, directory}, map[string]int{"short": 1059}, "short@dclab.test", "94408157", ""},
		{"AD only, dot-backslash", []unixidentity.Account{directory}, map[string]int{}, `.\short`, "", "no local account named"},
		{"local database unreadable", []unixidentity.Account{local}, nil, `.\short`, "", "could not look up"},
		{"another local account", []unixidentity.Account{local}, map[string]int{"short": 1059}, `.\other`, "", "no local account named"},
	}
	prevResolver, prevTwins, prevLocal := profileExplainResolver, sameNameProfileAccounts, unixidentity.LocalSpellingAccounts
	t.Cleanup(func() {
		profileExplainResolver, sameNameProfileAccounts, unixidentity.LocalSpellingAccounts = prevResolver, prevTwins, prevLocal
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profileExplainResolver = func(context.Context) unixidentity.Resolver {
				return localSpellingResolver{accounts: tc.accounts}
			}
			sameNameProfileAccounts = func(_ context.Context, _ unixidentity.Resolver, name string, account unixidentity.Account) ([]unixidentity.Account, error) {
				if strings.ContainsAny(name, `@\`) || strings.Trim(name, "0123456789") == "" || account.UID != local.UID || len(tc.accounts) < 2 {
					return nil, nil
				}
				return []unixidentity.Account{directory}, nil
			}
			unixidentity.LocalSpellingAccounts = func(context.Context) (map[string]int, error) {
				if tc.locals == nil {
					return nil, errors.New("passwd unreadable")
				}
				return tc.locals, nil
			}
			id, _, err := profileExplainAccount(tc.user)
			if tc.wantErr != "" {
				if err == nil || id != "" {
					t.Fatalf("profileExplainAccount(%q) = %q, %v; want an error", tc.user, id, err)
				}
				// The sentence the CLI prints for the failed lookup.
				said := unixidentity.AccountLookupError(tc.user, "", err).Error()
				if !strings.Contains(said, tc.wantErr) || strings.Contains(said, "per-user install") || strings.Contains(said, "refused") {
					t.Fatalf("lookup sentence %q; want it to say %q plainly", said, tc.wantErr)
				}
				return
			}
			if err != nil || id != tc.wantID {
				t.Fatalf("profileExplainAccount(%q) = %q, %v; want uid %s", tc.user, id, err, tc.wantID)
			}
		})
	}
}

// GAP-0759: the bare name two accounts share stays ambiguous; only the
// explicit local spelling names the local one.
func TestGAP0759BareNamesakeStaysAmbiguous(t *testing.T) {
	local := unixidentity.Account{Name: "short", UID: 1059}
	directory := unixidentity.Account{Name: "short@dclab.test", UID: 94408157}
	prevResolver, prevTwins := profileExplainResolver, sameNameProfileAccounts
	t.Cleanup(func() { profileExplainResolver, sameNameProfileAccounts = prevResolver, prevTwins })
	profileExplainResolver = func(context.Context) unixidentity.Resolver {
		return localSpellingResolver{accounts: []unixidentity.Account{local, directory}}
	}
	sameNameProfileAccounts = func(context.Context, unixidentity.Resolver, string, unixidentity.Account) ([]unixidentity.Account, error) {
		return []unixidentity.Account{directory}, nil
	}
	if _, _, err := profileExplainAccount("short"); !errors.As(err, new(*useridentity.AmbiguousAccountError)) {
		t.Fatalf("bare namesake: %v; want the ambiguity refusal", err)
	}
}

// GAP-0759: the per-user owner check takes the local spelling of the owner
// own account, and refuses the local namesake of the directory account that
// runs the gateway: that spelling names a different account.
func TestGAP0759PerUserOwnerCheckTakesOnlyTheOwnerLocalSpelling(t *testing.T) {
	local := unixidentity.Account{Name: "short", UID: 1059}
	directory := unixidentity.Account{Name: "short@dclab.test", UID: 94408157}
	prevResolver, prevOwner, prevLocal := profileExplainResolver, profileExplainGatewayOwner, unixidentity.LocalSpellingAccounts
	t.Cleanup(func() {
		profileExplainResolver, profileExplainGatewayOwner, unixidentity.LocalSpellingAccounts = prevResolver, prevOwner, prevLocal
	})
	profileExplainResolver = func(context.Context) unixidentity.Resolver {
		return localSpellingResolver{accounts: []unixidentity.Account{local, directory}}
	}
	unixidentity.LocalSpellingAccounts = func(context.Context) (map[string]int, error) {
		return map[string]int{"short": 1059}, nil
	}
	for _, tc := range []struct {
		owner   unixidentity.Account
		user    string
		refused bool
	}{
		{local, `.\short`, false},
		{local, `.\SHORT`, false},
		{local, "1059", false},
		{directory, `.\short`, true},
		{directory, `.\SHORT`, true},
		{directory, "94408157", false},
		{local, `.\nobody`, true},
	} {
		profileExplainGatewayOwner = func() (string, string, bool) { return strconv.Itoa(tc.owner.UID), tc.owner.Name, true }
		err := perUserExplainRefusal(tc.user)
		if (err != nil) != tc.refused {
			t.Errorf("owner %s, --user %s: refusal %v; want refused=%v", tc.owner.Name, tc.user, err, tc.refused)
		}
	}
}
