// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// ownNameResolver answers one local account.
type ownNameResolver struct{ account unixidentity.Account }

func (r ownNameResolver) LookupUser(name string) (unixidentity.Account, error) {
	if name == r.account.Name {
		return r.account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (r ownNameResolver) LookupUID(uid int) (unixidentity.Account, error) {
	if uid == r.account.UID {
		return r.account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (ownNameResolver) LookupGroupID(int) (unixidentity.Group, error) {
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (ownNameResolver) LookupGroup(string) (unixidentity.Group, error) {
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (ownNameResolver) GroupIDs(unixidentity.Account) ([]int, error) { return nil, nil }

func (ownNameResolver) ListUsers() ([]unixidentity.Account, bool, error) { return nil, false, nil }

// GAP-0269: on an AD-joined Linux host whose sssd.conf only root can read, a
// per-user gateway cannot tell whether a directory account shares a bare
// name (GAP-1131), and `profile explain --user <own name> --json` exited 1
// while the uid and no --user resolved. The account the per-user gateway runs
// as is the caller's own and resolves; a root gateway, another account's name
// and a name with a known twin keep their refusals.
func TestProfileExplainOwnNameOnAPerUserGatewayResolves(t *testing.T) {
	own := unixidentity.Account{Name: "r107sw7p", UID: 1059}
	unknown := &useridentity.NamesakesUnknownError{Name: own.Name, Err: errors.New("sssd.conf is readable by root only")}
	prevResolver, prevUID, prevTwins := profileExplainResolver, profileExplainGatewayUID, sameNameProfileAccounts
	t.Cleanup(func() {
		profileExplainResolver, profileExplainGatewayUID, sameNameProfileAccounts = prevResolver, prevUID, prevTwins
	})
	profileExplainResolver = func(context.Context) unixidentity.Resolver { return ownNameResolver{account: own} }
	cases := []struct {
		name       string
		gatewayUID int
		twins      []unixidentity.Account
		twinErr    error
		wantID     string
		wantErr    any
	}{
		{name: "own name, per-user gateway", gatewayUID: 1059, twinErr: unknown, wantID: "1059"},
		{name: "own name, root gateway", gatewayUID: 0, twinErr: unknown, wantErr: new(*useridentity.NamesakesUnknownError)},
		{name: "another account's name", gatewayUID: 1060, twinErr: unknown, wantErr: new(*useridentity.NamesakesUnknownError)},
		{name: "own name with a known twin", gatewayUID: 1059,
			twins:   []unixidentity.Account{{Name: "r107sw7p@dclab.test", UID: 94401116}},
			wantErr: new(*useridentity.AmbiguousAccountError)},
		{name: "twins ruled out", gatewayUID: 1060, wantID: "1059"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profileExplainGatewayUID = func() int { return tc.gatewayUID }
			sameNameProfileAccounts = func(context.Context, unixidentity.Resolver, string, unixidentity.Account) ([]unixidentity.Account, error) {
				return tc.twins, tc.twinErr
			}
			id, name, err := profileExplainAccount(own.Name)
			if tc.wantErr != nil {
				if err == nil || !errors.As(err, tc.wantErr) {
					t.Fatalf("profileExplainAccount(%q) = %q, %q, %v; want %T", own.Name, id, name, err, tc.wantErr)
				}
				return
			}
			if err != nil || id != tc.wantID || name != own.Name {
				t.Fatalf("profileExplainAccount(%q) = %q, %q, %v; want %s", own.Name, id, name, err, tc.wantID)
			}
		})
	}
}
