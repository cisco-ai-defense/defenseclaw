// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

type spoolAccountsResolver struct {
	unixidentity.Resolver
	accounts map[int]unixidentity.Account
}

func (r spoolAccountsResolver) LookupUID(uid int) (unixidentity.Account, error) {
	if account, ok := r.accounts[uid]; ok {
		return account, nil
	}
	return unixidentity.Account{}, errors.New("no such user")
}

// p0-round GAP-1389: a managed Linux or macOS gateway had no enrolled-account
// table for the runtime owner lookup. Each trusted identity record of the
// hook guardian is an enrolled account, with the home the account database
// names; a uid that now holds another name, an unknown uid and a home that
// is not a folder of its own are left out.
func TestIdentityRecordsAreTheRuntimeEnrolledAccounts(t *testing.T) {
	resolver := spoolAccountsResolver{accounts: map[int]unixidentity.Account{
		1001: {Name: "dcr-rv15m1", UID: 1001, Home: "/home/dcr-rv15m1/"},
		1002: {Name: "renamed", UID: 1002, Home: "/home/renamed"},
		1003: {Name: "rootless", UID: 1003, Home: "/"},
	}}
	for _, tc := range []struct {
		record enterprisehooks.IdentitySpoolRecord
		want   sensor.Account
		ok     bool
	}{
		{enterprisehooks.IdentitySpoolRecord{Key: "1001", User: "dcr-rv15m1"}, sensor.Account{Name: "dcr-rv15m1", Home: "/home/dcr-rv15m1"}, true},
		{enterprisehooks.IdentitySpoolRecord{Key: "1002", User: "earlier"}, sensor.Account{}, false},
		{enterprisehooks.IdentitySpoolRecord{Key: "1003", User: "rootless"}, sensor.Account{}, false},
		{enterprisehooks.IdentitySpoolRecord{Key: "1004", User: "gone"}, sensor.Account{}, false},
		{enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1", User: "x"}, sensor.Account{}, false},
	} {
		got, ok := spoolRecordAccount(resolver, tc.record)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("record %+v: got %+v %t, want %+v %t", tc.record, got, ok, tc.want, tc.ok)
		}
	}
	setIdentitySpoolDir("")
	if accounts := aiRuntimeSpoolAccounts(); len(accounts) != 0 {
		t.Fatalf("a gateway without an identity spool listed accounts: %+v", accounts)
	}
}
