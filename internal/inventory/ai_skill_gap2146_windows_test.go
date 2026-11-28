// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-2146: a deny entry for a group the account is in takes the right away,
// though an allow entry for Users gives it. The access list is read with the
// account's groups (AuthzAccessCheck), not only the entries that name the
// account or every account. Needs an elevated process: the account is an
// administrator, so it is in the Administrators group the deny entry names.
func TestGAP2146WindowsDenyEntryForAGroupTheAccountIsInRefuses(t *testing.T) {
	admins, me := gap2008Administrators(t), gap2008Me(t)
	home := t.TempDir()
	gap2008Secure(t, home, me, gap2008AdminOnly+"(A;OICI;FA;;;"+me.String()+")")
	member, err := windows.GetCurrentProcessToken().IsMember(admins)
	if err != nil || !member {
		t.Skipf("the account is not in Administrators (%v): run elevated", err)
	}
	trust := skillHomeOwnerTrust(home)
	folder := func(name, dacl string) string {
		dir := filepath.Join(home, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		gap2008Secure(t, dir, admins, dacl)
		return dir
	}
	allowed := folder("allowed", "(A;OICI;FA;;;SY)"+gap2008UsersRead)
	denied := folder("denied", "(D;OICI;0x1;;;BA)(A;OICI;FA;;;SY)"+gap2008UsersRead)
	if !trust(nil, allowed) {
		t.Fatalf("%s: a folder Users may list is not trusted", allowed)
	}
	if trust(nil, denied) {
		t.Fatalf("%s: a folder a group the account is in may not list is trusted", denied)
	}
}
