// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Loop round 2, finding 1: the Windows enumerator keeps an account's record
// through a failed publication when the record still proves what the pass
// found, and withdraws it when the pass disproved it (GAP-0329).
func TestIdentitySpoolRecordStillProves(t *testing.T) {
	const sid, strict, users = "S-1-5-21-1-2-3-4001", "S-1-5-21-1-2-3-7000", "S-1-5-32-545"
	base := IdentitySpoolRecord{
		Key: sid, User: `CORP\alice`, UpdatedAt: time.Now().Add(-time.Hour), UPNSource: UPNSourceIdentityStore,
		Facts: useridentity.DirectoryFacts{
			UPN: "alice@corp.example", Principal: "alice@corp.example", Domain: "corp.example",
			Directory: useridentity.DirectoryActiveDirectory, TenantID: "tenant-a", Groups: []string{strict, `CORP\strict`, users, `BUILTIN\Users`},
		},
	}
	for _, tc := range []struct {
		name   string
		change func(*IdentitySpoolRecord)
		want   bool
	}{
		{"the same facts, a newer timestamp", func(r *IdentitySpoolRecord) { r.UpdatedAt = time.Now() }, true},
		{"group names not resolved this pass", func(r *IdentitySpoolRecord) { r.Facts.Groups = []string{users, strict} }, true},
		{"the UPN not resolved this pass", func(r *IdentitySpoolRecord) { r.Facts.UPN, r.Facts.Principal = "", "" }, true},
		{"the account name not resolved this pass", func(r *IdentitySpoolRecord) { r.User = "" }, true},
		{"a realm resolved only this pass", func(r *IdentitySpoolRecord) { r.Facts.Realm = "CORP.EXAMPLE" }, true},
		{"another connector address", func(r *IdentitySpoolRecord) { r.ConnectorEmails = map[string]string{"codex": "a@b.example"} }, true},
		{"a SID in another case", func(r *IdentitySpoolRecord) { r.Facts.Groups = []string{"s-1-5-21-1-2-3-7000", users} }, true},
		{"a group added", func(r *IdentitySpoolRecord) { r.Facts.Groups = append(r.Facts.Groups, "S-1-5-21-1-2-3-7001") }, false},
		{"a group removed", func(r *IdentitySpoolRecord) { r.Facts.Groups = []string{users} }, false},
		{"signed out", func(r *IdentitySpoolRecord) { r.Facts.GroupsPartial, r.Facts.Groups = true, nil }, false},
		{"another account name", func(r *IdentitySpoolRecord) { r.User = `CORP\bob` }, false},
		{"another UPN", func(r *IdentitySpoolRecord) { r.Facts.UPN = "bob@corp.example" }, false},
		{"another principal", func(r *IdentitySpoolRecord) { r.Facts.Principal = "bob@corp.example" }, false},
		{"another domain", func(r *IdentitySpoolRecord) { r.Facts.Domain = "lab.example" }, false},
		{"another directory", func(r *IdentitySpoolRecord) { r.Facts.Directory = useridentity.DirectoryEntraID }, false},
		{"another tenant", func(r *IdentitySpoolRecord) { r.Facts.TenantID = "tenant-b" }, false},
		{"another account", func(r *IdentitySpoolRecord) { r.Key = "S-1-5-21-1-2-3-4002" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := base
			current.Facts.Groups = append([]string(nil), base.Facts.Groups...)
			tc.change(&current)
			if got := IdentitySpoolRecordStillProves(base, current); got != tc.want {
				t.Errorf("IdentitySpoolRecordStillProves = %v, want %v", got, tc.want)
			}
		})
	}
	// Both signed out: their groups decide nothing.
	out := base
	out.Facts.GroupsPartial, out.Facts.Groups = true, []string{users}
	again := out
	again.Facts.Groups = nil
	if !IdentitySpoolRecordStillProves(out, again) {
		t.Error("two signed-out records of one account disagreed on groups that decide nothing")
	}
}
