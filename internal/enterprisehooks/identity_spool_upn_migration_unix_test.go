// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// W2B-G-enum review loop 5: on the first pass after an upgrade from 1.0.3,
// whose records have no SID, an InfoPipe answer without userPrincipalName
// dropped the UPN the previous record held, where 1.0.3 kept it for a day,
// and a users entry written as that UPN fell to the default profile. The
// guardian now asks the directory who holds the UPN: it stays when the
// directory gives it to the account (and the record gets the SID, so later
// passes need no lookup); it goes when the directory gives it to another
// account. r104 identity: a directory that does not answer proves nothing,
// so the UPN goes too (GAP-0384) and the gateway takes the unproven-UPN
// path, which selects the strictest profile that may apply.
func TestIdentitySpoolKeepsAnUpgradedRecordsUPNWhileTheDirectoryBindsIt(t *testing.T) {
	const uid = 94401601
	const upn = "alice.alt@alt.dclab.test"
	legacy := testDirectoryRecord(uid, "dcad-alice", "dclab.test")
	legacy.Facts.UPN, legacy.Facts.Principal, legacy.Facts.Source = upn, upn, useridentity.SourceSSSDInfoPipe
	answer := testDirectoryRecord(uid, "dcad-alice", "dclab.test")
	answer.AccountSID, answer.UPNSource, answer.Facts.UPN, answer.Facts.Principal = testAccountSID, UPNSourceDerived, "", "dcad-alice@DCLAB.TEST"
	answer.AccountIncarnation = testSameIncarnation
	previousCollect, previousBind := identitySpoolCollect, identitySpoolBindUPN
	t.Cleanup(func() { identitySpoolCollect, identitySpoolBindUPN = previousCollect, previousBind })
	identitySpoolCollect = func(context.Context, IdentitySpoolAccount, time.Time) (IdentitySpoolRecord, error) {
		fresh := answer
		fresh.UpdatedAt = time.Now().UTC()
		return fresh, nil
	}
	for _, tc := range []struct {
		name string
		// bindings are the directory's answers at successive passes.
		bindings []UPNBinding
		// kept and sid are the record after each pass.
		kept []bool
		sid  []string
		// asked is how many passes asked the directory.
		asked int
	}{
		{"the directory binds the UPN", []UPNBinding{UPNBindingBound, UPNBindingOther}, []bool{true, true}, []string{testAccountSID, testAccountSID}, 1},
		{"the directory does not answer", []UPNBinding{UPNBindingUnknown, UPNBindingBound},
			[]bool{false, false}, []string{testAccountSID, testAccountSID}, 1},
		{"another account holds the UPN", []UPNBinding{UPNBindingOther}, []bool{false}, []string{testAccountSID}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestSpoolRecord(t, dir, legacy)
			asked := 0
			for pass, binding := range tc.bindings {
				identitySpoolBindUPN = func(_ context.Context, gotUID int, domain, gotUPN string, notFoundIsOther bool) UPNBinding {
					asked++
					if gotUID != uid || domain != "dclab.test" || gotUPN != upn || !notFoundIsOther {
						t.Errorf("pass %d: asked about uid %d, domain %q, UPN %q, notFoundIsOther %v", pass+1, gotUID, domain, gotUPN, notFoundIsOther)
					}
					return binding
				}
				if err := WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: uid, User: "dcad-alice"}}, nil, nil, nil); err != nil {
					t.Fatal(err)
				}
				record, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(uid), nil)
				if err != nil {
					t.Fatal(err)
				}
				if kept := record.Facts.UPN == upn; kept != tc.kept[pass] || record.AccountSID != tc.sid[pass] {
					t.Fatalf("pass %d: record %+v: UPN kept %v with SID %q, want kept %v with SID %q",
						pass+1, record, kept, record.AccountSID, tc.kept[pass], tc.sid[pass])
				}
				if tc.kept[pass] && (record.UPNSource != UPNSourceInfoPipeKept || record.UPNKeptSince.IsZero()) {
					t.Fatalf("pass %d: kept record %+v, want infopipe_kept with its day bound", pass+1, record)
				}
			}
			if asked != tc.asked {
				t.Fatalf("the directory was asked at %d passes, want %d", asked, tc.asked)
			}
		})
	}
}
