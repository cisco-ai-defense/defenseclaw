// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterprisehooks

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

// W2B-G-enum review loop 5: the directory binds a UPN an earlier pass
// verified to the account when SSSD finds the user by that UPN under the
// account's uid in its SSSD domain. A user found under another uid or in
// another domain holds it instead. A not-found answer means the UPN is gone
// only for an account SSSD holds a SID for (Active Directory, which SSSD
// searches by UPN); any failure proves nothing.
func TestBindIdentitySpoolUPNAsksSSSDWhoHoldsTheUPN(t *testing.T) {
	previous := infoPipeUserByName
	t.Cleanup(func() { infoPipeUserByName = previous })
	notFound := dbus.Error{Name: infoPipeNotFound}
	for _, tc := range []struct {
		name            string
		uid             int
		domain          string
		err             error
		notFoundIsOther bool
		want            UPNBinding
	}{
		{name: "the account holds it", uid: 94401601, domain: "dclab.test", want: UPNBindingBound},
		{name: "the account holds it, domain in another case", uid: 94401601, domain: "DCLAB.TEST", want: UPNBindingBound},
		{name: "another uid holds it", uid: 94401777, domain: "dclab.test", want: UPNBindingOther},
		{name: "another SSSD domain holds it", uid: 94401601, domain: "other.test", want: UPNBindingOther},
		{name: "no account holds it (Active Directory)", err: notFound, notFoundIsOther: true, want: UPNBindingOther},
		{name: "not found in a directory SSSD may not search by UPN", err: notFound, want: UPNBindingUnknown},
		{name: "InfoPipe does not answer", err: errors.New("sssd.service is not active"), notFoundIsOther: true, want: UPNBindingUnknown},
		{name: "the lookup times out", err: context.DeadlineExceeded, notFoundIsOther: true, want: UPNBindingUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asked := ""
			infoPipeUserByName = func(_ context.Context, name string) (int, string, error) {
				asked = name
				return tc.uid, tc.domain, tc.err
			}
			if got := bindIdentitySpoolUPN(context.Background(), 94401601, "dclab.test", "alice.alt@alt.dclab.test", tc.notFoundIsOther); got != tc.want {
				t.Fatalf("binding %d, want %d", got, tc.want)
			}
			if asked != "alice.alt@alt.dclab.test" {
				t.Fatalf("SSSD asked about %q, want the UPN", asked)
			}
		})
	}
}
