// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"testing"
)

// GAP-1949 (RV4-4): a uid filter hides the rows another holder of the uid
// left only while an account holds the uid. A uid nobody holds now lists
// every holder's rows, as before.
func TestUIDFilterOfAUIDNobodyHoldsHidesNoRows(t *testing.T) {
	previous := userScopedIdentityName
	t.Cleanup(func() { userScopedIdentityName = previous })
	names := map[string]string{"1006": "r4a"}
	userScopedIdentityName = func(id string) string { return names[id] }
	if got := adminViewBareAccountIDs("1006"); len(got) != 1 || got[0] != "1006" {
		t.Fatalf("held uid: %v; want [1006]", got)
	}
	if got := adminViewBareAccountIDs("1007"); got != nil {
		t.Fatalf("uid nobody holds: %v; want none", got)
	}
}
