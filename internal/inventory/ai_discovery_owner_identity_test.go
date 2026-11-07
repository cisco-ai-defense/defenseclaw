// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os/user"
	"testing"
)

// A per-user scan keeps the account database's full spelling for the
// gateway's current-holder check. The displayed short name is derived only
// when a record is emitted.
func TestGAP0619PerUserInventoryKeepsQualifiedAccountName(t *testing.T) {
	owner := processIDEOwner(&user.User{Uid: "700001", Username: "alice@corp.example"})
	if owner.id != "700001" || owner.name != "alice@corp.example" {
		t.Fatalf("inventory owner = %+v; want the full account spelling", owner)
	}
	local := processIDEOwner(&user.User{Uid: "700002", Username: "alice"})
	if local.id != "700002" || local.name != "alice" {
		t.Fatalf("local inventory owner = %+v", local)
	}
	windows := processIDEOwner(&user.User{Uid: "S-1-5-21-1-2-3-1105", Username: `CORP\alice`})
	if windows.name != "alice" {
		t.Fatalf("Windows inventory owner = %+v; want the existing short display name", windows)
	}
}
