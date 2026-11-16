// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	"testing"
)

// GAP-1183: a qualified filter for a deleted directory account lists only
// SIDs of the domain it names.
func TestRemovedAccountFilterKeepsWindowsDomainsApart(t *testing.T) {
	previous := windowsSIDDomainName
	windowsSIDDomainName = func(sid string) string {
		return map[string]string{"S-1-5-21-1-2-3-1201": "CORP", "S-1-5-21-9-8-7-1201": "OTHER"}[sid]
	}
	t.Cleanup(func() { windowsSIDDomainName = previous })
	if !adminViewDomainCouldHold(`CORP\alice`, "S-1-5-21-1-2-3-1201") {
		t.Fatal("the deleted CORP account is not listed by CORP\\alice")
	}
	if adminViewDomainCouldHold(`CORP\alice`, "S-1-5-21-9-8-7-1201") {
		t.Fatal("the deleted OTHER account is listed by CORP\\alice")
	}
	if adminViewDomainCouldHold(`CORP\alice`, "S-1-5-21-5-5-5-1201") {
		t.Fatal("a SID of a domain the LSA does not name is listed by CORP\\alice")
	}
}

// Review of GAP-1261: the Windows resolver reads .\name, which
// LookupAccountName does not take, and a bare name among this computer's
// own groups, the BUILTIN groups included.
func TestWindowsLocalGroupSpellingsResolve(t *testing.T) {
	const administrators = "S-1-5-32-544"
	for _, name := range []string{`.\Administrators`, `BUILTIN\Administrators`} {
		if sid, err := lsaProfileGroupSID(name); err != nil || sid != administrators {
			t.Fatalf("lsaProfileGroupSID(%s) = %q, %v; want %s", name, sid, err, administrators)
		}
	}
	if sid, err := profileGroupLocalSIDLookup("Administrators"); err != nil || sid != administrators {
		t.Fatalf("local lookup of the bare name = %q, %v; want %s", sid, err, administrators)
	}
	const missing = "dc-r104-no-such-group"
	if _, err := lsaProfileGroupSID(`.\` + missing); !errors.Is(err, errProfileGroupUnknown) {
		t.Fatalf(".\\%s: %v, want errProfileGroupUnknown", missing, err)
	}
	if _, err := profileGroupLocalSIDLookup(missing); !errors.Is(err, errProfileGroupUnknown) {
		t.Fatalf("local lookup of %s: %v, want errProfileGroupUnknown", missing, err)
	}
	if exists, err := profileGroupExists(context.Background(), `.\Users`); err != nil || !exists {
		t.Fatalf(".\\Users exists = %v, %v", exists, err)
	}
	if !profileGroupLocalName(`.\Users`) {
		t.Fatal(".\\Users is not classified as a group of this computer")
	}
}
