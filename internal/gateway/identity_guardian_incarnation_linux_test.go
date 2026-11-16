// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of GAP-0551 (loop 2): CORP's alice and OTHER's alice hold one uid
// in turn under one bare name. Until the guardian's next pass its record of
// the uid is CORP's, with the uid's key and the bare name. The gateway lays
// a record only over the facts of the account whose incarnation it names, so
// OTHER's alice gets neither CORP's domain, UPN and principal nor the
// profile assigned to them; nor does it from a record an older guardian
// wrote without an incarnation, or while the incarnation cannot be told.
func TestGuardianRecordOfAPriorHolderIsNotLaidOver(t *testing.T) {
	const uid = 41301
	key := strconv.Itoa(uid)
	const corp, other = "sid:S-1-5-21-1-1-1-1301", "sid:S-1-5-21-2-2-2-1301"
	dir := t.TempDir()
	write := func(incarnation string) {
		t.Helper()
		data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
			Key: key, User: "alice", UpdatedAt: time.Now().UTC(), SSSDDomain: "corp.example", AccountIncarnation: incarnation,
			UPNSource: enterprisehooks.UPNSourceInfoPipe,
			Facts: useridentity.DirectoryFacts{Source: useridentity.SourceSSSDInfoPipe, Domain: "corp.example", Realm: "CORP.EXAMPLE",
				UPN: "alice@corp.example", Principal: "alice@corp.example", Directory: useridentity.DirectoryActiveDirectory},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousValidate, previousDir, previousIncarnation := validateManagedGuardianAuthorization, currentIdentitySpoolDir(), managedHookPeerAccountIncarnation
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	setIdentitySpoolDir(dir)
	t.Cleanup(func() {
		validateManagedGuardianAuthorization, managedHookPeerAccountIncarnation = previousValidate, previousIncarnation
		setIdentitySpoolDir(previousDir)
	})
	holds := func(incarnation string, known bool) {
		managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return incarnation, known }
	}
	alice := unixidentity.Account{Name: "alice", UID: uid, Home: "/home/alice"}
	own := useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Domain: "other.example", Realm: "OTHER.EXAMPLE",
		Directory: useridentity.DirectoryActiveDirectory, Groups: []string{"other-open"}}
	facts := func() useridentity.DirectoryFacts {
		record, ok, _ := holderSpoolRecord(key, alice, "", time.Now())
		if !ok {
			return own
		}
		return mergeSpoolFacts(own, record)
	}
	notCorps := func(step string) {
		t.Helper()
		if got := facts(); got.UPN != "" || got.Principal != "" || got.Domain != "other.example" || got.Realm != "OTHER.EXAMPLE" {
			t.Fatalf("%s: OTHER's alice got %+v; want its own facts, not CORP's record", step, got)
		}
	}
	write(corp)
	holds(other, true)
	notCorps("CORP's record, OTHER holds the uid")
	holds("", false)
	notCorps("CORP's record, incarnation unknown")
	write("")
	holds(other, true)
	notCorps("a record without an incarnation")
	write(corp)
	holds(corp, true)
	if got := facts(); got.UPN != "alice@corp.example" || got.Principal != "alice@corp.example" {
		t.Fatalf("CORP's alice got %+v; want the UPN of its own record", got)
	}
}
