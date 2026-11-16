// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

const (
	tokenGroupsAccount = "S-1-5-21-1-2-3-4001"
	tokenGroupsWeak    = "S-1-5-21-1-2-3-7001"
	tokenGroupsStrict  = "S-1-5-21-1-2-3-7000"
)

// tokenGroupsPrevious is an account's record that lists only the weak group.
func tokenGroupsPrevious() IdentitySpoolRecord {
	return IdentitySpoolRecord{Key: tokenGroupsAccount, User: `CORP\alice`, UpdatedAt: time.Now().Add(-10 * time.Minute).UTC(),
		UPNSource: UPNSourceIdentityStore, Facts: useridentity.DirectoryFacts{UPN: "alice@corp.example", Domain: "corp.example",
			Directory: useridentity.DirectoryActiveDirectory, Groups: []string{tokenGroupsWeak, `CORP\weak`}}}
}

// Loop round 3, finding 2: a Windows pass that cannot publish an account's
// record withdraws the previous one only when it read and disproved it. One
// it could not read is unknown: it stays, as the release writer left it.
func TestIdentitySpoolWithdrawnByFailedWrite(t *testing.T) {
	current := tokenGroupsPrevious()
	current.Facts.Groups = []string{tokenGroupsWeak, tokenGroupsStrict}
	for _, tc := range []struct {
		name        string
		previous    IdentitySpoolRecord
		previousErr error
		want        bool
	}{
		{"no previous record", IdentitySpoolRecord{}, os.ErrNotExist, false},
		{"an unreadable previous record", IdentitySpoolRecord{}, errors.New("parse identity spool record: unexpected EOF"), false},
		{"an untrusted previous record", IdentitySpoolRecord{}, os.ErrPermission, false},
		{"a previous record the pass disproved", tokenGroupsPrevious(), nil, true},
		{"a previous record the pass confirmed", current, nil, false},
	} {
		if got := IdentitySpoolWithdrawnByFailedWrite(tc.previous, tc.previousErr, current); got != tc.want {
			t.Errorf("%s: withdrawn = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Loop round 3, finding 3: when an account's directory lookups do not answer
// in time, the pass still publishes the token groups it holds for the
// account this cycle, over its previous record's facts, so a strict group
// the user gained applies at once instead of the old record's weaker one.
func TestIdentitySpoolTokenGroupRecord(t *testing.T) {
	now := time.Now().UTC()
	t.Run("a gained strict group is published over the previous facts", func(t *testing.T) {
		previous := tokenGroupsPrevious()
		record, publish := IdentitySpoolTokenGroupRecord(previous, nil, tokenGroupsAccount, []string{tokenGroupsWeak, tokenGroupsStrict}, true, now)
		if !publish {
			t.Fatal("changed token groups were not published")
		}
		if want := []string{tokenGroupsWeak, `CORP\weak`, tokenGroupsStrict}; !slices.Equal(record.Facts.Groups, want) {
			t.Fatalf("groups = %v, want %v", record.Facts.Groups, want)
		}
		if record.Facts.GroupsPartial || !record.UpdatedAt.Equal(now) || record.Key != tokenGroupsAccount {
			t.Fatalf("record = %+v, want current token groups dated now", record)
		}
		if record.User != previous.User || record.Facts.UPN != previous.Facts.UPN || record.Facts.Directory != previous.Facts.Directory ||
			record.UPNSource != previous.UPNSource {
			t.Fatalf("record = %+v, want the previous record's identity facts kept", record)
		}
		if !slices.Equal(previous.Facts.Groups, []string{tokenGroupsWeak, `CORP\weak`}) {
			t.Fatalf("the previous record was changed: %v", previous.Facts.Groups)
		}
	})
	t.Run("a removed group is published", func(t *testing.T) {
		previous := tokenGroupsPrevious()
		previous.Facts.Groups = []string{tokenGroupsWeak, `CORP\weak`, tokenGroupsStrict, `CORP\strict`}
		record, publish := IdentitySpoolTokenGroupRecord(previous, nil, tokenGroupsAccount, []string{tokenGroupsStrict}, true, now)
		if !publish || !slices.Equal(record.Facts.Groups, []string{tokenGroupsStrict, `CORP\strict`}) {
			t.Fatalf("record = %+v, publish %v; want only the strict group", record.Facts.Groups, publish)
		}
	})
	t.Run("a sign-out is published as unknown groups", func(t *testing.T) {
		record, publish := IdentitySpoolTokenGroupRecord(tokenGroupsPrevious(), nil, tokenGroupsAccount, []string{tokenGroupsWeak}, false, now)
		if !publish || !record.Facts.GroupsPartial || len(record.Facts.Groups) != 0 {
			t.Fatalf("record = %+v, publish %v; want groups unknown", record.Facts, publish)
		}
	})
	t.Run("no previous record and a signed-in session", func(t *testing.T) {
		record, publish := IdentitySpoolTokenGroupRecord(IdentitySpoolRecord{}, os.ErrNotExist, tokenGroupsAccount, []string{tokenGroupsStrict}, true, now)
		if !publish || !slices.Equal(record.Facts.Groups, []string{tokenGroupsStrict}) || record.Facts.GroupsPartial ||
			record.Key != tokenGroupsAccount || record.Facts.ResolvedAt.IsZero() {
			t.Fatalf("record = %+v, publish %v; want the token groups alone", record, publish)
		}
	})
	for _, tc := range []struct {
		name        string
		previous    IdentitySpoolRecord
		previousErr error
		groups      []string
		signedIn    bool
	}{
		{"the same token groups", tokenGroupsPrevious(), nil, []string{tokenGroupsWeak}, true},
		{"still signed out", IdentitySpoolRecord{Key: tokenGroupsAccount, Facts: useridentity.DirectoryFacts{GroupsPartial: true}}, nil,
			[]string{tokenGroupsWeak}, false},
		{"an unreadable previous record", IdentitySpoolRecord{}, errors.New("sharing violation"), []string{tokenGroupsStrict}, true},
		{"no previous record and no session", IdentitySpoolRecord{}, os.ErrNotExist, []string{tokenGroupsStrict}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if record, publish := IdentitySpoolTokenGroupRecord(tc.previous, tc.previousErr, tokenGroupsAccount, tc.groups, tc.signedIn, now); publish {
				t.Fatalf("published %+v; want the record left as it is", record)
			}
		})
	}
}

// The gateway reads a withdrawal like a record: trusted, regular, naming its
// key. A record file is not a withdrawal, and a withdrawal is no record.
func TestIdentitySpoolWithdrawalIsReadApartFromTheRecord(t *testing.T) {
	dir := t.TempDir()
	const key = "94401901"
	if _, err := ReadIdentitySpoolWithdrawal(dir, key, nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("withdrawal of an empty spool: %v", err)
	}
	at := time.Now().Add(-time.Minute).UTC()
	data, err := MarshalIdentitySpoolRecord(IdentitySpoolRecord{Key: key, UpdatedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, key+IdentitySpoolWithdrawalSuffix), data, 0o640); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadIdentitySpoolWithdrawal(dir, key, nil); err != nil || !got.Equal(at) {
		t.Fatalf("withdrawal = %v (%v), want %v", got, err, at)
	}
	if _, err := ReadIdentitySpoolRecord(dir, key, nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a withdrawal was read as a record: %v", err)
	}
	if records := ReadIdentitySpoolRecords(dir, nil, 10); len(records) != 0 {
		t.Fatalf("records = %+v, want none", records)
	}
	if _, _, stale := IdentitySpoolStale(dir, time.Now().Add(2*IdentitySpoolMaxAge), time.Minute); stale {
		t.Fatal("a withdrawal made the spool stale")
	}
	refused := errors.New("not the guardian's")
	if _, err := ReadIdentitySpoolWithdrawal(dir, key, func(string, string) error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("an untrusted withdrawal was accepted: %v", err)
	}
	if _, err := ReadIdentitySpoolWithdrawal(dir, "94401902", nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("another uid's withdrawal: %v", err)
	}
}
