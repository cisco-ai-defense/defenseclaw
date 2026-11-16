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
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// #1197: only an enrolled Active Directory account that the system lists
// without its groups makes the caches stale, and the domains probed are
// those accounts' own: every one of them, not only the first, so a Mac with
// accounts in two domains asks each.
func TestDirectoryCachesStaleNamesTheADAccountsDomains(t *testing.T) {
	dir := t.TempDir()
	for _, record := range []IdentitySpoolRecord{
		{Key: "501", User: "admin", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}},
		{Key: "94401103", User: "ent-bob", Facts: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Domain: "DCLab.Test"}},
		{Key: "94401105", User: "emea-eve", Facts: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Domain: "emea.dclab.test"}},
		{Key: "94401106", User: "ent-ann", Facts: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Domain: "dclab.test"}},
		{Key: "94401104", User: "ent-ldap", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLDAP, Domain: "ldap.example.com"}},
	} {
		data, err := MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	accounts := []IdentitySpoolAccount{{UID: 501}, {UID: 94401105}, {UID: 94401104}, {UID: 94401103}, {UID: 94401106}, {UID: 94401199}}
	listed := map[int]bool{}
	lookup := func(uid int) bool { return listed[uid] }
	// Nothing names any account: only the AD ones count, each domain once.
	if domains := directoryCachesStale(dir, accounts, lookup); !slices.Equal(domains, []string{"dclab.test", "emea.dclab.test"}) {
		t.Fatalf("stale domains %v, want both AD domains", domains)
	}
	// The first domain's accounts are listed again, the second's are not.
	listed[94401103], listed[94401106] = true, true
	if domains := directoryCachesStale(dir, accounts, lookup); !slices.Equal(domains, []string{"emea.dclab.test"}) {
		t.Fatalf("stale domains %v, want only the domain still unlisted", domains)
	}
	listed[94401105] = true
	if domains := directoryCachesStale(dir, accounts, lookup); len(domains) != 0 {
		t.Fatalf("stale domains %v with every AD account listed: local, LDAP and unrecorded accounts do not count", domains)
	}
}

// The probe tries the domain's domain controllers from its SRV records on
// the LDAP port, falls back to the domain's own name, and refuses a name
// that is not a DNS domain without dialing.
func TestDomainControllerAnswers(t *testing.T) {
	prevSRV, prevDial := domainControllerSRV, domainControllerDial
	t.Cleanup(func() { domainControllerSRV, domainControllerDial = prevSRV, prevDial })
	var dialed []string
	up := map[string]bool{}
	domainControllerDial = func(_ context.Context, address string) error {
		dialed = append(dialed, address)
		if up[address] {
			return nil
		}
		return errors.New("connect: connection refused")
	}
	domainControllerSRV = func(_ context.Context, domain string) ([]*net.SRV, error) {
		if domain != "dclab.test" {
			return nil, errors.New("no such host")
		}
		return []*net.SRV{{Target: "dc1.dclab.test."}, {Target: "dc2.dclab.test."}}, nil
	}
	if DomainControllerAnswers(context.Background(), "DCLAB.TEST") {
		t.Fatal("answers with every domain controller away")
	}
	if !slices.Equal(dialed, []string{"dc1.dclab.test:389", "dc2.dclab.test:389"}) {
		t.Fatalf("dialed %v", dialed)
	}
	up["dc2.dclab.test:389"] = true
	if !DomainControllerAnswers(context.Background(), "dclab.test") {
		t.Fatal("dc2 answers")
	}
	dialed = nil
	up["other.example.com:389"] = true
	if !DomainControllerAnswers(context.Background(), "other.example.com") || !slices.Equal(dialed, []string{"other.example.com:389"}) {
		t.Fatalf("no SRV records: dialed %v, want the domain's own name", dialed)
	}
	dialed = nil
	for _, bad := range []string{"", "localhost", "-x.example.com", "a b.example.com", "x.example.com:389", "x..example.com"} {
		if DomainControllerAnswers(context.Background(), bad) {
			t.Fatalf("%q answered", bad)
		}
	}
	if len(dialed) != 0 {
		t.Fatalf("dialed %v for names that are not DNS domains", dialed)
	}
}

// The whole probe is bounded: the SRV lookup and every dial share one
// deadline of domainControllerProbeTimeout, even when the guardian context
// has none, so a resolver that hangs during the outage ends the probe as
// "no answer" before the next 15 second poll is long overdue.
func TestDomainControllerAnswersIsBounded(t *testing.T) {
	prevSRV, prevDial := domainControllerSRV, domainControllerDial
	t.Cleanup(func() { domainControllerSRV, domainControllerDial = prevSRV, prevDial })
	start := time.Now()
	var deadlines []time.Time
	domainControllerSRV = func(ctx context.Context, _ string) ([]*net.SRV, error) {
		d, _ := ctx.Deadline()
		deadlines = append(deadlines, d)
		return nil, errors.New("i/o timeout")
	}
	domainControllerDial = func(ctx context.Context, _ string) error {
		d, _ := ctx.Deadline()
		deadlines = append(deadlines, d)
		return errors.New("i/o timeout")
	}
	if DomainControllerAnswers(context.Background(), "dclab.test") {
		t.Fatal("answers with every lookup timing out")
	}
	if len(deadlines) != 2 {
		t.Fatalf("lookups %d, want the SRV lookup and one dial", len(deadlines))
	}
	for _, d := range deadlines {
		if d.IsZero() || d.Sub(start) > domainControllerProbeTimeout+time.Second || d != deadlines[0] {
			t.Fatalf("deadlines %v (start %v), want one shared deadline %v after the start", deadlines, start, domainControllerProbeTimeout)
		}
	}
}

// GAP-0092: the guardian lists the Active Directory domains whose domain
// controllers stopped answering for the gateway. The record is current for
// DirectoryUnreachableMaxAge, names only valid domains, is removed when none
// is away, and is not an account record (IdentitySpoolStale skips it).
func TestDirectoryUnreachableRecord(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := WriteDirectoryUnreachable(dir, []string{"DCLab.Test.", "emea.dclab.test", "not a domain", "dclab.test"}, now, nil); err != nil {
		t.Fatal(err)
	}
	if got := ReadDirectoryUnreachable(dir, nil, now.Add(time.Minute)); !slices.Equal(got, []string{"dclab.test", "emea.dclab.test"}) {
		t.Fatalf("domains = %v", got)
	}
	if got := ReadDirectoryUnreachable(dir, nil, now.Add(DirectoryUnreachableMaxAge+time.Second)); len(got) != 0 {
		t.Fatalf("an old record is trusted: %v", got)
	}
	if got := ReadDirectoryUnreachable(dir, nil, now.Add(-2*time.Minute)); len(got) != 0 {
		t.Fatalf("a record from the future is trusted: %v", got)
	}
	refuse := func(string, string) error { return os.ErrPermission }
	if got := ReadDirectoryUnreachable(dir, refuse, now); len(got) != 0 {
		t.Fatalf("an untrusted record is read: %v", got)
	}
	if _, key, stale := IdentitySpoolStale(dir, now.Add(2*time.Hour), time.Minute); stale || key != "" {
		t.Fatalf("IdentitySpoolStale counts the reachability record: %q %v", key, stale)
	}
	if err := WriteDirectoryUnreachable(dir, nil, now, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, DirectoryUnreachableFile)); !os.IsNotExist(err) {
		t.Fatalf("no domain away left the record: %v", err)
	}
	if err := WriteDirectoryUnreachable(dir, nil, now, nil); err != nil {
		t.Fatalf("removing an absent record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, DirectoryUnreachableFile), []byte(`{"v":1,"updated_at":"2027-01-15T08:00:00Z","domains":["dclab.test"],"x":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := ReadDirectoryUnreachable(dir, nil, time.Date(2027, 1, 15, 8, 0, 30, 0, time.UTC)); len(got) != 0 {
		t.Fatalf("a record with an unknown field is read: %v", got)
	}
}

// The guardian checks the domain controllers of the enrolled accounts'
// Active Directory domains only, each domain once.
func TestDirectoryADDomainsNamesTheEnrolledDomains(t *testing.T) {
	dir := t.TempDir()
	for _, record := range []IdentitySpoolRecord{
		{Key: "501", User: "admin", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal}},
		{Key: "94401103", User: "ent-bob", SSSDDomain: "DCLab.Test", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Domain: "DCLab.Test"}},
		{Key: "94401106", User: "ent-ann", SSSDDomain: "dclab.test", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Domain: "dclab.test"}},
		{Key: "94401104", User: "ent-ldap", SSSDDomain: "ldap.example.com", Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLDAP, Domain: "ldap.example.com"}},
	} {
		data, err := MarshalIdentitySpoolRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, record.Key+".json"), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	accounts := []IdentitySpoolAccount{{UID: 501}, {UID: 94401103}, {UID: 94401104}, {UID: 94401106}, {UID: 94401199}}
	if got := directoryADDomains(dir, accounts, nil); !slices.Equal(got, []string{"dclab.test"}) {
		t.Fatalf("domains = %v, want the AD domain once", got)
	}
	// A Mac checks the Active Directory domains; Linux asks SSSD about every
	// SSSD domain InfoPipe holds an enrolled account in (GAP-0191).
	want := []string{"dclab.test"}
	if runtime.GOOS == "linux" {
		want = []string{"dclab.test", "ldap.example.com"}
	}
	if got := DirectoryDomains(dir, accounts); !slices.Equal(got, want) {
		t.Fatalf("DirectoryDomains = %v, want %v", got, want)
	}
}
