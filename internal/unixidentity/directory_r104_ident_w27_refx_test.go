//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0677: on an sss-first host the gateway cannot ask sssctl whether an
// SSSD miss is definitive. The guardian has recorded that root-only fact for
// this account. The recorded lookup must carry it through the owner walk as
// well as the shared-uid check, then resolve the local account's groups.
func TestRecordedSSSDMissReachesLocalOwnerAndGroups(t *testing.T) {
	const uid = 49201
	line := "t7ar-u1:x:49201:49202::/home/t7ar-u1:/bin/bash\n"
	accountHost(t, line, "local-team:x:7000:t7ar-u1\n", "passwd: sss files\ninitgroups: files\ngroup: files\n")
	sssdConfiguredHost(t)
	startFakeSSSD(t, nil)
	previousEUID, previousOnline := sssdEUID, sssdDomainsOnline
	t.Cleanup(func() { sssdEUID, sssdDomainsOnline = previousEUID, previousOnline })
	sssdEUID, sssdDomainsOnline = func() int { return 1001 }, sssctlDomainsOnline
	run := &fakeRun{results: map[string]commandResult{
		"passwd 49201":          {stdout: []byte(line)},
		"-s files passwd 49201": {stdout: []byte(line)},
	}}
	r := newFakeNSS(run)
	if _, err := r.DirectoryFactsForUID(uid, time.Now()); !UnsharedUIDNeedsRoot(err) {
		t.Fatalf("ordinary lookup = %v; want the root-only SSSD absence proof", err)
	}
	facts, err := r.DirectoryFactsForRecordedUnsharedUID(uid, time.Now())
	if err != nil || facts.Directory != useridentity.DirectoryLocal || facts.Source != useridentity.SourceNSSFiles ||
		!slices.Contains(facts.Groups, "local-team") || !slices.Contains(facts.Groups, "49202") {
		t.Fatalf("recorded lookup = %+v, %v; want the confirmed local account and groups", facts, err)
	}
	if got, known := r.AccountIncarnation(uid, "t7ar-u1"); known || got != "" {
		t.Fatalf("ordinary incarnation = %q, %v; want unknown without guardian proof", got, known)
	}
	if got, known := r.AccountIncarnationForRecordedUnsharedUID(uid, "t7ar-u1"); !known || got != "files" {
		t.Fatalf("recorded incarnation = %q, %v; want files", got, known)
	}
	if got, known := r.AccountIncarnationForRecordedUnsharedUID(uid, "other-user"); known || got != "" {
		t.Fatalf("another account's incarnation = %q, %v; want unknown", got, known)
	}

	// A new SSSD holder must defeat the guardian's earlier proof even when
	// the account has the same name and uid as the local entry.
	sharedLine := "t7ar-u1:*:49201:49202:SSSD user:/home/t7ar-u1:/bin/bash\n"
	run.results["passwd 49201"] = commandResult{stdout: []byte(sharedLine)}
	run.results["-s sss passwd 49201"] = commandResult{stdout: []byte(sharedLine)}
	if got, known := r.AccountIncarnationForRecordedUnsharedUID(uid, "t7ar-u1"); !known || got == "files" {
		t.Fatalf("new SSSD holder incarnation = %q, %v; want a non-local owner", got, known)
	}
	if facts, err := r.DirectoryFactsForRecordedUnsharedUID(uid, time.Now()); !isSharedUID(err) {
		t.Fatalf("new SSSD holder facts = %+v, %v; want shared uid", facts, err)
	}
	delete(run.results, "-s sss passwd 49201")
	run.results["passwd 49201"] = commandResult{stdout: []byte(line)}
	sssdDomainsOnline = func(context.Context) error { return errors.New("SSSD domain offline") }
	if facts, err := r.DirectoryFactsForRecordedUnsharedUID(uid, time.Now()); err == nil ||
		facts.Directory == useridentity.DirectoryLocal {
		t.Fatalf("offline SSSD facts = %+v, %v; the recorded proof covers only the root check", facts, err)
	}

	// The same root record also works when files leads passwd. That order
	// confirms the local holder first but must still check the later SSSD
	// source for a second holder before accepting the account and groups.
	writeTestFile(t, nsswitchPath, "passwd: files sss\ninitgroups: files\ngroup: files\n")
	sssdDomainsOnline = sssctlDomainsOnline
	facts, err = r.DirectoryFactsForRecordedUnsharedUID(uid, time.Now())
	if err != nil || facts.Directory != useridentity.DirectoryLocal || facts.Source != useridentity.SourceNSSFiles ||
		!slices.Contains(facts.Groups, "local-team") || !slices.Contains(facts.Groups, "49202") {
		t.Fatalf("files-first recorded lookup = %+v, %v; want the confirmed local account and groups", facts, err)
	}
}

func isSharedUID(err error) bool {
	var shared *SharedUIDError
	return errors.As(err, &shared)
}
