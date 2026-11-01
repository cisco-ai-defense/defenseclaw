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

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// homeGoneFixture records five pending Hermes cleanups. dcad-gone and
// dcad-kept are removed macOS AD mobile accounts, whose directory home is
// now /var/empty: gone's recorded home no longer exists, kept's folder was
// kept (sysadminctl -deleteUser -keepHome). dcad-moved is a live account
// the directory re-homed to a path that does not exist while its recorded
// home is still there. The sample accounts have missing recorded homes,
// including one beneath an available automount parent. Their new homes
// have the wrong owner, so the guardian must not run a worker there.
func homeGoneFixture(t *testing.T) (f *standaloneFixture, resolver standaloneTestResolver, gone, kept, moved string) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	resolver = standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f = newStandaloneFixture(t, resolver)
	useReportingStandaloneRunner(t)
	gone = filepath.Join(f.homes, "dcad-gone") // removed with the mobile account
	kept = f.home(t, "dcad-kept", 0o700)
	moved = f.home(t, "dcad-moved", 0o700)
	automountParent := filepath.Join(f.homes, "sample-automount-parent")
	if err := os.Mkdir(automountParent, 0o755); err != nil {
		t.Fatal(err)
	}
	resolver.accounts["dcad-gone"] = unixidentity.Account{Name: "dcad-gone", UID: uid, GID: gid, Home: "/var/empty"}
	resolver.accounts["dcad-kept"] = unixidentity.Account{Name: "dcad-kept", UID: uid + 1, GID: gid, Home: "/var/empty"}
	resolver.accounts["dcad-moved"] = unixidentity.Account{Name: "dcad-moved", UID: uid + 2, GID: gid, Home: filepath.Join(f.homes, "dcad-moved-new")}
	// Both new homes belong to the test uid, not the accounts' uid+3/+4.
	resolver.accounts["sample-rehomed"] = unixidentity.Account{Name: "sample-rehomed", UID: uid + 3, GID: gid, Home: f.home(t, "sample-rehomed-new", 0o700)}
	resolver.accounts["sample-automount"] = unixidentity.Account{Name: "sample-automount", UID: uid + 4, GID: gid, Home: f.home(t, "sample-automount-new", 0o700)}
	f.writeManifest(t)
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{
		{Connector: "hermes", UID: uid, User: "dcad-gone", UserHome: gone, RecordedAt: "2026-10-14T00:00:00Z"},
		{Connector: "hermes", UID: uid + 1, User: "dcad-kept", UserHome: kept, RecordedAt: "2026-10-14T00:00:00Z"},
		{Connector: "hermes", UID: uid + 2, User: "dcad-moved", UserHome: moved, RecordedAt: "2026-10-14T00:00:00Z"},
		{Connector: "hermes", UID: uid + 3, User: "sample-rehomed", UserHome: filepath.Join(f.homes, "sample-rehomed-old"), RecordedAt: "2026-10-14T00:00:00Z"},
		{Connector: "hermes", UID: uid + 4, User: "sample-automount", UserHome: filepath.Join(automountParent, "sample-automount-old"), RecordedAt: "2026-10-14T00:00:00Z"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return f, resolver, gone, kept, moved
}

// A live account with an untrusted new home keeps its cleanup when the
// recorded home is missing. A trusted new home is covered by
// TestStandaloneCleanupRunsInTrustedCurrentHomeAndEndsRow.
func TestStandaloneCleanupKeepsRehomedTargetsWithUntrustedNewHomes(t *testing.T) {
	f, resolver, _, _, _ := homeGoneFixture(t)
	pending, err := loadEnterpriseHookUserCleanups(f.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	attempted := 0
	for _, entry := range pending {
		if entry.User != "sample-rehomed" && entry.User != "sample-automount" {
			continue
		}
		attempted++
		t.Run(entry.User, func(t *testing.T) {
			var log bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &log, entry, resolver)
			if outcome != enterpriseHookUserCleanupFailed || err == nil || errors.Is(err, errEnterpriseHookCleanupHomeGone) {
				t.Fatalf("live re-homed cleanup = %v, %v; want failed without home-gone retirement", outcome, err)
			}
			if !strings.Contains(err.Error(), "no longer matches the directory home") ||
				!strings.Contains(err.Error(), "owner uid=") || strings.Contains(log.String(), "home gone") {
				t.Fatalf("unexpected cleanup error or retirement log: %v; %s", err, log.String())
			}
		})
	}
	if attempted != 2 {
		t.Fatalf("tested %d live re-homed accounts, want two", attempted)
	}
	if len(f.workerTargets()) != 0 {
		t.Fatalf("no worker may run in an untrusted new home: %+v", f.workerTargets())
	}
}

// GAP-0543: the guardian retried forever the cleanup of a removed macOS AD
// mobile account, whose recorded home is gone and whose directory home is
// now /var/empty. It retires such a cleanup as "home gone", without also
// saying the cleanup was done (Codex F8). A kept home and live re-homed
// accounts whose new homes are missing or wrong-owner keep their cleanups;
// no trusted worker could remove those registrations.
func TestStandaloneCleanupRetiresATargetWhoseHomeIsGone(t *testing.T) {
	f, resolver, _, kept, moved := homeGoneFixture(t)
	var log bytes.Buffer
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &log, manifest,
		enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, time.Now()); err != nil {
		t.Fatal(err)
	}
	pending, err := loadEnterpriseHookUserCleanups(f.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 4 || pending[0].User != "dcad-kept" || pending[0].UserHome != kept ||
		!strings.Contains(pending[0].LastError, "no longer matches the directory home /var/empty, which is no home") ||
		pending[1].User != "dcad-moved" || pending[1].UserHome != moved ||
		!strings.Contains(pending[1].LastError, "no longer matches the directory home") || strings.Contains(pending[1].LastError, "no home") {
		t.Fatalf("the kept-home and untrusted new-home cleanups must stay with their errors: %+v", pending)
	}
	for i, name := range []string{"sample-automount", "sample-rehomed"} {
		entry := pending[i+2]
		if entry.User != name || !strings.Contains(entry.LastError, "no longer matches the directory home") ||
			!strings.Contains(entry.LastError, "owner uid=") || strings.Contains(entry.LastError, "which is no home") {
			t.Fatalf("live re-homed cleanup was retired or given the wrong error: %+v", entry)
		}
		if !strings.Contains(log.String(), "warn: per-user cleanup of hermes/"+name+": ") || strings.Contains(log.String(), "hermes/"+name+": home gone") {
			t.Fatalf("the guardian must warn and keep %s without retiring it: %s", name, log.String())
		}
	}
	if !strings.Contains(log.String(), "hermes/dcad-gone: home gone") {
		t.Fatalf("the guardian does not say why it retired the cleanup: %s", log.String())
	}
	if strings.Contains(log.String(), "hermes/dcad-gone: no longer enrolled; per-user cleanup done") {
		t.Fatalf("a cleanup retired as home gone removed nothing, so it may not be logged done: %s", log.String())
	}
	if !strings.Contains(log.String(), "warn: per-user cleanup of hermes/dcad-kept: ") {
		t.Fatalf("the guardian does not warn for the kept home it keeps retrying: %s", log.String())
	}
	if len(f.workerTargets()) != 0 {
		t.Fatalf("no worker may run in a home that is gone or mismatched: %+v", f.workerTargets())
	}
}

// GAP-0553: a managed uninstall stopped with per_user_hooks_remaining for
// removed AD mobile accounts with pending guardian cleanups. remove-all
// reports them as pending, each with a reason that names the recorded home
// (the uninstall warns and goes on): a home that is gone, and a kept home
// of an account the directory now gives /var/empty. A live account
// re-homed to a missing or wrong-owner new home stays a failure.
func TestRemoveAllReportsAPendingCleanupWhoseHomeIsGoneAsPending(t *testing.T) {
	_, _, gone, kept, _ := homeGoneFixture(t)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
	if len(report.Pending) != 2 || report.Removed != 0 ||
		!strings.HasPrefix(report.Pending[0], "dcad-gone/hermes: its recorded home "+gone+" is gone") ||
		!strings.HasPrefix(report.Pending[1], "dcad-kept/hermes: the directory gives the account no home (/var/empty)") ||
		!strings.Contains(report.Pending[1], "remove them from the hermes config in "+kept) {
		t.Fatalf("the cleanups of removed accounts must be reported pending with their recorded home, not removed: %+v", report)
	}
	for _, entry := range report.Pending {
		if strings.Contains(entry, "once it is") {
			t.Fatalf("a removed account's home will not become available: %q", entry)
		}
	}
	if len(report.Failed) != 3 || !strings.HasPrefix(report.Failed[0], "dcad-moved/hermes: ") ||
		!strings.HasPrefix(report.Failed[1], "sample-rehomed/hermes: ") ||
		!strings.HasPrefix(report.Failed[2], "sample-automount/hermes: ") ||
		skip[os.Getuid()+2] != enterpriseHookPurgeSkipFailed || skip[os.Getuid()+3] != enterpriseHookPurgeSkipFailed || skip[os.Getuid()+4] != enterpriseHookPurgeSkipFailed ||
		skip[os.Getuid()+1] != enterpriseHookPurgeSkipKeptHome || skip[os.Getuid()] != "" {
		t.Fatalf("untrusted new homes must fail, and a pending kept home must block purge: %+v, %v", report, skip)
	}
}

// The directory homes a removed or disabled account answers with are no
// home; a real path is one.
func TestEnterpriseHookDirectoryNoHome(t *testing.T) {
	for home, want := range map[string]bool{
		"/var/empty":   true,
		"/var/empty/":  true,
		"/dev/null":    true,
		"/nonexistent": true,
		"var/empty":    true,
		" ":            true,
		"/Users/dcad":  false,
		"/home/dcad":   false,
		"/var/root":    false,
	} {
		if got := enterpriseHookDirectoryNoHome(home); got != want {
			t.Errorf("enterpriseHookDirectoryNoHome(%q) = %v, want %v", home, got, want)
		}
	}
}

// A recorded home is gone only when its parent answers, holds other
// entries, and the home is not there: a missing parent, an empty parent (the
// mount point of an unmounted volume, GAP-0443) or a home that exists is not.
func TestEnterpriseHookRecordedHomeGone(t *testing.T) {
	root := t.TempDir()
	present := filepath.Join(root, "present")
	if err := os.Mkdir(present, 0o700); err != nil {
		t.Fatal(err)
	}
	mountPoint := filepath.Join(root, "mountpoint")
	if err := os.Mkdir(mountPoint, 0o755); err != nil {
		t.Fatal(err)
	}
	for home, want := range map[string]bool{
		filepath.Join(root, "missing"):              true,
		present:                                     false,
		filepath.Join(mountPoint, "missing"):        false,
		filepath.Join(root, "unmounted", "missing"): false,
		"relative/home":                             false,
		"/":                                         false,
	} {
		if got := enterpriseHookRecordedHomeGone(home); got != want {
			t.Errorf("enterpriseHookRecordedHomeGone(%q) = %v, want %v", home, got, want)
		}
	}
}
