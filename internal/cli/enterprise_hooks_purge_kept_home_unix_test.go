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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// A pending cleanup for one connector keeps a removed account's state while
// another connector's manifest row is removed. An unrelated enrolled account
// still gets its purge.
func TestRemoveAllPurgeKeepsStateForAPendingCleanupWithAKeptHome(t *testing.T) {
	keptUID, otherUID, gid := os.Getuid()+1, os.Getuid()+2, os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"sample-kept": {Name: "sample-kept", UID: keptUID, GID: gid, Home: "/var/empty"},
	}}
	f := newStandaloneFixture(t, resolver)
	keptHome := f.home(t, "sample-kept", 0o700)
	otherHome := f.home(t, "sample-enrolled", 0o700)
	enterpriseHookCheckHome = func(home string, uid int) enterprisehooks.HomeCheck {
		if (home == keptHome && uid == keptUID) || (home == otherHome && uid == otherUID) {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-kept", UID: &keptUID, GID: &gid, UserHome: keptHome},
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-enrolled", UID: &otherUID, GID: &gid, UserHome: otherHome},
	)
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	rows := resolveEnterpriseHookRemoveRows(manifest)
	jobs, pendingRows, failedRows := enterpriseHookRemoveJobs(rows)
	if len(pendingRows) != 0 || len(failedRows) != 0 || !enterpriseHookJobRemoves(jobs[keptUID], "codex") || !enterpriseHookJobRemoves(jobs[otherUID], "codex") {
		t.Fatalf("manifest removal jobs: pending=%v failed=%v jobs=%+v", pendingRows, failedRows, jobs)
	}
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{{
		Connector: "hermes", UID: keptUID, User: "sample-kept", UserHome: keptHome, RecordedAt: "2026-10-14T00:00:00Z",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	failed := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
	if len(report.Pending) != 1 || !strings.HasPrefix(report.Pending[0], "sample-kept/hermes: ") || len(report.Failed) != 0 || failed[keptUID] != enterpriseHookPurgeSkipKeptHome || failed[otherUID] != "" {
		t.Fatalf("pending cleanup must protect the kept home without failing uninstall: %+v, %v", report, failed)
	}
	notPurged := addEnterpriseHookStatePurges(jobs, rows, failed)
	if len(notPurged) != 1 || notPurged[0] != "sample-kept: "+enterpriseHookPurgeSkipKeptHome ||
		strings.Contains(notPurged[0], enterpriseHookPurgeSkipFailed) {
		t.Fatalf("purge must name the account whose state stays: %v", notPurged)
	}
	for _, target := range jobs[keptUID].Request.Targets {
		if target.Mode == enterpriseHookWorkerModePurge {
			t.Fatalf("purge scheduled for account with a pending cleanup: %+v", target)
		}
	}
	purges := 0
	for _, target := range jobs[otherUID].Request.Targets {
		if target.Mode == enterpriseHookWorkerModePurge && target.Options.DataDir == filepath.Join(otherHome, ".defenseclaw") {
			purges++
		}
	}
	if purges != 1 {
		t.Fatalf("unrelated enrolled account got %d purges, want one: %+v", purges, jobs[otherUID].Request.Targets)
	}
}

func purgeTestJobs(t *testing.T, f *standaloneFixture, targets ...enterprisehooks.ManifestTarget) (map[int]*enterpriseHookWorkerJob, []enterpriseHookRemoveRow) {
	t.Helper()
	f.writeManifest(t, targets...)
	manifest, err := enterprisehooks.LoadManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	rows := resolveEnterpriseHookRemoveRows(manifest)
	jobs, pending, failed := enterpriseHookRemoveJobs(rows)
	if len(pending) != 0 || len(failed) != 0 || len(jobs) != len(targets) {
		t.Fatalf("manifest removal jobs: pending=%v failed=%v jobs=%+v", pending, failed, jobs)
	}
	return jobs, rows
}

func purgeTestTargetCount(t *testing.T, job *enterpriseHookWorkerJob, want int) {
	t.Helper()
	if job == nil {
		t.Fatal("missing removal job")
	}
	got := 0
	for _, target := range job.Request.Targets {
		if target.Mode == enterpriseHookWorkerModePurge {
			got++
			if target.Options.DataDir != filepath.Join(job.Account.Home, ".defenseclaw") {
				t.Fatalf("purge targets wrong data directory: %+v", target)
			}
		}
	}
	if got != want {
		t.Fatalf("purge targets for %s = %d, want %d: %+v", job.Account.User, got, want, job.Request.Targets)
	}
}

func TestRemoveAllPurgeKeepsStateWhenPendingDirectoryUnavailable(t *testing.T) {
	uid, otherUID, gid := os.Getuid()+1, os.Getuid()+2, os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{"sample-sssd": true}}
	f := newStandaloneFixture(t, resolver)
	home := f.home(t, "sample-sssd", 0o700)
	otherHome := f.home(t, "sample-enrolled", 0o700)
	resolver.accounts["sample-sssd"] = unixidentity.Account{Name: "sample-sssd", UID: uid, GID: gid, Home: home}
	enterpriseHookCheckHome = func(h string, u int) enterprisehooks.HomeCheck {
		if (h == home && u == uid) || (h == otherHome && u == otherUID) {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	jobs, rows := purgeTestJobs(t, f,
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-sssd", UID: &uid, GID: &gid, UserHome: home},
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-enrolled", UID: &otherUID, GID: &gid, UserHome: otherHome},
	)
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{{
		Connector: "hermes", UID: uid, User: "sample-sssd", UserHome: home, RecordedAt: "2026-10-14T00:00:00Z",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{OK: true}
	skip := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
	if !report.OK || len(report.Failed) != 0 || len(report.Pending) != 1 || report.Pending[0] != "sample-sssd/hermes" ||
		skip[uid] != enterpriseHookPurgeSkipPending || skip[otherUID] != "" {
		t.Fatalf("directory outage must leave cleanup pending and skip its uid: report=%+v skip=%v", report, skip)
	}
	notPurged := addEnterpriseHookStatePurges(jobs, rows, skip)
	if len(notPurged) != 1 || notPurged[0] != "sample-sssd: "+enterpriseHookPurgeSkipPending {
		t.Fatalf("pending cleanup purge reason: %v", notPurged)
	}
	purgeTestTargetCount(t, jobs[uid], 0)
	purgeTestTargetCount(t, jobs[otherUID], 1)
}

func TestRemoveAllPurgeKeepsStateWhenPendingHomeUnavailable(t *testing.T) {
	uid, otherUID, gid := os.Getuid()+1, os.Getuid()+2, os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	home := f.home(t, "sample-slow", 0o700)
	otherHome := f.home(t, "sample-enrolled", 0o700)
	resolver.accounts["sample-slow"] = unixidentity.Account{Name: "sample-slow", UID: uid, GID: gid, Home: home}
	checks := 0
	enterpriseHookCheckHome = func(h string, u int) enterprisehooks.HomeCheck {
		if h == home && u == uid {
			checks++
			if checks > 1 {
				return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending}
			}
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		}
		if h == otherHome && u == otherUID {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	jobs, rows := purgeTestJobs(t, f,
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-slow", UID: &uid, GID: &gid, UserHome: home},
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-enrolled", UID: &otherUID, GID: &gid, UserHome: otherHome},
	)
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{{
		Connector: "hermes", UID: uid, User: "sample-slow", UserHome: home, RecordedAt: "2026-10-14T00:00:00Z",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{OK: true}
	skip := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
	if checks < 2 || !report.OK || len(report.Failed) != 0 || len(report.Pending) != 1 || report.Pending[0] != "sample-slow/hermes" ||
		skip[uid] != enterpriseHookPurgeSkipPending || skip[otherUID] != "" {
		t.Fatalf("unavailable home must leave cleanup pending and skip its uid: checks=%d report=%+v skip=%v", checks, report, skip)
	}
	notPurged := addEnterpriseHookStatePurges(jobs, rows, skip)
	if len(notPurged) != 1 || notPurged[0] != "sample-slow: "+enterpriseHookPurgeSkipPending {
		t.Fatalf("pending cleanup purge reason: %v", notPurged)
	}
	purgeTestTargetCount(t, jobs[uid], 0)
	purgeTestTargetCount(t, jobs[otherUID], 1)
}

func TestRemoveAllPurgeSkipsEveryAccountWhenCleanupLedgerUnreadable(t *testing.T) {
	uid, otherUID, gid := os.Getuid()+1, os.Getuid()+2, os.Getgid()
	f := newStandaloneFixture(t, standaloneTestResolver{})
	home := f.home(t, "sample-first", 0o700)
	otherHome := f.home(t, "sample-second", 0o700)
	enterpriseHookCheckHome = func(h string, u int) enterprisehooks.HomeCheck {
		if (h == home && u == uid) || (h == otherHome && u == otherUID) {
			return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
		}
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeUntrusted}
	}
	jobs, rows := purgeTestJobs(t, f,
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-first", UID: &uid, GID: &gid, UserHome: home},
		enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-second", UID: &otherUID, GID: &gid, UserHome: otherHome},
	)
	if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{{
		Connector: "hermes", UID: uid, User: "sample-first", UserHome: home, RecordedAt: "2026-10-14T00:00:00Z",
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enterpriseHookUserCleanupPath(f.dataDir), []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	report := enterpriseHooksRemoveAllReport{}
	skip := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
	if len(report.Failed) != 1 || !strings.HasPrefix(report.Failed[0], "pending per-user cleanups: ") ||
		skip[uid] != enterpriseHookPurgeSkipUnreadableLedger || skip[otherUID] != enterpriseHookPurgeSkipUnreadableLedger {
		t.Fatalf("unreadable ledger must skip every worker uid: report=%+v skip=%v", report, skip)
	}
	notPurged := addEnterpriseHookStatePurges(jobs, rows, skip)
	if len(notPurged) != 2 || notPurged[0] != "sample-first: "+enterpriseHookPurgeSkipUnreadableLedger ||
		notPurged[1] != "sample-second: "+enterpriseHookPurgeSkipUnreadableLedger {
		t.Fatalf("unreadable ledger purge reasons: %v", notPurged)
	}
	purgeTestTargetCount(t, jobs[uid], 0)
	purgeTestTargetCount(t, jobs[otherUID], 0)
}

func TestRemoveAllPurgeSkipReasonPrefersFailure(t *testing.T) {
	for _, connectors := range [][]string{{"amp", "hermes"}, {"hermes", "amp"}} {
		t.Run(strings.Join(connectors, "-"), func(t *testing.T) {
			uid, gid := os.Getuid()+1, os.Getgid()
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			home := f.home(t, "sample-order", 0o700)
			resolver.accounts["sample-order"] = unixidentity.Account{Name: "sample-order", UID: uid, GID: gid, Home: home}
			enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
				return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
			}
			jobs, rows := purgeTestJobs(t, f, enterprisehooks.ManifestTarget{Connector: "codex", User: "sample-order", UID: &uid, GID: &gid, UserHome: home})
			enterpriseHookWorkerRunner = func(_ context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				target := request.Targets[0]
				result := enterpriseHookWorkerTargetResult{Index: target.Index}
				if target.Options.ConnectorName == "hermes" {
					result.Pending = true
				} else {
					result.Error = "sample cleanup failure"
				}
				return enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion, Targets: []enterpriseHookWorkerTargetResult{result}}, nil
			}
			entries := make([]enterpriseHookUserCleanup, 0, 2)
			for _, connector := range connectors {
				entries = append(entries, enterpriseHookUserCleanup{Connector: connector, UID: uid, User: "sample-order", UserHome: home, RecordedAt: "2026-10-14T00:00:00Z"})
			}
			if err := saveEnterpriseHookUserCleanups(f.dataDir, entries, time.Now()); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
			notPurged := addEnterpriseHookStatePurges(jobs, rows, skip)
			if len(report.Failed) != 1 || len(report.Pending) != 1 || skip[uid] != enterpriseHookPurgeSkipFailed || len(notPurged) != 1 ||
				notPurged[0] != "sample-order: "+enterpriseHookPurgeSkipFailed {
				t.Fatalf("failure must take precedence: report=%+v skip=%v notPurged=%v", report, skip, notPurged)
			}
			purgeTestTargetCount(t, jobs[uid], 0)
		})
	}
}
