//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// GAP-2103: the retries of a pass that read a skill folder unreadable scanned
// the accounts the pass started with. An account excluded (exclude_users,
// exempt_users) between the pass and its retry was scanned again and got a fresh
// spool record. Each retry now drops the accounts that are left out by then; the
// other accounts' records are not touched.
func TestStandaloneAIDiscoveryRetryDropsAnAccountExcludedSincePassStart(t *testing.T) {
	b := newAIDiscoveryBurstFixture(t)
	b.permanentlyUnreadable = true
	// bob is enrolled but pending: his last record is kept, not scanned.
	bob := enterpriseHookReconcileRow{User: "bob", UserHome: filepath.Join(t.TempDir(), "bob"), Connector: "codex", OK: true,
		UID: os.Getuid() + 7, HomeInode: 11, Pending: true}
	if err := ensureEnterpriseHookStandaloneAuthDir(b.dir); err != nil {
		t.Fatal(err)
	}
	if err := writeEnterpriseHookAIDiscoveryRecord(b.dir, enterpriseHookWorkerAccount{UID: bob.UID, User: bob.User},
		enterpriseHookAIDiscoveryHolder(bob), inventory.AIDiscoveryReport{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.rows = append(b.rows, bob)

	previousExcluded := cfg.Enterprise.Enrollment.ExcludeUsers
	t.Cleanup(func() { cfg.Enterprise.Enrollment.ExcludeUsers = previousExcluded })
	wait := enterpriseHookAIDiscoveryWait
	excluded := false
	enterpriseHookAIDiscoveryWait = func(ctx context.Context, d time.Duration) bool {
		if !excluded {
			// The administrator excludes alice while the first retry waits.
			excluded = true
			cfg.Enterprise.Enrollment.ExcludeUsers = []string{"alice"}
		}
		return wait(ctx, d)
	}

	b.tick(0)
	if !excluded {
		t.Fatal("the first pass read nothing unreadable, so no retry waited: the fixture does not cover a retry")
	}
	if got := len(b.snapshot()); got != 1 {
		t.Fatalf("scans = %d, want 1: the retries scanned an account that was excluded after the pass started (%+v)", got, b.snapshot())
	}
	record, err := readTestUserScanRecord(filepath.Join(b.dir, strconv.Itoa(bob.UID)+".json"))
	if err != nil || record.UID != bob.UID || record.Holder != enterpriseHookAIDiscoveryHolder(bob) {
		t.Fatalf("bob's record = %+v, %v; want it kept as it was", record, err)
	}
}

// An account that only eligible-accounts.json put in the rows (no hook row
// stands behind it) is dropped from a retry once the file no longer lists it;
// an account with a hook row stays whatever the file says.
func TestStandaloneAIDiscoveryRetryRowsFollowTheEligibleList(t *testing.T) {
	previousLoad := enterpriseHookLoadEligibleAccounts
	t.Cleanup(func() { enterpriseHookLoadEligibleAccounts = previousLoad })
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{{User: "carol", UID: 2003}}, nil
	}
	rows := []enterpriseHookReconcileRow{
		{User: "alice", UID: 2001, Connector: "codex", OK: true},
		{User: "bob", UID: 2002, OK: true},
		{User: "carol", UID: 2003, OK: true},
	}
	run := enterpriseHookReconcileRun{Manifest: "/nonexistent/manifest.json"}
	got := enterpriseHookAIDiscoveryRetryRows(context.Background(), io.Discard, run, rows)
	if len(got) != 2 || got[0].User != "alice" || got[1].User != "carol" {
		t.Fatalf("retry rows = %+v, want alice (hook row) and carol (still eligible); bob left the list", got)
	}
}
