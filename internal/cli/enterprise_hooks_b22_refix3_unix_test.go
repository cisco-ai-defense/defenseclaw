//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// A cleanup remove-all finishes leaves the guardian's ledger at once. The
// ledger kept the row, with its old error, until the guardian's next retry
// after its retry interval (rel-1-0-3 GAP-0204). A cleanup that fails keeps
// its row.
func TestRemoveAllDropsTheLedgerRowsItFinished(t *testing.T) {
	t.Run("finished", func(t *testing.T) {
		c := setupRehomedOpenCodeCase(t, false, true)
		entry := c.entry
		entry.Attempts, entry.LastAttemptAt = 1, time.Now().UTC().Format(time.RFC3339Nano)
		entry.LastError = "enterprise hooks: user home is group/other writable"
		if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{entry}, time.Now()); err != nil {
			t.Fatal(err)
		}
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		report := enterpriseHooksRemoveAllReport{}
		runEnterpriseHookPendingCleanupsWith(cmd, &report, map[int]*enterpriseHookWorkerJob{}, c.resolver)
		if report.Removed != 1 || len(report.Failed) != 0 {
			t.Fatalf("remove-all = %+v", report)
		}
		if remaining, err := loadEnterpriseHookUserCleanups(c.fixture.dataDir); err != nil || len(remaining) != 0 {
			t.Fatalf("the finished cleanup stayed in the ledger: %+v, %v", remaining, err)
		}
	})
	t.Run("failed", func(t *testing.T) {
		c := setupRehomedOpenCodeCase(t, false, false)
		alterCopiedPluginFirstLine(t, c.newPlugin)
		if err := saveEnterpriseHookUserCleanups(c.fixture.dataDir, []enterpriseHookUserCleanup{c.entry}, time.Now()); err != nil {
			t.Fatal(err)
		}
		cmd := &cobra.Command{}
		cmd.SetContext(context.Background())
		report := enterpriseHooksRemoveAllReport{}
		runEnterpriseHookPendingCleanupsWith(cmd, &report, map[int]*enterpriseHookWorkerJob{}, c.resolver)
		if report.Removed != 0 || len(report.Failed) != 1 {
			t.Fatalf("remove-all = %+v", report)
		}
		if remaining, err := loadEnterpriseHookUserCleanups(c.fixture.dataDir); err != nil || len(remaining) != 1 {
			t.Fatalf("the failed cleanup left the ledger: %+v, %v", remaining, err)
		}
	})
}

// The saved cleanup error keeps its home-check reason and the remedy for
// homes at any depth: long paths go by their last element first. The reason
// was cut at 512 bytes, so a long checkout path failed
// TestStandaloneCleanupRetiresATargetWhoseHomeIsGone (rel-1-0-3 GAP-0212).
func TestRehomedCleanupErrorKeepsTheReasonForLongHomes(t *testing.T) {
	const tail = "owner uid=0 does not match target uid=1001"
	for depth := 1; depth <= 14; depth++ {
		root := "/" + strings.Repeat("checkout-folder/", depth)
		changed := &enterpriseHookTargetHomeChangedError{name: "sample-automount",
			home: root + "sample-automount-old", directoryHome: root + "sample-automount"}
		reason := "home check of " + changed.directoryHome + ": " + tail
		text := enterpriseHookUserCleanupFailureText(enterpriseHookRehomedCleanupError(changed, reason))
		if len(text) > enterpriseHookUserCleanupErrorMax+3 || !strings.Contains(text, tail) ||
			!strings.Contains(text, "then rerun; current home check: ") || !strings.Contains(text, "no longer matches the directory home") {
			t.Fatalf("depth %d: %d bytes: %q", depth, len(text), text)
		}
	}
}

// A manifest target the directory now gives no home (a removed macOS
// mobile account answers with /var/empty) is pending in the reconcile, and
// verify accepts it as the recorded pending target: status and verify
// stayed failed with guardian_target_failed until a reinstall (rel-1-0-3
// GAP-0177).
func TestStandaloneTargetWithNoDirectoryHomeIsPending(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	recorded := f.home(t, "mobile-user", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	resolver.accounts["mobile-user"] = unixidentity.Account{Name: "mobile-user", UID: uid + 1, GID: gid, Home: "/var/empty", Shell: "/bin/bash"}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"},
		enterprisehooks.ManifestTarget{User: "mobile-user", UserHome: recorded, Connector: "hermes"},
	)
	var log bytes.Buffer
	enterpriseHookWorkerLog = &log
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if len(run.Rows) != 2 || run.Failures != 0 || run.Pending != 1 || !run.Rows[0].OK ||
		!run.Rows[1].Pending || run.Rows[1].Error != "" {
		t.Fatalf("rows = %+v failures=%d pending=%d", run.Rows, run.Failures, run.Pending)
	}
	if !strings.Contains(log.String(), "pending: the directory now gives account \"mobile-user\" no home on this computer (/var/empty") {
		t.Fatalf("the reconcile did not say why the target waits: %s", log.String())
	}

	_, sha, err := enterprisehooks.LoadManifestWithSHA256(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	standalone := cfg
	cfg = &config.Config{DataDir: f.dataDir}
	if err := writeEnterpriseHookGuardianState(f.dataDir, f.manifest, sha, []enterpriseHookReconcileRow{
		protectedRow("alice", alice, "hermes"), {User: "mobile-user", UserHome: recorded, Connector: "hermes", Pending: true},
	}, 0, true); err != nil {
		t.Fatal(err)
	}
	cfg = standalone
	verify, err := runEnterpriseHookVerifyAttempt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if verify.Failures != 1 || verify.Pending != 1 || verify.Rows[0].OK ||
		!strings.Contains(verify.Rows[0].Error, "session-only HERMES_HOME") || !verify.Rows[1].Pending {
		t.Fatalf("verify rows=%+v failures=%d pending=%d", verify.Rows, verify.Failures, verify.Pending)
	}
	if got := filepath.Clean(verify.Rows[1].UserHome); got != recorded {
		t.Fatalf("verify row home = %s, want the recorded %s", got, recorded)
	}
}
