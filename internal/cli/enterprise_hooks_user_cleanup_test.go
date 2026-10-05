// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

const (
	userCleanupSIDA = "S-1-5-21-1000000000-2000000000-3000000000-1017"
	userCleanupSIDB = "S-1-5-21-1000000000-2000000000-3000000000-1018"
)

func userCleanupPerUser(name string) bool {
	switch name {
	case "amp", "antigravity", "copilot", "devin", "hermes", "kiro", "opencode":
		return true
	}
	return false
}

func userCleanupRow(connectorName, sid, home string) enterpriseHookReconcileRow {
	return enterpriseHookReconcileRow{
		User:      filepath.Base(home),
		UserHome:  home,
		SID:       sid,
		Connector: connectorName,
		OK:        true,
		Result: &enterprisehooks.InstallResult{
			Connector: connectorName,
			UserHome:  home,
			DataDir:   filepath.Join(home, ".defenseclaw"),
		},
	}
}

func userCleanupManifest(rows ...[2]string) enterprisehooks.Manifest {
	manifest := enterprisehooks.Manifest{Version: 1}
	for _, row := range rows {
		manifest.Targets = append(manifest.Targets, enterprisehooks.ManifestTarget{
			Connector: row[0],
			SID:       row[1],
			UserHome:  "/home/" + row[1],
		})
	}
	return manifest
}

// A revoked user's per-user rows become cleanups; rows the manifest still
// enrolls, machine-policy connectors, and rows without an identity do not.
func TestPlanEnterpriseHookUserCleanupsRecordsOnlyRevokedPerUserRows(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	homeA, homeB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	previous := []enterpriseHookReconcileRow{
		userCleanupRow("devin", userCleanupSIDA, homeA),
		userCleanupRow("opencode", userCleanupSIDA, homeA),
		userCleanupRow("codex", userCleanupSIDA, homeA),
		userCleanupRow("hermes", userCleanupSIDB, homeB),
		{Connector: "amp", OK: true},
	}
	manifest := userCleanupManifest([2]string{"hermes", strings.ToLower(userCleanupSIDB)})
	planned := planEnterpriseHookUserCleanups(nil, previous, enterpriseHookManifestAdmits(manifest), userCleanupPerUser, now)
	if len(planned) != 2 || planned[0].Connector != "devin" || planned[1].Connector != "opencode" {
		t.Fatalf("planned = %+v, want devin and opencode for the revoked user", planned)
	}
	for _, entry := range planned {
		if entry.SID != userCleanupSIDA || entry.UserHome != homeA ||
			entry.DataDir != filepath.Join(homeA, ".defenseclaw") || entry.RecordedAt == "" {
			t.Fatalf("incomplete cleanup entry %+v", entry)
		}
	}

	// A recorded cleanup is dropped once the manifest enrolls the user
	// again and the guardian protects that row, and never duplicated by the
	// ledger row it came from.
	readmitted := userCleanupManifest([2]string{"devin", userCleanupSIDA})
	replanned := planEnterpriseHookUserCleanups(planned, previous, enterpriseHookManifestAdmits(readmitted), userCleanupPerUser, now)
	if len(replanned) != 2 || replanned[0].Connector != "hermes" || replanned[1].Connector != "opencode" {
		t.Fatalf("replanned = %+v, want hermes and opencode only", replanned)
	}

	// Re-enrolled but not protected yet (the reinstall has not run): the
	// record stays.
	unprotected := planEnterpriseHookUserCleanups(planned, nil, enterpriseHookManifestAdmits(readmitted), userCleanupPerUser, now)
	if len(unprotected) != 2 || unprotected[0].Connector != "devin" || unprotected[1].Connector != "opencode" {
		t.Fatalf("unprotected replan = %+v, want devin and opencode kept", unprotected)
	}
}

// A signed-out revoked user's cleanup is recorded and kept until it can run.
// A user enrolled again while signed out stays deferred, so the guardian does
// not protect the row until the reinstall succeeds. The recorded cleanup must
// survive that window without being attempted, so a second revocation
// before the reinstall still removes the registration.
func TestReconcileEnterpriseHookUserCleanupsForSignedOutUsers(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	home := filepath.Join(t.TempDir(), "alice")
	protectedRow := userCleanupRow("devin", userCleanupSIDA, home)
	deferredRow := enterpriseHookReconcileRow{
		User:      "alice",
		UserHome:  home,
		SID:       userCleanupSIDA,
		Connector: "devin",
		Pending:   true,
	}
	revoked := enterprisehooks.Manifest{Version: 1}
	readmitted := userCleanupManifest([2]string{"devin", userCleanupSIDA})

	var attempts []string
	attempt := func(_ context.Context, entry enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
		attempts = append(attempts, enterpriseHookUserCleanupLabel(entry))
		return enterpriseHookUserCleanupPending, nil
	}
	protected := []enterpriseHookReconcileRow{protectedRow}
	writeUserCleanupAuthorization(t, dataDir, protected...)
	now := time.Now()
	// reconcile runs the cleanup step, then publishes this run's rows
	// through the production merge, as runEnterpriseHookReconcileOnce does.
	reconcile := func(manifest enterprisehooks.Manifest, rows ...enterpriseHookReconcileRow) []enterpriseHookUserCleanup {
		t.Helper()
		attempts = nil
		var log bytes.Buffer
		if err := reconcileEnterpriseHookUserCleanups(context.Background(), &log, dataDir, manifest, userCleanupPerUser, attempt, now); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		now = now.Add(time.Minute)
		protected = mergeProtectedEnterpriseHookTargets(protected, rows)
		writeUserCleanupAuthorization(t, dataDir, protected...)
		pending, err := loadEnterpriseHookUserCleanups(dataDir)
		if err != nil {
			t.Fatalf("load ledger: %v", err)
		}
		return pending
	}
	label := "devin/" + userCleanupSIDA

	if pending := reconcile(revoked); len(pending) != 1 || strings.Join(attempts, ",") != label || len(protected) != 0 {
		t.Fatalf("revoked while signed out: pending=%+v attempts=%v protected=%d", pending, attempts, len(protected))
	}
	if pending := reconcile(readmitted, deferredRow); len(pending) != 1 || len(attempts) != 0 || len(protected) != 0 {
		t.Fatalf("re-enrolled while signed out: pending=%+v attempts=%v protected=%d", pending, attempts, len(protected))
	}
	if pending := reconcile(revoked); len(pending) != 1 || strings.Join(attempts, ",") != label {
		t.Fatalf("revoked again before the reinstall: pending=%+v attempts=%v", pending, attempts)
	}

	// Enrolled again and reinstalled: the record is dropped, never
	// attempted, once the guardian protects the row again.
	if pending := reconcile(readmitted, protectedRow); len(pending) != 1 || len(attempts) != 0 || len(protected) != 1 {
		t.Fatalf("reinstall run: pending=%+v attempts=%v protected=%d", pending, attempts, len(protected))
	}
	if pending := reconcile(readmitted, protectedRow); len(pending) != 0 || len(attempts) != 0 {
		t.Fatalf("protected again: pending=%+v attempts=%v", pending, attempts)
	}

	// The guardian records a signed-out revoked user's cleanup before its state
	// publication drops the row, keeps it until the user signs in, and removes
	// the record once the cleanup succeeds.
	t.Run("recorded until sign-in", func(t *testing.T) {
		dataDir := useUserCleanupStateDir(t)
		home := filepath.Join(t.TempDir(), "alice")
		writeUserCleanupAuthorization(t, dataDir,
			userCleanupRow("devin", userCleanupSIDA, home),
			userCleanupRow("opencode", userCleanupSIDB, home+"b"),
		)
		manifest := userCleanupManifest([2]string{"opencode", userCleanupSIDB})
		signedIn := false
		calls := 0
		attempt := func(_ context.Context, entry enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
			calls++
			if entry.Connector != "devin" || entry.SID != userCleanupSIDA || entry.UserHome != home {
				t.Fatalf("unexpected cleanup %+v", entry)
			}
			if signedIn {
				return enterpriseHookUserCleanupDone, nil
			}
			return enterpriseHookUserCleanupPending, nil
		}
		var log bytes.Buffer
		now := time.Now()
		if err := reconcileEnterpriseHookUserCleanups(context.Background(), &log, dataDir, manifest, userCleanupPerUser, attempt, now); err != nil {
			t.Fatalf("first reconcile: %v", err)
		}
		pending, err := loadEnterpriseHookUserCleanups(dataDir)
		if err != nil || len(pending) != 1 || pending[0].Connector != "devin" || pending[0].SID != userCleanupSIDA {
			t.Fatalf("recorded cleanups = %+v, %v", pending, err)
		}
		if !strings.Contains(log.String(), "recorded for cleanup at next sign-in") {
			t.Fatalf("log = %q", log.String())
		}

		// The state publication that follows drops the revoked row; the record
		// alone carries the cleanup from here, and a waiting ledger is not
		// rewritten.
		writeUserCleanupAuthorization(t, dataDir, userCleanupRow("opencode", userCleanupSIDB, home+"b"))
		path := enterpriseHookUserCleanupPath(dataDir)
		before, _ := os.ReadFile(path)
		log.Reset()
		if err := reconcileEnterpriseHookUserCleanups(context.Background(), &log, dataDir, manifest, userCleanupPerUser, attempt, now.Add(time.Minute)); err != nil {
			t.Fatalf("second reconcile: %v", err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) || log.Len() != 0 {
			t.Fatalf("waiting ledger rewritten or logged again: log=%q", log.String())
		}

		signedIn = true
		if err := reconcileEnterpriseHookUserCleanups(context.Background(), &log, dataDir, manifest, userCleanupPerUser, attempt, now.Add(2*time.Minute)); err != nil {
			t.Fatalf("sign-in reconcile: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("completed cleanup ledger remains: %v", err)
		}
		if calls != 3 || !strings.Contains(log.String(), "removed DefenseClaw registration devin/"+userCleanupSIDA) {
			t.Fatalf("calls=%d log=%q", calls, log.String())
		}
	})
}

func TestRunEnterpriseHookUserCleanupsKeepsSignedOutAndFailedUsers(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	entries := []enterpriseHookUserCleanup{
		{Connector: "amp", SID: userCleanupSIDA, UserHome: "/h/a", RecordedAt: "r"},
		{Connector: "devin", SID: userCleanupSIDA, UserHome: "/h/a", RecordedAt: "r"},
		{Connector: "hermes", SID: userCleanupSIDB, UserHome: "/h/b", RecordedAt: "r"},
		{
			Connector: "opencode", SID: userCleanupSIDB, UserHome: "/h/b", RecordedAt: "r",
			Attempts: 1, LastAttemptAt: now.Add(-time.Minute).Format(time.RFC3339Nano), LastError: "earlier",
		},
	}
	attempted := map[string]int{}
	attempt := func(_ context.Context, entry enterpriseHookUserCleanup) (enterpriseHookUserCleanupOutcome, error) {
		attempted[entry.Connector]++
		switch entry.Connector {
		case "amp":
			return enterpriseHookUserCleanupDone, nil
		case "devin":
			return enterpriseHookUserCleanupPending, nil
		default:
			return enterpriseHookUserCleanupFailed, errors.New("access   denied\nby policy")
		}
	}
	remaining, result := runEnterpriseHookUserCleanups(context.Background(), entries, attempt, now)
	if attempted["opencode"] != 0 {
		t.Fatal("an entry that failed a minute ago was retried before its interval")
	}
	if len(result.Removed) != 1 || result.Removed[0] != "amp/"+userCleanupSIDA {
		t.Fatalf("removed = %v", result.Removed)
	}
	if len(remaining) != 3 || remaining[0] != entries[1] || remaining[2] != entries[3] {
		t.Fatalf("a waiting or backing-off entry changed: %+v", remaining)
	}
	failed := remaining[1]
	if failed.Connector != "hermes" || failed.Attempts != 1 || failed.LastError != "access denied by policy" ||
		failed.LastAttemptAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("failed entry bookkeeping = %+v", failed)
	}
	if len(result.Pending) != 2 || len(result.Failed) != 1 || !strings.HasPrefix(result.Failed[0], "hermes/"+userCleanupSIDB+": ") {
		t.Fatalf("result = %+v", result)
	}

	later := now.Add(enterpriseHookUserCleanupRetryInterval)
	runEnterpriseHookUserCleanups(context.Background(), remaining, attempt, later)
	if attempted["opencode"] != 1 || attempted["hermes"] != 2 {
		t.Fatalf("failed entries were not retried after their interval: %v", attempted)
	}
}

func useUserCleanupStateDir(t *testing.T) string {
	t.Helper()
	originalOwnership := enterpriseHookAuthorizationOwnershipSetter
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	t.Cleanup(func() { enterpriseHookAuthorizationOwnershipSetter = originalOwnership })
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(t.TempDir(), "hook-guardian-state"))
	return t.TempDir()
}

func writeUserCleanupAuthorization(t *testing.T, dataDir string, rows ...enterpriseHookReconcileRow) {
	t.Helper()
	dir, err := prepareEnterpriseHookAuthorizationDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(enterpriseHookGuardianAuthorization{
		Version:          1,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		OK:               true,
		TargetCount:      len(rows),
		SuccessCount:     len(rows),
		ProtectedTargets: rows,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hookGuardianAuthorizationFile), body, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEnterpriseHookUserCleanupsRejectsIncompleteEntries(t *testing.T) {
	dataDir := useUserCleanupStateDir(t)
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"version":2,"updated_at":"x","pending":[]}`,
		`{"version":1,"updated_at":"x","pending":[{"connector":"devin","sid":"","user_home":"/h","recorded_at":"r"}]}`,
		`{"version":1,"updated_at":"x","pending":[{"connector":"devin","sid":"S-1","user_home":"relative","recorded_at":"r"}]}`,
		`{"version":1,"updated_at":"x","pending":[],"extra":true}`,
	} {
		if err := os.WriteFile(enterpriseHookUserCleanupPath(dataDir), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := loadEnterpriseHookUserCleanups(dataDir); err == nil {
			t.Fatalf("accepted ledger %s", body)
		}
	}
}
