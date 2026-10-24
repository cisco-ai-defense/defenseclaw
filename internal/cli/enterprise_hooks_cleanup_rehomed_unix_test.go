//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

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

func rehomedTestUID(t *testing.T, home string) (int, int) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 1001, 1001
		if err := os.Chown(home, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	return uid, gid
}

func writeRehomedTestRegistration(t *testing.T, home string, uid, gid int) string {
	t.Helper()
	dir := filepath.Join(home, ".hermes")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("hooks: defenseclaw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		for _, path := range []string{dir, path} {
			if err := os.Chown(path, uid, gid); err != nil {
				t.Fatal(err)
			}
		}
	}
	return path
}

func TestStandaloneCleanupRunsInTrustedCurrentHomeAndEndsRow(t *testing.T) {
	for _, oldPresent := range []bool{false, true} {
		name := "old-missing"
		if oldPresent {
			name = "old-present"
		}
		t.Run(name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			useReportingStandaloneRunner(t)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			oldHome := filepath.Join(f.homes, "sample-user-old")
			if oldPresent {
				oldHome = f.home(t, "sample-user-old", 0o755)
				_, _ = rehomedTestUID(t, oldHome)
				writeRehomedTestRegistration(t, oldHome, uid, gid)
			}
			if check := enterpriseHookCheckHome(newHome, uid); check.State != enterprisehooks.HomeAvailable {
				t.Fatalf("current home must be trusted for this test: %+v", check)
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome, RecordedAt: "2026-10-14T00:00:00Z"}
			entry.DataDir = filepath.Join(oldHome, ".defenseclaw", "moved-state")
			wantDataDir := filepath.Join(newHome, ".defenseclaw", "moved-state")
			originalRunner := enterpriseHookWorkerRunner
			var accounts []enterpriseHookWorkerAccount
			enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				accounts = append(accounts, account)
				return originalRunner(ctx, account, request)
			}
			var attemptLog bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &attemptLog, entry, resolver)
			if outcome != enterpriseHookUserCleanupDone || err != nil {
				t.Fatalf("trusted re-home cleanup = %v, %v", outcome, err)
			}
			wantAudit := "the account's home moved from " + oldHome + " to " + newHome
			if oldPresent {
				wantAudit = "the account's home changed from " + oldHome + " to " + newHome + ", and the recorded home still holds files, so this is a copy, not a move"
			}
			if strings.Count(attemptLog.String(), wantAudit) != 1 {
				t.Fatalf("re-home audit line = %q", attemptLog.String())
			}
			wantHomes := []string{newHome}
			if oldPresent {
				wantHomes = append(wantHomes, oldHome)
			}
			if len(accounts) != len(wantHomes) {
				t.Fatalf("worker accounts = %+v, want homes %v", accounts, wantHomes)
			}
			requests := f.requests
			if len(requests) != len(wantHomes) {
				t.Fatalf("worker requests = %+v, want homes %v", requests, wantHomes)
			}
			for i, wantHome := range wantHomes {
				if accounts[i].UID != uid || accounts[i].GID != gid || accounts[i].Home != wantHome || accounts[i].User != "sample-user" {
					t.Fatalf("worker account %d = %+v, want uid %d in %s", i, accounts[i], uid, wantHome)
				}
				if requests[i].Operation != enterpriseHookWorkerOpApply || !requests[i].Standalone || len(requests[i].Targets) != 1 {
					t.Fatalf("worker request %d = %+v", i, requests[i])
				}
				target := requests[i].Targets[0]
				dataDir := wantDataDir
				if i == 1 {
					dataDir = entry.DataDir
				}
				if target.Mode != enterpriseHookWorkerModeRemove || target.Options.ConnectorName != "hermes" ||
					target.Options.UserHome != wantHome || target.Options.OwnerUID != uid || target.Options.OwnerGID != gid ||
					target.Options.DataDir != dataDir {
					t.Fatalf("cleanup worker target %d = %+v, want home %s data dir %s uid %d", i, target, wantHome, dataDir, uid)
				}
			}
			f.writeManifest(t)
			now := time.Now()
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, now); err != nil {
				t.Fatal(err)
			}
			manifest, err := enterprisehooks.LoadManifest(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			var guardianLog bytes.Buffer
			bindings := enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest, bindings, nil, resolver, now); err != nil {
				t.Fatal(err)
			}
			remaining, err := loadEnterpriseHookUserCleanups(f.dataDir)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("cleanup ledger after reconcile = %+v, %v", remaining, err)
			}
			if strings.Count(guardianLog.String(), wantAudit) != 1 || strings.Count(guardianLog.String(), "no longer enrolled; per-user cleanup done") != 1 {
				t.Fatalf("guardian completion audit = %q", guardianLog.String())
			}
			guardianLog.Reset()
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest, bindings, nil, resolver, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if guardianLog.Len() != 0 {
				t.Fatalf("second reconcile repeated the audit: %q", guardianLog.String())
			}
		})
	}
}

func TestStandaloneCleanupReconcileRemovesRegistrationInBothHomes(t *testing.T) {
	for _, newPresent := range []bool{false, true} {
		name := "new-home-empty"
		if newPresent {
			name = "both-homes-registered"
		}
		t.Run(name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			useReportingStandaloneRunner(t)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			oldHome := f.home(t, "sample-user-old", 0o700)
			rehomedTestUID(t, oldHome)
			oldConfig := writeRehomedTestRegistration(t, oldHome, uid, gid)
			newConfig := filepath.Join(newHome, ".hermes", "config.yaml")
			if newPresent {
				writeRehomedTestRegistration(t, newHome, uid, gid)
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome, RecordedAt: "2026-10-14T00:00:00Z"}
			originalRunner := enterpriseHookWorkerRunner
			enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				response, err := originalRunner(ctx, account, request)
				if err == nil {
					config := filepath.Join(account.Home, ".hermes", "config.yaml")
					if err := os.Remove(config); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
				}
				return response, err
			}
			f.writeManifest(t)
			now := time.Now()
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, now); err != nil {
				t.Fatal(err)
			}
			manifest, err := enterprisehooks.LoadManifest(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			var log bytes.Buffer
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &log, manifest,
				enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, now); err != nil {
				t.Fatal(err)
			}
			remaining, err := loadEnterpriseHookUserCleanups(f.dataDir)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("cleanup ledger = %+v, %v", remaining, err)
			}
			if len(f.requests) != 2 || f.requests[0].Targets[0].Options.UserHome != newHome ||
				f.requests[1].Targets[0].Options.UserHome != oldHome ||
				f.requests[1].Targets[0].Options.DataDir != filepath.Join(oldHome, ".defenseclaw") {
				t.Fatalf("worker requests = %+v, want current then recorded home", f.requests)
			}
			for _, config := range []string{oldConfig, newConfig} {
				if _, err := os.Stat(config); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("registration %s remains: %v", config, err)
				}
			}
			if strings.Count(log.String(), "the account's home changed from "+oldHome+" to "+newHome+", and the recorded home still holds files, so this is a copy, not a move") != 1 ||
				strings.Count(log.String(), "no longer enrolled; per-user cleanup done") != 1 {
				t.Fatalf("guardian audit = %q", log.String())
			}
		})
	}
}

func TestStandaloneCleanupKeepsRowWhenRecordedHomeWorkerDoesNotFinish(t *testing.T) {
	for _, kind := range []string{"error", "non-ok", "pending"} {
		t.Run(kind, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			useReportingStandaloneRunner(t)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			oldHome := f.home(t, "sample-user-old", 0o700)
			rehomedTestUID(t, oldHome)
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome, RecordedAt: "2026-10-14T00:00:00Z"}
			originalRunner := enterpriseHookWorkerRunner
			enterpriseHookWorkerRunner = func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				response, err := originalRunner(ctx, account, request)
				if account.Home == oldHome {
					switch kind {
					case "error":
						return enterpriseHookWorkerResponse{}, errors.New("recorded-home worker failed")
					case "non-ok":
						response.Targets[0].OK = false
						response.Targets[0].Error = "recorded-home removal failed"
					case "pending":
						response.Targets[0].OK = false
						response.Targets[0].Pending = true
					}
				}
				return response, err
			}
			var attemptLog bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &attemptLog, entry, resolver)
			want := enterpriseHookUserCleanupFailed
			if kind == "pending" {
				want = enterpriseHookUserCleanupPending
			}
			if outcome != want || kind == "pending" && err != nil || kind != "pending" && err == nil {
				t.Fatalf("recorded-home worker %s = %v, %v", kind, outcome, err)
			}
			if len(f.requests) != 2 || f.requests[0].Targets[0].Options.UserHome != newHome ||
				f.requests[1].Targets[0].Options.UserHome != oldHome || strings.Contains(attemptLog.String(), "the account was re-homed") {
				t.Fatalf("worker requests = %+v, audit = %q", f.requests, attemptLog.String())
			}
			f.writeManifest(t)
			now := time.Now()
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, now); err != nil {
				t.Fatal(err)
			}
			manifest, err := enterprisehooks.LoadManifest(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			var guardianLog bytes.Buffer
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest,
				enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, now); err != nil {
				t.Fatal(err)
			}
			remaining, err := loadEnterpriseHookUserCleanups(f.dataDir)
			if err != nil || len(remaining) != 1 || strings.Contains(guardianLog.String(), "no longer enrolled; per-user cleanup done") {
				t.Fatalf("unfinished recorded-home cleanup ended: %+v, %v, log %q", remaining, err, guardianLog.String())
			}
		})
	}
}

func TestStandaloneCleanupKeepsUntrustedRecordedHomeAndReportsPending(t *testing.T) {
	for _, kind := range []string{"symlink", "group-writable", "other-writable", "wrong-owner", "long-path"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "wrong-owner" && os.Getuid() != 0 {
				t.Skip("changing a home owner requires root")
			}
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			useReportingStandaloneRunner(t)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			oldName := "sample-user-old"
			if kind == "long-path" {
				oldName += strings.Repeat("x", 180)
			}
			oldHome := f.home(t, oldName, 0o700)
			if kind != "wrong-owner" {
				rehomedTestUID(t, oldHome)
			}
			switch kind {
			case "symlink":
				writeRehomedTestRegistration(t, oldHome, uid, gid)
				link := filepath.Join(f.homes, "sample-user-old-link")
				if err := os.Symlink(oldHome, link); err != nil {
					t.Fatal(err)
				}
				oldHome = link
			case "group-writable":
				if err := os.Chmod(oldHome, 0o770); err != nil {
					t.Fatal(err)
				}
			case "other-writable", "long-path":
				if err := os.Chmod(oldHome, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome, RecordedAt: "2026-10-14T00:00:00Z"}
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
			var oldKept *enterpriseHookCleanupOldHomeKeptError
			var kept *enterpriseHookCleanupHomeKeptError
			var changed *enterpriseHookTargetHomeChangedError
			if outcome != enterpriseHookUserCleanupFailed || !errors.As(err, &oldKept) || errors.As(err, &kept) ||
				errors.As(err, &changed) || errors.Is(err, errEnterpriseHookCleanupHomeGone) ||
				!strings.Contains(err.Error(), oldHome) || !strings.Contains(err.Error(), newHome) || !strings.Contains(err.Error(), "hermes") {
				t.Fatalf("untrusted recorded home = %v, %v", outcome, err)
			}
			if len(f.requests) != 1 || f.requests[0].Targets[0].Options.UserHome != newHome ||
				f.requests[0].Targets[0].Options.OwnerUID != uid {
				t.Fatalf("untrusted old home ran a worker: %+v", f.requests)
			}
			f.writeManifest(t)
			now := time.Now()
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, now); err != nil {
				t.Fatal(err)
			}
			manifest, err := enterprisehooks.LoadManifest(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			var guardianLog bytes.Buffer
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest,
				enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, now); err != nil {
				t.Fatal(err)
			}
			remaining, err := loadEnterpriseHookUserCleanups(f.dataDir)
			// The ledger keeps the remedy within 512 bytes by shortening long
			// paths while retaining their basename. This unusually long path
			// is always shortened; the others are too when the checkout path
			// (the fixture's root) is long (rel-1-0-4 GAP-0559).
			namesHome := strings.Contains(guardianLog.String(), shortEnterpriseHookReportPath(oldHome)) ||
				(kind != "long-path" && strings.Contains(guardianLog.String(), oldHome))
			if err != nil || len(remaining) != 1 ||
				!strings.Contains(guardianLog.String(), "warn: per-user cleanup of hermes/sample-user:") ||
				!namesHome ||
				!strings.Contains(guardianLog.String(), "fix owner/permissions and rerun") ||
				strings.Contains(guardianLog.String(), "no longer enrolled; per-user cleanup done") {
				t.Fatalf("untrusted recorded-home guardian result = %+v, %v, log %q", remaining, err, guardianLog.String())
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
			if report.Removed != 0 || len(report.Pending) != 1 || len(report.Failed) != 0 ||
				!strings.Contains(report.Pending[0], oldHome) || !strings.Contains(report.Pending[0], newHome) ||
				!strings.Contains(report.Pending[0], "hermes config") || skip[uid] != enterpriseHookPurgeSkipKeptHome ||
				len(f.requests) != 3 {
				t.Fatalf("untrusted recorded-home remove-all = %+v, skip = %+v, requests = %+v", report, skip, f.requests)
			}
			for _, request := range f.requests {
				if request.Targets[0].Options.UserHome != newHome || request.Targets[0].Options.OwnerUID != uid {
					t.Fatalf("worker entered an untrusted old home: %+v", request)
				}
			}
		})
	}
}

func TestStandaloneCleanupLeavesExternalDataDirAsRecorded(t *testing.T) {
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	useReportingStandaloneRunner(t)
	newHome := f.home(t, "sample-user-new", 0o700)
	uid, gid := rehomedTestUID(t, newHome)
	resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
	dataDir := filepath.Join(f.homes, "shared-data")
	entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: filepath.Join(f.homes, "sample-user-old"), DataDir: dataDir}
	if outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver); outcome != enterpriseHookUserCleanupDone || err != nil {
		t.Fatalf("cleanup = %v, %v", outcome, err)
	}
	if got := f.requests[0].Targets[0].Options.DataDir; got != dataDir {
		t.Fatalf("external data dir = %s, want %s", got, dataDir)
	}
}

func TestStandaloneCleanupRefusesUnsafeCurrentHomes(t *testing.T) {
	for _, kind := range []string{"symlink", "other-writable", "group-writable", "wrong-owner", "missing", "relative-no-home", "reserved-no-home", "gone-no-home"} {
		t.Run(kind, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			useReportingStandaloneRunner(t)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			oldHome := filepath.Join(f.homes, "sample-user-old")
			switch kind {
			case "symlink":
				link := filepath.Join(f.homes, "sample-user-link")
				if err := os.Symlink(newHome, link); err != nil {
					t.Fatal(err)
				}
				newHome = link
			case "other-writable":
				if err := os.Chmod(newHome, 0o777); err != nil {
					t.Fatal(err)
				}
			case "group-writable":
				if err := os.Chmod(newHome, 0o770); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				uid++
			case "missing":
				newHome = filepath.Join(f.homes, "sample-user-missing")
			case "relative-no-home":
				oldHome = f.home(t, "sample-user-old", 0o700)
				newHome = "relative/home"
			case "reserved-no-home":
				oldHome = f.home(t, "sample-user-old", 0o700)
				newHome = "/var/empty"
			case "gone-no-home":
				newHome = "/nonexistent"
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome}
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver)
			if len(f.requests) != 0 {
				t.Fatalf("unsafe or no-home account ran a worker: %+v", f.requests)
			}
			switch kind {
			case "gone-no-home":
				if outcome != enterpriseHookUserCleanupDone || !errors.Is(err, errEnterpriseHookCleanupHomeGone) {
					t.Fatalf("gone/no-home cleanup = %v, %v", outcome, err)
				}
			case "relative-no-home", "reserved-no-home":
				var kept *enterpriseHookCleanupHomeKeptError
				if outcome != enterpriseHookUserCleanupFailed || !errors.As(err, &kept) {
					t.Fatalf("kept/no-home cleanup = %v, %v", outcome, err)
				}
			default:
				var changed *enterpriseHookTargetHomeChangedError
				var kept *enterpriseHookCleanupHomeKeptError
				if outcome != enterpriseHookUserCleanupFailed || !errors.As(err, &changed) || errors.As(err, &kept) || errors.Is(err, errEnterpriseHookCleanupHomeGone) ||
					!strings.Contains(err.Error(), oldHome) || !strings.Contains(err.Error(), newHome) ||
					!strings.Contains(err.Error(), "fix the account's home") || !strings.Contains(err.Error(), "remove the account") {
					t.Fatalf("unsafe re-home cleanup = %v, %v", outcome, err)
				}
			}
		})
	}
}

func TestStandaloneCleanupDropsGoneOrReassignedAccountsWithoutWorker(t *testing.T) {
	for _, kind := range []string{"gone", "reassigned"} {
		t.Run(kind, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			useReportingStandaloneRunner(t)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			if kind == "reassigned" {
				resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid + 1, GID: gid, Home: newHome}
			}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: filepath.Join(f.homes, "sample-user-old")}
			if outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &bytes.Buffer{}, entry, resolver); outcome != enterpriseHookUserCleanupDone || err != nil {
				t.Fatalf("gone/reassigned cleanup = %v, %v", outcome, err)
			}
			if len(f.requests) != 0 {
				t.Fatalf("gone/reassigned account ran a worker: %+v", f.requests)
			}
		})
	}
}

func TestStandaloneCleanupHandlesEmptyDirectoryHome(t *testing.T) {
	for _, kind := range []string{"recorded-home-gone", "recorded-home-kept-trusted", "recorded-home-kept-untrusted"} {
		t.Run(kind, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			useReportingStandaloneRunner(t)
			oldHome := filepath.Join(f.homes, "sample-user-old")
			uid, gid := os.Getuid()+1, os.Getgid()
			if kind != "recorded-home-gone" {
				oldHome = f.home(t, "sample-user-old", 0o700)
				uid, gid = rehomedTestUID(t, oldHome)
			}
			if kind == "recorded-home-kept-untrusted" {
				if err := os.Chmod(oldHome, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: ""}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: oldHome, RecordedAt: "2026-10-14T00:00:00Z"}
			var attemptLog bytes.Buffer
			outcome, err := attemptEnterpriseHookStandaloneUnixCleanup(context.Background(), &attemptLog, entry, resolver)
			switch kind {
			case "recorded-home-kept-trusted":
				if outcome != enterpriseHookUserCleanupDone || err != nil || len(f.requests) != 1 ||
					f.requests[0].Targets[0].Options.UserHome != oldHome || f.requests[0].Targets[0].Options.OwnerUID != uid {
					t.Fatalf("trusted recorded home = %v, %v, workers %+v", outcome, err, f.requests)
				}
			case "recorded-home-kept-untrusted":
				var kept *enterpriseHookCleanupHomeKeptError
				var changed *enterpriseHookTargetHomeChangedError
				if outcome != enterpriseHookUserCleanupFailed || err == nil || !strings.Contains(err.Error(), "enterprise hooks:") ||
					!strings.Contains(err.Error(), "group/other writable") || errors.As(err, &kept) || errors.As(err, &changed) ||
					errors.Is(err, errEnterpriseHookCleanupHomeGone) || len(f.requests) != 0 {
					t.Fatalf("untrusted recorded home = %v, %v, workers %+v", outcome, err, f.requests)
				}
			case "recorded-home-gone":
				if outcome != enterpriseHookUserCleanupDone || !errors.Is(err, errEnterpriseHookCleanupHomeGone) ||
					strings.Count(attemptLog.String(), "home gone:") != 1 || len(f.requests) != 0 {
					t.Fatalf("gone recorded home = %v, %v, workers %+v, log %q", outcome, err, f.requests, attemptLog.String())
				}
			}
			f.writeManifest(t)
			now := time.Now()
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, now); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, map[int]*enterpriseHookWorkerJob{})
			switch kind {
			case "recorded-home-kept-trusted":
				if report.Removed != 1 || len(report.Pending) != 0 || len(report.Failed) != 0 || skip[uid] != "" {
					t.Fatalf("trusted recorded-home remove-all = %+v, skip %+v", report, skip)
				}
			case "recorded-home-kept-untrusted":
				if report.Removed != 0 || len(report.Pending) != 0 || len(report.Failed) != 1 ||
					skip[uid] != enterpriseHookPurgeSkipFailed {
					t.Fatalf("untrusted recorded-home remove-all = %+v, skip %+v", report, skip)
				}
			case "recorded-home-gone":
				if report.Removed != 0 || len(report.Pending) != 1 || len(report.Failed) != 0 || skip[uid] != "" {
					t.Fatalf("gone recorded-home remove-all = %+v, skip %+v", report, skip)
				}
			}
			manifest, err := enterprisehooks.LoadManifest(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			var guardianLog bytes.Buffer
			if err := reconcileEnterpriseHookStandaloneUnixCleanups(context.Background(), &guardianLog, manifest,
				enterpriseHookUnixBindings{Bindings: map[string]enterpriseHookUnixBinding{}}, nil, resolver, now); err != nil {
				t.Fatal(err)
			}
			remaining, err := loadEnterpriseHookUserCleanups(f.dataDir)
			if err != nil {
				t.Fatal(err)
			}
			// remove-all already dropped the rows it finished (rel-1-0-3
			// GAP-0204): the guardian has nothing left to run for them.
			switch kind {
			case "recorded-home-kept-trusted":
				if len(remaining) != 0 || strings.Contains(guardianLog.String(), "per-user cleanup") ||
					len(f.requests) != 2 || f.requests[1].Targets[0].Options.UserHome != oldHome {
					t.Fatalf("trusted recorded home did not finish in remove-all: %+v, log %q, workers %+v", remaining, guardianLog.String(), f.requests)
				}
			case "recorded-home-kept-untrusted":
				if len(remaining) != 1 || !strings.Contains(guardianLog.String(), "will retry") || len(f.requests) != 0 {
					t.Fatalf("untrusted recorded home was retired: %+v, log %q, workers %+v", remaining, guardianLog.String(), f.requests)
				}
			case "recorded-home-gone":
				if len(remaining) != 0 || strings.Contains(guardianLog.String(), "home gone:") ||
					strings.Contains(guardianLog.String(), "no longer enrolled; per-user cleanup done") || len(f.requests) != 0 {
					t.Fatalf("gone recorded home was not retired once, by remove-all: %+v, log %q, workers %+v", remaining, guardianLog.String(), f.requests)
				}
			}
		})
	}
}

func TestRemoveAllReportsTrustedRehomeRemovedAndUnsafeRehomeFailed(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		name := "trusted"
		if !trusted {
			name = "untrusted"
		}
		t.Run(name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			useReportingStandaloneRunner(t)
			newHome := f.home(t, "sample-user-new", 0o700)
			uid, gid := rehomedTestUID(t, newHome)
			if !trusted {
				if err := os.Chmod(newHome, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			resolver.accounts["sample-user"] = unixidentity.Account{Name: "sample-user", UID: uid, GID: gid, Home: newHome}
			entry := enterpriseHookUserCleanup{Connector: "hermes", User: "sample-user", UID: uid, UserHome: filepath.Join(f.homes, "sample-user-old"), RecordedAt: "2026-10-14T00:00:00Z"}
			if err := saveEnterpriseHookUserCleanups(f.dataDir, []enterpriseHookUserCleanup{entry}, time.Now()); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			report := enterpriseHooksRemoveAllReport{}
			jobs := map[int]*enterpriseHookWorkerJob{uid: {Account: enterpriseHookWorkerAccount{UID: uid, GID: gid, User: "sample-user", Home: newHome}}}
			skip := runEnterpriseHookPendingCleanups(cmd, &report, jobs)
			report.OK = len(report.Failed) == 0
			if trusted {
				if report.Removed != 1 || len(report.Failed) != 0 || len(report.Pending) != 0 || !report.OK || skip[uid] != "" || len(f.requests) != 1 {
					t.Fatalf("trusted re-home remove-all report = %+v, skip = %+v, workers = %+v", report, skip, f.requests)
				}
			} else {
				if report.Removed != 0 || len(report.Failed) != 1 || !strings.HasPrefix(report.Failed[0], "sample-user/hermes: ") ||
					!strings.Contains(report.Failed[0], "fix the account's home") || !strings.Contains(report.Failed[0], "remove the account") ||
					report.OK || skip[uid] != enterpriseHookPurgeSkipFailed || len(f.requests) != 0 {
					t.Fatalf("unsafe re-home remove-all report = %+v, skip = %+v, workers = %+v", report, skip, f.requests)
				}
			}
		})
	}
}
