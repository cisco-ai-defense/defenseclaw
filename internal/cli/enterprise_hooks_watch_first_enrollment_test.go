// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/spf13/cobra"
)

// gap2176Fixture runs the target-scoped guardian watch loop over the real
// in-process reconcile (the path the standalone Windows guardian runs), with
// the vendor install and verification replaced. Account A has a protected
// claudecode row; account B has a protected row that keeps failing (an
// account that is signed out). The account's DefenseClaw contract lock is a
// file every connector row of the account owns, as on Windows.
type gap2176Fixture struct {
	t                   *testing.T
	dataDir             string
	homeA, homeB        string
	manifestPath        string
	lockPath            string
	mu                  sync.Mutex
	hermesInstalls      int
	hermesCancelled     int
	claudeARepairs      []time.Time
	tamperMidPass       bool
	tamperedAt          time.Time
	tamperWritten       bool
	manifestAfterReturn string
	log                 gap2176Log
}

const (
	gap2176SIDA = "S-1-5-21-1-2-3-2176"
	gap2176SIDB = "S-1-5-21-1-2-3-2177"
)

func gap2176ManifestRow(home, sid, connector string) string {
	versions := map[string]string{"claudecode": "2.1.187", "hermes": "0.21.5"}
	row := fmt.Sprintf("  - user_home: %q\n", home)
	if runtime.GOOS == "windows" {
		row += fmt.Sprintf("    agent_version: %s\n", versions[connector])
	} else {
		row += fmt.Sprintf("    uid: %d\n    gid: %d\n", os.Getuid(), os.Getgid())
	}
	return row + fmt.Sprintf("    sid: %s\n    connector: %s\n", sid, connector)
}

func gap2176SameHome(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// gap2176Log is the guardian log of one fixture, written by the watch loop
// and read by the test.
type gap2176Log struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *gap2176Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *gap2176Log) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newGAP2176Fixture(t *testing.T, tamperMidPass bool) *gap2176Fixture {
	t.Helper()
	restoreEnterpriseHooksLifecycleTestState(t)
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	stubEnterpriseHookTokenSources(t)
	enableEnterpriseHookGuardianRestores(t, true)
	previousManifest, previousAPI, previousProxy := enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr
	previousVerifier, previousInstaller := enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller
	previousSession, previousCleanup := enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup
	previousReconcile := enterpriseHookWatchReconcileOnce
	previousPlatformWatch := enterpriseHookWatchPlatformWatch
	previousTargetScoped := enterpriseHookWatchTargetScoped
	previousInterval, previousDebounce, previousSettle := enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle
	previousRetryMin, previousRetryMax := enterpriseHookWatchRepairRetryMin, enterpriseHookWatchRepairRetryMax
	previousWindow := enterpriseHookReconcileRecheckWindow
	t.Cleanup(func() {
		enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = previousManifest, previousAPI, previousProxy
		enterpriseHookReconcileVerifier, enterpriseHookReconcileInstaller = previousVerifier, previousInstaller
		enterpriseHookReconcileSessionAvailable, enterpriseForeignHookCleanup = previousSession, previousCleanup
		enterpriseHookWatchReconcileOnce = previousReconcile
		enterpriseHookWatchPlatformWatch = previousPlatformWatch
		enterpriseHookWatchTargetScoped = previousTargetScoped
		enterpriseHookWatchInterval, enterpriseHookWatchDebounce, enterpriseHookWatchSettle = previousInterval, previousDebounce, previousSettle
		enterpriseHookWatchRepairRetryMin, enterpriseHookWatchRepairRetryMax = previousRetryMin, previousRetryMax
		enterpriseHookReconcileRecheckWindow = previousWindow
	})
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseHookReconcileSessionAvailable = func(enterprisehooks.ManifestTarget) (bool, error) { return true, nil }

	scope := t.TempDir()
	f := &gap2176Fixture{
		t:             t,
		dataDir:       filepath.Join(scope, "runtime"),
		homeA:         filepath.Join(scope, "home-a"),
		homeB:         filepath.Join(scope, "home-b"),
		manifestPath:  filepath.Join(scope, "manifest", "targets.yaml"),
		tamperMidPass: tamperMidPass,
	}
	f.lockPath = filepath.Join(f.homeA, ".defenseclaw", "hook_contract_lock.json")
	for _, dir := range []string{f.dataDir, f.homeB, filepath.Dir(f.lockPath), filepath.Dir(f.manifestPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.lockPath, []byte("claudecode entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(hookGuardianAuthorizationDirEnv, filepath.Join(scope, "authorization"))
	// Account B comes last, so its row runs after account A's new row.
	before := "version: 1\ntargets:\n" + gap2176ManifestRow(f.homeA, gap2176SIDA, "claudecode") +
		gap2176ManifestRow(f.homeB, gap2176SIDB, "claudecode")
	f.manifestAfterReturn = "version: 1\ntargets:\n" + gap2176ManifestRow(f.homeA, gap2176SIDA, "claudecode") +
		gap2176ManifestRow(f.homeA, gap2176SIDA, "hermes") + gap2176ManifestRow(f.homeB, gap2176SIDB, "claudecode")
	if err := os.WriteFile(f.manifestPath, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	_, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(f.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{DataDir: f.dataDir, DeploymentMode: "local"}
	enterpriseHookManifest, enterpriseHookAPIAddr, enterpriseHookProxyAddr = f.manifestPath, "127.0.0.1:18970", "127.0.0.1:4000"
	protected := []enterpriseHookReconcileRow{
		{UserHome: f.homeA, SID: gap2176SIDA, Connector: "claudecode", OK: true},
		{UserHome: f.homeB, SID: gap2176SIDB, Connector: "claudecode", OK: true},
	}
	if err := writeEnterpriseHookGuardianState(f.dataDir, f.manifestPath, manifestSHA256, protected, 0, true); err != nil {
		t.Fatal(err)
	}

	enterpriseHookReconcileVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if gap2176SameHome(opts.UserHome, f.homeB) {
			return enterprisehooks.InstallResult{}, errors.New("account signed out")
		}
		if opts.ConnectorName == "claudecode" {
			data, err := os.ReadFile(f.lockPath)
			if err != nil {
				return enterprisehooks.InstallResult{}, err
			}
			if strings.Contains(string(data), "tampered") {
				return enterprisehooks.InstallResult{}, errors.New("hook contract lock does not verify")
			}
		}
		return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
	}
	enterpriseHookReconcileInstaller = func(ctx context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		switch {
		case gap2176SameHome(opts.UserHome, f.homeB):
			f.mu.Lock()
			tamper := f.tamperMidPass && !f.tamperWritten && f.hermesInstalls > 0
			if tamper {
				f.tamperWritten = true
				f.tamperedAt = time.Now()
			}
			f.mu.Unlock()
			if tamper {
				// Someone else rewrites account A's contract lock after the
				// pass finished account A: that is not the pass's own write.
				if err := os.WriteFile(f.lockPath, []byte("tampered\n"), 0o600); err != nil {
					return enterprisehooks.InstallResult{}, err
				}
				time.Sleep(500 * time.Millisecond)
			}
			return enterprisehooks.InstallResult{}, errors.New("account signed out")
		case opts.ConnectorName == "hermes":
			f.mu.Lock()
			f.hermesInstalls++
			n := f.hermesInstalls
			f.mu.Unlock()
			// A first enrollment records the connector in the account's
			// contract lock with a fresh stamp, a file the account's other
			// rows own.
			body := fmt.Sprintf("claudecode entry\nhermes entry %d %d\n", n, time.Now().UnixNano())
			if err := os.WriteFile(f.lockPath, []byte(body), 0o600); err != nil {
				return enterprisehooks.InstallResult{}, err
			}
			// The write's filesystem event reaches the watch loop while the
			// pass is still running.
			time.Sleep(500 * time.Millisecond)
			if ctx.Err() != nil {
				f.mu.Lock()
				f.hermesCancelled++
				f.mu.Unlock()
			}
			return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
		default:
			f.mu.Lock()
			f.claudeARepairs = append(f.claudeARepairs, time.Now())
			f.mu.Unlock()
			if err := os.WriteFile(f.lockPath, []byte("claudecode entry\nhermes entry repaired\n"), 0o600); err != nil {
				return enterprisehooks.InstallResult{}, err
			}
			return enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}, nil
		}
	}
	// The real reconcile names the account's contract lock as a file every
	// connector row of account A owns, as the Windows owned-file lists do.
	enterpriseHookWatchReconcileOnce = func(ctx context.Context) (enterpriseHookReconcileRun, error) {
		run, err := runEnterpriseHookReconcileOnce(ctx)
		if run.WatchPathOwners == nil {
			run.WatchPathOwners = map[string][]string{}
		}
		for _, row := range run.Rows {
			if gap2176SameHome(row.UserHome, f.homeA) {
				enterpriseHookWatchAddPathOwner(run.WatchPathOwners, filepath.Clean(f.lockPath), enterpriseHookProtectedTargetKey(row))
			}
		}
		run.WatchExclusiveFiles = append(run.WatchExclusiveFiles, filepath.Clean(f.lockPath))
		run.WatchDirs = append(run.WatchDirs, filepath.Dir(filepath.Clean(f.lockPath)))
		return run, err
	}
	enterpriseHookWatchTargetScoped = func() bool { return true }
	enterpriseHookWatchInterval = 30 * time.Second
	enterpriseHookWatchDebounce = 250 * time.Millisecond
	enterpriseHookWatchSettle = 500 * time.Millisecond
	// Account B's retries run every 4 s, so none starts on the manifest
	// publish 1 s after the startup pass (the publish would preempt it).
	enterpriseHookWatchRepairRetryMin = 4 * time.Second
	enterpriseHookWatchRepairRetryMax = 4 * time.Second
	return f
}

func (f *gap2176Fixture) start() {
	f.t.Helper()
	ready := make(chan struct{})
	var once sync.Once
	enterpriseHookWatchPlatformWatch = func(context.Context, io.Writer) { once.Do(func() { close(ready) }) }
	ctx, cancel := context.WithCancel(context.Background())
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	cmd.SetErr(&f.log)
	done := make(chan error, 1)
	go func() { done <- runEnterpriseHooksWatch(cmd, nil) }()
	f.t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				f.t.Errorf("guardian exit: %v", err)
			}
		case <-time.After(10 * time.Second):
			f.t.Error("guardian did not stop")
		}
		if f.t.Failed() || os.Getenv("GAP2176_DEBUG") != "" {
			f.t.Logf("guardian log:\n%s", f.log.String())
		}
	})
	select {
	case <-ready:
	case err := <-done:
		f.t.Fatalf("guardian exited before the watch started: %v", err)
	case <-time.After(20 * time.Second):
		f.t.Fatal("watcher did not start")
	}
}

// hermesPublished reports the guardian records naming hermes for account A
// as protected: the state row and the protected authorization.
func (f *gap2176Fixture) hermesPublished() (bool, enterpriseHookGuardianState, enterpriseHookGuardianAuthorization) {
	state, ok, err := loadEnterpriseHookGuardianState(f.dataDir)
	if err != nil || !ok {
		return false, state, enterpriseHookGuardianAuthorization{}
	}
	authorization, ok, err := loadEnterpriseHookGuardianAuthorization(f.dataDir)
	if err != nil || !ok {
		return false, state, authorization
	}
	inState, inAuthorization := false, false
	for _, row := range state.Results {
		if row.Connector == "hermes" && row.OK && gap2176SameHome(row.UserHome, f.homeA) {
			inState = true
		}
	}
	for _, row := range authorization.ProtectedTargets {
		if row.Connector == "hermes" && gap2176SameHome(row.UserHome, f.homeA) {
			inAuthorization = true
		}
	}
	return inState && inAuthorization, state, authorization
}

func (f *gap2176Fixture) returnHermes() {
	f.t.Helper()
	// Let the startup pass's settle window end before the enumerator
	// publishes the returned row.
	time.Sleep(time.Second)
	// Published in one step (a temporary file renamed over it), so the
	// manifest gives one event, not a truncate and a write.
	staged := f.manifestPath + ".staged"
	if err := os.WriteFile(staged, []byte(f.manifestAfterReturn), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Rename(staged, f.manifestPath); err != nil {
		f.t.Fatal(err)
	}
}

// GAP-2176 / GAP-1798: the guardian's own first-enrollment write into a file
// the account's other rows own must not cancel the pass that makes it. On
// rel/1.0.11 348f3fbae9 each pass after the Hermes row returned was cancelled
// by that write. The standalone guardian publishes nothing from a cancelled
// pass, and the next pass made the same first enrollment and the same write
// again: state, activation and ledger stayed frozen while another account's
// rows kept failing, and only a guardian restart (Setup /ensure, whose
// startup pass is not preempted) recovered. The test runs on the local
// profile, which still publishes a cancelled pass, so it checks the
// cancellation itself and the publication.
func TestGAP2176ReturnedTargetPublishesWhileOtherAccountFails(t *testing.T) {
	f := newGAP2176Fixture(t, false)
	f.start()
	f.returnHermes()
	returned := time.Now()
	// Well within one guardian interval (30 s here, 60 s on a host).
	deadline := returned.Add(15 * time.Second)
	for {
		published, state, authorization := f.hermesPublished()
		if published {
			f.mu.Lock()
			installs, cancelled := f.hermesInstalls, f.hermesCancelled
			f.mu.Unlock()
			if cancelled != 0 || installs != 1 {
				t.Fatalf("the pass that enrolled hermes was cancelled by its own contract-lock write (%d of %d installs cancelled); want one install in a pass that runs to its end",
					cancelled, installs)
			}
			// Fail closed for the account that really fails: its row stays a
			// failure and the records stay unhealthy, so verify stays red.
			failingB := false
			for _, row := range state.Results {
				if gap2176SameHome(row.UserHome, f.homeB) && !row.OK && !row.Pending && row.Error != "" {
					failingB = true
				}
			}
			if !failingB || state.OK || authorization.OK || state.FailureCount != 1 {
				t.Fatalf("published state ok=%v failures=%d authorization ok=%v failingB=%v; want account B's row still failing and the records unhealthy",
					state.OK, state.FailureCount, authorization.OK, failingB)
			}
			return
		}
		if time.Now().After(deadline) {
			f.mu.Lock()
			installs := f.hermesInstalls
			f.mu.Unlock()
			t.Fatalf("hermes for account A was not published %s after its row returned (hermes installs=%d, state updated %s): the guardian never finished a pass",
				time.Since(returned).Round(time.Second), installs, state.UpdatedAt)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The pass's own write is told from someone else's by what the pass left in
// the file: a rewrite of account A's owned file after the pass finished
// account A is still acted on, the owning row is repaired and the returned
// row is still published.
func TestGAP2176TamperAfterTheAccountWorkStillRepairs(t *testing.T) {
	f := newGAP2176Fixture(t, true)
	f.start()
	f.returnHermes()
	deadline := time.Now().Add(20 * time.Second)
	for {
		f.mu.Lock()
		tampered, tamperedAt := f.tamperWritten, f.tamperedAt
		var repairedAfter bool
		for _, at := range f.claudeARepairs {
			if tampered && at.After(tamperedAt) {
				repairedAfter = true
			}
		}
		f.mu.Unlock()
		published, _, _ := f.hermesPublished()
		if repairedAfter && published {
			data, err := os.ReadFile(f.lockPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "tampered") {
				t.Fatalf("contract lock still holds the tamper: %q", data)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tampered=%v repaired after the tamper=%v hermes published=%v; want the tamper repaired and hermes published", tampered, repairedAfter, published)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
