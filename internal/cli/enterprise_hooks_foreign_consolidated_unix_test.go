// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// foreignHookPipeFence is the worker's side of the fence pipes, served by
// session in this process as the guardian serves a worker's
// (attachEnterpriseHookWorkerFence): the same messages, over in-memory
// pipes.
func foreignHookPipeFence(t *testing.T, session *enterpriseForeignHookFenceSession) *enterpriseHookWorkerFencePipe {
	t.Helper()
	askRead, askWrite := io.Pipe()
	replyRead, replyWrite := io.Pipe()
	served := make(chan struct{})
	go func() {
		defer close(served)
		session.serve(context.Background(), askRead, replyWrite)
		_ = replyWrite.Close()
	}()
	t.Cleanup(func() {
		_ = askWrite.Close()
		<-served
		session.release()
	})
	replies := bufio.NewScanner(replyRead)
	replies.Buffer(make([]byte, 0, 1024), enterpriseHookWorkerFenceMessageLimit)
	return &enterpriseHookWorkerFencePipe{replies: replies, asks: askWrite}
}

func foreignHookTestCleanups(connectorName string) []enterpriseHookWorkerForeignCleanup {
	return []enterpriseHookWorkerForeignCleanup{{
		Connector:  connectorName,
		HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook",
		Policy:     foreignHookTestCursorPolicy(),
	}}
}

// Item 1 for the per-user worker: the worker's removal over the fence pipes
// (its lock ask names the files) and a real worker process, as the user,
// talking to this process's session. The change happens in the worker; the
// lock, the rotation, both records and the release in the guardian.
func TestForeignHookWorkerRemovalRotatesTheKeyBeforeItPublishes(t *testing.T) {
	cleanups := foreignHookTestCleanups("cursor")
	var account enterpriseHookWorkerAccount
	runForeignHookRemovalOrderCases(t, []foreignHookRemovalOrderCase{
		{
			name: "the worker's pipe protocol",
			want: "lock,rotate,ledger,change,ledger,release",
			run: func(t *testing.T, trace *foreignHookRemovalTrace, home, path string) {
				var stderr bytes.Buffer
				session := newEnterpriseForeignHookFenceSession(cleanups, &stderr, "1001", home)
				pipe := foreignHookPipeFence(t, session)
				report := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{Home: home, Standalone: true, ForeignCleanup: cleanups}, time.Now(), pipe)["cursor"]
				if report.Error != "" || len(report.Removed) != 1 || report.Removed[0] != path {
					t.Fatalf("cleanup report %+v; %s", report, stderr.String())
				}
				if left := session.uncommitted("cursor", report.Removed); len(left) != 0 {
					t.Fatalf("the commit must cover the removal: %v", left)
				}
			},
		},
		{
			name: "a real worker process",
			want: "lock,rotate,ledger,change,ledger,release",
			home: func(t *testing.T) string {
				useEnterpriseHookWorkerHelper(t, "real")
				account = selfWorkerAccount(t)
				return account.Home
			},
			run: func(t *testing.T, trace *foreignHookRemovalTrace, home, path string) {
				var stderr bytes.Buffer
				session := newEnterpriseForeignHookFenceSession(cleanups, &stderr, "1001", home)
				response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
					Operation: enterpriseHookWorkerOpForeignCleanup, Standalone: true, ForeignCleanup: cleanups, cleanupFence: session,
				})
				if err != nil {
					t.Fatal(err)
				}
				report := response.Cleanup["cursor"]
				if report.Error != "" || len(report.Removed) != 1 {
					t.Fatalf("cleanup report %+v; %s", report, stderr.String())
				}
				session.release()
				if left := session.uncommitted("cursor", report.Removed); len(left) != 0 {
					t.Fatalf("the worker's commit must cover the removal: %v", left)
				}
			},
		},
	})
}

// The real worker asks for a commit only when it is about to remove a hook:
// a worker with nothing to remove finishes while a gateway exchange holds
// the account's lock, without asking for it.
func TestForeignCleanupWorkerLocksOnlyToRemove(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "real")
	useForeignHookGuardian(t, nil)
	account := selfWorkerAccount(t)
	exchange, err := enterprisepolicy.LockForeignHookAccountExchange(context.Background(), cfg.DataDir, "1001")
	if err != nil {
		t.Fatal(err)
	}
	defer exchange()
	trace := traceForeignHookRemovals(t)
	cleanups := foreignHookTestCleanups("cursor")
	session := newEnterpriseForeignHookFenceSession(cleanups, io.Discard, "1001", account.Home)
	start := time.Now()
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpForeignCleanup, Standalone: true, ForeignCleanup: cleanups, cleanupFence: session,
	})
	if err != nil || response.Cleanup["cursor"].Error != "" || len(response.Cleanup["cursor"].Removed) != 0 {
		t.Fatalf("a clean home: %+v %v", response.Cleanup, err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second || trace.String() != "" {
		t.Fatalf("a clean home asked for the account's lock (%v): %s", elapsed, trace)
	}
}

// The lead's guard (1.0.4): a standalone worker the guardian gave no commit
// channel removes nothing, whatever it finds: every removal is refused, the
// hooks stay in place and are reported. A worker that is not standalone
// cleans without a commit (TestWorkerForeignCleanupRemovesTheUsersForeignHook).
func TestStandaloneWorkerWithoutACommitChannelRemovesNothing(t *testing.T) {
	home := t.TempDir()
	plugins := foreignHookTestOpenCodePlugins(t, home)
	hooks := foreignHookTestCursorHook(t, home)
	reports := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{
		Home: home, Standalone: true,
		ForeignCleanup: append(foreignHookTestCleanups("opencode"), foreignHookTestCleanups("cursor")...),
	}, time.Now(), nil)
	for _, name := range []string{"opencode", "cursor"} {
		report := reports[name]
		if report.Error == "" || len(report.Removed) != 0 || len(report.Reported) == 0 {
			t.Fatalf("%s: a standalone worker without a commit channel must remove nothing and report the hooks: %+v", name, report)
		}
	}
	for _, path := range plugins {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s was removed without a commit: %v", path, err)
		}
	}
	if !foreignHookTestHookPresent(hooks) {
		t.Fatal("the Cursor hook was removed without a commit")
	}
}

// Item 2 through the worker: a rotation that could not end the key refuses
// the removal (the worker's report names it, every plugin stays, and the
// second plugin's removal is refused without asking the guardian again); a
// rotation that ended the key but made no new one warns in the guardian's
// log and the removals go on.
func TestForeignHookWorkerRemovalAndTheKeyRotation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rotate  func(root, identity string) error
		refused bool
	}{
		{name: "the key could not be ended", refused: true, rotate: func(string, string) error {
			return fmt.Errorf("%w: the key file is in use", enterprisepolicy.ErrPublishedSessionKeyAlive)
		}},
		{name: "the key ended, no new one", rotate: func(root, identity string) error {
			if err := enterprisepolicy.RevokePublishedSessionKey(root, identity); err != nil {
				return fmt.Errorf("%w: %v", enterprisepolicy.ErrPublishedSessionKeyAlive, err)
			}
			return errors.New("create the protected session record key: no space left on device")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := useForeignHookGuardian(t, nil)
			process := runtime.GOOS + ":b:1:100"
			g.allow(t, "1001", process)
			rotations := 0
			enterpriseForeignHookRotateSessionKey = func(root, identity string, _ enterprisepolicy.PublishedSessionTrust) error {
				rotations++
				return tc.rotate(root, identity)
			}
			trace := traceForeignHookRemovals(t)
			home := t.TempDir()
			plugins := foreignHookTestOpenCodePlugins(t, home)
			var stderr bytes.Buffer
			cleanups := foreignHookTestCleanups("opencode")
			session := newEnterpriseForeignHookFenceSession(cleanups, &stderr, "1001", home)
			report := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{Home: home, Standalone: true, ForeignCleanup: cleanups}, time.Now(), foreignHookPipeFence(t, session))["opencode"]
			if tc.refused {
				if !strings.Contains(report.Error, enterprisepolicy.ErrPublishedSessionKeyAlive.Error()) || len(report.Removed) != 0 || len(report.Reported) < len(plugins) {
					t.Fatalf("the refused rotation must be reported and every plugin kept: %+v", report)
				}
				for _, path := range plugins {
					if _, err := os.Lstat(path); err != nil {
						t.Fatalf("%s changed although the key could not be rotated: %v", path, err)
					}
				}
				if rotations != 1 || trace.String() != "lock,rotate,release" || g.ledgerExists() {
					t.Fatalf("nothing may be recorded, the later removal is refused without asking (rotations %d): %s", rotations, trace)
				}
				return
			}
			if report.Error != "" || len(report.Removed) != len(plugins) {
				t.Fatalf("a rotation that ended the key must not refuse the removals: %+v", report)
			}
			if rotations != len(plugins) || !strings.Contains(stderr.String(), "guarded calls block during a gateway outage until a later pass makes one") {
				t.Fatalf("each removal rotates, and the missing key is reported (rotations %d): %q", rotations, stderr.String())
			}
			for _, path := range plugins {
				if _, ok := g.entry(t, "1001", "opencode", path); !ok {
					t.Fatalf("%s is not recorded", path)
				}
			}
			if g.proves("1001", process) {
				t.Fatal("the old allow must prove nothing")
			}
		})
	}
}

// foreignHookWorkerPass is a standalone guardian with the Cursor machine
// policy, eligible accounts with temporary homes, and runner as the
// per-user worker.
func foreignHookWorkerPass(t *testing.T, users []string, runner func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error)) (*foreignHookGuardian, map[string]string) {
	t.Helper()
	previousManifest := enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	t.Cleanup(func() {
		enterpriseHookManifest = previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.unrepaired = nil
	})
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	g := useForeignHookGuardian(t, map[string]config.EnterpriseConnectorPolicy{"cursor": {}})
	enterpriseHookManifest = "/etc/defenseclaw/hook-guardian/targets.yaml"
	homes := map[string]string{}
	var accounts []enterprisehooks.UnixEligibleAccount
	for i, user := range users {
		home := t.TempDir()
		homes[user] = home
		accounts = append(accounts, enterprisehooks.UnixEligibleAccount{User: user, UID: 4242 + i, GID: 4242 + i, Home: home, HomeInode: 7})
	}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) { return accounts, nil }
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable, Inode: 7}
	}
	enterpriseHookWorkerRunner = runner
	return g, homes
}

func foreignHookWorkerTargets(request enterpriseHookWorkerRequest) []enterpriseHookWorkerTargetResult {
	var targets []enterpriseHookWorkerTargetResult
	for _, target := range request.Targets {
		targets = append(targets, enterpriseHookWorkerTargetResult{Index: target.Index, OK: true})
	}
	return targets
}

// Item 6: a worker that ended after its lock and before its commit (killed,
// timed out, crashed). The guardian ends that commit first: it records the
// locked files with the mark of now and lets go of the account's lock; only
// then does the fallback record the other removals the worker reported and
// no commit recorded, which takes the lock again. Both finish in bounded
// time (the fallback would otherwise wait on the commit's own lock).
func TestForeignHookWorkerThatDiedAfterItsLock(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report bool // the worker still answered, with an uncommitted removal
		want   string
	}{
		{name: "the worker died", want: "lock,rotate,ledger,ledger,release"},
		{name: "the worker reported a removal no commit covered", report: true, want: "lock,rotate,ledger,ledger,release,lock,rotate,ledger,ledger,release"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var locked, other string
			var trace *foreignHookRemovalTrace
			g, homes := foreignHookWorkerPass(t, []string{"alice"}, func(ctx context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
				if request.cleanupFence == nil {
					return enterpriseHookWorkerResponse{}, errors.New("no fence session")
				}
				if err := request.cleanupFence.lock(ctx, "cursor", []string{locked}); err != nil {
					return enterpriseHookWorkerResponse{}, err
				}
				if err := foreignHookTestRemoveHook(locked); err != nil {
					return enterpriseHookWorkerResponse{}, err
				}
				if !tc.report {
					return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d timed out: %w", account.UID, context.DeadlineExceeded)
				}
				if err := foreignHookTestRemoveHook(other); err != nil {
					return enterpriseHookWorkerResponse{}, err
				}
				return enterpriseHookWorkerResponse{Targets: foreignHookWorkerTargets(request), Cleanup: map[string]enterpriseHookWorkerCleanupReport{
					"cursor": {Removed: []string{locked, other}, BackupDir: account.Home + "/.defenseclaw/foreign-hooks-backup/cursor/x"},
				}}, nil
			})
			locked = foreignHookTestCursorHook(t, homes["alice"])
			other = filepath.Join(homes["alice"], ".cursor", "other.json")
			if err := os.WriteFile(other, []byte(`{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`), 0o644); err != nil {
				t.Fatal(err)
			}
			trace = traceForeignHookRemovals(t)
			var log strings.Builder
			start := time.Now()
			runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Now(), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
			if elapsed := time.Since(start); elapsed > enterprisepolicy.ForeignHookRemovalGateWait/3 {
				t.Fatalf("the pass took %v: the fallback waited on the open commit's lock; log:\n%s", elapsed, log.String())
			}
			if got := trace.String(); got != tc.want {
				t.Fatalf("commit order\n got %s\nwant %s\nlog:\n%s", got, tc.want, log.String())
			}
			removal, ok := g.entry(t, "4242", "cursor", locked)
			if !ok {
				t.Fatalf("the locked file must be recorded: %+v", g.removals(t))
			}
			requireForeignHookMarkCommitted(t, removal)
			if tc.report {
				removal, ok := g.entry(t, "4242", "cursor", other)
				if !ok {
					t.Fatalf("the uncommitted removal must be recorded by the fallback: %+v", g.removals(t))
				}
				requireForeignHookMarkCommitted(t, removal)
			}
			if !accountRemovalLockFree(t, "4242", time.Second) {
				t.Fatal("the account's lock is still held after the pass")
			}
		})
	}
}

// The per-user workers run concurrently and none of their work holds an
// account's removal lock: only a removal does, through its commit. A worker
// that scans for a long time never keeps its account's gateway exchanges,
// or another account's cleanup, waiting. What the workers report and no
// commit recorded is recorded once each ends.
func TestStandaloneForeignCleanupWorkersDoNotHoldTheLock(t *testing.T) {
	var mu sync.Mutex
	active, peak := 0, 0
	both := make(chan struct{})
	g, _ := foreignHookWorkerPass(t, []string{"alice", "bob"}, func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		if active == 2 {
			close(both)
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		if len(request.ForeignCleanup) == 0 || request.cleanupFence == nil {
			t.Errorf("worker for %s has no foreign cleanup commit session", account.User)
		}
		for _, uid := range []int{4242, 4243} {
			if !accountRemovalLockFree(t, strconv.Itoa(uid), 100*time.Millisecond) {
				t.Errorf("the worker for %s holds uid %d's removal lock before any removal", account.User, uid)
			}
		}
		select {
		case <-both:
		case <-time.After(2 * time.Second):
			t.Errorf("the worker for %s ran alone: the accounts' workers must run concurrently", account.User)
		}
		return enterpriseHookWorkerResponse{Targets: foreignHookWorkerTargets(request), Cleanup: map[string]enterpriseHookWorkerCleanupReport{
			"cursor": {Removed: []string{account.Home + "/.cursor/hooks.json"}, BackupDir: account.Home + "/.defenseclaw/foreign-hooks-backup/cursor/x"},
		}}, nil
	})
	var log strings.Builder
	runEnterpriseHookStandaloneForeignCleanup(context.Background(), &log, time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC), enterprisehooks.Manifest{}, map[string]map[string]bool{}, "")
	if peak != 2 {
		t.Fatalf("peak concurrent workers = %d, want 2; log:\n%s", peak, log.String())
	}
	var identities []string
	for _, removal := range g.removals(t) {
		identities = append(identities, removal.Identity)
	}
	if got := strings.Join(identities, ","); !strings.Contains(got, "4242") || !strings.Contains(got, "4243") {
		t.Fatalf("both accounts' removals must reach the ledger, got %q; log:\n%s", got, log.String())
	}
	for _, uid := range []string{"4242", "4243"} {
		if !accountRemovalLockFree(t, uid, 100*time.Millisecond) {
			t.Fatalf("uid %s's removal lock is still held after the pass", uid)
		}
	}
}

// The guardian's session of one worker opens one removal's commit at a
// time. The account's lock it holds keeps that account's gateway exchanges
// and the account's other cleanups out until the commit, which then go on
// (queued within their own bound, never abandoned); another account never
// waits. The session refuses a connector outside the job, a removal that
// names no file, a second open commit, a commit that holds no lock or
// another connector's, a second commit, and takes at most its bound of
// commits per connector.
func TestForeignHookFenceSessionCommitsOneRemovalAtATime(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	g := useForeignHookGuardian(t, nil)
	cleanups := []enterpriseHookWorkerForeignCleanup{{Connector: "cursor"}, {Connector: "claudecode"}}
	session := func(uid, home string) *enterpriseForeignHookFenceSession {
		return newEnterpriseForeignHookFenceSession(cleanups, io.Discard, uid, home)
	}
	alice, alice2, bob := session("4242", "/home/alice"), session("4242", "/home/alice"), session("4243", "/home/bob")
	if err := alice.lock(context.Background(), "cursor", []string{"/home/alice/.cursor/hooks.json"}); err != nil {
		t.Fatal(err)
	}
	if accountRemovalLockFree(t, "4242", 50*time.Millisecond) {
		t.Fatal("a removal in progress must hold the account's lock against the gateway")
	}
	start := time.Now()
	if err := bob.lock(context.Background(), "cursor", []string{"/home/bob/.cursor/hooks.json"}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > enterprisepolicy.ForeignHookRemovalDrainWait/2 {
		t.Fatalf("another account's removal waited %v for alice's", elapsed)
	}
	if err := bob.commit("cursor", []string{"/home/bob/.cursor/hooks.json"}); err != nil {
		t.Fatal(err)
	}
	queued := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		queued <- alice2.lock(ctx, "cursor", []string{"/home/alice/.cursor/other.json"})
	}()
	select {
	case err := <-queued:
		t.Fatalf("the account's second cleanup passed its removal in progress: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, ok := g.entry(t, "4242", "cursor", "/home/alice/.cursor/other.json"); ok {
		t.Fatal("the queued removal was recorded while the first one held the lock")
	}
	if err := alice.commit("cursor", []string{"/home/alice/.cursor/hooks.json"}); err != nil {
		t.Fatal(err)
	}
	if err := <-queued; err != nil {
		t.Fatalf("a queued cleanup of the account was abandoned: %v", err)
	}
	if err := alice2.commit("cursor", []string{"/home/alice/.cursor/other.json"}); err != nil {
		t.Fatal(err)
	}
	if !accountRemovalLockFree(t, "4242", 100*time.Millisecond) {
		t.Fatal("the lock stays held after the last commit")
	}

	if err := alice.lock(context.Background(), "codex", []string{"/home/alice/.codex/hooks.json"}); err == nil {
		t.Fatal("locked for a connector outside the job")
	}
	if err := alice.lock(context.Background(), "cursor", nil); err == nil {
		t.Fatal("locked for a removal that names no file")
	}
	if err := alice.commit("claudecode", []string{"/home/alice/.claude/settings.json"}); err == nil {
		t.Fatal("committed without the lock")
	}
	if err := alice.lock(context.Background(), "cursor", []string{"/home/alice/.cursor/late.json"}); err != nil {
		t.Fatalf("a later removal of the same connector must take the lock again: %v", err)
	}
	if err := alice.lock(context.Background(), "claudecode", []string{"/home/alice/.claude/settings.json"}); err == nil {
		t.Fatal("locked while another removal of the job holds the lock")
	}
	if err := alice.commit("claudecode", []string{"/home/alice/.claude/settings.json"}); err == nil {
		t.Fatal("committed for a connector whose removal does not hold the lock")
	}
	if err := alice.commit("cursor", []string{"/home/alice/.cursor/late.json"}); err != nil {
		t.Fatal(err)
	}
	if err := alice.commit("cursor", nil); err == nil {
		t.Fatal("committed twice for one lock")
	}
	if got := alice.uncommitted("cursor", []string{"/home/alice/.cursor/hooks.json", "/home/alice/.cursor/late.json", "/home/alice/.cursor/never.json"}); strings.Join(got, ",") != "/home/alice/.cursor/never.json" {
		t.Fatalf("uncommitted = %v", got)
	}
	alice.locks["claudecode"] = enterpriseHookWorkerFenceLockLimit
	if err := alice.lock(context.Background(), "claudecode", []string{"/home/alice/.claude/settings.json"}); err == nil {
		alice.release()
		t.Fatal("locked past the per-connector bound")
	}
	if !accountRemovalLockFree(t, "4242", 100*time.Millisecond) {
		t.Fatal("the lock stays held after the session's commits")
	}
}

// The worker opens and commits a removal per change, before it reads on: a
// cleanup with two foreign plugins locks and commits once per plugin, and
// the second plugin is untouched when the first one commits. A refused
// commit leaves every hook in place, asked for once.
func TestForeignCleanupWorkerReleasesTheFenceAfterEachRemoval(t *testing.T) {
	present := func(path string) bool { _, err := os.Lstat(path); return err == nil }
	cleanups := foreignHookTestCleanups("opencode")

	home := t.TempDir()
	plugins := foreignHookTestOpenCodePlugins(t, home)
	fence := &recordingCleanupFence{}
	commits := 0
	fence.onCommit = func(removed []string) {
		commits++
		if commits == 1 && (len(removed) != 1 || present(removed[0]) || !present(plugins[0]) && !present(plugins[1])) {
			t.Errorf("the first commit must cover one removed plugin while the other is still in place: %v", removed)
		}
	}
	report := runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{Home: home, Standalone: true, ForeignCleanup: cleanups}, time.Now(), fence)["opencode"]
	if report.Error != "" || len(report.Removed) != 2 {
		t.Fatalf("cleanup report %+v", report)
	}
	locks := 0
	for _, event := range fence.events {
		if strings.HasPrefix(event, "lock opencode /") {
			locks++
		}
	}
	if locks != 2 || commits != 2 || len(fence.events) != 4 || fence.held {
		t.Fatalf("each removal must lock, naming its file, and commit on its own: %v", fence.events)
	}
	for _, path := range plugins {
		if present(path) {
			t.Fatalf("%s was not removed", path)
		}
	}

	home = t.TempDir()
	plugins = foreignHookTestOpenCodePlugins(t, home)
	refused := &recordingCleanupFence{lockErr: errors.New("fence busy")}
	report = runEnterpriseHookWorkerForeignCleanup(enterpriseHookWorkerRequest{Home: home, Standalone: true, ForeignCleanup: cleanups}, time.Now(), refused)["opencode"]
	if report.Error == "" || len(report.Removed) != 0 || len(report.Reported) < 2 || len(refused.events) != 1 {
		t.Fatalf("a refused fence: report %+v, fence %v", report, refused.events)
	}
	for _, path := range plugins {
		if !present(path) {
			t.Fatalf("%s was removed without the fence", path)
		}
	}
}
