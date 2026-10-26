// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// foreignHookGuardian holds the temporary removal ledger used by the
// account removal tests.
type foreignHookGuardian struct{ ledger string }

func useForeignHookRemovalRecords(t *testing.T) *foreignHookGuardian {
	t.Helper()
	if cfg == nil {
		t.Fatal("set cfg before the foreign-hook guardian fixture")
	}
	previousOwner, previousDirTrust, previousFileTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck
	t.Cleanup(func() {
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck = previousOwner, previousDirTrust, previousFileTrust
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	cfg.DataDir = t.TempDir()
	guardianDir := filepath.Join(cfg.DataDir, "guardian")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	if _, err := prepareEnterpriseHookAuthorizationDir(cfg.DataDir); err != nil {
		t.Fatal(err)
	}
	return &foreignHookGuardian{ledger: filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)}
}

// useForeignHookGuardian makes cfg a standalone enterprise config with the
// machine policy connectors policy (restored after the test) and the
// guardian of useForeignHookRemovalRecords.
func useForeignHookGuardian(t *testing.T, policy map[string]config.EnterpriseConnectorPolicy) *foreignHookGuardian {
	t.Helper()
	previousCfg := cfg
	t.Cleanup(func() { cfg = previousCfg })
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile:       managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: policy},
		},
	}
	return useForeignHookRemovalRecords(t)
}

// skipForeignHookLedgerOnWindows skips a test that writes the removal
// ledger: on Windows the protected write sets a SYSTEM-owned DACL.
func skipForeignHookLedgerOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the protected ledger write sets a SYSTEM-owned DACL")
	}
}

// removals is the ledger ("" entries when there is none).
func (g *foreignHookGuardian) removals(t *testing.T) []enterprisepolicy.ForeignHookRemoval {
	t.Helper()
	removals, err := loadEnterpriseForeignHookRemovals(g.ledger)
	if err != nil {
		t.Fatal(err)
	}
	return removals
}

// entry is the ledger's entry for identity, connector and path.
func (g *foreignHookGuardian) entry(t *testing.T, identity, connectorName, path string) (enterprisepolicy.ForeignHookRemoval, bool) {
	t.Helper()
	for _, removal := range g.removals(t) {
		if removal.Identity == identity && removal.Connector == connectorName && removal.Path == path {
			return removal, true
		}
	}
	return enterprisepolicy.ForeignHookRemoval{}, false
}

func (g *foreignHookGuardian) ledgerExists() bool {
	_, err := os.Lstat(g.ledger)
	return err == nil
}

// accountRemovalLockFree reports whether a gateway exchange of identity could
// take the account's lock within wait: no removal holds it.
func accountRemovalLockFree(t *testing.T, identity string, wait time.Duration) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	release, err := enterprisepolicy.LockForeignHookAccountExchange(ctx, cfg.DataDir, identity)
	if err != nil {
		return false
	}
	release()
	return true
}

// foreignHookTestMarkClock splits an agentprocess mark (goos:boot:clock).
func foreignHookTestMarkClock(t *testing.T, mark string) (string, int64) {
	t.Helper()
	parts := strings.Split(mark, ":")
	if len(parts) != 3 {
		t.Fatalf("mark %q", mark)
	}
	clock, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		t.Fatalf("mark %q: %v", mark, err)
	}
	return parts[0] + ":" + parts[1], clock
}

// foreignHookTestProcessAt names an agent process with pid that started at
// the clock of mark plus delta.
func foreignHookTestProcessAt(t *testing.T, mark string, pid int, delta int64) string {
	t.Helper()
	boot, clock := foreignHookTestMarkClock(t, mark)
	return fmt.Sprintf("%s:%d:%d", boot, pid, clock+delta)
}

// foreignHookMarkAhead reports a mark that is not ahead of now, or that
// does not deny an agent process that starts now. It does not touch t, so a
// seam that runs on another goroutine (the fence session's) may call it.
func foreignHookMarkAhead(mark string) error {
	now := agentprocess.Now()
	nowBoot, nowClock, err := foreignHookMarkParts(now)
	if err != nil {
		return err
	}
	markBoot, markClock, err := foreignHookMarkParts(mark)
	if err != nil {
		return err
	}
	starting := fmt.Sprintf("%s:%d:%d", nowBoot, 4242, nowClock)
	if markBoot != nowBoot || markClock <= nowClock || !agentprocess.StartedBefore(starting, mark) {
		return fmt.Errorf("while the file changes the record must be ahead of now (mark %q, now %q)", mark, now)
	}
	return nil
}

// foreignHookMarkCommitted reports a mark later than now: the second record
// did not replace the mark ahead.
func foreignHookMarkCommitted(mark string) error {
	now := agentprocess.Now()
	nowBoot, nowClock, err := foreignHookMarkParts(now)
	if err != nil {
		return err
	}
	_, markClock, err := foreignHookMarkParts(mark)
	if err != nil {
		return err
	}
	later := fmt.Sprintf("%s:%d:%d", nowBoot, 4243, nowClock+1)
	if markClock > nowClock || agentprocess.StartedBefore(later, mark) {
		return fmt.Errorf("after the commit the mark must be now, not ahead (mark %q, now %q)", mark, now)
	}
	return nil
}

func foreignHookMarkParts(mark string) (string, int64, error) {
	parts := strings.Split(mark, ":")
	if len(parts) != 3 {
		return "", 0, fmt.Errorf("mark %q (the process clock may be unavailable)", mark)
	}
	clock, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("mark %q: %v", mark, err)
	}
	return parts[0] + ":" + parts[1], clock, nil
}

func requireForeignHookMarkAhead(t *testing.T, removal enterprisepolicy.ForeignHookRemoval) {
	t.Helper()
	if agentprocess.Now() == "" {
		t.Skip("the process clock is unavailable here")
	}
	if err := foreignHookMarkAhead(removal.Mark); err != nil {
		t.Fatal(err)
	}
}

func requireForeignHookMarkCommitted(t *testing.T, removal enterprisepolicy.ForeignHookRemoval) {
	t.Helper()
	if agentprocess.Now() == "" {
		t.Skip("the process clock is unavailable here")
	}
	if err := foreignHookMarkCommitted(removal.Mark); err != nil {
		t.Fatal(err)
	}
}

// foreignHookRemovalTrace logs the account lock, each ledger write, the
// file change and the release in one removal commit.
type foreignHookRemovalTrace struct {
	mu      sync.Mutex
	events  []string
	observe func(event string) string
}

func traceForeignHookRemovals(t *testing.T) *foreignHookRemovalTrace {
	t.Helper()
	trace := &foreignHookRemovalTrace{}
	lock, owner := enterpriseForeignHookLockAccount, enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() {
		enterpriseForeignHookLockAccount, enterpriseHookAuthorizationOwnershipSetter = lock, owner
	})
	enterpriseForeignHookLockAccount = func(ctx context.Context, dataDir, identity string) (func(), bool, error) {
		release, drained, err := lock(ctx, dataDir, identity)
		if err != nil {
			trace.add("lock-refused")
			return nil, false, err
		}
		trace.add("lock")
		var once sync.Once
		return func() { once.Do(func() { trace.add("release"); release() }) }, drained, nil
	}
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		if strings.Contains(filepath.Base(path), enterprisepolicy.ForeignHookRemovalsFile) {
			trace.add("ledger")
		}
		return owner(path)
	}
	return trace
}

func (tr *foreignHookRemovalTrace) add(event string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.observe != nil {
		if before := tr.observe(event); before != "" {
			tr.events = append(tr.events, before)
		}
	}
	tr.events = append(tr.events, event)
}

func (tr *foreignHookRemovalTrace) String() string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return strings.Join(tr.events, ",")
}

func (tr *foreignHookRemovalTrace) count(event string) int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	n := 0
	for _, e := range tr.events {
		if e == event {
			n++
		}
	}
	return n
}

// foreignHookTestCursorHook writes a Cursor hooks.json with one unapproved
// hook into home and returns its path.
func foreignHookTestCursorHook(t *testing.T, home string) string {
	t.Helper()
	path := filepath.Join(home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// foreignHookTestHookPresent reports whether the unapproved hook is still in
// the file at path.
func foreignHookTestHookPresent(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(data), "rewrite.sh")
}

// foreignHookTestRemoveHook is a removal's change: the file without the hook.
func foreignHookTestRemoveHook(path string) error {
	return os.WriteFile(path, []byte(`{"version": 1, "hooks": {}}`), 0o644)
}

func foreignHookTestCursorPolicy() enterprisepolicy.PublicConnectorPolicy {
	return enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}
}

// foreignHookTestInProcessRequest is the guard request of an in-process
// Cursor cleanup of home.
func foreignHookTestInProcessRequest(connectorName, home string) enterprisepolicy.GuardRequest {
	return enterprisepolicy.GuardRequest{
		Connector:   connectorName,
		GOOS:        runtime.GOOS,
		Home:        home,
		AccountHome: home,
		HookBinary:  "/opt/defenseclaw/bin/defenseclaw-hook",
		Policy:      foreignHookTestCursorPolicy(),
	}
}

// useInProcessCleanupAsSelf runs the in-process cleanup as this process (a
// test cannot take on another account's token).
func useInProcessCleanupAsSelf(t *testing.T) {
	t.Helper()
	previous := enterpriseForeignHookRunAsTarget
	t.Cleanup(func() { enterpriseForeignHookRunAsTarget = previous })
	enterpriseForeignHookRunAsTarget = func(_ enterprisehooks.TargetCredentials, fn func() error) error { return fn() }
}

func foreignHookTestTarget(home string) enterprisehooks.TargetCredentials {
	if runtime.GOOS == "windows" {
		return enterprisehooks.TargetCredentials{UserHome: home, UID: -1, GID: -1, SID: "S-1-5-21-1-2-3-1001"}
	}
	return enterprisehooks.TargetCredentials{UserHome: home, UID: 1001, GID: 1001}
}

// recordingCleanupFence is a cleanup fence that records its use.
type recordingCleanupFence struct {
	events    []string
	held      bool
	lockErr   error
	commitErr error
	onCommit  func(removed []string)
}

func (f *recordingCleanupFence) lock(connector string, paths []string) error {
	f.events = append(f.events, "lock "+connector+" "+strings.Join(paths, ","))
	if f.lockErr != nil {
		return f.lockErr
	}
	if f.held {
		return errors.New("locked while held")
	}
	f.held = true
	return nil
}

func (f *recordingCleanupFence) commit(connector string, removed []string) error {
	f.events = append(f.events, "commit "+connector+" "+strings.Join(removed, ","))
	if !f.held {
		return errors.New("committed without the fence")
	}
	f.held = false
	if f.onCommit != nil {
		f.onCommit(removed)
	}
	return f.commitErr
}

// Each removal opens its own commit for the files it changes, and commits
// only what it removed; a refused commit or a failed one stops the
// cleanup's later removals without asking again.
func TestForeignHookRemovalGuardFencesEachRemovalOnItsOwn(t *testing.T) {
	fence := &recordingCleanupFence{}
	guard := enterpriseForeignHookRemovalGuard("cursor", fence)
	for _, path := range []string{"/home/a/one.json", "/home/a/two.json"} {
		if err := guard([]string{path}, func() error {
			if !fence.held {
				t.Errorf("%s was removed without the fence", path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if fence.held {
			t.Fatalf("the fence is still held after %s was committed", path)
		}
	}
	failed := errors.New("rewrite failed")
	if err := guard([]string{"/home/a/three.json"}, func() error { return failed }); !errors.Is(err, failed) {
		t.Fatalf("a failed removal must return its error, got %v", err)
	}
	want := "lock cursor /home/a/one.json|commit cursor /home/a/one.json|lock cursor /home/a/two.json|commit cursor /home/a/two.json|lock cursor /home/a/three.json|commit cursor "
	if got := strings.Join(fence.events, "|"); got != want {
		t.Fatalf("fence use\n got %s\nwant %s", got, want)
	}

	refused := &recordingCleanupFence{lockErr: errors.New("fence busy")}
	guard = enterpriseForeignHookRemovalGuard("cursor", refused)
	for i := 0; i < 2; i++ {
		if err := guard([]string{"/home/a/one.json"}, func() error {
			t.Error("a removal ran without the fence")
			return nil
		}); !errors.Is(err, refused.lockErr) {
			t.Fatalf("a refused fence must refuse the removal, got %v", err)
		}
	}
	if len(refused.events) != 1 {
		t.Fatalf("a refused fence was asked again: %v", refused.events)
	}

	broken := &recordingCleanupFence{commitErr: errors.New("fence pipe closed")}
	guard = enterpriseForeignHookRemovalGuard("cursor", broken)
	if err := guard([]string{"/home/a/one.json"}, func() error { return nil }); !errors.Is(err, broken.commitErr) {
		t.Fatalf("a failed commit must surface, got %v", err)
	}
	if err := guard([]string{"/home/a/two.json"}, func() error {
		t.Error("a removal ran after a failed commit")
		return nil
	}); err == nil {
		t.Fatal("a removal after a failed commit must be refused")
	}
	if len(broken.events) != 2 {
		t.Fatalf("fence use after a failed commit: %v", broken.events)
	}
}

// foreignHookRemovalOrderCase is one removal entry point: run removes the
// unapproved hook in the Cursor hooks file path of home for the account
// "1001" through it.
type foreignHookRemovalOrderCase struct {
	name string
	// want is the trace of the run.
	want string
	// logsChange: run logs the change itself; otherwise the trace inserts
	// "change" before the first event that finds the file changed.
	logsChange bool
	// markAtEnd: the change was made before the commit opened (the
	// fallback), so its first record carries the mark of when the cleanup
	// ended, not one ahead.
	markAtEnd bool
	home      func(t *testing.T) string
	run       func(t *testing.T, trace *foreignHookRemovalTrace, home, path string)
}

// runForeignHookRemovalOrderCases keeps every removal entry point behind
// its account lock and a ledger write before changing the hook file.
func runForeignHookRemovalOrderCases(t *testing.T, cases []foreignHookRemovalOrderCase) {
	t.Helper()
	const identity = "1001"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := useForeignHookGuardian(t, nil)
			home := t.TempDir()
			if tc.home != nil {
				home = tc.home(t)
			}
			path := foreignHookTestCursorHook(t, home)
			trace := traceForeignHookRemovals(t)
			changed, ledgers := false, 0
			trace.observe = func(event string) string {
				before := ""
				if !changed && !foreignHookTestHookPresent(path) {
					changed = true
					if !tc.logsChange {
						before = "change"
					}
				}
				if event == "ledger" {
					ledgers++
					if ledgers == 2 && changed && !tc.markAtEnd {
						removals, err := loadEnterpriseForeignHookRemovals(g.ledger)
						found := false
						for _, removal := range removals {
							if removal.Identity == identity && removal.Connector == "cursor" && removal.Path == path+enterprisepolicy.ForeignHookRemovalInProgressSuffix {
								found = true
								if err := foreignHookMarkAhead(removal.Mark); err != nil {
									t.Error(err)
								}
							}
						}
						if err != nil || !found {
							t.Errorf("file changed before its pending denial: %+v %v", removals, err)
						}
					}
				}
				return before
			}
			tc.run(t, trace, home, path)
			if got := trace.String(); got != tc.want {
				t.Fatalf("commit order\n got %s\nwant %s", got, tc.want)
			}
			if foreignHookTestHookPresent(path) {
				t.Fatal("the unapproved hook is still in place")
			}
			removal, ok := g.entry(t, identity, "cursor", path)
			if !ok {
				t.Fatalf("the removal is not in the ledger: %+v", g.removals(t))
			}
			requireForeignHookMarkCommitted(t, removal)
			if !accountRemovalLockFree(t, identity, time.Second) {
				t.Fatal("the account lock is still held")
			}
		})
	}
}

// Item 1, the entry points every build has: the in-process guard (the
// reconcile loop's cleanup and the Windows machine-policy pass), the
// in-process cleanup of a real hook file, and the fallback that records a
// removal no commit recorded (a worker that changed a file and ended before
// its commit: the change came first, and the fallback still records it).
// The worker's pipe protocol and the real worker process are in
// the Unix file.
func TestForeignHookRemovalRecordsBeforeTheFileChanges(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	runForeignHookRemovalOrderCases(t, []foreignHookRemovalOrderCase{
		{
			name:       "the in-process guard",
			want:       "lock,ledger,change,ledger,release",
			logsChange: true,
			run: func(t *testing.T, trace *foreignHookRemovalTrace, home, path string) {
				guard := enterpriseForeignHookRemovalGuard("cursor", newEnterpriseForeignHookInProcessFence("1001", home))
				if err := guard([]string{path}, func() error {
					trace.add("change")
					return foreignHookTestRemoveHook(path)
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "the in-process cleanup of the user's hook file",
			want: "lock,ledger,change,ledger,release",
			run: func(t *testing.T, trace *foreignHookRemovalTrace, home, path string) {
				useInProcessCleanupAsSelf(t)
				result, err := cleanEnterpriseForeignHooksFenced(foreignHookTestTarget(home), foreignHookTestInProcessRequest("cursor", home), time.Now())
				if err != nil || len(result.Removed) != 1 {
					t.Fatalf("cleanup %+v: %v", result, err)
				}
			},
		},
		{
			name:      "the fallback for a removal no commit recorded",
			want:      "change,lock,ledger,ledger,release",
			markAtEnd: true,
			run: func(t *testing.T, trace *foreignHookRemovalTrace, home, path string) {
				if err := foreignHookTestRemoveHook(path); err != nil {
					t.Fatal(err)
				}
				var stderr bytes.Buffer
				recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "cursor", []string{path})
				if stderr.Len() != 0 {
					t.Fatal(stderr.String())
				}
			},
		},
	})
}

// foreignHookTestOpenCodePlugins writes two unapproved OpenCode plugins into
// home: each is its own removal. The worker cleans with its own environment,
// which here is the test's: an XDG_CONFIG_HOME or OPENCODE_CONFIG_DIR of the
// host (a GitHub runner sets XDG_CONFIG_HOME=/home/runner/.config) would
// send OpenCode, and the cleanup, to that directory instead of home/.config.
func foreignHookTestOpenCodePlugins(t *testing.T, home string) []string {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("OPENCODE_CONFIG", "")
	dir := filepath.Join(home, ".config", "opencode", "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	plugins := []string{filepath.Join(dir, "a-mutate.mjs"), filepath.Join(dir, "b-mutate.mjs")}
	for _, path := range plugins {
		if err := os.WriteFile(path, []byte("export default {}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return plugins
}

// Item 3 (GAP-0381, GAP-0457: the cleanup must not precede the removal
// record): when the file changes, the ledger already holds its entry, with a
// mark ahead of now, so the gateway denies an agent process that started
// while the file changed or shortly after; once committed the mark is now:
// the process that ran during the change stays denied, one started after
// the commit is allowed.
func TestForeignHookRemovalIsRecordedAheadBeforeTheFileChanges(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	g := useForeignHookGuardian(t, nil)
	home := t.TempDir()
	path := foreignHookTestCursorHook(t, home)
	var running string
	guard := enterpriseForeignHookRemovalGuard("cursor", newEnterpriseForeignHookInProcessFence("1001", home))
	if err := guard([]string{path}, func() error {
		removal, ok := g.entry(t, "1001", "cursor", path+enterprisepolicy.ForeignHookRemovalInProgressSuffix)
		if !ok {
			t.Fatal("the file changes before the ledger holds its removal")
		}
		requireForeignHookMarkAhead(t, removal)
		now := agentprocess.Now()
		running = foreignHookTestProcessAt(t, now, 4242, 0)
		soon := foreignHookTestProcessAt(t, agentprocess.NowAfter(time.Minute), 4244, 0)
		for _, process := range []string{running, soon} {
			key := enterprisepolicy.SessionKey{Connector: "cursor", Session: "s-1", Process: process}
			if got := enterprisepolicy.ApplyForeignHookRemovals(enterprisepolicy.GuardDecision{}, key, g.removals(t), nil, time.Now()); !got.Deny {
				t.Fatalf("an agent process that may load the file while it changes must be denied: %s %+v", process, got)
			}
		}
		return foreignHookTestRemoveHook(path)
	}); err != nil {
		t.Fatal(err)
	}
	removal, ok := g.entry(t, "1001", "cursor", path)
	if !ok {
		t.Fatal("the commit dropped the removal")
	}
	requireForeignHookMarkCommitted(t, removal)
	removals := g.removals(t)
	if len(removals) != 1 {
		t.Fatalf("the commit must replace the first record, not add one: %+v", removals)
	}
	key := enterprisepolicy.SessionKey{Connector: "cursor", Session: "s-1", Process: running}
	if got := enterprisepolicy.ApplyForeignHookRemovals(enterprisepolicy.GuardDecision{}, key, removals, nil, time.Now()); !got.Deny {
		t.Fatalf("the agent that ran during the change must stay denied: %+v", got)
	}
	key.Process = foreignHookTestProcessAt(t, agentprocess.Now(), 4245, 1)
	if got := enterprisepolicy.ApplyForeignHookRemovals(enterprisepolicy.GuardDecision{}, key, removals, nil, time.Now()); got.Deny {
		t.Fatalf("an agent started after the commit must be allowed: %+v", got)
	}
}

// Item 4: a ledger that cannot be read, that is full
// (ErrForeignHookRemovalLedgerFull), or whose folder cannot be trusted
// refuses the removal: the hook stays in place, the ledger is not replaced,
// and the pass's later removals are refused.
func TestForeignHookRemovalRefusedWhenTheLedgerCannotTakeIt(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, g *foreignHookGuardian)
		is    error
	}{
		{name: "a ledger that cannot be read", setup: func(t *testing.T, g *foreignHookGuardian) {
			if err := os.WriteFile(g.ledger, []byte("{not a ledger"), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a full ledger", is: enterprisepolicy.ErrForeignHookRemovalLedgerFull, setup: func(t *testing.T, g *foreignHookGuardian) {
			// As many accounts' denials as the ledger keeps, each its own
			// horizon: the new account's would push one out.
			at := time.Now().UTC().Format(time.RFC3339)
			mark := agentprocess.Now()
			if mark == "" {
				t.Skip("the process clock is unavailable here")
			}
			var existing []enterprisepolicy.ForeignHookRemoval
			for i := 0; i < 1024; i++ {
				existing = append(existing, enterprisepolicy.ForeignHookRemoval{Identity: strconv.Itoa(2000 + i), Connector: "cursor",
					Path: "/home/u/.cursor/hooks.json", At: at, Mark: mark})
			}
			data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, existing, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(g.ledger, data, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a ledger folder that cannot be trusted", setup: func(t *testing.T, g *foreignHookGuardian) {
			enterpriseHookAuthorizationDirTrustCheck = func(string) error { return errors.New("the folder is writable by other accounts") }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := useForeignHookGuardian(t, nil)
			useInProcessCleanupAsSelf(t)
			tc.setup(t, g)
			before, _ := os.ReadFile(g.ledger)
			trace := traceForeignHookRemovals(t)
			home := t.TempDir()
			plugins := foreignHookTestOpenCodePlugins(t, home)
			result, err := cleanEnterpriseForeignHooksFenced(foreignHookTestTarget(home), foreignHookTestInProcessRequest("opencode", home), time.Now())
			if err == nil || (tc.is != nil && !errors.Is(err, tc.is)) {
				t.Fatalf("the cleanup must report the refused record (want %v), got %v", tc.is, err)
			}
			if len(result.Removed) != 0 || len(result.Reported) < len(plugins) {
				t.Fatalf("every plugin must stay reported: %+v", result)
			}
			for _, path := range plugins {
				if _, err := os.Lstat(path); err != nil {
					t.Fatalf("%s changed although its removal could not be recorded: %v", path, err)
				}
			}
			if after, _ := os.ReadFile(g.ledger); !bytes.Equal(before, after) {
				t.Fatal("a refused record must leave the ledger as it was")
			}
			if trace.count("lock") != 1 || trace.count("release") != 1 {
				t.Fatalf("one refused commit, the later removals refused without asking: %s", trace)
			}
			if !accountRemovalLockFree(t, "1001", time.Second) {
				t.Fatal("a refused removal must let go of the account's lock")
			}
		})
	}
}

// A removal waits for the account's online answer in progress (the gateway
// exchange holds the account's lock shared): it publishes nothing until that
// answer lets go of the lock, or until the drain bound, after which it goes
// on (the answer is cut). Another account's
// removal never waits.
func TestForeignHookRemovalWaitsForTheAccountsOnlineAnswer(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	for _, tc := range []struct {
		name  string
		start func(t *testing.T, home, path string) <-chan error
	}{
		{name: "the in-process guard", start: func(t *testing.T, home, path string) <-chan error {
			done := make(chan error, 1)
			go func() {
				guard := enterpriseForeignHookRemovalGuard("cursor", newEnterpriseForeignHookInProcessFence("1001", home))
				done <- guard([]string{path}, func() error { return foreignHookTestRemoveHook(path) })
			}()
			return done
		}},
		{name: "the fallback record", start: func(t *testing.T, home, path string) <-chan error {
			done := make(chan error, 1)
			go func() {
				var stderr bytes.Buffer
				recordEnterpriseForeignHookRemovals(&stderr, "1001", home, "cursor", []string{path})
				// Past the drain bound the removal says it went on.
				if log := stderr.String(); log != "" && !strings.Contains(log, "did not finish within") {
					done <- errors.New(log)
					return
				}
				done <- nil
			}()
			return done
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := useForeignHookGuardian(t, nil)
			home := t.TempDir()
			path := foreignHookTestCursorHook(t, home)
			exchange, err := enterprisepolicy.LockForeignHookAccountExchange(context.Background(), cfg.DataDir, "1001")
			if err != nil {
				t.Fatal(err)
			}
			done := tc.start(t, home, path)
			time.Sleep(enterprisepolicy.ForeignHookRemovalDrainWait / 3)
			wentEarly := g.ledgerExists() || (tc.name == "the in-process guard" && !foreignHookTestHookPresent(path))
			// Another account's removal does not wait for this account.
			var stderr bytes.Buffer
			if !wentEarly {
				recordEnterpriseForeignHookRemovals(&stderr, "1002", t.TempDir(), "cursor", []string{"/home/bob/.cursor/hooks.json"})
			}
			exchange()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the removal did not go on once the answer let go of the lock")
			}
			if wentEarly {
				t.Fatal("the removal went on while the account's online answer was inside its bound")
			}
			if stderr.Len() != 0 {
				t.Fatalf("another account's removal waited: %s", stderr.String())
			}
			if _, ok := g.entry(t, "1001", "cursor", path); !ok {
				t.Fatal("the removal is not recorded")
			}

			// An answer that keeps the lock past the drain bound does not hold
			// the removal off for longer.
			exchange, err = enterprisepolicy.LockForeignHookAccountExchange(context.Background(), cfg.DataDir, "1001")
			if err != nil {
				t.Fatal(err)
			}
			defer exchange()
			path = foreignHookTestCursorHook(t, t.TempDir())
			start := time.Now()
			done = tc.start(t, filepath.Dir(filepath.Dir(path)), path)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(enterprisepolicy.ForeignHookRemovalDrainWait + 5*time.Second):
				t.Fatal("an answer past its bound held the removal off")
			}
			if elapsed := time.Since(start); elapsed < enterprisepolicy.ForeignHookRemovalDrainWait-100*time.Millisecond {
				t.Fatalf("the removal went on after %v, inside the drain bound", elapsed)
			}
			if _, ok := g.entry(t, "1001", "cursor", path); !ok {
				t.Fatal("the removal past the bound is not recorded")
			}
		})
	}
}

// The reconcile loop's foreign-hook cleanup takes no lock of its own: a
// cleanup that is scanning, or that removes nothing, never keeps the
// account's gateway exchanges waiting.
func TestReconcileForeignHooksHoldsNoLockWhileItCleans(t *testing.T) {
	useForeignHookGuardian(t, nil)
	previousCleanup := enterpriseForeignHookCleanup
	t.Cleanup(func() { enterpriseForeignHookCleanup = previousCleanup })
	calls := 0
	enterpriseForeignHookCleanup = func(target enterprisehooks.TargetCredentials, _, _ string) (enterprisepolicy.CleanupResult, error) {
		calls++
		if !accountRemovalLockFree(t, enterpriseForeignHookAccountID(target.SID, target.UID), 200*time.Millisecond) {
			t.Error("the reconcile cleanup holds the account's removal lock while it scans")
		}
		return enterprisepolicy.CleanupResult{}, nil
	}
	reconcileEnterpriseForeignHooks(enterprisehooks.InstallOptions{ConnectorName: "cursor", UserHome: t.TempDir(), OwnerUID: 4242, OwnerGID: 4242})
	if calls != 1 {
		t.Fatalf("cleanup calls = %d", calls)
	}
}

// The guardian's in-process cleanup takes the account's lock only to
// remove: a cleanup with nothing to remove finishes while a gateway exchange
// holds the lock, without asking for it, and changes nothing.
func TestInProcessForeignCleanupLocksOnlyToRemove(t *testing.T) {
	skipForeignHookLedgerOnWindows(t)
	g := useForeignHookGuardian(t, nil)
	useInProcessCleanupAsSelf(t)
	home := t.TempDir()
	path := foreignHookTestCursorHook(t, home)
	target := foreignHookTestTarget(home)
	identity := enterpriseForeignHookAccountID(target.SID, target.UID)
	result, err := cleanEnterpriseForeignHooksFenced(target, foreignHookTestInProcessRequest("cursor", home), time.Now())
	if err != nil || len(result.Removed) != 1 || foreignHookTestHookPresent(path) {
		t.Fatalf("cleanup %+v: %v", result, err)
	}
	if removals := g.removals(t); len(removals) != 1 {
		t.Fatalf("the removal must be recorded once: %+v", removals)
	}
	exchange, err := enterprisepolicy.LockForeignHookAccountExchange(context.Background(), cfg.DataDir, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer exchange()
	trace := traceForeignHookRemovals(t)
	start := time.Now()
	second, err := cleanEnterpriseForeignHooksFenced(target, foreignHookTestInProcessRequest("cursor", home), time.Now())
	if err != nil || len(second.Removed) != 0 {
		t.Fatalf("a clean config: %+v (%v)", second, err)
	}
	if elapsed := time.Since(start); elapsed > enterprisepolicy.ForeignHookRemovalDrainWait/2 || trace.String() != "" {
		t.Fatalf("a cleanup with nothing to remove asked for the lock (%v): %s", elapsed, trace)
	}
	if removals := g.removals(t); len(removals) != 1 {
		t.Fatalf("a clean config changed the ledger: %+v", removals)
	}
}
