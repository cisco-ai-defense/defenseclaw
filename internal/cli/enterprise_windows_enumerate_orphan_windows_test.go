// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// orphanProfileCount is the orphan profiles of deleted accounts the
// GAP-1109 host had, every one named in enterprise.enrollment.exclude_users.
const orphanProfileCount = 37

func orphanExcludedProfiles() []enterprisehooks.ManifestTarget {
	out := make([]enterprisehooks.ManifestTarget, 0, orphanProfileCount)
	for i := 0; i < orphanProfileCount; i++ {
		out = append(out, enterprisehooks.ManifestTarget{
			SID:      fmt.Sprintf("S-1-5-21-1004336348-1177238915-682003330-%d", 2001+i),
			UserHome: fmt.Sprintf(`C:\Users\dcw-orphan%02d`, i),
		})
	}
	return out
}

// orphanRevoker replaces the inventory revoker. With block set every call
// waits until the test ends, as taking an inherited grant off a large
// profile tree does. Cleanup releases it and waits until the background
// revoke is idle before the seams are restored.
type orphanRevoker struct {
	mu      sync.Mutex
	calls   int
	release chan struct{}
	once    sync.Once
}

func (r *orphanRevoker) unblock() { r.once.Do(func() { close(r.release) }) }

func installOrphanRevoker(t *testing.T, block bool) *orphanRevoker {
	t.Helper()
	r := &orphanRevoker{release: make(chan struct{})}
	if !block {
		r.unblock()
	}
	previous := enterpriseWindowsInventoryReadRevoker
	enterpriseWindowsInventoryReadRevoker = func(enterprisehooks.Manifest) error {
		r.mu.Lock()
		r.calls++
		r.mu.Unlock()
		<-r.release
		return nil
	}
	t.Cleanup(func() {
		r.unblock()
		state := &enterpriseWindowsExcludedRevoked
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			state.Lock()
			idle := len(state.queued) == 0
			state.Unlock()
			if idle {
				break
			}
		}
		enterpriseWindowsInventoryReadRevoker = previous
		resetEnterpriseWindowsExcludedRevoked()
	})
	return r
}

func (r *orphanRevoker) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func resetEnterpriseWindowsExcludedRevoked() {
	state := &enterpriseWindowsExcludedRevoked
	state.Lock()
	state.sids, state.queued, state.wanted, state.current = map[string]bool{}, map[string]bool{}, map[string]bool{}, ""
	state.Unlock()
}

// stubOrphanExcludedCycle stubs a cycle whose walk excludes the profiles
// excludedFor(cycle) returns (cycle counts from 0).
func stubOrphanExcludedCycle(t *testing.T, excludedFor func(cycle int) []enterprisehooks.ManifestTarget) string {
	t.Helper()
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{ExcludeUsers: []string{"dcw-orphan00"}})
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	previousWaiter := enterpriseWindowsEnumerateOnceWalkWaiter
	previousWait := enterpriseWindowsExcludedRevokeWait
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
		enterpriseWindowsEnumerateOnceWalkWaiter = previousWaiter
		enterpriseWindowsExcludedRevokeWait = previousWait
	})
	resetEnterpriseWindowsExcludedRevoked()
	enterpriseWindowsExcludedRevokeWait = 300 * time.Millisecond
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	cycle := 0
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		for _, orphan := range excludedFor(cycle) {
			opts.ReportExcluded(orphan)
		}
		cycle++
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
	enterpriseWindowsEnumerateOnceWalkWaiter = func(context.Context) bool { return false }
	return manifest
}

func allOrphansEveryCycle(int) []enterprisehooks.ManifestTarget { return orphanExcludedProfiles() }

// runEnumerateCommand runs the enumerate subcommand with args, as Setup and
// the hot config apply start it, and fails the test after limit.
func runEnumerateCommand(t *testing.T, limit time.Duration, args ...string) (string, error) {
	t.Helper()
	cmd := newEnterpriseWindowsEnumerateCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(context.Background()) }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(limit):
		t.Fatalf("enumerate %s still runs after %s", strings.Join(args, " "), limit)
		return "", nil
	}
}

// GAP-1109: Setup's enumerate --once on a computer with 37 orphan profiles
// of deleted (excluded) accounts ran past Setup's 900 seconds, near idle,
// and the first install rolled back. Setup's --once --defer-excluded-revoke
// publishes without the excluded profiles' revoke, which the enumerator
// service does after activation.
func TestEnterpriseWindowsEnumerateSetupOnceDefersExcludedOrphanRevoke(t *testing.T) {
	manifest := stubOrphanExcludedCycle(t, allOrphansEveryCycle)
	revoker := installOrphanRevoker(t, true)
	out, err := runEnumerateCommand(t, 20*time.Second, "--manifest", manifest, "--once", "--defer-excluded-revoke")
	if err != nil {
		t.Fatalf("enumerate --once --defer-excluded-revoke: %v\n%s", err, out)
	}
	if calls := revoker.callCount(); calls != 0 {
		t.Fatalf("Setup's --once started %d revoke(s) of excluded profiles; the process exits after its cycle and would stop one halfway", calls)
	}
	if !strings.Contains(out, "enumerator service's first cycle after Setup") {
		t.Fatalf("output does not say who takes the access off:\n%s", out)
	}
}

// Another --once caller (the hot config apply) still takes the access off
// a newly excluded profile before it exits.
func TestEnterpriseWindowsEnumerateOnceStillRevokesExcludedProfiles(t *testing.T) {
	manifest := stubOrphanExcludedCycle(t, allOrphansEveryCycle)
	revoker := installOrphanRevoker(t, false)
	if out, err := runEnumerateCommand(t, 20*time.Second, "--manifest", manifest, "--once"); err != nil {
		t.Fatalf("enumerate --once: %v\n%s", err, out)
	}
	if calls := revoker.callCount(); calls != orphanProfileCount {
		t.Fatalf("revoke calls = %d before --once exited, want %d", calls, orphanProfileCount)
	}
}

// GAP-1109: the enumerator service's cycle waits for the excluded profiles'
// revoke a bounded time, names the profile it is at by folder name and SID
// (never the absolute path), and starts no second revoke of a queued
// profile.
func TestEnterpriseWindowsEnumerateCycleBoundsExcludedOrphanRevoke(t *testing.T) {
	manifest := stubOrphanExcludedCycle(t, allOrphansEveryCycle)
	revoker := installOrphanRevoker(t, true)
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- runEnterpriseWindowsEnumerateSingleCycle(context.Background(), &stderr, manifest) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cycle: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the cycle still waits on the excluded orphan profiles' revoke after 30 s (%d revoke call(s) blocked)", revoker.callCount())
	}
	first := orphanExcludedProfiles()[0]
	log := stderr.String()
	if !strings.Contains(log, "dcw-orphan00 ("+first.SID+")") {
		t.Fatalf("the cycle did not name the excluded profile its revoke is at:\n%s", log)
	}
	for _, orphan := range orphanExcludedProfiles() {
		if strings.Contains(log, orphan.UserHome) {
			t.Fatalf("the log names the excluded profile path %s:\n%s", orphan.UserHome, log)
		}
	}
	var again bytes.Buffer
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), &again, manifest); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if calls := revoker.callCount(); calls != 1 {
		t.Fatalf("revoke calls = %d after a second cycle, want the one still running and no second start", calls)
	}
}

// A profile queued for the revoke that a later cycle no longer excludes
// (enrolled again) is skipped, so its new grant stays.
func TestEnterpriseWindowsEnumerateSkipsQueuedRevokeOfReenrolledProfile(t *testing.T) {
	manifest := stubOrphanExcludedCycle(t, func(cycle int) []enterprisehooks.ManifestTarget {
		if cycle == 0 {
			return orphanExcludedProfiles()
		}
		return nil
	})
	revoker := installOrphanRevoker(t, true)
	for cycle := 0; cycle < 2; cycle++ {
		if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), new(bytes.Buffer), manifest); err != nil {
			t.Fatalf("cycle %d: %v", cycle, err)
		}
	}
	revoker.unblock()
	state := &enterpriseWindowsExcludedRevoked
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		state.Lock()
		idle := len(state.queued) == 0
		state.Unlock()
		if idle {
			break
		}
	}
	if calls := revoker.callCount(); calls != 1 {
		t.Fatalf("revoke calls = %d, want only the one in flight before the profiles were enrolled again", calls)
	}
}
