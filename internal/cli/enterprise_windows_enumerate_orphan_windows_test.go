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

	"github.com/spf13/cobra"

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

// blockingOrphanRevoker replaces the inventory revoker with one that blocks
// every call until the test ends, as taking an inherited grant off a large
// profile tree does. Cleanup releases it and waits until every orphan's
// revoke has returned before the seams are restored.
type blockingOrphanRevoker struct {
	mu      sync.Mutex
	calls   int
	targets int
	release chan struct{}
}

func installBlockingOrphanRevoker(t *testing.T) *blockingOrphanRevoker {
	t.Helper()
	r := &blockingOrphanRevoker{release: make(chan struct{})}
	previous := enterpriseWindowsInventoryReadRevoker
	enterpriseWindowsInventoryReadRevoker = func(m enterprisehooks.Manifest) error {
		r.mu.Lock()
		r.calls++
		r.targets += len(m.Targets)
		r.mu.Unlock()
		<-r.release
		return nil
	}
	t.Cleanup(func() {
		close(r.release)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			r.mu.Lock()
			calls, targets := r.calls, r.targets
			r.mu.Unlock()
			if calls == 0 || targets >= orphanProfileCount {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		// The background revoke clears its queue right after the last call.
		time.Sleep(100 * time.Millisecond)
		enterpriseWindowsInventoryReadRevoker = previous
		enterpriseWindowsExcludedRevoked.sids = map[string]bool{}
	})
	return r
}

func (r *blockingOrphanRevoker) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func stubOrphanExcludedCycle(t *testing.T) string {
	t.Helper()
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{ExcludeUsers: []string{"dcw-orphan00"}})
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	previousWaiter := enterpriseWindowsEnumerateOnceWalkWaiter
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
		enterpriseWindowsEnumerateOnceWalkWaiter = previousWaiter
	})
	enterpriseWindowsExcludedRevoked.sids = map[string]bool{}
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		for _, orphan := range orphanExcludedProfiles() {
			opts.ReportExcluded(orphan)
		}
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
	enterpriseWindowsEnumerateOnceWalkWaiter = func(context.Context) bool { return false }
	return manifest
}

// GAP-1109: Setup's enumerate --once on a computer with 37 orphan profiles
// of deleted (excluded) accounts ran past Setup's 900 seconds, near idle,
// and the first install rolled back. --once must publish without waiting on
// the excluded profiles' revoke, which the enumerator service does.
func TestEnterpriseWindowsEnumerateOnceDoesNotWaitOnExcludedOrphanRevoke(t *testing.T) {
	manifest := stubOrphanExcludedCycle(t)
	revoker := installBlockingOrphanRevoker(t)
	cmd := &cobra.Command{}
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	done := make(chan error, 1)
	go func() {
		done <- runEnterpriseWindowsEnumerate(context.Background(), cmd, &enterpriseWindowsEnumerateOptions{manifestPath: manifest, once: true})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("enumerate --once: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("enumerate --once still waits on the excluded orphan profiles' revoke after 20 s (%d revoke call(s) blocked)", revoker.callCount())
	}
	if calls := revoker.callCount(); calls != 0 {
		t.Fatalf("enumerate --once started %d revoke(s) of excluded profiles; the process exits after its cycle and would stop one halfway", calls)
	}
}

// GAP-1109: the enumerator service's cycle waits for the excluded profiles'
// revoke a bounded time, names the profile it is at, and starts no second
// revoke of a queued profile.
func TestEnterpriseWindowsEnumerateCycleBoundsExcludedOrphanRevoke(t *testing.T) {
	manifest := stubOrphanExcludedCycle(t)
	revoker := installBlockingOrphanRevoker(t)
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
	if log := stderr.String(); !strings.Contains(log, first.UserHome) || !strings.Contains(log, first.SID) {
		t.Fatalf("the cycle did not name the excluded profile its revoke is at:\n%s", log)
	}
	var again bytes.Buffer
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), &again, manifest); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if calls := revoker.callCount(); calls != 1 {
		t.Fatalf("revoke calls = %d after a second cycle, want the one still running and no second start", calls)
	}
}
