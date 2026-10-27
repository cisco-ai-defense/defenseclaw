// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// A cycle whose discovery workers stall must still finish within its
// discovery budget, so the unprotected-agents record stays fresh, and must
// report every account it could not inspect instead of skipping it.
func TestEnumerateUnixDiscoveryBudgetBoundsTheCycle(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stall bool
	}{{"stalled workers", true}, {"healthy workers", false}} {
		t.Run(tc.name, func(t *testing.T) {
			root := trustedTestDir(t)
			homes := filepath.Join(root, "homes")
			if err := os.MkdirAll(homes, 0o755); err != nil {
				t.Fatal(err)
			}
			uid, gid := os.Getuid(), os.Getgid()
			names := []string{"alice", "bob", "carol"}
			accounts := map[string]unixidentity.Account{}
			for _, name := range names {
				accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: gid, Home: makeHome(t, homes, name), Shell: "/bin/bash"}
			}
			var mu sync.Mutex
			var asked []string
			discover := func(ctx context.Context, account unixidentity.Account, _ []string) (UnixDiscovery, error) {
				mu.Lock()
				asked = append(asked, account.Name)
				mu.Unlock()
				if !tc.stall {
					return UnixDiscovery{Versions: map[string]string{"codex": "0.150.0"}}, nil
				}
				// A stalled worker answers only when the cycle stops it.
				select {
				case <-ctx.Done():
					return UnixDiscovery{}, ctx.Err()
				case <-time.After(30 * time.Second):
					return UnixDiscovery{}, errors.New("the cycle never stopped the stalled worker")
				}
			}
			started := time.Now()
			_, report, err := EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), UnixEnumerateOptions{
				Resolver: &fakeResolver{accounts: accounts, listed: names}, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
				DiscoverSurfaces: discover, DiscoveryBudget: 300 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(started); elapsed > 10*time.Second {
				t.Fatalf("the cycle took %s with a 300ms discovery budget", elapsed)
			}
			incomplete := map[string]bool{}
			for _, agent := range report.Unprotected {
				if agent.Code == UnprotectedCodeInstallScanIncomplete && agent.Connector == "codex" {
					incomplete[agent.User] = true
				}
			}
			if !tc.stall {
				if len(asked) != len(names) || len(incomplete) != 0 {
					t.Fatalf("a budget that is not spent must change nothing: asked %v, incomplete %v", asked, incomplete)
				}
				return
			}
			if len(asked) != 1 {
				t.Fatalf("discovery ran for %v: no worker may start once the budget is spent", asked)
			}
			for _, name := range names {
				if !incomplete[name] {
					t.Fatalf("%s is not reported as not inspected this cycle: %+v", name, report.Unprotected)
				}
			}
		})
	}
}

// A directory open that never returns (here a FIFO with no writer, standing
// in for a stalled mount or a privacy-managed folder) must not hold the scan:
// it answers incomplete shortly after its context ends.
func TestDiscoverUnixPrivateInstallsAnswersWhenAnOpenBlocks(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	if err := syscall.Mkfifo(home, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Release the blocked open so the scan goroutine ends.
		if f, err := os.OpenFile(home, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan []PrivateAgentInstall, 1)
	go func() { done <- DiscoverUnixPrivateAgentInstalls(ctx, home, []string{"claudecode", "codex"}) }()
	select {
	case found := <-done:
		got := map[string]string{}
		for _, install := range found {
			if install.Incomplete {
				got[install.Connector] = install.Skipped
			}
		}
		if got["claudecode"] != PrivateInstallSkippedHome || got["codex"] != PrivateInstallSkippedHome {
			t.Fatalf("a blocked scan must report each connector incomplete (%s): %+v", PrivateInstallSkippedHome, found)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the private install scan did not answer 10s after its 200ms context ended")
	}
}
