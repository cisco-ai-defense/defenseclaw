// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// With the cycle's discovery budget, accounts that stall and sort first by
// name spent the budget every cycle, so the same later account (a new user
// "zoe") was never inspected or enrolled while the stall lasted (GAP-1586).
// The accounts a cycle did not reach go first in the next cycle, and the ones
// that failed go last, so every account is inspected within two cycles.
func TestEnumerateUnixDiscoveryBudgetReachesLateAccountsNextCycle(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "homes")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	var names []string
	accounts := map[string]unixidentity.Account{}
	for i := 0; i < 10; i++ {
		names = append(names, fmt.Sprintf("a%02d", i))
	}
	names = append(names, "zoe")
	for _, name := range names {
		accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: gid, Home: makeHome(t, homes, name), Shell: "/bin/bash"}
	}
	var mu sync.Mutex
	inspected := map[string]bool{}
	discover := func(ctx context.Context, account unixidentity.Account, _ []string) (UnixDiscovery, error) {
		if account.Name != "zoe" {
			// A stalled home: its worker times out (50ms here, the worker
			// timeout in the product) and the cycle goes on.
			select {
			case <-ctx.Done():
				return UnixDiscovery{}, ctx.Err()
			case <-time.After(50 * time.Millisecond):
				return UnixDiscovery{}, context.DeadlineExceeded
			}
		}
		mu.Lock()
		inspected[account.Name] = true
		mu.Unlock()
		return UnixDiscovery{Versions: map[string]string{"codex": "0.150.0"}}, nil
	}
	state := &UnixEnumeratorState{Version: 1}
	for cycle := 1; cycle <= 2; cycle++ {
		_, _, err := EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), UnixEnumerateOptions{
			Resolver: &fakeResolver{accounts: accounts, listed: names}, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
			DiscoverSurfaces: discover, DiscoveryBudget: 300 * time.Millisecond, State: state,
		})
		if err != nil {
			t.Fatal(err)
		}
		// The state survives the restart of the service between cycles.
		path := filepath.Join(t.TempDir(), "state.json")
		if err := SaveUnixEnumeratorState(path, state); err != nil {
			t.Fatal(err)
		}
		state = LoadUnixEnumeratorState(path)
	}
	if !inspected["zoe"] {
		t.Fatalf("zoe was never inspected in two cycles while earlier accounts stalled (deferred %v)", state.DiscoveryDeferred)
	}
	if state.DiscoveryDeferred["zoe"] != "" || state.DiscoveryDeferred["a00"] != unixDiscoveryDeferredFailed {
		t.Fatalf("deferred after the second cycle: %v", state.DiscoveryDeferred)
	}
}
