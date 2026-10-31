// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// status-v2 GAP-0008 desk proof: a lookup of an account the gateway holds no
// facts for (a SID, as on Windows) that fails while the directory is down
// makes the identity block of status and verify read failing, and the
// account's next lookup after the directory answers again makes it ok. On a
// live Windows host the LSA answers a signed-in account from its logon
// cache, so this lookup cannot be formed there (identity-sources.mdx).
func TestIdentityStateFailsForANeverCachedLookupDuringAnOutageAndRecovers(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-4067"
	var clock atomic.Int64
	clock.Store(time.Unix(2_000_000, 0).UnixNano())
	var down atomic.Bool
	down.Store(true)
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		if down.Load() {
			return useridentity.DirectoryFacts{}, errors.New("the specified domain either does not exist or could not be contacted")
		}
		return useridentity.DirectoryFacts{Groups: []string{"engineering"}, ResolvedAt: time.Now()}, nil
	})
	cache.logf = nil
	cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	state := func() string {
		t.Helper()
		body, err := json.Marshal(map[string]any{"identity": identityHealthSummary(cache.health(), nil, cache.now())})
		if err != nil {
			t.Fatal(err)
		}
		return enterprisestatus.ParseIdentityHealth(body).State
	}

	if answer := cache.explain(sid, time.Second); answer.ok {
		t.Fatal("a never-cached account's failed lookup gave facts")
	}
	if h := cache.health(); h.Failing != 1 || len(h.Accounts) != 1 || h.Accounts[0] != sid {
		t.Fatalf("health after a never-cached lookup failed: %+v; want that account failing", h)
	}
	if got := state(); got != enterprisestatus.IdentityStateFailing {
		t.Fatalf("identity.state during the outage = %q, want failing", got)
	}

	down.Store(false)
	clock.Add(int64(identityExplainFresh + time.Second))
	if answer := cache.explain(sid, time.Second); !answer.ok {
		t.Fatal("the lookup after the directory came back gave no facts")
	}
	if h := cache.health(); h.Failing != 0 {
		t.Fatalf("health after recovery: %+v; want no failing account", h)
	}
	if got := state(); got == enterprisestatus.IdentityStateFailing {
		t.Fatalf("identity.state after recovery = %q, want not failing", got)
	}
}
