// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
)

// TestSubstrateGAP0566PerActorBudgetIsTheClustersAcrossReplicas is
// substrate-1 GAP-0566 (CERT-110 J43 on E5): with two gateway replicas, a
// flooding actor got 400 requests per 10 s, twice per_actor_rps 20, because
// each replica held it to the whole budget. The docs promise the budget on
// the actor Service. Here one actor floods two replicas that share a leader
// with about 250 requests a second each; after the first exchange (one
// second) the two together admit close to 20 a second, and never starve it.
func TestSubstrateGAP0566PerActorBudgetIsTheClustersAcrossReplicas(t *testing.T) {
	_, chains := newTestChainLeaderService(t)
	limits := func(c *SubstrateConfig) {
		c.Chains = chains
		c.Limiter = ratelimit.New(ratelimit.Config{PerActorRPS: 20, PerAtespaceRPS: 500})
	}
	replicas := []*substrateFixture{newSubstrateFixture(t, limits), newSubstrateFixture(t, limits)}
	const flood, window = 4 * time.Second, 2 * time.Second
	start := time.Now()
	var mu sync.Mutex
	admitted, refused := 0, 0
	var wg sync.WaitGroup
	for _, f := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Since(start) < flood {
				at := time.Since(start)
				rec := f.do(t, f.actor, http.MethodGet, "/api/v1/substrate/hook/claudecode", "tok-alice", "")
				if at >= flood-window {
					mu.Lock()
					if rec.Code == http.StatusTooManyRequests {
						refused++
					} else {
						admitted++
					}
					mu.Unlock()
				}
				time.Sleep(4 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	perSec := float64(admitted) / window.Seconds()
	t.Logf("GAP-0566: in the last %s of a %s flood over 2 replicas: %d admitted (%.1f/s), %d refused", window, flood, admitted, perSec, refused)
	if refused == 0 {
		t.Fatalf("the flood was never refused: %d admitted", admitted)
	}
	if perSec > 25 {
		t.Fatalf("the two replicas admitted %.1f requests/s of one actor, want close to per_actor_rps 20 in total", perSec)
	}
	if perSec < 12 {
		t.Fatalf("the two replicas admitted %.1f requests/s of one actor, want close to 20: the share starves it", perSec)
	}
}
