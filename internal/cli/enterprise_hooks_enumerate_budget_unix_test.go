// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// The enumerator service's discovery budget plus its interval and the rest
// of the cycle must fit the record's freshness window, so a healthy verify
// never sees a stale record however many accounts stall.
func TestEnumerateDiscoveryBudgetFitsTheRecordFreshness(t *testing.T) {
	for _, interval := range []time.Duration{0, 5 * time.Minute} {
		budget := enterpriseHooksEnumerateDiscoveryBudget(interval)
		if budget < enterpriseHookWorkerTimeout || budget+interval+enterpriseHooksEnumerateCycleReserve > enterprisehooks.UnprotectedAgentsMaxAge {
			t.Fatalf("interval %s: discovery budget %s does not fit the %s freshness window", interval, budget, enterprisehooks.UnprotectedAgentsMaxAge)
		}
	}
	if got := enterpriseHooksEnumerateDiscoveryBudget(5 * time.Minute); got != 8*time.Minute {
		t.Fatalf("the service's 5m interval gives a %s budget, want 8m", got)
	}
}
