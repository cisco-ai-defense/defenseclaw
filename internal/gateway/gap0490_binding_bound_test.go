// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// The binding open request bound is sized for the longest a managed request
// stays open: the receipt window, and the longest rendered hook attempt, must
// not outlast the lifetime the bound was computed for (rel-1-0-6 GAP-0490).
func TestGAP0490BindingBoundCoversManagedRequestLifetimes(t *testing.T) {
	lifetime := time.Duration(sandboxauth.MaxRequestLifetimeSeconds) * time.Second
	first, retry := connector.SandboxHookAttemptBudgets()
	for name, window := range map[string]time.Duration{
		"receipt window": sandboxHookReceiptWindow, "first attempt": first, "retry attempt": retry,
	} {
		if window > lifetime {
			t.Errorf("%s is %v, longer than the %v the binding bound covers", name, window, lifetime)
		}
	}
	limits := sandboxauth.DefaultLimiterConfig()
	if want := limits.HookBurst + int(limits.HookRPS*lifetime.Seconds()); limits.MaxInFlight < want {
		t.Errorf("binding bound %d is below the %d calls its rate admits in %v", limits.MaxInFlight, want, lifetime)
	}
}
