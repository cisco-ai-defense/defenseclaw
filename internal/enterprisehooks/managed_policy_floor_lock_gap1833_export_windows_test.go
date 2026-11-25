//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// GAP1833RealLockFixtureForTest installs the managed Claude Code policy into a
// test tree (the fixture of the lock-hold tests) and times every hold of the
// real Claude Code managed policy transaction lock from then on: the acquire,
// its hardening and trust checks, and the body. It returns the folder that
// stands in for Program Files (ClaudeCode is under it) and a function that
// returns the holds so far, sorted, and resets them. It exists for the
// enterprisehooks_test package, which can import internal/enterprisepolicy
// (the version floor, the fourth user of the lock) without an import cycle.
func GAP1833RealLockFixtureForTest(t *testing.T) (string, func() []time.Duration) {
	t.Helper()
	requireGAP633Elevated(t) // a standard user is refused the managed policy folder (rel-1-0-10 GAP-1519)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	// The fixture stands in a no-op transaction; time the real one.
	previous := windowsClaudeManagedPolicyTransaction
	t.Cleanup(func() { windowsClaudeManagedPolicyTransaction = previous })
	var holds []time.Duration
	windowsClaudeManagedPolicyTransaction = func(fn func() error) error {
		start := time.Now()
		defer func() { holds = append(holds, time.Since(start)) }()
		return withWindowsClaudeManagedPolicyTransaction(fn)
	}
	taken := func() []time.Duration {
		out := holds
		holds = nil
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	// policyPath is <Program Files>\ClaudeCode\managed-settings.d\90-defenseclaw.json.
	return filepath.Dir(filepath.Dir(filepath.Dir(fixture.policyPath))), taken
}
