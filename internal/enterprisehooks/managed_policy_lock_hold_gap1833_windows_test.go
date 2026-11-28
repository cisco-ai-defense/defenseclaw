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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1833: a live sampler on a managed host saw the Claude managed policy
// lock busy for up to 274 ms per guardian pass, against the 200 ms smoke bar
// (GAP-1713 had 9-14 s). Each guardian-pass user of the lock (the standalone
// ensure, the drift restore, the managed_hooks_only apply) must hold it, from
// the acquire through its body, well under that bar on an unchanged pass;
// the acquire and the steps it runs under the lock are logged.
// gap1833SmokeBar is the lead smoke bar for one hold of the lock.
const gap1833SmokeBar = 200 * time.Millisecond

func TestGAP1833UnchangedPassesHoldTheClaudePolicyLockUnderTheSmokeBar(t *testing.T) {
	requireGAP633Elevated(t) // a standard user is refused the managed policy folder (rel-1-0-10 GAP-1519)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setStandaloneProfileForTest(t, true)
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	// The fixture stands in a no-op transaction; the hold is the real lock:
	// the acquire, its hardening and trust checks, and the body.
	transaction := withWindowsClaudeManagedPolicyTransaction
	previous := windowsClaudeManagedPolicyTransaction
	t.Cleanup(func() { windowsClaudeManagedPolicyTransaction = previous })
	var whole, inner []time.Duration
	timed := func(fn func() error) error {
		outer := time.Now()
		err := transaction(func() error {
			start := time.Now()
			defer func() { inner = append(inner, time.Since(start)) }()
			return fn()
		})
		whole = append(whole, time.Since(outer))
		return err
	}
	const passes = 20
	report := func(name string) {
		sort.Slice(whole, func(i, j int) bool { return whole[i] < whole[j] })
		sort.Slice(inner, func(i, j int) bool { return inner[i] < inner[j] })
		// A user that takes no lock proves nothing: each unchanged pass takes
		// it at least once.
		if len(whole) < passes {
			t.Errorf("%s took the Claude managed policy lock %d times in %d unchanged passes, want at least one per pass", name, len(whole), passes)
			whole, inner = nil, nil
			return
		}
		t.Logf("GAP1833 %-28s lock-held p50 %8s max %8s | fn p50 %8s max %8s (n=%d)", name,
			whole[len(whole)/2], whole[len(whole)-1], inner[len(inner)/2], inner[len(inner)-1], len(whole))
		if worst := whole[len(whole)-1]; worst >= gap1833SmokeBar {
			t.Errorf("%s held the Claude managed policy lock %s on an unchanged pass, at or above the %s smoke bar", name, worst, gap1833SmokeBar)
		}
		whole, inner = nil, nil
	}
	ensure := connector.SetupOpts{APIAddr: opts.APIAddr, HookExecutable: fixture.hookExe}
	windowsClaudeManagedPolicyTransaction = timed
	for i := 0; i < passes; i++ {
		if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
			t.Fatal(err)
		}
	}
	report("standalone ensure")
	for i := 0; i < passes; i++ {
		if _, err := RestoreWindowsClaudeManagedPolicyDrift(); err != nil {
			t.Logf("drift restore: %v", err)
		}
	}
	report("drift restore")
	for i := 0; i < passes; i++ {
		if _, err := ApplyWindowsClaudeManagedHooksOnlyLock(); err != nil {
			t.Logf("hooks-only lock: %v", err)
		}
	}
	report("hooks-only lock apply")
	// The fourth user: the guardian's version floor reconcile
	// (enterprisepolicy.PublishWindowsClaudeVersionFloor) enters the same lock
	// through WithWindowsClaudeManagedPolicyTransaction; the floor body it runs
	// under the lock is timed in internal/enterprisepolicy.
	for i := 0; i < passes; i++ {
		if err := WithWindowsClaudeManagedPolicyTransaction(func(string) error { return nil }); err != nil {
			t.Errorf("version floor lock: %v", err)
		}
	}
	report("version floor lock (empty body)")
	step := func(name string, fn func() error) {
		var d []time.Duration
		for i := 0; i < 20; i++ {
			start := time.Now()
			if err := fn(); err != nil {
				t.Logf("%s: %v", name, err)
			}
			d = append(d, time.Since(start))
		}
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		t.Logf("GAP1833 step %-30s p50 %8s max %8s", name, d[len(d)/2], d[len(d)-1])
	}
	path, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(filepath.Dir(path), windowsClaudeManagedLockFile)
	step("empty transaction", func() error { return transaction(func() error { return nil }) })
	step("lock protection rewrite", func() error { return setWindowsManagedPolicyProtection(lockPath, false, false) })
	step("lock trust check", func() error { return windowsManagedPolicyFileTrustCheck(lockPath) })
	step("ensure directory", func() error { return ensureWindowsManagedPolicyDirectory(filepath.Dir(path)) })
	statePath := filepath.Join(filepath.Dir(path), windowsClaudeManagedStateFile)
	step("state trust check", func() error { return windowsManagedPolicyFileTrustCheck(statePath) })
	setup := withWindowsClaudeManagedHooksOnly(connector.SetupOpts{APIAddr: opts.APIAddr, HookExecutable: fixture.hookExe, ManagedEnterprise: true, HookFailMode: "closed"})
	step("higher policy check", func() error { return windowsClaudeHigherPolicyCheck(setup) })
	step("file policy compatibility", func() error { return inspectWindowsClaudeFilePolicyCompatibility(path) })
}
