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
	transaction := windowsClaudeManagedPolicyTransaction
	t.Cleanup(func() { windowsClaudeManagedPolicyTransaction = transaction })
	var whole, inner []time.Duration
	windowsClaudeManagedPolicyTransaction = func(fn func() error) error {
		outer := time.Now()
		err := transaction(func() error {
			start := time.Now()
			defer func() { inner = append(inner, time.Since(start)) }()
			return fn()
		})
		whole = append(whole, time.Since(outer))
		return err
	}
	report := func(name string) {
		sort.Slice(whole, func(i, j int) bool { return whole[i] < whole[j] })
		sort.Slice(inner, func(i, j int) bool { return inner[i] < inner[j] })
		if len(whole) == 0 {
			t.Logf("GAP1833 %-28s took no lock", name)
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
	for i := 0; i < 20; i++ {
		if err := EnsureWindowsStandaloneClaudeManagedPolicy(ensure); err != nil {
			t.Fatal(err)
		}
	}
	report("standalone ensure")
	for i := 0; i < 20; i++ {
		if _, err := RestoreWindowsClaudeManagedPolicyDrift(); err != nil {
			t.Logf("drift restore: %v", err)
		}
	}
	report("drift restore")
	for i := 0; i < 20; i++ {
		if _, err := ApplyWindowsClaudeManagedHooksOnlyLock(); err != nil {
			t.Logf("hooks-only lock: %v", err)
		}
	}
	report("hooks-only lock apply")
	for i := 0; i < 20; i++ {
		_ = transaction(func() error { return nil })
	}
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
