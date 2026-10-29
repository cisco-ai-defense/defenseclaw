// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// prepareWithHeldBundleLock runs prepare for a BUNDLE= delivery while this
// test holds bundle.lock through a second handle, released after holdFor
// (never when holdFor is 0).
func prepareWithHeldBundleLock(t *testing.T, wait, holdFor time.Duration) (*windowsEnterpriseLifecycleOptions, string, bool, error) {
	t.Helper()
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		t.Fatalf("hold bundle.lock: %v", err)
	}
	released := make(chan struct{})
	if holdFor > 0 {
		go func() { time.Sleep(holdFor); unlock(); close(released) }()
		t.Cleanup(func() { <-released })
	} else {
		t.Cleanup(unlock)
	}
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true, bundleLockWait: wait}
	done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
	cleanupPreparedWindowsBundle(t, opts)
	return opts, out.String(), done, err
}

// A4: without --lock-wait a held bundle.lock is lifecycle_busy (1618) at
// once, as before.
func TestWindowsBundleApplyWithoutLockWaitFailsAtOnce(t *testing.T) {
	start := time.Now()
	_, out, done, err := prepareWithHeldBundleLock(t, 0, 0)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitBusy || !strings.Contains(out, `"lifecycle_busy"`) {
		t.Fatalf("held lock without --lock-wait: done=%v exit=%d out=%s", done, commandExitCode(err), out)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("a run without --lock-wait waited %s", elapsed)
	}
}

// A4: --lock-wait waits for bundle.lock and then runs.
func TestWindowsBundleApplyLockWaitTakesTheReleasedLock(t *testing.T) {
	saved := windowsBundleDeploymentInstalled
	t.Cleanup(func() { windowsBundleDeploymentInstalled = saved })
	windowsBundleDeploymentInstalled = func() bool { return true }
	opts, out, done, err := prepareWithHeldBundleLock(t, 30*time.Second, 300*time.Millisecond)
	if done || err != nil || opts.bundle == nil || opts.bundle.prepared == nil {
		t.Fatalf("--lock-wait 30s with the lock released after 300ms: done=%v err=%v out=%s", done, err, out)
	}
}

// GAP-2438: a run that waited for bundle.lock while Setup /uninstall PURGE=1
// held it reads the deployment record again and refuses not_managed before
// it creates or runs anything; the uninstall then finishes. A run that did
// not wait, and one whose deployment is still installed, are unchanged.
func TestWindowsBundleApplyLockWaitRefusesAfterAnUninstall(t *testing.T) {
	saved := windowsBundleDeploymentInstalled
	t.Cleanup(func() { windowsBundleDeploymentInstalled = saved })
	installed := false
	windowsBundleDeploymentInstalled = func() bool { return installed }
	// opts.bundle stays nil: the run refused before it took the store
	// (no directory prepared, no anchors staged, no ensure).
	opts, out, done, err := prepareWithHeldBundleLock(t, 30*time.Second, 300*time.Millisecond)
	if !done || opts.bundle != nil || !strings.Contains(out, `"not_managed"`) ||
		!strings.Contains(out, "uninstalled while this run waited for the policy bundle lock") {
		t.Fatalf("waited out an uninstall: done=%v err=%v exit=%d out=%s", done, err, commandExitCode(err), out)
	}
	// Still installed after the wait: the run goes on.
	installed = true
	if opts, out, done, err := prepareWithHeldBundleLock(t, 30*time.Second, 300*time.Millisecond); done || err != nil || opts.bundle == nil {
		t.Fatalf("waited, still installed: done=%v err=%v out=%s", done, err, out)
	}
	// No wait (the lock was free): the record is not read again.
	installed = false
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	stubWindowsBundleHost(t)
	cmd, buf := windowsBundleCommand()
	free := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true, bundleLockWait: 30 * time.Second}
	done, err = prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", free)
	cleanupPreparedWindowsBundle(t, free)
	if done || err != nil || free.bundle == nil {
		t.Fatalf("free lock: done=%v err=%v out=%s", done, err, buf.String())
	}
}

// A4: a wait that expires is lifecycle_busy 1618 and names the wait.
func TestWindowsBundleApplyLockWaitExpiresBusy(t *testing.T) {
	_, out, done, err := prepareWithHeldBundleLock(t, 300*time.Millisecond, 0)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitBusy || !strings.Contains(out, `"lifecycle_busy"`) ||
		!strings.Contains(out, "still held after --lock-wait 300ms") {
		t.Fatalf("expired --lock-wait: done=%v exit=%d out=%s", done, commandExitCode(err), out)
	}
}

// A4: apply forwards --lock-wait, not --reason, and refuses a wait outside
// 0..15m with 1639 before anything runs.
func TestWindowsBundleApplyForwardsLockWaitOnly(t *testing.T) {
	cmd := newEnterpriseBundleApplyCommand()
	if err := cmd.Flags().Parse([]string{"--bundle", `C:\x.dcbundle`, "--reason", "management", "--lock-wait", "10m"}); err != nil {
		t.Fatal(err)
	}
	opts := &bundleApplyOptions{bundle: `C:\x.dcbundle`, reason: "management", lockWait: 10 * time.Minute}
	lifecycle, err := windowsBundleApplyLifecycleOptions(cmd, opts)
	if err != nil || lifecycle.bundleLockWait != 10*time.Minute || lifecycle.bundlePath != `C:\x.dcbundle` {
		t.Fatalf("options %+v, %v", lifecycle, err)
	}
	over := &cobra.Command{Use: "apply"}
	addLockWaitFlag(over.Flags(), &opts.lockWait)
	if err := over.Flags().Parse([]string{"--lock-wait", "16m"}); err != nil {
		t.Fatal(err)
	}
	if _, err := windowsBundleApplyLifecycleOptions(over, opts); commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs ||
		!strings.Contains(err.Error(), "--lock-wait takes at most 15m, not 16m") {
		t.Fatalf("--lock-wait 16m: %v (exit %d)", err, commandExitCode(err))
	}
}

// F10: apply forwards --delivery-id to the Windows ensure, and refuses an
// empty, too long or out-of-charset one with 1639 before anything runs.
func TestWindowsBundleApplyForwardsDeliveryID(t *testing.T) {
	parsed := func(t *testing.T, id string) *cobra.Command {
		t.Helper()
		cmd := newEnterpriseBundleApplyCommand()
		if err := cmd.Flags().Parse([]string{"--bundle", `C:\x.dcbundle`, "--delivery-id", id}); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	lifecycle, err := windowsBundleApplyLifecycleOptions(parsed(t, "agent-7:d.1"), &bundleApplyOptions{bundle: `C:\x.dcbundle`, deliveryID: "agent-7:d.1"})
	if err != nil || lifecycle.bundleDeliveryID != "agent-7:d.1" {
		t.Fatalf("options %+v, %v", lifecycle, err)
	}
	for _, bad := range []string{"", "agent 7", strings.Repeat("a", 129), "agent\x1b7", `agent\7`} {
		_, err := windowsBundleApplyLifecycleOptions(parsed(t, bad), &bundleApplyOptions{bundle: `C:\x.dcbundle`, deliveryID: bad})
		if commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs || !strings.Contains(err.Error(), "--delivery-id") {
			t.Fatalf("--delivery-id %q: %v (exit %d)", bad, err, commandExitCode(err))
		}
	}
}

// F10: the Windows prepare records the delivery id on the receipt it starts.
func TestWindowsBundlePrepareRecordsDeliveryID(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	stubWindowsBundleHost(t)
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true, bundleDeliveryID: "agent-7:d.1"}
	done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
	cleanupPreparedWindowsBundle(t, opts)
	if done || err != nil || opts.bundle == nil || opts.bundle.prepared == nil || opts.bundle.prepared.Receipt == nil {
		t.Fatalf("prepare: done=%v err=%v out=%s", done, err, out.String())
	}
	if got := opts.bundle.prepared.Receipt.DeliveryID; got != "agent-7:d.1" {
		t.Fatalf("receipt delivery id = %q", got)
	}
}
