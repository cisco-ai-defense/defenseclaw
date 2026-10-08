// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func writeChangedConfig(t *testing.T, h *testHost, from, to string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	changed := strings.Replace(string(DefaultConfig(h.env.Layout)), from, to, 1)
	if err := os.WriteFile(cfg, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func touched(calls []string, unit string) []string {
	var out []string
	for _, call := range calls {
		if call == "stop "+unit || call == "start "+unit || call == "restart "+unit {
			out = append(out, call)
		}
	}
	return out
}

// A change made while a transaction runs fires the apply path unit, whose
// run then waits for the lifecycle lock. Quiesce stopped that waiting run
// 27 ms later, which left defenseclaw-enterprise-apply.service failed (seen
// on RHEL and Ubuntu) and dropped the administrator change that fired it.
// The queued run is left alone through the change and a rollback.
func TestTransactionsLeaveAQueuedApplyRunAlone(t *testing.T) {
	t.Run("linux", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		h.services.active[unitApplyService] = true // queued, waiting for the lock
		before := len(h.services.calls)
		requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")}))
		if calls := touched(h.services.calls[before:], unitApplyService); len(calls) > 0 || !h.services.isActive(unitApplyService) {
			t.Fatalf("ensure stopped the queued apply run: %v", calls)
		}
		h.healthy = false
		before = len(h.services.calls)
		failed := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
		requireError(t, failed, codeActivate)
		if calls := touched(h.services.calls[before:], unitApplyService); len(calls) > 0 || !h.services.isActive(unitApplyService) {
			t.Fatalf("the rollback stopped the queued apply run: %v", calls)
		}
	})
	t.Run("darwin", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		if !h.services.isActive(labelApply) {
			t.Fatal("the apply job is not loaded after install")
		}
		before := len(h.services.calls)
		requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")}))
		if calls := touched(h.services.calls[before:], labelApply); len(calls) > 0 || !h.services.isActive(labelApply) {
			t.Fatalf("ensure booted out or kickstarted the apply job: %v", calls)
		}
	})
}

// The snapshot hard-linked config.yaml while the apply path unit still
// watched it; the link count change fired the unit, whose ensure queued
// behind the transaction and held the lock after it, so a verify right
// after every ensure --config failed lifecycle_busy (GAP-0354).
func TestSnapshotLeavesTheWatchedConfigLinkCountAlone(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	snap, err := h.env.takeSnapshot("trigger", []string{h.env.Layout.ConfigPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.env.discardSnapshot(snap)
	info, err := os.Stat(h.env.P(h.env.Layout.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	if links := info.Sys().(*syscall.Stat_t).Nlink; links != 1 {
		t.Fatalf("the snapshot linked the watched config.yaml (%d links)", links)
	}
}

// A failed oneshot sat in status and verify as failed/failed under a green
// check with no warning.
func TestStatusWarnsAboutAFailedOneshot(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.services.failed[unitApplyService] = true
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if got := messagesOf(r.Warnings, "unit_failed"); !strings.Contains(got, unitApplyService+" failed") || !strings.Contains(got, "journalctl -u "+unitApplyService) {
			t.Fatalf("%s does not warn about the failed apply service: %+v", action, r.Warnings)
		}
	}
}

// A queued apply run is left alone during a transaction. When that
// transaction upgraded the deployment, the queued run is the previous
// binary: it stands down instead of rendering its older files over the
// upgrade.
func TestAQueuedApplyRunFromAnOlderBinaryStandsDown(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.ProductVersion = "1.0.1"
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}))
	h.env.ProductVersion = "1.0.0" // the run that waited through the upgrade
	before := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure, Reason: "path", ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	if !r.Noop || r.NoopReason != "superseded" || len(h.services.calls) != before {
		t.Fatalf("the older apply run did not stand down: noop=%v reason=%q calls=%v", r.Noop, r.NoopReason, h.services.calls[before:])
	}
	// Any other run, and the apply run of the installed binary, proceed.
	h.env.ProductVersion = "1.0.1"
	if again := h.run(Options{Action: ActionEnsure, Reason: "path"}); again.NoopReason == "superseded" {
		t.Fatal("the installed binary's apply run stood down")
	}
	h.env.ProductVersion = "dev"
	if again := h.run(Options{Action: ActionEnsure, Reason: "path"}); again.NoopReason == "superseded" {
		t.Fatal("a development build stood down")
	}
}

// The stand-down is for a run that waited while a newer binary was
// installed. When the binaries on disk are older than the record (a
// package downgrade whose own ensure was refused), the running binary is
// the installed one: its apply runs must report the mismatch, not stand
// down with exit 0 and skip every config change.
func TestAnApplyRunOfTheInstalledOlderBinaryDoesNotStandDown(t *testing.T) {
	h := newTestHost(t, "linux")
	h.env.ProductVersion = "2.0.0"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("2.0.0")}))
	older := h.payload("1.0.0")
	for _, name := range []string{binGateway, binHook, binSensorHelper, binACP} {
		data, err := os.ReadFile(filepath.Join(older, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.BinDir, name)), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.env.ProductVersion = "1.0.0"
	edited := strings.Replace(h.read(h.env.Layout.ConfigPath), "mode: observe", "mode: action", 1)
	if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionEnsure, Reason: "path"})
	if r.NoopReason == "superseded" || (r.OK && r.Noop) {
		t.Fatalf("the installed older binary's apply run stood down: ok=%v noop=%v reason=%q", r.OK, r.Noop, r.NoopReason)
	}
	if r.OK || len(r.Errors) == 0 {
		t.Fatalf("the binary mismatch is not reported: %+v", r)
	}
}

// GAP-0585: a package upgrade that lands while the daily verify runs must
// not leave the verify unit failed. The change leaves a waiting verify run
// alone, clears a verify failure from before it, and a verify run during the
// package transaction skips its checks (exit 75, a success for the unit).
func TestAPackageUpgradeDoesNotLeaveTheDailyVerifyFailed(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.services.active[unitVerifyService] = true
	h.services.failed[unitVerifyService] = true
	h.env.ProductVersion = "1.0.1"
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}))
	if !h.services.active[unitVerifyService] {
		t.Fatalf("the upgrade stopped the waiting verify run: %v", h.services.calls)
	}
	// The committed change clears the failure (clearSupersededUnitFailures,
	// GAP-0423).
	if h.services.failed[unitVerifyService] {
		t.Fatalf("the verify failure from before the upgrade is kept: %v", h.services.calls)
	}
	marker := h.env.P(packageTransactionMarker)
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	requireError(t, h.run(Options{Action: ActionVerify}), codeBusy)
}

// Right after an administrator replaced config.yaml, status and verify failed
// with "modified after install ... run repair" while the apply trigger was
// still applying the change; a repair then fought the apply (GAP-0919).
func TestStatusAndVerifyWhileTheApplyTriggerRunsAreBusyNotFailed(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.services.activating = map[string]bool{unitApplyService: true}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if len(r.Errors) != 1 || r.Errors[0].Code != codeBusy || !strings.Contains(r.Errors[0].Message, "configuration change is being applied") {
			t.Fatalf("%s during an apply: %+v", action, r.Errors)
		}
	}
}
