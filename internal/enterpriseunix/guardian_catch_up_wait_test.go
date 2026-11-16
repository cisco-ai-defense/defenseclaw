// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// startGuardianCatchUpHost installs, then arranges for the enumerator
// restart of the next ensure to rewrite targets.yaml (as a roster change
// does) before it publishes its scan; afterGuardianWork runs in the same
// goroutine, after delay, as the guardian catching up.
func startGuardianCatchUpHost(t *testing.T, goos string, delay time.Duration, afterGuardianWork func(h *testHost)) (*testHost, func() bool) {
	t.Helper()
	h := newTestHost(t, goos)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeStampedInstallScanRecord(t, h)
	h.env.InstallScanTimeout = 10 * time.Second
	enumerator := unitOf(goos, "enumerator")
	finished := make(chan struct{})
	started := false
	h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
		if unit != enumerator || started {
			return
		}
		started = true
		go func() {
			defer close(finished)
			manifest := h.env.P(h.env.Layout.ManifestPath)
			data, err := os.ReadFile(manifest)
			if err == nil {
				err = os.WriteFile(manifest, append(data, "\n"...), 0o600)
			}
			if err != nil {
				t.Error(err)
				return
			}
			// The scan record is written last: it ends the install scan wait.
			time.Sleep(200 * time.Millisecond)
			scan, err := h.marshalCompletedScan(nil)
			if err == nil {
				err = os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), scan, 0o600)
			}
			if err != nil {
				t.Error(err)
			}
			time.Sleep(delay)
			afterGuardianWork(h)
		}()
	}}
	t.Cleanup(func() {
		if started {
			<-finished
		}
	})
	return h, func() bool { return started }
}

// GAP-0842: a roster change makes the enumerator rewrite targets.yaml after
// the guardian reported, so the result was read before the guardian
// attested it: guardian_reconcile_pending and coverage_complete=false on a
// quiet host. The change now waits, inside the install scan bound, for the
// guardian to attest the targets.yaml it produced.
func TestEnsureWaitsForTheGuardianToReconcileTheRewrittenTargets(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h, started := startGuardianCatchUpHost(t, goos, 600*time.Millisecond, func(h *testHost) {
				ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true})
				h.publishLedger(ledger)
			})
			r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
			requireOK(t, r)
			if !started() {
				t.Fatal("the change did not restart the enumerator; the test proves nothing")
			}
			if hasWarning(r, codeGuardianReconcilePending) || !r.Readiness.Guardian || !r.CoverageComplete {
				t.Fatalf("ensure returned before the guardian reconciled: guardian=%v coverage=%v warnings=%+v", r.Readiness.Guardian, r.CoverageComplete, r.Warnings)
			}
		})
	}
}

// A guardian that never reconciles leaves the truthful pending warning and a
// zero exit after the bound: the wait names the transient and is not a failure.
func TestEnsureNamesTheGuardianCatchUpWhenTheGuardianDoesNotReconcileInTime(t *testing.T) {
	h, started := startGuardianCatchUpHost(t, "darwin", 0, func(*testHost) {})
	h.env.InstallScanTimeout = 600 * time.Millisecond
	r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	if !started() {
		t.Fatal("the change did not restart the enumerator; the test proves nothing")
	}
	if !hasWarning(r, codeGuardianReconcilePending) || r.CoverageComplete {
		t.Fatalf("a guardian that did not reconcile must stay named as pending: coverage=%v warnings=%+v", r.CoverageComplete, r.Warnings)
	}
}

// The wait also covers a per-user cleanup this change started: the ensure
// returns after the guardian removed the registration, not before.
func TestEnsureWaitsForAGuardianCleanupItStarted(t *testing.T) {
	h, started := startGuardianCatchUpHost(t, "darwin", 600*time.Millisecond, func(h *testHost) {
		ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true})
		h.publishLedger(ledger)
		_ = os.Remove(filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianUserCleanupFile))
	})
	cleanup, _ := json.Marshal(map[string]any{"version": 1, "pending": []map[string]any{{
		"connector": "hermes", "user": "sample-user", "uid": 1001, "user_home": "/Users/sample-user",
		"recorded_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
	}}})
	if err := os.WriteFile(filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianUserCleanupFile), cleanup, 0o640); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	if !started() {
		t.Fatal("the change did not restart the enumerator; the test proves nothing")
	}
	if hasWarning(r, codeGuardianCleanupPending) {
		t.Fatalf("ensure returned before the guardian finished the cleanup it started: %+v", r.Warnings)
	}
}

// A cleanup left from before the change, or one that already failed with its
// reason, is not this change business: no wait for it, and its warning
// stays.
func TestChangeDoesNotWaitForAnOlderOrAFailedGuardianCleanup(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeStampedInstallScanRecord(t, h)
	h.env.InstallScanTimeout = time.Minute
	cleanup, _ := json.Marshal(map[string]any{"version": 1, "pending": []map[string]any{
		{"connector": "hermes", "user": "older", "uid": 1001, "user_home": "/Users/older", "recorded_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)},
		{"connector": "hermes", "user": "failed", "uid": 1002, "user_home": "/Users/failed", "recorded_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), "last_error": "worker failed"},
	}})
	if err := os.WriteFile(filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianUserCleanupFile), cleanup, 0o640); err != nil {
		t.Fatal(err)
	}
	begun := time.Now()
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if took := time.Since(begun); took > 20*time.Second {
		t.Fatalf("repair waited %s for cleanups it did not start or that already failed", took)
	}
}

// The guardian publishes its authorization ledger, then state, audit and
// owned-file records, then the attestation bound to the ledger. A read
// between the first and the last sees a torn ledger, which is the guardian
// mid-reconcile, not a guardian that is current.
func TestGuardianCatchUpIsPendingBetweenTheLedgerAndItsAttestation(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	l := &lifecycle{env: h.env}
	since := time.Now().Add(-time.Minute)
	if l.guardianCatchUpPending(since) {
		t.Fatal("a guardian whose attestation matches its ledger and targets.yaml is not pending")
	}
	authorization := h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile))
	oldLedger, err := os.ReadFile(authorization)
	if err != nil {
		t.Fatal(err)
	}
	newLedger := append(oldLedger, 0x0a)
	if err := os.WriteFile(authorization, newLedger, 0o640); err != nil {
		t.Fatal(err)
	}
	if problem, torn := h.env.attestationProblem(newLedger); !torn || !strings.Contains(problem, "does not match") {
		t.Fatalf("fixture did not reach the interval between the ledger and attestation writes: %q torn=%v", problem, torn)
	}
	if !l.guardianCatchUpPending(since) {
		t.Fatal("the wait would end before the guardian publishes the attestation bound to its new ledger")
	}
	h.publishLedger(newLedger)
	if l.guardianCatchUpPending(since) {
		t.Fatal("the wait must end once the attestation is bound to the published ledger")
	}
}

// The ensure holds for the staged publication and reports coverage complete.
func TestEnsureWaitsForTheAttestationAfterTheGuardianPublishesItsLedger(t *testing.T) {
	h, started := startGuardianCatchUpHost(t, "darwin", 0, func(h *testHost) {
		authorization := h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile))
		oldLedger, err := os.ReadFile(authorization)
		if err != nil {
			t.Error(err)
			return
		}
		newLedger := append(oldLedger, 0x0a)
		if err := os.WriteFile(authorization, newLedger, 0o640); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(3 * time.Second)
		h.publishLedger(newLedger)
	})
	h.env.PollInterval = 50 * time.Millisecond
	h.env.InstallScanTimeout = 6 * time.Second
	r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	if !started() {
		t.Fatal("the change did not restart the enumerator; the test proves nothing")
	}
	if !r.CoverageComplete {
		t.Fatalf("ensure returned during the guardian staged publication: warnings=%+v", r.Warnings)
	}
}

// A guardian whose attestation follows its new ledger after the bound is the
// same transient as one that has not reconciled the targets: named as
// pending, coverage incomplete, exit 0 (the twin of the targets.yaml case
// above, for the second torn state of one reconcile).
func TestEnsureNamesTheGuardianCatchUpWhenTheAttestationOutlastsTheBound(t *testing.T) {
	h, started := startGuardianCatchUpHost(t, "darwin", 0, func(h *testHost) {
		authorization := h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile))
		oldLedger, err := os.ReadFile(authorization)
		if err != nil {
			t.Error(err)
			return
		}
		if err := os.WriteFile(authorization, append(oldLedger, 0x0a), 0o640); err != nil {
			t.Error(err)
		}
	})
	h.env.PollInterval = 50 * time.Millisecond
	h.env.InstallScanTimeout = 600 * time.Millisecond
	r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	if !started() {
		t.Fatal("the change did not restart the enumerator; the test proves nothing")
	}
	if !hasWarning(r, codeGuardianReconcilePending) || r.CoverageComplete {
		t.Fatalf("a ledger published without its attestation at the bound must be named as pending: coverage=%v warnings=%+v", r.CoverageComplete, r.Warnings)
	}
}
