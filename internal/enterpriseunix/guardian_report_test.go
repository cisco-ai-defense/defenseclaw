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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func writeGuardianState(h *testHost, at time.Time, results []map[string]any) error {
	data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": at.UTC().Format(time.RFC3339Nano), "results": results})
	path := h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Switching guardrail.mode to action with `ensure --config` left
// devin for one user without DefenseClaw hooks (no verified contract for its
// version in that mode), but ensure printed a bare "done": its result was
// described before the restarted guardian reported. The result now waits
// for that report and carries the target warnings.
func TestEnsureReportsTheGuardianTargetsAfterTheChange(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n  - user: alice\n    uid: 501\n    connector: devin\n")
			// The guardian's report from before the change: everything protected.
			if err := writeGuardianState(h, time.Now().Add(-time.Hour), []map[string]any{{"user": "alice", "connector": "devin", "ok": true}}); err != nil {
				t.Fatal(err)
			}
			h.env.GuardianReportTimeout = 10 * time.Second
			guardian := unitOf(goos, "guardian")
			reported := make(chan error, 1)
			started := false
			h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
				if unit != guardian || started {
					return
				}
				started = true
				// The restarted guardian reconciles and reports a moment later.
				go func() {
					time.Sleep(200 * time.Millisecond)
					reported <- writeGuardianState(h, time.Now(), []map[string]any{{"user": "alice", "connector": "devin", "ok": false,
						"error": `enterprise hooks: connector devin agent version "3000.11.3" is not verified against a known hook contract: no hook contract matches normalized agent version`}})
				}()
			}}
			t.Cleanup(func() {
				if err := <-reported; err != nil {
					t.Error(err)
				}
			})
			r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
			requireOK(t, r)
			if got := messagesOf(r.Warnings, codeHookContractUnverified); got == "" || r.SecurityComplete {
				t.Fatalf("ensure does not report the target the change left unprotected: %+v", r.Warnings)
			}
		})
	}
}

// A guardian that does not report in time is named instead of reading as
// "done".
func TestEnsureSaysWhenTheGuardianHasNotReported(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n  - user: alice\n    uid: 501\n    connector: codex\n")
	r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	if !hasWarning(r, "guardian_report_pending") {
		t.Fatalf("ensure does not say the guardian has not reported: %+v", r.Warnings)
	}
}

// With no enrollment targets yet, a package install read the guardian as not
// ready: its unit was active, but it had not published its authorization
// ledger. The result now waits for the guardian report written after it.
func TestInstallWaitsForTheGuardianWithoutTargets(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GuardianReportTimeout = 10 * time.Second
	guardian := unitOf("darwin", "guardian")
	published := make(chan error, 1)
	started := false
	h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
		if unit != guardian || started {
			return
		}
		started = true
		go func() {
			time.Sleep(200 * time.Millisecond)
			data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format(time.RFC3339), "ok": true})
			h.publishLedger(data)
			published <- writeGuardianState(h, time.Now(), nil)
		}()
	}}
	t.Cleanup(func() {
		if err := <-published; err != nil {
			t.Error(err)
		}
	})
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireOK(t, r)
	if !r.Readiness.Guardian || !r.CoverageComplete {
		t.Fatalf("install result reads the starting guardian as not ready: %+v", r.Readiness)
	}
}

// The guardian's first reconcile writes its ledger and target report before
// its credential attestation. The CI pkg lane read in between and reported
// readiness.guardian false (GAP-2577); the read now retries a missing
// attestation like any other torn read.
func TestInstallWaitsForTheFirstGuardianAttestation(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GuardianReportTimeout = 10 * time.Second
	h.env.PollInterval = 50 * time.Millisecond
	guardian := unitOf("darwin", "guardian")
	published := make(chan error, 1)
	started := false
	h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
		if unit != guardian || started {
			return
		}
		started = true
		go func() {
			data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format(time.RFC3339), "ok": true})
			h.publishLedger(data)
			attestation := h.env.attestationPath()
			body, err := os.ReadFile(attestation)
			if err == nil {
				err = os.Remove(attestation)
			}
			if err == nil {
				err = writeGuardianState(h, time.Now(), nil)
			}
			if err == nil {
				time.Sleep(100 * time.Millisecond)
				err = os.WriteFile(attestation, body, 0o600)
			}
			published <- err
		}()
	}}
	t.Cleanup(func() {
		if err := <-published; err != nil {
			t.Error(err)
		}
	})
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireOK(t, r)
	if !r.Readiness.Guardian || !r.CoverageComplete {
		t.Fatalf("install result read the guardian before its first attestation: %+v", r.Readiness)
	}
}

// An earlier success the authorization ledger carries forward is not
// current readiness: verify needs the guardian's root-only credential
// attestation from the reconcile that wrote the ledger, and names a target
// that attestation reports failed even when the guardian state in DataDir,
// which the service account can replace, reports it protected.
func TestGuardianReadinessNeedsTheCurrentAttestation(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format(time.RFC3339), "ok": true})
	h.publishLedger(ledger)
	requireOK(t, h.run(Options{Action: ActionVerify}))

	path := h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile))
	if err := os.WriteFile(path, append(ledger, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	verify := h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	if verify.Readiness.Guardian || !strings.Contains(messagesOf(verify.Errors, codeVerify), "does not match its last credential attestation") {
		t.Fatalf("a ledger without its attestation counted as ready: %+v %+v", verify.Readiness, verify.Errors)
	}

	h.publishLedger(ledger, enterprisehooks.CredentialAttestationTarget{Connector: "codex", User: "bob", UID: 1002, State: enterprisehooks.CredentialTargetFailed})
	if err := writeGuardianState(h, time.Now(), []map[string]any{{"user": "bob", "connector": "codex", "ok": true}}); err != nil {
		t.Fatal(err)
	}
	verify = h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	if verify.SecurityComplete || !strings.Contains(messagesOf(verify.Errors, codeVerify), "codex for user bob is not protected") {
		t.Fatalf("a failure the attestation reports was hidden by the guardian state: %+v", verify.Errors)
	}

	// The attestation must be in the current format, for the current
	// targets.yaml, and bind each credential to the one the key it names
	// derives for that account; the next reconcile rewrites an older one.
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n  - user: alice\n    uid: 1001\n    connector: codex\n")
	// targets.yaml changed long ago, so a guardian behind it is a failure.
	settled := h.env.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(h.env.P(h.env.Layout.ManifestPath), settled, settled); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a1", 32)
	if err := os.MkdirAll(filepath.Dir(h.env.committedUserKeyPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.committedUserKeyPath(), []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, _ := connector.UserScopedHookAPIToken(key, "codex", "1001")
	for _, tc := range []struct {
		name, want string
		change     func(*enterprisehooks.CredentialAttestation)
	}{
		{"bound", "", func(*enterprisehooks.CredentialAttestation) {}},
		{"another credential", "whose credentials are not the ones key", func(a *enterprisehooks.CredentialAttestation) {
			a.Targets[0].CredentialID = strings.Repeat("f", 64)
		}},
		{"older format", "older format 1", func(a *enterprisehooks.CredentialAttestation) {
			a.Version, a.Targets[0].CredentialID = enterprisehooks.LegacyCredentialAttestationVersion, ""
		}},
		{"another roster", "lists 2 target(s), but targets.yaml enables 1", func(a *enterprisehooks.CredentialAttestation) {
			a.Targets = append(a.Targets, enterprisehooks.CredentialAttestationTarget{Connector: "codex", User: "bob", UID: -1, State: enterprisehooks.CredentialTargetPending})
		}},
		{"another targets.yaml", "has not reconciled the current targets.yaml", func(a *enterprisehooks.CredentialAttestation) {
			a.ManifestSHA256 = strings.Repeat("d", 64)
		}},
	} {
		h.publishLedger(ledger, enterprisehooks.CredentialAttestationTarget{
			Connector: "codex", User: "alice", UID: 1001, State: enterprisehooks.CredentialTargetCurrent,
			Credentials: true, Verified: true, CredentialID: connector.UserScopedCredentialKeyID(credential),
		})
		data, _ := os.ReadFile(h.env.attestationPath())
		var attestation enterprisehooks.CredentialAttestation
		if err := json.Unmarshal(data, &attestation); err != nil {
			t.Fatal(err)
		}
		attestation.KeyID = connector.UserScopedTokenKeyFingerprint(key)
		tc.change(&attestation)
		data, _ = json.Marshal(attestation)
		if err := os.WriteFile(h.env.attestationPath(), data, 0o600); err != nil {
			t.Fatal(err)
		}
		verify := h.run(Options{Action: ActionVerify})
		if got := messagesOf(verify.Errors, codeVerify); verify.Readiness.Guardian != (tc.want == "") || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Fatalf("%s: guardian ready=%v errors=%s", tc.name, verify.Readiness.Guardian, got)
		}
	}
	// GAP-0691: right after an apply rewrote targets.yaml, keep the
	// catch-up guidance but report coverage incomplete until reconciliation.
	now := h.env.Now()
	if err := os.Chtimes(h.env.P(h.env.Layout.ManifestPath), now, now); err != nil {
		t.Fatal(err)
	}
	verify = h.run(Options{Action: ActionVerify})
	if verify.Readiness.Guardian || verify.CoverageComplete || verify.SecurityComplete ||
		!hasWarning(verify, codeGuardianReconcilePending) ||
		!strings.Contains(messagesOf(verify.Errors, codeVerify), guardianManifestNotReconciled) {
		t.Fatalf("a just-changed targets.yaml: guardian ready=%v warnings=%+v errors=%+v", verify.Readiness.Guardian, verify.Warnings, verify.Errors)
	}
}
