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
	"testing"
	"time"

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
			ledger := filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianAuthorizationFile)
			data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format(time.RFC3339), "ok": true})
			if err := os.WriteFile(ledger, data, 0o640); err != nil {
				published <- err
				return
			}
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
