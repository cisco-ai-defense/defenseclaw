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
)

// writeGuardianResults writes the guardian's per-target report as its last
// reconcile left it.
func writeGuardianResults(t *testing.T, h *testHost, results ...map[string]any) {
	t.Helper()
	state, _ := json.Marshal(map[string]any{"results": results})
	if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
		t.Fatal(err)
	}
}

const unprotectedHermes = "hermes for user alice is not protected: connector hermes hook verification failed: owned hook command not present"

// GAP-0846: ensure, upgrade and repair returned ok and exit 0 while the
// guardian reported an enrolled target it could not protect (only a
// guardian_target_failed warning next to security_complete false). Every
// mutating action now fails with the target and its cause; status still
// reports it as a warning.
func TestChangeFailsWhileAnEnrolledTargetIsUnprotected(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeGuardianResults(t, h,
				map[string]any{"user": "bob", "user_home": "/home/bob", "connector": "codex", "ok": true},
				map[string]any{"user": "alice", "user_home": "/home/alice", "connector": "hermes", "ok": false,
					"error": "enterprise hooks: connector hermes hook verification failed: owned hook command not present"})
			status := h.run(Options{Action: ActionStatus})
			requireOK(t, status)
			if !strings.Contains(messagesOf(status.Warnings, codeGuardianTargetFailed), unprotectedHermes) {
				t.Fatalf("status warnings do not name the target: %+v", status.Warnings)
			}
			for _, step := range []struct {
				name string
				opts Options
			}{
				{"ensure", Options{Action: ActionEnsure}},
				{"upgrade", Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1"), ProductVersion: "1.0.1"}},
				{"repair", Options{Action: ActionRepair, ProductVersion: "1.0.1"}},
				{"ensure after the upgrade", Options{Action: ActionEnsure, ProductVersion: "1.0.1"}},
			} {
				name := step.name
				r := h.run(step.opts)
				requireError(t, r, codeGuardianTargetFailed)
				if r.ExitCode == 0 || r.SecurityComplete {
					t.Fatalf("%s: exit %d, security_complete %v, want a failure", name, r.ExitCode, r.SecurityComplete)
				}
				errs := messagesOf(r.Errors, codeGuardianTargetFailed)
				if !strings.Contains(errs, unprotectedHermes) || !strings.Contains(errs, " reconcile`") || strings.Contains(errs, "user bob") {
					t.Fatalf("%s: errors = %q, want alice's target with its cause and the next step", name, errs)
				}
				if strings.Count(errs, unprotectedHermes) != 1 {
					t.Fatalf("%s: target reported more than once: %q", name, errs)
				}
			}
		})
	}
}

// The guardian targets verify does not fail on do not fail a change either:
// a path the account broke in its own home, an account that is gone, an
// agent version with no verified hook contract.
func TestChangeKeepsTheTargetsVerifyAcceptsAsWarnings(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeGuardianResults(t, h,
		map[string]any{"user": "alice", "user_home": "/home/alice", "connector": "hermes", "ok": false,
			"error": "enterprise hooks: refusing symlink in hook config path: /home/alice/.hermes/config.yaml"},
		map[string]any{"user": "bob", "user_home": "/home/bob", "connector": "devin", "ok": false,
			"error": `enterprise hooks: connector devin agent version "3999.0.0" is not verified against a known hook contract: no hook contract matches normalized agent version`})
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	if r.SecurityComplete {
		t.Fatal("ensure reports security_complete with unprotected agents")
	}
	if messagesOf(r.Warnings, codeGuardianTargetUserPath) == "" || messagesOf(r.Warnings, codeHookContractUnverified) == "" {
		t.Fatalf("ensure warnings = %+v, want the user-path and unverified-contract targets", r.Warnings)
	}
}
