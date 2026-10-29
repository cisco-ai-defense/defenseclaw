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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gap0051Reason is the guardian's reason, after the "enterprise hooks: "
// prefix, for an enrolled Antigravity account that ran chmod 000 ~/.gemini
// (live, managed RHEL 9.8 rc.8): the bootstrap of the missing hook config
// is refused by its lstat, inside the installer's bootstrap wrapper.
const gap0051Reason = "bootstrap missing hook config for antigravity: enterprise hooks: inspect hook config " +
	"/home/carol/.gemini/config/hooks.json before bootstrap: lstat /home/carol/.gemini/config/hooks.json: permission denied"

// A refusal of one path in the account's own home is that account's
// guardian_target_user_path warning also when it comes wrapped by the
// bootstrap of a missing hook config (GAP-0051). The wrapper does not widen
// what counts: the wrapped refusal must still be one of the whole-reason
// refusals of a path strictly inside the home.
func TestUserHomePathRefusalSeesThroughTheBootstrapWrapper(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		want   bool
	}{
		{"bootstrap lstat refused in the home", gap0051Reason, true},
		{"bootstrap of a symlinked config", "bootstrap missing hook config for amp: enterprise hooks: refusing symlink in hook config path: /home/carol/.config/amp/settings.json", true},
		{"bare refusal unchanged", "inspect hook config parent /home/carol/.gemini: lstat /home/carol/.gemini: permission denied", true},
		{"bootstrap refused outside the home", strings.ReplaceAll(gap0051Reason, "/home/carol/", "/home/dave/"), false},
		{"bootstrap of the home itself", "bootstrap missing hook config for antigravity: enterprise hooks: inspect hook config /home/carol before bootstrap: lstat /home/carol: permission denied", false},
		{"bootstrap write failure", "bootstrap missing hook config for antigravity: enterprise hooks: write hook config /home/carol/.gemini/config/hooks.json: no space left on device", false},
		{"bootstrap containment refusal", `bootstrap missing hook config for antigravity: enterprise hooks: hook config stub path "/etc/x" is not inside user home "/home/carol"`, false},
		{"connector name is not a plain name", "bootstrap missing hook config for anti gravity: x: enterprise hooks: inspect hook config /home/carol/.gemini/config/hooks.json before bootstrap: lstat /home/carol/.gemini/config/hooks.json: permission denied", false},
		{"wrapper text quoted after another error", "validate hook config: bootstrap missing hook config for antigravity: enterprise hooks: inspect hook config /home/carol/.g before bootstrap: lstat /home/carol/.g: permission denied", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := userHomePathRefusal(tc.reason, "/home/carol"); got != tc.want {
				t.Fatalf("userHomePathRefusal(%q) = %t, want %t", tc.reason, got, tc.want)
			}
		})
	}
}

// Live repro of GAP-0051: status, verify and reconcile report the wrapped
// Antigravity refusal as the account's guardian_target_user_path warning,
// as operations.mdx and troubleshooting.mdx document, not as a
// guardian_target_failed that fails verify and reconcile for the host.
func TestAnUnreadableAgentConfigFolderIsTheAccountsOwnPath(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": false, "target_count": 2, "success_count": 1, "failure_count": 1})
	h.publishLedger(data)
	writeState := func(reason string) {
		t.Helper()
		state, _ := json.Marshal(map[string]any{"results": []map[string]any{
			{"user": "alice", "connector": "codex", "ok": true},
			{"user": "carol", "user_home": "/home/carol", "connector": "antigravity", "ok": false, "error": "enterprise hooks: " + reason},
		}})
		receipt, _ := json.Marshal(map[string]any{"updated_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), "failure_count": 1})
		for path, data := range map[string][]byte{filepath.Join(h.env.Layout.DataDir, guardianStateFile): state, filepath.Join(h.env.Layout.GuardianAuthDir, guardianActivationFile): receipt} {
			if err := os.WriteFile(h.env.P(path), data, 0o640); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeState(gap0051Reason)
	status := h.run(Options{Action: ActionStatus})
	if hasWarning(status, codeGuardianTargetFailed) {
		t.Fatalf("the account's own unreadable ~/.gemini is reported as a protection failure: %+v", status.Warnings)
	}
	if got := messagesOf(status.Warnings, codeGuardianTargetUserPath); !strings.Contains(got, "antigravity for user carol is not protected: bootstrap missing hook config for antigravity") ||
		!strings.Contains(got, "only that account is affected") {
		t.Fatalf("status does not report the account's own path: %+v", status.Warnings)
	}
	verify := h.run(Options{Action: ActionVerify})
	requireOK(t, verify)
	if !hasWarning(verify, codeGuardianTargetUserPath) {
		t.Fatalf("verify does not report the account's own path: %+v", verify.Warnings)
	}
	failed := errors.New("the guardian reconcile command exited 1")
	h.services.failStart[unitGuardianOneshot] = failed
	h.env.Runner = failingReconcileRunner{Runner: h.runner, err: failed}
	writeState(gap0051Reason)
	reconcile := h.run(Options{Action: ActionReconcile})
	requireOK(t, reconcile)
	if !hasWarning(reconcile, codeGuardianTargetUserPath) {
		t.Fatalf("reconcile does not report the account's own path as a warning: %+v", reconcile.Warnings)
	}
	// The same bootstrap refusal of a path outside the account's home still
	// fails verify and reconcile.
	writeState(strings.ReplaceAll(gap0051Reason, "/home/carol/", "/home/dave/"))
	verify = h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	if !hasWarning(verify, codeGuardianTargetFailed) {
		t.Fatalf("a bootstrap refusal outside the account's home does not fail verify: %+v", verify.Warnings)
	}
	reconcile = h.run(Options{Action: ActionReconcile})
	requireError(t, reconcile, codeReconcile)
}
