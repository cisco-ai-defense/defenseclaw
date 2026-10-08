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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// failingReconcileRunner fails `enterprise hooks reconcile` with err.
type failingReconcileRunner struct {
	Runner
	err error
}

func (r failingReconcileRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if strings.HasPrefix(strings.Join(args, " "), "enterprise hooks reconcile ") {
		return CommandResult{ExitCode: 1}, r.err
	}
	return r.Runner.Run(ctx, name, args...)
}

// After an enrolled account was deleted, verify failed
// ("openhands for user bob is not protected: target account ... does
// not exist: no such account") until the enumerator revoked the target, so
// MDM detection reported the host non-compliant. The account is gone; the
// target is reported as a warning until it is revoked. Likewise an account
// that broke a path in its own home (its Amp plugins folder replaced by a
// file) failed verify for the whole host until it undid the change; that
// target is reported for the account only, while the same refusal of a path
// outside the account's home still fails verify. reconcile also failed for
// the account's own path, giving the guardian command line, the manifest
// path and the guardian's log output (a foreign-hook guard line) as the
// reason. It no longer fails for that path, and it names any other failed
// target in the words of its warning. reconcile failed for the deleted
// account's target too, while verify only warned; it warns now as well.
func TestOneAccountsTargetDoesNotFailTheHost(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": false, "target_count": 3, "success_count": 1, "failure_count": 2})
			h.publishLedger(data)
			if before := h.run(Options{Action: ActionStatus}); !before.SecurityComplete {
				t.Fatalf("the test host must start security-complete: %+v %+v", before.Readiness, before.Warnings)
			}
			bob := map[string]any{"user": "bob", "connector": "openhands", "ok": false, "error": `enterprise hooks: target account "bob" does not exist: no such account`}
			// The enumerator last saw bob in the local account database, so
			// "no such account" is definitive for him.
			writeEnumeratorState(t, h, map[string]string{"bob": "files"}, nil)
			writeState := func(ampPath string, deleted ...map[string]any) {
				results := append([]map[string]any{{"user": "alice", "connector": "codex", "ok": true}}, deleted...)
				results = append(results, map[string]any{"user": "carol", "user_home": "/home/carol", "connector": "amp", "ok": false, "error": "enterprise hooks: hook config parent is not a directory: " + ampPath})
				state, _ := json.Marshal(map[string]any{"results": results})
				// Dated after the next reconcile starts, as the receipt of its report is.
				receipt, _ := json.Marshal(map[string]any{"updated_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), "failure_count": len(results) - 1})
				for path, data := range map[string][]byte{filepath.Join(h.env.Layout.DataDir, guardianStateFile): state, filepath.Join(h.env.Layout.GuardianAuthDir, guardianActivationFile): receipt} {
					if err := os.WriteFile(h.env.P(path), data, 0o640); err != nil {
						t.Fatal(err)
					}
				}
			}
			writeState("/home/carol/.config/amp/plugins", bob)
			status := h.run(Options{Action: ActionStatus})
			if hasWarning(status, codeGuardianTargetFailed) {
				t.Fatalf("one account's target is reported as a protection failure: %+v", status.Warnings)
			}
			if got := messagesOf(status.Warnings, codeGuardianTargetAccountRemoved); !strings.Contains(got, "openhands for user bob: the account no longer exists") || !strings.Contains(got, "after 3 consecutive definitive misses") {
				t.Fatalf("status does not report the deleted account's target: %+v", status.Warnings)
			}
			if got := messagesOf(status.Warnings, codeGuardianTargetUserPath); !strings.Contains(got, "amp for user carol is not protected: hook config parent is not a directory: /home/carol/.config/amp/plugins") {
				t.Fatalf("status does not report the account's own path: %+v", status.Warnings)
			}
			if !status.SecurityComplete {
				t.Fatal("one account's target made the host security-incomplete")
			}
			verify := h.run(Options{Action: ActionVerify})
			requireOK(t, verify)
			if !hasWarning(verify, codeGuardianTargetAccountRemoved) || !hasWarning(verify, codeGuardianTargetUserPath) {
				t.Fatalf("verify does not report the account targets: %+v", verify.Warnings)
			}
			// The guardian's reconcile exits 1 for a failed target.
			failed := errors.New("the guardian reconcile command exited 1")
			h.services.failStart[unitGuardianOneshot] = failed
			h.env.Runner = failingReconcileRunner{Runner: h.runner, err: failed}
			writeState("/home/carol/.config/amp/plugins", bob)
			reconcile := h.run(Options{Action: ActionReconcile})
			requireOK(t, reconcile)
			if !hasWarning(reconcile, codeGuardianTargetUserPath) || !hasWarning(reconcile, codeGuardianTargetAccountRemoved) {
				t.Fatalf("reconcile does not report the account targets as warnings: %+v", reconcile.Warnings)
			}
			if goos == "linux" && !strings.Contains(strings.Join(h.runner.calls, "\n"), "systemctl reset-failed "+unitGuardianOneshot) {
				t.Fatalf("the reconcile oneshot is left failed: %v", h.runner.calls)
			}
			writeState("/home/dave/.config/amp/plugins", bob)
			verify = h.run(Options{Action: ActionVerify})
			requireError(t, verify, codeVerify)
			if !hasWarning(verify, codeGuardianTargetFailed) || verify.SecurityComplete {
				t.Fatalf("a refused path outside the account's home does not fail verify: %+v", verify.Warnings)
			}
			reconcile = h.run(Options{Action: ActionReconcile})
			requireError(t, reconcile, codeReconcile)
			if got := messagesOf(reconcile.Errors, codeReconcile); !strings.Contains(got, "amp for user carol is not protected: hook config parent is not a directory: /home/dave/.config/amp/plugins") || strings.Contains(got, failed.Error()) {
				t.Fatalf("reconcile does not name the failed target: %+v", reconcile.Errors)
			}
		})
	}
}

// A registration the hook guardian still has to remove from a user's home
// (its per-user cleanup ledger) is reported by status and verify as a
// warning that does not fail verify.
func TestGuardianCleanupPendingIsReported(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	authDir := h.env.P(h.env.Layout.GuardianAuthDir)
	ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 0, "success_count": 0, "failure_count": 0})
	cleanup, _ := json.Marshal(map[string]any{"version": 1, "pending": []map[string]any{
		{"connector": "kiro", "sid": "", "uid": 1001, "user": "alice", "user_home": "/home/alice"},
	}})
	h.publishLedger(ledger)
	if err := os.WriteFile(filepath.Join(authDir, managed.HookGuardianUserCleanupFile), cleanup, 0o640); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		requireOK(t, result)
		if got := messagesOf(result.Warnings, codeGuardianCleanupPending); !strings.Contains(got, "kiro") || !strings.Contains(got, "alice") {
			t.Fatalf("%s does not report the pending cleanup: %+v", action, result.Warnings)
		}
	}
}

// The deleted-account warning must not hide a real failure, and must not
// blame a deleted account for a directory outage. A failure of an account
// that still exists stays a failure, whatever its text. An account that
// does not resolve is not a protection failure; it is reported as removed
// only when the enumerator confirmed it is gone: a local account, or a
// counted definitive miss. A directory account the enumerator could not
// confirm (the directory does not answer, GAP-0593) is neither, and whatever
// the reconcile error (a removed home, GAP-0692) it never fails the host.
func TestAccountRemovedWarningNeedsAConfirmedMiss(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.accounts.accounts["alice"] = Account{Name: "alice", UID: 1500, GID: 1500}
	writeEnumeratorState(t, h,
		map[string]string{"gone1": "files", "gone2": "directory", "gone3": "directory"},
		map[string]int{"gone3\x00codex": 1})
	quoted := `parse Codex config for hook guardian: toml: key does not exist: no such account is already defined`
	for _, tc := range []struct {
		name, user, message string
		removed, failed     bool
	}{
		{"a user's file text for an existing account", "alice", quoted, false, true},
		{"the exact error for an account that still exists", "alice", `enterprise hooks: target account "alice" does not exist: no such account`, false, true},
		{"a missing local account", "gone1", `enterprise hooks: target account "gone1" does not exist: no such account`, true, false},
		{"a missing directory account not confirmed", "gone2", `enterprise hooks: target account "gone2" does not exist: no such account`, false, false},
		{"a confirmed directory account whose home is gone", "gone3", "user home /home/gone3 is not available yet: no such file or directory", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := json.Marshal(map[string]any{"results": []map[string]any{
				{"user": tc.user, "connector": "codex", "ok": false, "error": tc.message},
			}})
			if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
				t.Fatal(err)
			}
			status := h.run(Options{Action: ActionStatus})
			if got := hasWarning(status, codeGuardianTargetAccountRemoved); got != tc.removed {
				t.Fatalf("account-removed warning = %v, want %v: %+v", got, tc.removed, status.Warnings)
			}
			if got := hasWarning(status, codeGuardianTargetFailed); got != tc.failed {
				t.Fatalf("target-failed warning = %v, want %v: %+v", got, tc.failed, status.Warnings)
			}
		})
	}
}

// writeEnumeratorState writes the hook enumerator state beside targets.yaml.
func writeEnumeratorState(t *testing.T, h *testHost, sources map[string]string, misses map[string]int) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"version": 1, "sources": sources, "misses": misses})
	path := h.env.P(filepath.Join(filepath.Dir(h.env.Layout.ManifestPath), enumeratorStateFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
}
