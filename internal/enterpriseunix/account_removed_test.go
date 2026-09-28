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

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// After an enrolled account was deleted, verify failed
// ("openhands for user bob is not protected: target account ... does
// not exist: no such account") until the enumerator revoked the target, so
// MDM detection reported the host non-compliant. The account is gone; the
// target is reported as a warning until it is revoked.
func TestDeletedAccountTargetDoesNotFailTheHost(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			ledger := filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianAuthorizationFile)
			data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": false, "target_count": 2, "success_count": 1, "failure_count": 1})
			if err := os.WriteFile(ledger, data, 0o640); err != nil {
				t.Fatal(err)
			}
			if before := h.run(Options{Action: ActionStatus}); !before.SecurityComplete {
				t.Fatalf("the test host must start security-complete: %+v %+v", before.Readiness, before.Warnings)
			}
			state, _ := json.Marshal(map[string]any{"results": []map[string]any{
				{"user": "alice", "connector": "codex", "ok": true},
				{"user": "bob", "connector": "openhands", "ok": false, "error": `enterprise hooks: target account "bob" does not exist: no such account`},
			}})
			if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
				t.Fatal(err)
			}
			status := h.run(Options{Action: ActionStatus})
			if hasWarning(status, codeGuardianTargetFailed) {
				t.Fatalf("a deleted account is reported as a protection failure: %+v", status.Warnings)
			}
			if got := messagesOf(status.Warnings, codeGuardianTargetAccountRemoved); !strings.Contains(got, "openhands for user bob: the account no longer exists") || !strings.Contains(got, "after 3 consecutive definitive misses") {
				t.Fatalf("status does not report the deleted account's target: %+v", status.Warnings)
			}
			if !status.SecurityComplete {
				t.Fatal("a deleted account made the host security-incomplete")
			}
			verify := h.run(Options{Action: ActionVerify})
			requireOK(t, verify)
			if !hasWarning(verify, codeGuardianTargetAccountRemoved) {
				t.Fatalf("verify does not report the deleted account's target: %+v", verify.Warnings)
			}
		})
	}
}

// The deleted-account warning must not hide a real failure. The guardian's
// per-target error can quote text from a user's own files (a TOML parser
// reports a duplicated quoted key verbatim), so a failure of an account that
// still exists was reported as "account removed" when it merely contained
// the text. The message must now be exactly the guardian's "no such
// account" error, and the host's own lookup must also find no account.
func TestAccountRemovedWarningNeedsTheWholeErrorAndAMissingAccount(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.accounts.accounts["alice"] = Account{Name: "alice", UID: 1500, GID: 1500}
	quoted := `parse Codex config for hook guardian: toml: key does not exist: no such account is already defined`
	for _, tc := range []struct {
		name, user, message string
		removed             bool
	}{
		{"a user's file text for an existing account", "alice", quoted, false},
		{"the exact error for an account that still exists", "alice", `enterprise hooks: target account "alice" does not exist: no such account`, false},
		{"the exact error for a missing account", "gone1", `enterprise hooks: target account "gone1" does not exist: no such account`, true},
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
			if got := hasWarning(status, codeGuardianTargetFailed); got == tc.removed {
				t.Fatalf("target-failed warning = %v, want %v: %+v", got, !tc.removed, status.Warnings)
			}
		})
	}
}
