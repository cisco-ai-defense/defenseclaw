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

// A pending guardian cleanup of a live account that was given another home
// says the account is still present with that home and what ends the
// cleanup, not that the account was deleted (rel-1-0-2 GAP-0602).
func TestGuardianCleanupOfARehomedLiveAccountNamesItsCurrentHome(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 0, "success_count": 0, "failure_count": 0})
	cleanup, _ := json.Marshal(map[string]any{"version": 1, "pending": []map[string]any{
		{"connector": "hermes", "uid": 1003, "user": "moved", "user_home": "/home/moved"},
		{"connector": "kiro", "uid": 1001, "user": "gone", "user_home": "/home/gone"},
	}})
	h.publishLedger(ledger)
	if err := os.WriteFile(filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianUserCleanupFile), cleanup, 0o640); err != nil {
		t.Fatal(err)
	}
	h.runner.replies = map[string]fakeReply{
		"getent passwd 1003": {result: CommandResult{Stdout: []byte("moved:x:1003:1003::/home/moved-new:/bin/bash\n")}},
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		got := messagesOf(h.run(Options{Action: action}).Warnings, codeGuardianCleanupPending)
		if !strings.Contains(got, "hermes for user moved: the account is still present with home /home/moved-new; its recorded home /home/moved no longer exists") ||
			!strings.Contains(got, "removes DefenseClaw's hook registration from /home/moved-new as that user") ||
			!strings.Contains(got, "also ends when the account is removed") {
			t.Errorf("%s does not say the account is live with its current home: %s", action, got)
		}
		if strings.Contains(got, "was deleted") || strings.Contains(got, "drops this entry") {
			t.Errorf("%s calls a live account deleted: %s", action, got)
		}
		// An account the lookup does not find keeps the plain text.
		if !strings.Contains(got, "kiro for user gone: the recorded home /home/gone no longer exists") {
			t.Errorf("%s lost the unknown-account text: %s", action, got)
		}
	}
}
