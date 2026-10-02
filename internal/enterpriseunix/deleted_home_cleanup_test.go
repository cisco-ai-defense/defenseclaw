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

// GAP-1205: after an enrolled account was deleted (home removed), status
// said the guardian would remove its hook registration "once the home is
// available", for a home that no longer exists. It now says the account was
// deleted; a cleanup in a home that still exists keeps the old message.
func TestGuardianCleanupOfADeletedHomeSaysTheAccountWasDeleted(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if err := os.MkdirAll(h.env.P("/Users/kept"), 0o755); err != nil {
		t.Fatal(err)
	}
	ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 0, "success_count": 0, "failure_count": 0})
	cleanup, _ := json.Marshal(map[string]any{"version": 1, "pending": []map[string]any{
		{"connector": "kiro", "uid": 1001, "user": "gone", "user_home": "/Users/gone"},
		{"connector": "amp", "uid": 1002, "user": "kept", "user_home": "/Users/kept"},
	}})
	h.publishLedger(ledger)
	if err := os.WriteFile(filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianUserCleanupFile), cleanup, 0o640); err != nil {
		t.Fatal(err)
	}
	result := h.run(Options{Action: ActionStatus})
	requireOK(t, result)
	got := messagesOf(result.Warnings, codeGuardianCleanupPending)
	if !strings.Contains(got, "kiro for user gone: the home /Users/gone no longer exists (the account was deleted)") {
		t.Fatalf("status does not say the account was deleted: %s", got)
	}
	if strings.Contains(got, "still in /Users/gone") {
		t.Fatalf("status still promises a cleanup in the deleted home: %s", got)
	}
	if !strings.Contains(got, "amp for user kept is no longer enrolled, but DefenseClaw's hook registration is still in /Users/kept") {
		t.Fatalf("the cleanup in an existing home lost its message: %s", got)
	}
}

// GAP-1867: while targets.yaml still enrolls a deleted account (until the
// enumerator's next pass), status and verify name the account as deleted
// with its connectors; an account whose home exists is not named.
func TestStatusNamesAnEnrolledAccountWhoseHomeWasDeleted(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if err := os.MkdirAll(h.env.P("/Users/kept"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n"+
		"  - user: gone\n    uid: 506\n    user_home: /Users/gone\n    connector: kiro\n"+
		"  - user: gone\n    uid: 506\n    user_home: /Users/gone\n    connector: amp\n"+
		"  - user: kept\n    uid: 507\n    user_home: /Users/kept\n    connector: amp\n")
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		got := messagesOf(result.Warnings, codeEnrolledAccountDeleted)
		if !strings.Contains(got, "user gone (home /Users/gone) was deleted") || !strings.Contains(got, "amp, kiro") {
			t.Fatalf("%s does not name the deleted account: %q", action, got)
		}
		if strings.Contains(got, "kept") {
			t.Fatalf("%s names an account whose home exists: %q", action, got)
		}
	}
}
