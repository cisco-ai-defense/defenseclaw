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
)

// GAP-0564: the guardian recreated a missing Hermes config.yaml with its
// hooks only and status and verify read ok while the account's model and
// Bedrock settings were gone. A protected target whose agent config the
// guardian put back or recreated is now reported for that account from the
// guardian's notice record (the hooks are in place, so the host stays
// security-complete and verify passes).
func TestStatusAndVerifyReportAgentSettingsTheGuardianCouldNotPutBack(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 2, "success_count": 2, "failure_count": 0})
			h.publishLedger(ledger)
			record, _ := json.Marshal(map[string]any{"version": 1, "updated_at": time.Now().UTC().Format(time.RFC3339Nano), "targets": []map[string]any{
				{"user": "erin", "connector": "hermes", "agent_config": "settings_lost"},
				{"user": "bob", "connector": "devin", "agent_config": "restored_last_good"},
				// A code the guardian does not write, and a connector without an
				// agent config, are not worded.
				{"user": "mallory", "connector": "hermes", "agent_config": "\u001b[31m anything"},
				{"user": "alice", "connector": "codex", "agent_config": "settings_lost"},
			}})
			state, _ := json.Marshal(map[string]any{"results": []map[string]any{
				{"user": "alice", "connector": "codex", "ok": true},
				{"user": "erin", "user_home": "/home/erin", "connector": "hermes", "ok": true},
				{"user": "bob", "user_home": "/home/bob", "connector": "devin", "ok": true},
			}})
			receipt, _ := json.Marshal(map[string]any{"updated_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), "failure_count": 0})
			for path, data := range map[string][]byte{
				filepath.Join(h.env.Layout.DataDir, guardianStateFile):              state,
				filepath.Join(h.env.Layout.DataDir, guardianNoticesFile):            record,
				filepath.Join(h.env.Layout.GuardianAuthDir, guardianActivationFile): receipt,
			} {
				if err := os.WriteFile(h.env.P(path), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				requireOK(t, r)
				got := messagesOf(r.Warnings, codeAgentSettingsNotRestored)
				if !strings.Contains(got, "hermes for user erin: the Hermes config.yaml went missing and DefenseClaw had no copy") ||
					!strings.Contains(got, "devin for user bob: the Devin config.json went missing; the guardian put back") {
					t.Fatalf("%s warnings = %+v", action, r.Warnings)
				}
				if strings.Contains(got, "alice") || strings.Contains(got, "mallory") {
					t.Fatalf("%s words a notice it must not: %q", action, got)
				}
				if !r.SecurityComplete || hasWarning(r, codeGuardianTargetFailed) {
					t.Fatalf("%s: a lost agent setting is reported as a protection failure: %+v", action, r.Warnings)
				}
			}
		})
	}
}

// The guardian writes its notice record root:root 0600 in the data folder,
// as it writes its repair and restore records: verify must not report it and
// ensure must not give it to the service account (the GAP-0499 lesson).
func TestStateModesKeepTheGuardianNoticeRecordRootOwned(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			account := h.accounts.accounts[h.env.Layout.ServiceUser]
			canonical := filepath.Join(h.env.Layout.DataDir, guardianNoticesFile)
			if err := os.WriteFile(h.env.P(canonical), []byte(`{"version":1,"updated_at":"2026-10-14T05:48:49Z","targets":[{"user":"u","connector":"hermes","agent_config":"settings_lost"}]}`+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			h.owners[h.env.P(canonical)] = [2]int{0, 0}
			if problems := h.env.stateModeProblems(account); len(problems) != 0 {
				t.Fatalf("state-mode problems with the notice record as the guardian writes it: %v", problems)
			}
			verify := h.run(Options{Action: ActionVerify})
			if got := messagesOf(verify.Errors, codeVerify); got != "" {
				t.Fatalf("verify reports the notice record: %s", got)
			}
			requireOK(t, verify)
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			uid, gid, err := h.env.OwnerOf(h.env.P(canonical))
			if err != nil || uid != 0 || gid != 0 || h.mode(canonical) != 0o600 {
				t.Errorf("after ensure the notice record is %04o %d:%d (%v), want 0600 0:0", h.mode(canonical), uid, gid, err)
			}
		})
	}
}
