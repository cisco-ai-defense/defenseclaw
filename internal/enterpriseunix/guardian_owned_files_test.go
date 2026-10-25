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

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0044: a user overwrote the Hermes scoped token between two guardian
// passes, and status and verify kept security_complete true for the 22 s the
// guardian took to put it back. Status and verify now compare each verified
// target's hook files with the fingerprints the guardian recorded and report
// a changed one until the guardian's next pass records it put back.
func TestStatusReportsHookFilesChangedSinceTheGuardianPass(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	ledger, err := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 1, "success_count": 1, "failure_count": 0})
	if err != nil {
		t.Fatal(err)
	}
	h.publishLedger(ledger)
	if before := h.run(Options{Action: ActionStatus}); !before.SecurityComplete || hasWarning(before, codeGuardianRepairPending) {
		t.Fatalf("baseline without a record: security_complete=%v warnings=%v", before.SecurityComplete, before.Warnings)
	}
	token := "/home/u/.defenseclaw/hooks/.hook-hermes.token"
	writeHostFile(t, h, token, "issued\n")
	record := enterprisehooks.GuardianOwnedFilesRecord{Version: 1, UpdatedAt: "2026-10-17T21:18:21Z", Targets: []enterprisehooks.GuardianOwnedTarget{{
		User: "u", UID: 502, Connector: "hermes",
		Files: []enterprisehooks.GuardianOwnedFile{{Path: token, Fingerprint: enterprisehooks.OwnedFileFingerprint(h.env.P(token))}},
	}}}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(h.env.Layout.DataDir, enterprisehooks.GuardianOwnedFilesFile)
	writeHostFile(t, h, recordPath, string(data))
	// The guardian writes its records root-only.
	if err := os.Chmod(h.env.P(recordPath), 0o600); err != nil {
		t.Fatal(err)
	}
	if clean := h.run(Options{Action: ActionStatus}); !clean.SecurityComplete || hasWarning(clean, codeGuardianRepairPending) {
		t.Fatalf("files as the guardian left them: security_complete=%v warnings=%v errors=%v", clean.SecurityComplete, clean.Warnings, clean.Errors)
	}
	// Overwritten in place, mode kept.
	if err := os.WriteFile(h.env.P(token), []byte("lane-made\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		got := messagesOf(result.Warnings, codeGuardianRepairPending)
		if !strings.Contains(got, "user u for hermes changed since the hook guardian last verified them") || !strings.Contains(got, token) || result.SecurityComplete {
			t.Fatalf("%s with an overwritten token: security_complete=%v warning=%q", action, result.SecurityComplete, got)
		}
		if strings.Contains(got, "lane-made") || strings.Contains(got, "issued") {
			t.Fatalf("%s shows token content: %q", action, got)
		}
	}
	// The guardian put it back.
	if err := os.WriteFile(h.env.P(token), []byte("issued\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if repaired := h.run(Options{Action: ActionVerify}); !repaired.SecurityComplete || hasWarning(repaired, codeGuardianRepairPending) {
		t.Fatalf("after the put-back: security_complete=%v warnings=%v", repaired.SecurityComplete, repaired.Warnings)
	}
	// An unreadable record is not taken as clean.
	writeHostFile(t, h, recordPath, "{not json")
	if err := os.Chmod(h.env.P(recordPath), 0o600); err != nil {
		t.Fatal(err)
	}
	if bad := h.run(Options{Action: ActionStatus}); bad.SecurityComplete || !strings.Contains(messagesOf(bad.Warnings, codeGuardianRepairPending), "cannot be read") {
		t.Fatalf("invalid record: security_complete=%v warnings=%v", bad.SecurityComplete, bad.Warnings)
	}
}

func TestVerifyAndEnsureFailNonExecutableRegisteredHermesHook(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			ledger, err := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 1, "success_count": 1, "failure_count": 0})
			if err != nil {
				t.Fatal(err)
			}
			h.publishLedger(ledger)
			script := "/home/u/.defenseclaw/hooks/hermes-hook.sh"
			writeHostFile(t, h, script, "#!/bin/sh\nexit 0\n")
			if err := os.Chmod(h.env.P(script), 0o700); err != nil {
				t.Fatal(err)
			}
			record := enterprisehooks.GuardianOwnedFilesRecord{Version: 1, Targets: []enterprisehooks.GuardianOwnedTarget{{
				User: "u", UID: 502, Connector: "hermes",
				Files: []enterprisehooks.GuardianOwnedFile{{Path: script, Fingerprint: enterprisehooks.OwnedFileFingerprint(h.env.P(script))}},
			}}}
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			recordPath := filepath.Join(h.env.Layout.DataDir, enterprisehooks.GuardianOwnedFilesFile)
			writeHostFile(t, h, recordPath, string(data))
			if err := os.Chmod(h.env.P(recordPath), 0o600); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionVerify}))
			if err := os.Chmod(h.env.P(script), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{ActionVerify, ActionEnsure} {
				result := h.run(Options{Action: action})
				if result.OK || !strings.Contains(messagesOf(result.Errors, codeVerify), "registered Hermes hook is not executable") || result.SecurityComplete {
					t.Fatalf("%s accepted non-executable registered hook: ok=%v complete=%v errors=%v warnings=%v", action, result.OK, result.SecurityComplete, result.Errors, result.Warnings)
				}
			}
			if err := os.Chmod(h.env.P(script), 0o700); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionVerify}))
		})
	}
}
