// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// An enrolled user's home on a stalled FUSE mount: status and verify read
// that user's hook files in this process, a thread stuck in the kernel lookup
// kept the process from exiting after it had printed its answer (GAP-1751).
// The hook folder is looked up out of process first; one that does not
// answer is reported unconfirmed and its files are never read here.
func TestStatusAndVerifyDoNotReadHookFilesBelowAStalledHome(t *testing.T) {
	h := newTestHost(t, "linux")
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

	stalled := h.env.P("/home/u")
	origAnswers, origFingerprint, origLstat := guardianOwnedFolderAnswers, guardianOwnedFileFingerprint, hermesHookLstat
	t.Cleanup(func() {
		guardianOwnedFolderAnswers, guardianOwnedFileFingerprint, hermesHookLstat = origAnswers, origFingerprint, origLstat
	})
	var reads atomic.Int32
	below := func(path string) bool {
		return path == stalled || strings.HasPrefix(path, stalled+string(filepath.Separator))
	}
	guardianOwnedFolderAnswers = func(path string) bool { return !below(path) }
	guardianOwnedFileFingerprint = func(path string) string {
		if below(path) {
			reads.Add(1)
		}
		return origFingerprint(path)
	}
	hermesHookLstat = func(path string) (os.FileInfo, error) {
		if below(path) {
			reads.Add(1)
		}
		return origLstat(path)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if got := messagesOf(result.Warnings, codeGuardianRepairPending); !strings.Contains(got, "did not answer a lookup") || result.SecurityComplete {
			t.Fatalf("%s with a stalled home: complete=%v warnings=%q, want the hook files reported unconfirmed", action, result.SecurityComplete, got)
		}
	}
	if n := reads.Load(); n != 0 {
		t.Fatalf("status/verify read %d hook file(s) of the stalled home in process", n)
	}
	guardianOwnedFolderAnswers, guardianOwnedFileFingerprint, hermesHookLstat = origAnswers, origFingerprint, origLstat
	requireOK(t, h.run(Options{Action: ActionVerify}))
}
