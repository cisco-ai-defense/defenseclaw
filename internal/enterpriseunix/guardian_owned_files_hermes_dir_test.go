// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// searchlessDir reports a folder as its owner would see it after chmod 000.
type searchlessDir struct{ fs.FileInfo }

func (d searchlessDir) Mode() fs.FileMode { return fs.ModeDir }

// A registered Hermes hook whose mode is intact but whose hooks folder or
// data folder its owner cannot search (chmod 000 ~/.defenseclaw/hooks with
// the guardian paused) runs nothing: verify and ensure fail on it (GAP-1628).
// Root still reads the hook and its fingerprint, so the folders are checked.
func TestVerifyAndEnsureFailAHermesHookInAnUnsearchableFolder(t *testing.T) {
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
	orig := hermesHookLstat
	t.Cleanup(func() { hermesHookLstat = orig })
	for _, folder := range []string{"/home/u/.defenseclaw/hooks", "/home/u/.defenseclaw"} {
		hidden := h.env.P(folder)
		hermesHookLstat = func(path string) (fs.FileInfo, error) {
			info, err := orig(path)
			if err == nil && filepath.Clean(path) == hidden {
				return searchlessDir{info}, nil
			}
			return info, err
		}
		for _, action := range []string{ActionVerify, ActionEnsure} {
			result := h.run(Options{Action: action})
			if result.OK || !strings.Contains(messagesOf(result.Errors, codeVerify), "registered Hermes hook is not executable") || result.SecurityComplete {
				t.Fatalf("%s accepted a registered hook below unsearchable %s: ok=%v complete=%v errors=%v", action, folder, result.OK, result.SecurityComplete, result.Errors)
			}
		}
	}
	hermesHookLstat = orig
	requireOK(t, h.run(Options{Action: ActionVerify}))
}
