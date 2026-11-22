// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"
)

// rel-1-0-10 GAP-0904: an account file whose PowerShell -EncodedCommand
// cannot be decoded may name any launch folder. The scan records it under
// the folder "unknown", and prune matched folder names only, so it kept
// nothing for it and could remove the superseded folder that file starts.
// Like an unverified account file, it keeps every superseded folder.
func TestHookImagePruneKeepsEverySupersededFolderForAnUndecodableAccountFile(t *testing.T) {
	const (
		old    = "0123456789abcdef"
		newer  = "fedcba9876543210"
		file   = `C:\Users\dcw-std2\.copilot\hooks\defenseclaw-vscode.json`
		script = `{"hooks":{"PreToolUse":[{"command":"powershell -NoProfile -EncodedCommand !!not-base64!!"}]}}`
	)
	scan := scanWindowsHookImageConfigFiles(
		[]windowsHookImageConfigFile{{Path: file, User: true, Home: `C:\Users\dcw-std2`, SID: "S-1-5-21-1-2-3-1018"}},
		hookImageTestBin, func(windowsHookImageConfigFile) ([]byte, error) { return []byte(script), nil })
	if len(scan.Named[windowsHookImageUnknownFolder]) != 1 || len(scan.Incomplete) != 0 {
		t.Fatalf("scan of an undecodable account file = %+v", scan)
	}
	stagedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	staged := map[string]time.Time{old: stagedAt, newer: stagedAt.Add(time.Hour)}
	policy := windowsHookImagePrunePolicy{Scan: scan, Now: stagedAt.Add(60 * 24 * time.Hour)}
	why := windowsHookImageRetainReason(old, staged, policy)
	if !strings.HasPrefix(why, "undecodable_account_file:") || !strings.Contains(why, file) {
		t.Fatalf("retain reason of a folder superseded 60 days ago = %q, want undecodable_account_file:%s", why, file)
	}
	// Control: the same folder goes once no file may name it.
	policy.Scan = windowsHookImageConfigScan{Named: map[string][]string{}}
	if why := windowsHookImageRetainReason(old, staged, policy); why != "" {
		t.Fatalf("retain reason with nothing naming it = %q, want removable", why)
	}
}
