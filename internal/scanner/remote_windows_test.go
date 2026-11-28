// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"context"
	"os"
	"strings"
	"testing"
)

// The scanner sidecar is Linux only (the chart's container). On Windows the
// client refuses the jobs folder it just made, because Windows reports mode
// 0777 for every folder, so a scan never reaches a worker and never returns
// a result: the fail mode decides. The scanworker and cli sidecar tests skip
// on Windows for this reason (GAP-1050).
func TestRemoteScannerRefusesEveryScanOnWindows(t *testing.T) {
	dir := shortSocketDir(t)
	forgedRemoteServer(t, dir)
	res, err := (&RemoteScanner{Kind: RemoteKindSkill, Dir: dir}).Scan(context.Background(), remoteTarget(t))
	if res != nil || err == nil || !strings.Contains(err.Error(), "is not a private folder of this user") {
		t.Fatalf("a Windows scan was not refused by the private-folder check: result=%+v err=%v", res, err)
	}
}

// shortSocketDir is a new folder with a short path for a unix socket: a
// socket path over 108 characters fails to bind on Windows, and t.TempDir
// under a standard user's TMP is longer.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dcrs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
