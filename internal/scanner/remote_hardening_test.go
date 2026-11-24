// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// skipSidecarClientOnWindows skips a test of the Linux-only scanner sidecar's
// client. Off Linux the client refuses before it asks a worker, so the test
// would pass or fail for another reason than the one it pins
// (TestRemoteScannerRefusesEveryScanOnWindows pins the Windows refusal).
func skipSidecarClientOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the scanner sidecar client is Linux only: it refuses every folder on Windows (GAP-1050)")
	}
}

func forgedRemoteServer(t *testing.T, dir string) {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(dir, ScanSocketName))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(rw).Encode(RemoteScanAnswer{Result: &ScanResult{Scanner: "skill-scanner"}})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func remoteTarget(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: fixture\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRemoteScannerRefusesAnswerWithoutJob(t *testing.T) {
	skipSidecarClientOnWindows(t)
	dir := t.TempDir()
	forgedRemoteServer(t, dir)
	res, err := (&RemoteScanner{Kind: RemoteKindSkill, Dir: dir}).Scan(context.Background(), remoteTarget(t))
	if res != nil || err == nil {
		t.Fatalf("forged clean result was accepted: result=%+v err=%v", res, err)
	}
}

func TestRemoteScannerRefusesLinkedJobsFolder(t *testing.T) {
	skipSidecarClientOnWindows(t)
	dir := t.TempDir()
	forgedRemoteServer(t, dir)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, ScanJobsDirName)); err != nil {
		t.Fatal(err)
	}
	res, err := (&RemoteScanner{Kind: RemoteKindSkill, Dir: dir}).Scan(context.Background(), remoteTarget(t))
	if res != nil || err == nil {
		t.Fatalf("linked jobs folder was accepted: result=%+v err=%v", res, err)
	}
}
