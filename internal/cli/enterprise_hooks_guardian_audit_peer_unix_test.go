// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGuardianRepairAuditRefusesAnotherAccountHookSocket(t *testing.T) {
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("another account received a guardian repair report")
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	previous := enterpriseHookStandaloneHookTransport
	enterpriseHookStandaloneHookTransport = func() (string, int, error) { return socket, os.Geteuid() + 1, nil }
	t.Cleanup(func() { enterpriseHookStandaloneHookTransport = previous })
	reportEnterpriseHookGuardianRepairs(context.Background(), socket, []enterpriseHookGuardianAuditReport{
		{User: "private-user", UID: os.Geteuid(), Connector: "opencode"},
	})
}

// shortSocketDir is a private, link-free directory short enough for a unix
// socket path: macOS caps sun_path at 104 bytes, and a t.TempDir under the
// macOS runner's TMPDIR made bind fail with "invalid argument".
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dc-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(canonical, 0o700); err != nil {
		t.Fatal(err)
	}
	return canonical
}
