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
	socket := filepath.Join(t.TempDir(), "hook.sock")
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
