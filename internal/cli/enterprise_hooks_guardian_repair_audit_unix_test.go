//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func TestStandaloneGuardianReportsRepairedHookToAuditSocket(t *testing.T) {
	previousFactory := guardianAuditClientFactory
	guardianAuditClientFactory = func(_ time.Duration, socket string, _ int) (*http.Client, error) {
		return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}}, nil
	}
	t.Cleanup(func() { guardianAuditClientFactory = previousFactory })
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	home := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "opencode"})
	f.writeLedger(t, protectedRow("alice", home, "opencode"))
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{
		enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "opencode"}): {
			UID: uid, Home: home, LockUpdatedAt: "lock", EntryUpdatedAt: "entry",
		},
	})
	enterpriseHookWorkerRunner = func(_ context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{
				Index: target.Index, OK: true, Repaired: true,
				Result: &enterprisehooks.InstallResult{
					Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome,
					HookContractLockUpdatedAt: "lock", HookContractEntryUpdatedAt: "entry",
				},
			})
		}
		return response, nil
	}
	socketDir, err := os.MkdirTemp("/tmp", "guard-audit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "audit.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	requests := make(chan struct {
		path, user, connector string
		uid                   int
	}, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report struct {
			User, Connector string
			UID             int
		}
		_ = json.NewDecoder(r.Body).Decode(&report)
		requests <- struct {
			path, user, connector string
			uid                   int
		}{r.URL.Path, report.User, report.Connector, report.UID}
		w.WriteHeader(http.StatusNoContent)
	})}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	enterpriseHookStandaloneHookTransport = func() (string, int, error) { return socket, 995, nil }
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if run.Repairs != 1 {
		t.Fatalf("repairs=%d, want one", run.Repairs)
	}
	select {
	case got := <-requests:
		if got.path != "/api/v1/managed/guardian-repair" || got.user != "alice" || got.uid != uid || got.connector != "opencode" {
			t.Fatalf("audit report = %+v", got)
		}
	default:
		t.Fatal("guardian repaired the hook without reporting an audit event")
	}
}
