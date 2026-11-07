//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// A watch event that cancels the pass while the first audit report is served
// must not drop the report of a second element the pass already restored.
func TestCompletedPassAuditsEveryRestoredElementWhenTheWatchCancelsIt(t *testing.T) {
	passCtx, cancelPass := context.WithCancel(context.Background())
	defer cancelPass()
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
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "alice", Connector: "hermes"})
	f.writeLedger(t, protectedRow("alice", home, "hermes"))
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{
		enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "hermes"}): {
			UID: uid, Home: home, LockUpdatedAt: "lock", EntryUpdatedAt: "entry",
		},
	})
	enterpriseHookWorkerRunner = func(_ context.Context, _ enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{
				Index: target.Index, OK: true, Repaired: true,
				RestoredElements: []string{"hook runtime file hermes-hook.sh", "hook runtime file _hardening.sh"},
				Result: &enterprisehooks.InstallResult{
					Connector: target.Options.ConnectorName, UserHome: target.Options.UserHome,
					HookContractLockUpdatedAt: "lock", HookContractEntryUpdatedAt: "entry",
				},
			})
		}
		return response, nil
	}
	socket := filepath.Join(shortSocketDir(t), "audit.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu       sync.Mutex
		elements []string
	)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report struct{ Element string }
		_ = json.NewDecoder(r.Body).Decode(&report)
		mu.Lock()
		elements = append(elements, report.Element)
		mu.Unlock()
		cancelPass() // another filesystem event arrives while the first row is served
		w.WriteHeader(http.StatusNoContent)
	})}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	enterpriseHookStandaloneHookTransport = func() (string, int, error) { return socket, 995, nil }
	run, err := runEnterpriseHookReconcileOnce(passCtx)
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if run.Repairs != 2 {
		t.Fatalf("repairs=%d, want two", run.Repairs)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"hook runtime file hermes-hook.sh", "hook runtime file _hardening.sh"}
	if strings.Join(elements, "|") != strings.Join(want, "|") {
		t.Fatalf("audit rows = %q, want %q", elements, want)
	}
}

// Both senders report what the guardian already did, so a canceled pass
// context sends every report, and each report has its own bound.
func TestGuardianAuditSendersIgnoreCancelOfThePassAndKeepTheirOwnBound(t *testing.T) {
	previousTransport, previousFactory := enterpriseHookStandaloneHookTransport, guardianAuditClientFactory
	t.Cleanup(func() {
		enterpriseHookStandaloneHookTransport, guardianAuditClientFactory = previousTransport, previousFactory
	})
	const socket = "/run/defenseclaw-hook/hook.sock"
	enterpriseHookStandaloneHookTransport = func() (string, int, error) { return socket, 995, nil }
	var paths []string
	var bounded bool
	guardianAuditClientFactory = func(_ time.Duration, _ string, _ int) (*http.Client, error) {
		return &http.Client{Transport: g693AuditTransport(func(request *http.Request) (*http.Response, error) {
			if err := request.Context().Err(); err != nil {
				t.Errorf("audit request to %s runs on a canceled context: %v", request.URL.Path, err)
			}
			if deadline, ok := request.Context().Deadline(); ok && time.Until(deadline) <= guardianAuditReportTimeout {
				bounded = true
			}
			paths = append(paths, request.URL.Path)
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
		})}, nil
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	reportEnterpriseHookGuardianRepairs(canceled, socket, []enterpriseHookGuardianAuditReport{
		{User: "alice", UID: 501, Connector: "hermes", Element: "hook runtime file hermes-hook.sh"},
		{User: "alice", UID: 501, Connector: "hermes", Element: "hook runtime file _hardening.sh"},
	})
	reportEnterpriseHookGuardianRemoved(canceled, socket, []enterpriseHookReconcileRow{
		{User: "removed", UID: 508, Connector: "hermes", Removed: true},
	})
	want := []string{enterpriseHookGuardianRepairAuditPath, enterpriseHookGuardianRepairAuditPath, enterpriseHookGuardianRemovedAuditPath}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("audit requests = %q, want %q", paths, want)
	}
	if !bounded {
		t.Fatal("audit reports carry no deadline of their own")
	}
}
