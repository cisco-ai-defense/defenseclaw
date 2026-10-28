//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestStandaloneForeignCleanupReportsOnlyRestoredCopilotLocalHookFile(t *testing.T) {
	previousFactory := guardianAuditClientFactory
	guardianAuditClientFactory = func(_ time.Duration, socket string, _ int) (*http.Client, error) {
		return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}}, nil
	}
	t.Cleanup(func() { guardianAuditClientFactory = previousFactory })
	previousCfg, previousManifest := cfg, enterpriseHookManifest
	previousLoad, previousCheck, previousRunner := enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner
	previousLoadRecord, previousWriteRecord := enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = previousCfg, previousManifest
		enterpriseHookLoadEligibleAccounts, enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousLoad, previousCheck, previousRunner
		enterpriseHookLoadCopilotVSCodeAccounts, enterpriseHookWriteCopilotVSCodeAccounts = previousLoadRecord, previousWriteRecord
		enterpriseHookForeignCleanupState.Lock()
		enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
		enterpriseHookForeignCleanupState.unrepaired = nil
		enterpriseHookForeignCleanupState.Unlock()
	})
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg = &config.Config{
		DataDir:        filepath.Join(root, "data"),
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile:       managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{"copilot": {}}},
		},
	}
	useStandaloneForeignHookFenceFixture(t)
	enterpriseHookManifest = filepath.Join(root, "targets.yaml")
	enterpriseHookForeignCleanupState.Lock()
	enterpriseHookForeignCleanupState.last, enterpriseHookForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookForeignCleanupState.unrepaired = nil
	enterpriseHookForeignCleanupState.Unlock()
	account := enterprisehooks.UnixEligibleAccount{User: "alice", UID: 4242, GID: 4242, Home: home}
	enterpriseHookLoadEligibleAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return []enterprisehooks.UnixEligibleAccount{account}, nil
	}
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	var recorded []enterprisehooks.UnixEligibleAccount
	enterpriseHookLoadCopilotVSCodeAccounts = func(string) ([]enterprisehooks.UnixEligibleAccount, error) {
		return append([]enterprisehooks.UnixEligibleAccount(nil), recorded...), nil
	}
	enterpriseHookWriteCopilotVSCodeAccounts = func(_ string, accounts []enterprisehooks.UnixEligibleAccount) error {
		recorded = append([]enterprisehooks.UnixEligibleAccount(nil), accounts...)
		return nil
	}
	duplicateChange := false
	enterpriseHookWorkerRunner = func(_ context.Context, workerAccount enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		request.Home = workerAccount.Home
		report := runEnterpriseHookWorkerCopilotVSCode(request)
		if duplicateChange && report != nil {
			report.Changed = append(report.Changed, report.Changed...)
		}
		return enterpriseHookWorkerResponse{CopilotVSCode: report}, nil
	}
	socketDir, err := os.MkdirTemp("/tmp", "delta4-audit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	listener, err := net.Listen("unix", filepath.Join(socketDir, "audit.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	reports := make(chan enterpriseHookGuardianAuditReport, 4)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != enterpriseHookGuardianRepairAuditPath || r.Method != http.MethodPost {
			t.Errorf("repair request: %s %s", r.Method, r.URL.Path)
		}
		var report enterpriseHookGuardianAuditReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Errorf("decode repair report: %v", err)
		}
		reports <- report
		w.WriteHeader(http.StatusNoContent)
	})}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	socket := listener.Addr().String()
	previousTransport := enterpriseHookStandaloneHookTransport
	enterpriseHookStandaloneHookTransport = func() (string, int, error) { return socket, os.Geteuid(), nil }
	t.Cleanup(func() { enterpriseHookStandaloneHookTransport = previousTransport })
	now := time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC)
	pass := func(at time.Time) {
		t.Helper()
		runEnterpriseHookStandaloneForeignCleanup(context.Background(), &bytes.Buffer{}, at, enterprisehooks.Manifest{}, nil, socket)
	}
	pass(now)
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	if _, err := os.Stat(hookFile); err != nil || len(recorded) != 1 {
		t.Fatalf("first pass did not write and record the hook file: err=%v recorded=%+v", err, recorded)
	}
	if len(reports) != 0 {
		t.Fatal("first write was reported as a repair")
	}
	pass(now.Add(time.Minute))
	if len(reports) != 0 {
		t.Fatal("intact hook file was reported as a repair")
	}
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	duplicateChange = true
	pass(now.Add(2 * time.Minute))
	if _, err := os.Stat(hookFile); err != nil {
		t.Fatalf("deleted hook file was not restored: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("deleted hook file produced %d repair reports, want one", len(reports))
	}
	if report := <-reports; report.User != "alice" || report.UID != 4242 || report.Connector != "copilot" {
		t.Fatalf("repair report = %+v", report)
	}
	pass(now.Add(3 * time.Minute))
	if len(reports) != 0 {
		t.Fatal("intact hook file produced another repair report")
	}
	// A worker changing only a plugin file has not repaired the hook file.
	actualRunner := enterpriseHookWorkerRunner
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		return enterpriseHookWorkerResponse{CopilotVSCode: &enterpriseHookWorkerCopilotVSCodeReport{
			Changed: []string{filepath.Join(home, ".vscode", "extensions", "plugin.json")},
		}}, nil
	}
	pass(now.Add(8 * time.Minute))
	if len(reports) != 0 {
		t.Fatal("plugin-only change was reported as a hook repair")
	}
	enterpriseHookWorkerRunner = actualRunner
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		return enterpriseHookWorkerResponse{CopilotVSCode: &enterpriseHookWorkerCopilotVSCodeReport{
			Changed: []string{hookFile}, Error: "write failed",
		}}, nil
	}
	pass(now.Add(9 * time.Minute))
	if len(reports) != 0 {
		t.Fatal("failed rewrite was reported as a repair")
	}
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		return enterpriseHookWorkerResponse{CopilotVSCode: &enterpriseHookWorkerCopilotVSCodeReport{
			Removed: []string{hookFile},
		}}, nil
	}
	pass(now.Add(15 * time.Minute))
	if len(reports) != 0 {
		t.Fatal("removal was reported as a repair")
	}
}
