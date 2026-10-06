// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// GAP-1144: an administrator had no command to read the AI Discovery
// inventory of a managed host; it was only in root-only JSON.
func TestEnterpriseDiscoveryListsEachAccountsInventory(t *testing.T) {
	previous := enterpriseDiscoveryReadRecord
	t.Cleanup(func() { enterpriseDiscoveryReadRecord = previous })
	stubEnterpriseDiscoveryRuntime(t, nil, errors.New("stub"))
	enterpriseDiscoveryReadRecord = func(path string) (inventory.UserScanRecord, error) {
		var record inventory.UserScanRecord
		data, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(data, &record)
		}
		return record, err
	}
	dir := t.TempDir()
	scanned := time.Date(2026, 10, 2, 6, 0, 0, 0, time.UTC)
	for uid, signals := range map[int][]inventory.AISignal{
		501: {
			{Name: "dccert-mcp", Category: "mcp_server", SupportedConnector: "claudecode", State: "active", Basenames: []string{".claude.json"}, LastSeen: scanned},
			{Name: "dccert-skill", Category: "skill", State: "new", LastSeen: scanned},
		},
		502: {{Name: "Codex CLI", Category: "agent_cli", SupportedConnector: "codex", State: "active", LastSeen: scanned}},
	} {
		user := map[int]string{501: "dcm-std1", 502: "dcm-std2"}[uid]
		record := inventory.UserScanRecord{Version: 1, UID: uid, User: user, UpdatedAt: scanned,
			Report: inventory.AIDiscoveryReport{Summary: inventory.AIDiscoverySummary{Result: "ok"}, Signals: signals}}
		data, _ := json.Marshal(record)
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(user)+".tmp"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, map[int]string{501: "501.json", 502: "502.json"}[uid]), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, inventory.UserScanPassName), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var summary bytes.Buffer
	if err := writeEnterpriseDiscovery(&summary, dir, "", false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dcm-std1 (uid 501): scanned 2026-10-02T06:00:00Z, result ok, 2 signal(s)", "mcp_server 1, skill 1", "dcm-std2 (uid 502)", "agent_cli 1"} {
		if !strings.Contains(summary.String(), want) {
			t.Fatalf("summary lacks %q:\n%s", want, summary.String())
		}
	}

	var one bytes.Buffer
	if err := writeEnterpriseDiscovery(&one, dir, "dcm-std1", false); err != nil {
		t.Fatal(err)
	}
	if got := one.String(); !strings.Contains(got, "dccert-mcp") || !strings.Contains(got, ".claude.json") || strings.Contains(got, "dcm-std2") {
		t.Fatalf("--user dcm-std1 output:\n%s", got)
	}

	var asJSON bytes.Buffer
	if err := writeEnterpriseDiscovery(&asJSON, dir, "502", true); err != nil {
		t.Fatal(err)
	}
	var report enterpriseDiscoveryReport
	if err := json.Unmarshal(asJSON.Bytes(), &report); err != nil || len(report.Accounts) != 1 || report.Accounts[0].Signals[0].Name != "Codex CLI" {
		t.Fatalf("--json --user 502 = %s (%v)", asJSON.String(), err)
	}

	if err := writeEnterpriseDiscovery(&bytes.Buffer{}, dir, "nobody", false); err == nil || !strings.Contains(err.Error(), `no AI Discovery record for account "nobody"`) {
		t.Fatalf("an unknown account = %v", err)
	}
	var empty bytes.Buffer
	if err := writeEnterpriseDiscovery(&empty, filepath.Join(dir, "missing"), "", false); err != nil || !strings.Contains(empty.String(), "no records yet") {
		t.Fatalf("a missing spool = %v:\n%s", err, empty.String())
	}
}

func stubEnterpriseDiscoveryRuntime(t *testing.T, view *enterpriseRuntimeView, err error) {
	t.Helper()
	previous := enterpriseDiscoveryRuntime
	t.Cleanup(func() { enterpriseDiscoveryRuntime = previous })
	enterpriseDiscoveryRuntime = func() (*enterpriseRuntimeView, error) { return view, err }
}

// GAP-1144: the admin view also shows runtime discovery (plane state, last
// poll, findings), which was only behind the gateway API's token.
func TestEnterpriseDiscoveryShowsRuntimePlanes(t *testing.T) {
	stubEnterpriseDiscoveryRuntime(t, &enterpriseRuntimeView{
		Gateway: "127.0.0.1:18970", Enabled: true, ScannedAt: "2026-10-02T20:00:00Z", Degraded: true,
		Planes: []enterpriseRuntimePlane{
			{Plane: "a", Name: "inference heartbeat", Available: true, Running: true, Mechanism: "ps(1)"},
			{Plane: "b", Name: "shadow egress", Available: true, Running: true, Mechanism: "lsof(8)", Reason: "dns capture is off"},
			{Plane: "c", Name: "agent actions", Available: false, Reason: "Endpoint Security needs Full Disk Access"},
		},
		Findings: []enterpriseRuntimeFinding{
			{PID: 41, Process: "node", User: "dcm-std1", AgentName: "Claude Code", Score: 70, Severity: "high"},
			{PID: 42, Process: "python3", User: "dcm-std2", Score: 40, Severity: "medium"},
		},
	}, nil)
	var out bytes.Buffer
	if err := writeEnterpriseDiscovery(&out, filepath.Join(t.TempDir(), "missing"), "", false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Runtime discovery (gateway 127.0.0.1:18970): degraded, last poll 2026-10-02T20:00:00Z, 2 finding(s)",
		"inference heartbeat: running via ps(1)",
		"shadow egress: partial, running via lsof(8) -- dns capture is off",
		"agent actions: unavailable -- Endpoint Security needs Full Disk Access",
		"Claude Code",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
	var asJSON bytes.Buffer
	if err := writeEnterpriseDiscovery(&asJSON, filepath.Join(t.TempDir(), "missing"), "", true); err != nil {
		t.Fatal(err)
	}
	var report enterpriseDiscoveryReport
	if err := json.Unmarshal(asJSON.Bytes(), &report); err != nil || report.Runtime == nil || len(report.Runtime.Planes) != 3 {
		t.Fatalf("--json runtime = %s (%v)", asJSON.String(), err)
	}

	stubEnterpriseDiscoveryRuntime(t, nil, errors.New("the gateway at 127.0.0.1:18970 did not answer"))
	var down bytes.Buffer
	if err := writeEnterpriseDiscovery(&down, filepath.Join(t.TempDir(), "missing"), "", false); err != nil ||
		!strings.Contains(down.String(), "Runtime discovery: not read: the gateway at 127.0.0.1:18970 did not answer") {
		t.Fatalf("gateway down = %v:\n%s", err, down.String())
	}
}

// GAP-1144: root's discovery view read root's own ~/.defenseclaw/config.yaml
// and never reached the managed gateway. The runtime read now pins the
// managed deployment's config first; this runs the real fetch against a
// gateway that only the pinned config and token reach.
func TestEnterpriseDiscoveryRuntimeReadsTheManagedDeployment(t *testing.T) {
	const token = "dc-test-discovery-token"
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ai-usage/runtime" || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"enabled":true,"scanned_at":"2026-10-02T23:00:00Z","planes":[{"plane":"a","name":"inference heartbeat","available":true,"running":true,"mechanism":"ps(1)"}],"findings":[]}`))
	}))
	t.Cleanup(gateway.Close)
	_, port, _ := net.SplitHostPort(gateway.Listener.Addr().String())

	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	raw := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_bind: 127.0.0.1\n  api_port: %s\n", filepath.ToSlash(dataDir), port)
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DEFENSECLAW_CONFIG", "")
	t.Setenv("DEFENSECLAW_HOME", "")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	previousCfg, previousPin := cfg, enterpriseDiscoveryPinManagedEnv
	t.Cleanup(func() { cfg, enterpriseDiscoveryPinManagedEnv = previousCfg, previousPin })
	pinned := false
	enterpriseDiscoveryPinManagedEnv = func() error {
		pinned = true
		_ = os.Setenv("DEFENSECLAW_CONFIG", configPath)
		return os.Setenv("DEFENSECLAW_HOME", dataDir)
	}

	view, err := fetchEnterpriseDiscoveryRuntime()
	if err != nil || !pinned {
		t.Fatalf("runtime fetch = %v (pinned %v)", err, pinned)
	}
	if view.Gateway != "127.0.0.1:"+port || !view.Enabled || len(view.Planes) != 1 || view.Planes[0].Mechanism != "ps(1)" {
		t.Fatalf("runtime view = %+v", view)
	}
}

// GAP-1964: managed Windows had no `enterprise windows discovery`. The
// gateway service scans every profile there, so the view groups its own
// report by the account each signal was found in.
func TestWindowsEnterpriseDiscoveryGroupsTheGatewayReportByAccount(t *testing.T) {
	stubEnterpriseDiscoveryRuntime(t, nil, errors.New("stub"))
	previous := enterpriseDiscoveryGatewayReport
	t.Cleanup(func() { enterpriseDiscoveryGatewayReport = previous })
	scanned := time.Date(2026, 10, 2, 22, 0, 0, 0, time.UTC)
	enterpriseDiscoveryGatewayReport = func() (enterpriseGatewayAIUsage, string, error) {
		return enterpriseGatewayAIUsage{Enabled: true, Summary: inventory.AIDiscoverySummary{ScannedAt: scanned, Result: "ok"}, Signals: []inventory.AISignal{
			{Name: "Amp", Category: "supported_connector", SupportedConnector: "amp", Detector: "config", UserName: "dcw-std2", UserID: "S-1-5-21-2", LastSeen: scanned},
			{Name: "Cursor", Category: "mcp_server", SupportedConnector: "cursor", UserName: `DCLAB\dcw-std1`, UserID: "S-1-5-21-1", LastSeen: scanned,
				Basenames: []string{"dccert-mcp", "mcp.json"}, Evidence: []inventory.AIEvidence{
					{Type: "mcp", Basename: "mcp.json"}, {Type: "mcp_server", Basename: "dccert-mcp"}}},
			// GAP-2337: a config file that declares no server is no MCP server.
			{Name: "Antigravity", Category: "mcp_server", SupportedConnector: "antigravity", UserName: `DCLAB\dcw-std1`, UserID: "S-1-5-21-1", LastSeen: scanned,
				Basenames: []string{"mcp_config.json"}, Evidence: []inventory.AIEvidence{{Type: "mcp", Basename: "mcp_config.json"}}},
			{Name: "Hermes Agent", Category: "skill", SupportedConnector: "hermes", UserName: `DCLAB\dcw-std1`, UserID: "S-1-5-21-1", LastSeen: scanned,
				Basenames: []string{"skills"}, Evidence: []inventory.AIEvidence{{Type: "skill", Basename: "skills"}},
				Partial: true, CoverageReason: "read_error"},
			{Name: "dccert-skill", Category: "skill", UserName: `DCLAB\dcw-std1`, UserID: "S-1-5-21-1", LastSeen: scanned,
				Basenames: []string{"skills", "ewr6-hello2"}, Evidence: []inventory.AIEvidence{
					{Type: "skill", Basename: "skills"}, {Type: "skill_entry", Basename: "ewr6-hello2"}}},
			{Name: "Ollama", Category: "local_ai_app", LastSeen: scanned},
		}}, "127.0.0.1:18970", nil
	}

	var summary bytes.Buffer
	if err := writeWindowsEnterpriseDiscovery(&summary, "", false); err != nil {
		t.Fatal(err)
	}
	got := summary.String()
	for _, want := range []string{
		"AI Discovery inventory from the gateway's scan of each user profile (gateway 127.0.0.1:18970)",
		"dcw-std1: scanned 2026-10-02T22:00:00Z, result ok, 3 signal(s)", "mcp_server 1, skill 2",
		"dcw-std2: scanned", "supported_connector 1", "machine-wide (no account): scanned",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary lacks %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "dcw-std1") > strings.Index(got, "dcw-std2") {
		t.Fatalf("accounts are not sorted:\n%s", got)
	}

	var one bytes.Buffer
	if err := writeWindowsEnterpriseDiscovery(&one, "DCW-STD1", false); err != nil {
		t.Fatal(err)
	}
	if got := one.String(); !strings.Contains(got, "dccert-mcp") || strings.Contains(got, "Amp") {
		t.Fatalf("--user dcw-std1 output:\n%s", got)
	}
	// GAP-2263: a skill row names the skills, not the skills folder itself.
	if got := one.String(); !strings.Contains(got, "  ewr6-hello2\n") || strings.Contains(got, "skills,") {
		t.Fatalf("--user dcw-std1 skill row:\n%s", got)
	}
	// GAP-2337: an MCP row names its servers, not the config file; a
	// partial scan says so.
	if got := one.String(); !strings.Contains(got, "  dccert-mcp\n") || strings.Contains(got, "mcp.json") ||
		strings.Contains(got, "Antigravity") || !strings.Contains(got, "  skills (partial: read_error)\n") {
		t.Fatalf("--user dcw-std1 MCP and partial rows:\n%s", got)
	}
	var oneJSON bytes.Buffer
	if err := writeWindowsEnterpriseDiscovery(&oneJSON, "dcw-std1", true); err != nil {
		t.Fatal(err)
	}
	var shaped enterpriseDiscoveryReport
	if err := json.Unmarshal(oneJSON.Bytes(), &shaped); err != nil || len(shaped.Accounts) != 1 || len(shaped.Accounts[0].Signals) != 3 {
		t.Fatalf("--json --user dcw-std1 = %s (%v)", oneJSON.String(), err)
	}
	for _, signal := range shaped.Accounts[0].Signals {
		if signal.Category != "skill" || signal.Partial {
			continue
		}
		if strings.Join(signal.Basenames, ",") != "ewr6-hello2" {
			t.Fatalf("--json skill basenames = %v", signal.Basenames)
		}
	}

	var asJSON bytes.Buffer
	if err := writeWindowsEnterpriseDiscovery(&asJSON, "S-1-5-21-2", true); err != nil {
		t.Fatal(err)
	}
	var report enterpriseDiscoveryReport
	if err := json.Unmarshal(asJSON.Bytes(), &report); err != nil || len(report.Accounts) != 1 ||
		report.Accounts[0].SID != "S-1-5-21-2" || report.Accounts[0].UID != nil || report.Gateway != "127.0.0.1:18970" {
		t.Fatalf("--json --user <sid> = %s (%v)", asJSON.String(), err)
	}

	// GAP-0079: the bare name selects the DOMAIN\name rows above; an
	// unknown account says what the scan did find.
	if err := writeWindowsEnterpriseDiscovery(&bytes.Buffer{}, "nobody", false); err == nil || !strings.Contains(err.Error(), "found signals for 2 other account(s)") {
		t.Fatalf("an unknown account = %v", err)
	}

	// GAP-2114: a standard account's --json refusal is JSON on stdout too.
	enterpriseDiscoveryGatewayReport = func() (enterpriseGatewayAIUsage, string, error) {
		return enterpriseGatewayAIUsage{}, "", withExitCode(errors.New("elevation_required: ask your administrator"), 5)
	}
	var refused bytes.Buffer
	err := writeWindowsEnterpriseDiscovery(&refused, "", true)
	var refusal struct {
		OK       bool                       `json:"ok"`
		Errors   []enterprisestatus.Message `json:"errors"`
		ExitCode int                        `json:"exit_code"`
	}
	if commandExitCode(err) != 5 || json.Unmarshal(refused.Bytes(), &refusal) != nil || refusal.OK || refusal.ExitCode != 5 ||
		len(refusal.Errors) != 1 || refusal.Errors[0].Code != "elevation_required" || refusal.Errors[0].Message != "ask your administrator" {
		t.Fatalf("--json refusal = %q (%v)", refused.String(), err)
	}
}
