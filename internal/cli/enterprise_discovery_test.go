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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
