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
