// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// rel-1-0-6 GAP-0184: on an AD-joined Linux host (SSSD, fully qualified
// names) the gateway now names a directory account's process owner as NSS
// does, so its runtime finding carries user@domain. --user lists it by that
// name, by the bare name and by the uid, and never under another account.
func TestEnterpriseDiscoveryListsADirectoryAccountsRuntimeFinding(t *testing.T) {
	const adUID = 94404116
	dir := t.TempDir()
	record := inventory.UserScanRecord{Version: inventory.UserScanRecordVersion, UID: adUID, User: "eng1@corp.example", UpdatedAt: time.Now().UTC(),
		Report: inventory.AIDiscoveryReport{Summary: inventory.AIDiscoverySummary{Result: "ok"}}}
	data, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(dir, "94404116.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	previousIDs, previousName, previousRead := enterpriseDiscoveryAccountIDs, enterpriseDiscoveryUIDName, enterpriseDiscoveryReadRecord
	t.Cleanup(func() {
		enterpriseDiscoveryAccountIDs, enterpriseDiscoveryUIDName, enterpriseDiscoveryReadRecord = previousIDs, previousName, previousRead
	})
	enterpriseDiscoveryAccountIDs = func(user string) []string {
		if user == "eng1@corp.example" {
			return []string{"94404116"}
		}
		return nil
	}
	enterpriseDiscoveryUIDName = func(uid int) string { return map[int]string{adUID: "eng1@corp.example", 1006: "lane-local"}[uid] }
	enterpriseDiscoveryReadRecord = func(path string) (inventory.UserScanRecord, error) {
		var record inventory.UserScanRecord
		data, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(data, &record)
		}
		return record, err
	}
	stubEnterpriseDiscoveryRuntime(t, &enterpriseRuntimeView{Enabled: true, Findings: []enterpriseRuntimeFinding{
		{PID: 51, Process: "python3", User: "eng1@corp.example", Attribution: "process_owner", Score: 40, Severity: "medium"},
		{PID: 52, Process: "python3", User: "lane-local", Attribution: "process_owner", Score: 40, Severity: "medium"},
		{PID: 53, Process: "python3", Attribution: "unattributed", Score: 40, Severity: "medium"},
	}}, nil)
	for _, spelling := range []string{"eng1@corp.example", "94404116", "eng1"} {
		var out bytes.Buffer
		var report enterpriseDiscoveryReport
		if err := writeEnterpriseDiscovery(&out, dir, spelling, true); err != nil || json.Unmarshal(out.Bytes(), &report) != nil {
			t.Fatalf("--user %s = %v:\n%s", spelling, err, out.String())
		}
		if report.Runtime == nil || len(report.Runtime.Findings) != 1 || report.Runtime.Findings[0].PID != 51 {
			t.Fatalf("--user %s runtime = %+v, want only pid 51 of the directory account", spelling, report.Runtime)
		}
	}
}
