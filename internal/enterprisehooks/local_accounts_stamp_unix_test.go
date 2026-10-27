// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-2025: the stamp the guardian read travels in the record's extension,
// so the gateway can compare it with the current one, and a 1.0.3 or 1.0.4
// reader of the first object still decodes the record.
func TestIdentityRecordCarriesTheAccountsStamp(t *testing.T) {
	dir := t.TempDir()
	data, err := MarshalIdentitySpoolRecord(IdentitySpoolRecord{
		Key: "1001", User: "alice", UpdatedAt: time.Now().UTC(), AccountIncarnation: "files",
		LegacyOwnerToken: "home:1:2:3", AccountsStamp: "1/100/7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1001.json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	record, err := ReadIdentitySpoolRecord(dir, "1001", nil)
	if err != nil {
		t.Fatal(err)
	}
	if record.AccountsStamp != "1/100/7" || record.LegacyOwnerToken != "home:1:2:3" {
		t.Fatalf("read back %+v", record)
	}
}
