// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteMachineVersion(t *testing.T) {
	originalVersion, originalCommit, originalDate := appVersion, appCommit, appBuildDate
	t.Cleanup(func() {
		appVersion, appCommit, appBuildDate = originalVersion, originalCommit, originalDate
	})
	appVersion = "1.2.3-rc.1"
	appCommit = "0123456789abcdef"
	appBuildDate = "2026-07-13T00:00:00Z"

	var output bytes.Buffer
	if err := writeMachineVersion(&output); err != nil {
		t.Fatal(err)
	}
	var report machineVersionReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.Name != "defenseclaw-gateway" ||
		report.Version != appVersion || report.Commit != appCommit || report.Built != appBuildDate {
		t.Fatalf("machine version report = %+v", report)
	}
}
