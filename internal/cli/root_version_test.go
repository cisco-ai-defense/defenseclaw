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
	// The management agent contract version is the only capability signal:
	// every build that prints it has the whole contract, so there is no
	// features list to read.
	var members map[string]any
	if err := json.Unmarshal(output.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	if members["management_contract"] != float64(1) || members["features"] != nil {
		t.Fatalf("machine version report members = %v", members)
	}
	// GAP-0335: the MDM wrappers pass secret set --bundle only to a build
	// that reports it.
	if members["secret_set_bundle"] != true {
		t.Fatalf("secret_set_bundle = %v, want true", members["secret_set_bundle"])
	}
}
