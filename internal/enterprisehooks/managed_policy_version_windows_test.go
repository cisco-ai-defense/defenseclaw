// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "testing"

// The managed gateway's --version-json names the management agent contract
// it implements; the runtime version check accepts that member and still
// refuses any other unknown one.
func TestWindowsClaudeManagedRuntimeVersionReportAcceptsManagementContract(t *testing.T) {
	ok := []byte(`{"schema_version":1,"name":"defenseclaw-gateway","version":"1.2.3","commit":"abc","built":"now","management_contract":1}` + "\n")
	if err := checkWindowsClaudeManagedRuntimeVersionReport(ok, "1.2.3"); err != nil {
		t.Fatalf("report with management_contract: %v", err)
	}
	bundle := []byte(`{"schema_version":1,"name":"defenseclaw-gateway","version":"1.2.3","commit":"abc","built":"now","management_contract":1,"secret_set_bundle":true}` + "\n")
	if err := checkWindowsClaudeManagedRuntimeVersionReport(bundle, "1.2.3"); err != nil {
		t.Fatalf("report with secret_set_bundle: %v", err)
	}
	wrongType := []byte(`{"schema_version":1,"name":"defenseclaw-gateway","version":"1.2.3","secret_set_bundle":"true"}`)
	if err := checkWindowsClaudeManagedRuntimeVersionReport(wrongType, "1.2.3"); err == nil {
		t.Fatal("report with a non-boolean capability was accepted")
	}
	unknown := []byte(`{"schema_version":1,"name":"defenseclaw-gateway","version":"1.2.3","surprise":true}`)
	if err := checkWindowsClaudeManagedRuntimeVersionReport(unknown, "1.2.3"); err == nil {
		t.Fatal("report with an unknown member was accepted")
	}
}
