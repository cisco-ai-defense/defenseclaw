// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// windowsLifecycleExitCodes is every exit_code a Windows lifecycle result
// carries: success, the codes windowsEnterpriseFailureCodeFor returns
// (elevation_required 5, failure 1603, busy 1618, invalid arguments 1639)
// and the reserved reboot code.
var windowsLifecycleExitCodes = []int{
	enterprisestatus.ExitOK,
	enterprisestatus.WindowsExitAccessDenied,
	enterprisestatus.WindowsExitFailure,
	enterprisestatus.WindowsExitBusy,
	enterprisestatus.WindowsExitInvalidArgs,
	enterprisestatus.WindowsExitReboot,
}

// The published lifecycle result schema allows exactly the Windows exit
// codes the lifecycle emits: a standard account's status or verify is
// elevation_required with exit 5, which the schema refused before
// management_contract 1.
func TestLifecycleSchemaWindowsExitCodesMatchTheLifecycle(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/mdm/contract/lifecycle-result.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		AllOf []struct {
			If struct {
				Properties struct {
					Platform struct {
						Const string `json:"const"`
					} `json:"platform"`
				} `json:"properties"`
			} `json:"if"`
			Then struct {
				Properties struct {
					ExitCode struct {
						Enum []int `json:"enum"`
					} `json:"exit_code"`
				} `json:"properties"`
			} `json:"then"`
		} `json:"allOf"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var allowed []int
	for _, clause := range schema.AllOf {
		// Other Windows clauses (the connectors rule) carry no exit codes.
		if clause.If.Properties.Platform.Const == "windows" && len(clause.Then.Properties.ExitCode.Enum) > 0 {
			allowed = clause.Then.Properties.ExitCode.Enum
		}
	}
	got, want := slices.Sorted(slices.Values(allowed)), slices.Sorted(slices.Values(windowsLifecycleExitCodes))
	if !slices.Equal(got, want) {
		t.Fatalf("lifecycle-result.schema.json allows Windows exit codes %v; the lifecycle emits %v", got, want)
	}
}
