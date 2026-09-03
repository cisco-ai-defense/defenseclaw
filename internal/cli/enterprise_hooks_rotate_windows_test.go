// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"
)

func TestEnterpriseHookRotationCommandsRefuseWindows(t *testing.T) {
	_, err := executeEnterpriseHookRotationPrepare(enterpriseHookRotationRequest{
		OperationID:  strings.Repeat("1", 32),
		Generation:   strings.Repeat("2", 32),
		Manifest:     `C:\ProgramData\DefenseClaw\targets.yaml`,
		Fingerprints: `C:\ProgramData\DefenseClaw\expected-fingerprints.json`,
	})
	if err == nil || !strings.Contains(err.Error(), "native guardian adapter") {
		t.Fatalf("windows prepare error = %v, want native adapter refusal", err)
	}
}
