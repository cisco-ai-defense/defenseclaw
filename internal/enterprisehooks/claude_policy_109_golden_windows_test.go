//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The 1.0.9 form renders the drop-in the published 1.0.9 Setup wrote, byte
// for byte (testdata: 90-defenseclaw.json from a 1.0.9 standalone install,
// the hook at its default install path, gateway 127.0.0.1:18970, lock on).
func TestGAP1495Guard109FormIsThePublished109DropIn(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	published, err := os.ReadFile(filepath.Join("testdata", "claude-managed-policy-109-standalone.json"))
	if err != nil {
		t.Fatal(err)
	}
	record := windowsClaudeManagedPolicyState{
		HookExecutable: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:    "127.0.0.1:18970",
	}
	for _, contract := range windowsClaudeRecordedPolicyContracts() {
		rendered, err := renderWindowsClaudeRecordedPolicy(record, contract, true, windowsClaudeFormGuard109)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(rendered, published) {
			current, err := renderWindowsClaudeRecordedPolicy(record, contract, true)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(current, published) {
				t.Fatal("the current form is the 1.0.9 drop-in: the fixture tells nothing apart")
			}
			return
		}
	}
	t.Fatal("no recorded contract renders the published 1.0.9 drop-in in the 1.0.9 guard form")
}
