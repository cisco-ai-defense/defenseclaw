// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os/exec"
	"testing"
)

func createTestDirectoryRedirect(t *testing.T, link, target string) {
	t.Helper()
	// Directory junctions need neither Developer Mode nor
	// SeCreateSymbolicLinkPrivilege and exercise the same reparse-point trust
	// boundary on end-user systems and hosted CI.
	if output, err := exec.Command(
		"cmd.exe", "/D", "/C", "mklink", "/J", link, target,
	).CombinedOutput(); err != nil {
		t.Fatalf("create directory junction fixture: %v\n%s", err, output)
	}
}
