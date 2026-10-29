// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
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

// grantTestUntrustedWriter gives Everyone write access to path. A mode bit
// does not do this on Windows, and the process user may itself be an
// administrator principal, which the trust walk accepts as drift; Everyone
// is a standard-user writer on every runner.
func grantTestUntrustedWriter(t *testing.T, path string) {
	t.Helper()
	setHookAPITokenWindowsUntrustedDACL(t, path, windows.GENERIC_WRITE)
}
