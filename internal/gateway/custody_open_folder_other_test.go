// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"testing"
)

// custodyFolderRepairCommand is the command a custody refusal of an open
// folder prints.
const custodyFolderRepairCommand = "chmod go-w"

// openFolderToOtherAccounts lets every account write dir (mode 0757) and
// returns the call that makes it private again.
func openFolderToOtherAccounts(t *testing.T, dir string) (closeFolder func()) {
	t.Helper()
	if err := os.Chmod(dir, 0o757); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}
