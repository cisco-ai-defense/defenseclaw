// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// hermeticAccountHome points the two homes a late call reads, $HOME and the
// account database home (hookpaths.AccountHomeDir), at one empty scratch
// folder for the test. The late-call scan indexes the protected and state
// files of both; on a shared box the real account home held about 9,000
// entries in .defenseclaw, and walking them under load pushed the ordinary
// hard link rows of TestLateOrdinaryCallProtectedReach past their answer
// budget (substrate-1:GAP-0277).
func hermeticAccountHome(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "account")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	restore := hookpaths.AccountHomeDir
	hookpaths.AccountHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { hookpaths.AccountHomeDir = restore })
	return home
}
