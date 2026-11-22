// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// rel-1-0-10:GAP-1074 review 1: the bounded regular-file read of the managed
// agent hook config guard asked the share gate and then read the name again
// (safefile). It now reads under the gate's hold: a file moved away after
// the walk and replaced by a link to a share on another machine is refused,
// and the file the walk read is read as before.
func TestReadRegularFileBoundedReadsTheFileTheGateRead(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(base, "remote")
	if err := os.Mkdir(remote, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remote, "file"), []byte("longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreShares := overrideNetworkShares(func(path string) string {
		if path == remote || len(path) > len(remote) && path[:len(remote)+1] == remote+string(filepath.Separator) {
			return `\\g1074-review.invalid\share`
		}
		return ""
	}, func(string) { t.Error("the share on another machine was asked") }, func(string) bool { return false })
	defer restoreShares()
	local := filepath.Join(base, "local")
	if err := os.WriteFile(local, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if body, err := ReadRegularFileBounded(local, 64); err != nil || string(body) != "one" {
		t.Fatalf("control read = %q, %v; want the local file", body, err)
	}
	if err := os.Symlink(filepath.Join(remote, "file"), filepath.Join(base, "probe")); err != nil {
		t.Skip("no symbolic link here:", err)
	}
	forgetPlainFolders()
	swapped := false
	restore := pathidentity.SetPinnedStatHookForTest(func(path string) {
		if path != local || swapped {
			return
		}
		swapped = true
		if err := os.Rename(local, local+".old"); err == nil {
			_ = os.Symlink(filepath.Join(remote, "file"), local)
		}
	})
	body, err := ReadRegularFileBounded(local, 64)
	restore()
	if !swapped {
		t.Fatal("the walk did not read the file")
	}
	if string(body) == "longer" {
		t.Fatalf("the bounded read read the share's file after the gate (err %v)", err)
	}
}
