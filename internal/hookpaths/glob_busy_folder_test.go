// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// errorPrivilegeNotHeld is Windows ERROR_PRIVILEGE_NOT_HELD (1314): a file
// symbolic link needs SeCreateSymbolicLinkPrivilege, which a standard user
// does not hold unless Developer Mode is on.
const errorPrivilegeNotHeld = syscall.Errno(1314)

// A folder of more than actionGlobMaxNames names (/tmp, a build cache) is read
// whole: a pattern in it that names no key is an ordinary glob, a pattern that
// selects an alias of the key still decides (rel-1-0-10:GAP-0018).
func TestGlobInBusyFolderIsExpanded(t *testing.T) {
	_, home, cwd := globFactsFixture(t, false)
	busy := filepath.Join(cwd, "busy")
	if err := os.MkdirAll(busy, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < actionGlobMaxNames+904; i++ {
		if err := os.WriteFile(filepath.Join(busy, fmt.Sprintf("f%05d.dat", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		`cp payload busy/zz9*.log`,
		`rm -f busy/f0001*.dat`,
		`echo busy/x*.log; pgrep -fa go`,
		`cd busy && cp payload ./q*.txt`,
	} {
		if got := posixShellDecision(command, cwd, home); got != "" {
			t.Errorf("%s: decision = %q, want allow", command, got)
		}
	}
	// The alias sorts anywhere in the folder's order; the pattern finds it.
	var aliased []string
	key := filepath.Join(home, ".ssh", "authorized_keys")
	switch err := os.Symlink(key, filepath.Join(busy, "zzkey.lnk")); {
	case err == nil:
		aliased = append(aliased, `cp payload busy/zz*.lnk`, `cd busy && cp payload zzkey.l*`)
	case runtime.GOOS == "windows" && errors.Is(err, errorPrivilegeNotHeld):
		t.Logf("no file symlink for this user (%v); the junction alias below still runs", err)
	default:
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// A directory junction needs no privilege, so a standard user can
		// place this alias of the key folder in a busy folder too.
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(busy, "zzkeys.lnk"), filepath.Join(home, ".ssh")).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v %s", err, out)
		}
		aliased = append(aliased, `cp payload busy/zz*.lnk/authorized_keys`, `cd busy && cp payload zzkeys.l*/authorized_keys`)
	}
	for _, command := range aliased {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%s: decision = %q, want protected-target", command, got)
		}
	}
}
