//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookruntime

import (
	"errors"
	"testing"
)

// GAP-2149: the launcher path is resolved once per hook word by the ownership
// checks; the Known Folder lookup behind it runs once per process.
func TestGAP2149CurrentUserPathsLooksUpTheKnownFolderOnce(t *testing.T) {
	previous := lookupLocalAppData
	localAppDataMu.Lock()
	saved := localAppData
	localAppData = ""
	localAppDataMu.Unlock()
	t.Cleanup(func() {
		lookupLocalAppData = previous
		localAppDataMu.Lock()
		localAppData = saved
		localAppDataMu.Unlock()
	})
	lookups := 0
	fail := true
	lookupLocalAppData = func() (string, error) {
		lookups++
		if fail {
			return "", errors.New("known folder unavailable")
		}
		return `C:\Users\u\AppData\Local`, nil
	}
	if _, err := CurrentUserPaths(); err == nil {
		t.Fatal("a failed lookup must fail")
	}
	fail = false
	var first Paths
	for i := 0; i < 100; i++ {
		paths, err := CurrentUserPaths()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = paths
		} else if paths != first {
			t.Fatalf("paths changed: %+v vs %+v", paths, first)
		}
	}
	if lookups != 2 {
		t.Fatalf("the Known Folder was looked up %d times, want 2 (a failure is not kept, a success is)", lookups)
	}
	if first.Launcher != `C:\Users\u\AppData\Local\DefenseClaw\HookRuntime\`+LauncherName {
		t.Fatalf("launcher = %q", first.Launcher)
	}
}
