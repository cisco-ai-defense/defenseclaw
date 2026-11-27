//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winfolders

import (
	"errors"
	"testing"
)

// GAP-2149: UserProgramFiles asks the shell once per process; a failure is
// asked again.
func TestGAP2149UserProgramFilesIsResolvedOnce(t *testing.T) {
	previous := resolveUserProgramFiles
	userProgramFilesMu.Lock()
	saved := userProgramFilesPath
	userProgramFilesPath = ""
	userProgramFilesMu.Unlock()
	t.Cleanup(func() {
		resolveUserProgramFiles = previous
		userProgramFilesMu.Lock()
		userProgramFilesPath = saved
		userProgramFilesMu.Unlock()
	})
	lookups := 0
	fail := true
	resolveUserProgramFiles = func() (string, error) {
		lookups++
		if fail {
			return "", errors.New("unavailable")
		}
		return `C:\Users\u\AppData\Local\Programs`, nil
	}
	if _, err := UserProgramFiles(); err == nil {
		t.Fatal("a failed lookup must fail")
	}
	fail = false
	for i := 0; i < 50; i++ {
		got, err := UserProgramFiles()
		if err != nil || got != `C:\Users\u\AppData\Local\Programs` {
			t.Fatalf("got %q err %v", got, err)
		}
	}
	if lookups != 2 {
		t.Fatalf("resolved %d times, want 2", lookups)
	}
}
