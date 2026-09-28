// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winfolders"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// For the process user, the commands built from explicit Known Folders are
// the ones per-user teardown builds from that user's Known Folder lookups.
func TestCursorNativeHookCommandsInUserFoldersMatchPerUserTeardown(t *testing.T) {
	localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		t.Fatal(err)
	}
	programs, err := winfolders.UserProgramFiles()
	if err != nil {
		t.Fatal(err)
	}
	commands := cursorNativeHookCommandsInUserFolders(localAppData, programs)
	if len(commands) != 3 {
		t.Fatalf("commands = %v, want three", commands)
	}
	teardown := make(map[string]struct{})
	for _, command := range legacyCursorNativeHookCommands() {
		teardown[command] = struct{}{}
	}
	for _, command := range commands {
		if _, ok := teardown[command]; !ok {
			t.Fatalf("command %q is not one per-user teardown removes (%v)", command, legacyCursorNativeHookCommands())
		}
	}
}
