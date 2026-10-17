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

// For the process user, the cleanup matches the handler per-user setup
// writes, and everything it matches is a handler per-user teardown removes.
func TestClaudeCodePerUserHookRegistrationsMatchPerUserSetupAndTeardown(t *testing.T) {
	localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		t.Fatal(err)
	}
	programs, err := winfolders.UserProgramFiles()
	if err != nil {
		t.Fatal(err)
	}
	matcher := newClaudeCodePerUserHookMatcher(append(
		legacyNativeHookBinaries(),
		nativeHookBinariesInUserFolders(localAppData, programs)...,
	))

	for _, launcher := range []string{defenseclawHookBinary(), canonicalNativeWindowsHookBinary()} {
		command, args := claudeCodeHookInvocation(SetupOpts{HookExecutable: launcher}, "")
		handler := map[string]interface{}{"type": "command", "command": command, "args": stringsToInterfaces(args)}
		if _, owned := matcher.owns(handler); !owned {
			t.Fatalf("per-user setup handler %#v is not matched", handler)
		}
	}

	if len(matcher.executables) < 3 {
		t.Fatalf("matched executables = %v, want at least the three in the user's folders", matcher.executables)
	}
	for executable := range matcher.executables {
		for _, handler := range []map[string]interface{}{
			{"type": "command", "command": executable, "args": []interface{}{"hook", "--connector", "claudecode"}},
			{"type": "command", "command": windowsQuoteExe(executable) + " " + nativeHookFlag + "claudecode"},
		} {
			if _, owned := matcher.owns(handler); !owned {
				t.Fatalf("handler %#v is not matched", handler)
			}
			if !isOwnedHookHandler(handler, "") && !hookUsesLegacyClaudeCodeNativeCommand(handler) {
				t.Fatalf("handler %#v is matched but per-user teardown does not remove it", handler)
			}
		}
	}
}

func stringsToInterfaces(values []string) []interface{} {
	out := make([]interface{}, len(values))
	for index, value := range values {
		out[index] = value
	}
	return out
}
