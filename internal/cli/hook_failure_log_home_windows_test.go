// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Agent runtimes can redirect the inherited USERPROFILE. A managed hook's
// failure rows still go to the invoking user's token-bound profile, on an
// active runtime and on one that failed its checks.
func TestManagedWindowsHookFailureLogIgnoresRedirectedUserProfile(t *testing.T) {
	profile, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_Profile)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(profile, config.DefaultDataDirName)
	redirected := t.TempDir()
	t.Setenv("USERPROFILE", redirected)
	if got := managedHookFailureLogHome(); got != want {
		t.Fatalf("failure log home = %q, want the token profile's %q", got, want)
	}
	_, _ = stageTrustedNativeHookForTest(t, "open")
	userRuntime := filepath.Join(t.TempDir(), ".defenseclaw")
	for name, resolveErr := range map[string]error{"active": nil, "failed": errors.New("tampered managed ownership state")} {
		t.Run(name, func(t *testing.T) {
			stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
				return enterprisehooks.WindowsManagedHookRuntime{
					Connector:          "claudecode",
					DataDir:            userRuntime,
					PolicyActive:       true,
					Registered:         true,
					GatewayAddr:        "127.0.0.1:18977",
					GatewayServiceName: "DefenseClawGateway",
					ScopedToken:        "authenticated-generation-token",
					GenerationID:       "0123456789abcdef0123456789abcdef",
				}, resolveErr
			})
			_ = prepareEnterpriseManagedHookRuntime("claudecode")
			opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "open", true)
			if opts.FailureLogHome == nil {
				t.Fatal("managed hook options carry no failure log home")
			}
			if got := opts.FailureLogHome(); got != want || strings.HasPrefix(strings.ToLower(got), strings.ToLower(redirected)) {
				t.Fatalf("failure log home = %q, want %q (USERPROFILE redirected to %q)", got, want, redirected)
			}
		})
	}
}
