//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func installedStateFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "runtime")
	authorizationDir := filepath.Join(root, "hook-guardian-state")
	guardianDir := filepath.Join(root, StateDirName)
	for _, dir := range []string{runtimeDir, authorizationDir, guardianDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawCertGateway_ReadinessFixture`)
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authorizationDir)
	return runtimeDir, authorizationDir, PathForStateRoot(guardianDir)
}

func TestPathForDataDirWindowsInstalledGuardianTransitions(t *testing.T) {
	runtimeDir, _, actualState := installedStateFixture(t)
	path := PathForDataDir(runtimeDir)
	if path != actualState {
		t.Fatalf("state path = %q, want installed guardian path %q", path, actualState)
	}
	wrongPath := filepath.Join(runtimeDir, StateDirName, FileName)
	if _, err := os.Stat(wrongPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected runtime state file: %v", err)
	}
	if got := ReadState(path); got != StateUnknown {
		t.Fatalf("missing guardian state = %q", got)
	}
	for _, state := range []string{StateWaitingForTargets, StateReady, StateWaitingForTargets, StateReady} {
		if err := WriteState(actualState, state); err != nil {
			t.Fatal(err)
		}
		if got := ReadState(path); got != state {
			t.Fatalf("guardian transition = %q, want %q", got, state)
		}
	}
	if err := os.Remove(actualState); err != nil {
		t.Fatal(err)
	}
	if got := ReadState(path); got != StateUnknown {
		t.Fatalf("removed guardian state = %q", got)
	}
	if _, err := os.Stat(wrongPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolver created runtime state: %v", err)
	}
}

func TestPathForDataDirWindowsIgnoresRuntimeReadyFile(t *testing.T) {
	runtimeDir, _, actualState := installedStateFixture(t)
	wrongDir := filepath.Join(runtimeDir, StateDirName)
	if err := os.Mkdir(wrongDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(PathForStateRoot(wrongDir), StateReady); err != nil {
		t.Fatal(err)
	}
	path := PathForDataDir(runtimeDir)
	if got := ReadState(path); got != StateUnknown {
		t.Fatalf("runtime ready file influenced missing guardian state: %q", got)
	}
	if err := WriteState(actualState, StateWaitingForTargets); err != nil {
		t.Fatal(err)
	}
	if got := ReadState(path); got != StateWaitingForTargets {
		t.Fatalf("runtime ready file overrode guardian state: %q", got)
	}
}

func TestPathForDataDirWindowsRejectsInvalidInstalledLayout(t *testing.T) {
	runtimeDir, authorizationDir, actualState := installedStateFixture(t)
	if err := WriteState(actualState, StateReady); err != nil {
		t.Fatal(err)
	}
	wrongDir := filepath.Join(runtimeDir, StateDirName)
	if err := os.Mkdir(wrongDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(PathForStateRoot(wrongDir), StateReady); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, dataDir, authDir string }{
		{"missing authorization pin", runtimeDir, ""},
		{"relative authorization pin", runtimeDir, `hook-guardian-state`},
		{"mismatched state root", runtimeDir, filepath.Join(t.TempDir(), "hook-guardian-state")},
		{"wrong authorization leaf", runtimeDir, filepath.Join(filepath.Dir(runtimeDir), "runtime")},
		{"noncanonical authorization pin", runtimeDir, authorizationDir + `\..\hook-guardian-state`},
		{"authorization whitespace", runtimeDir, authorizationDir + " "},
		{"authorization newline", runtimeDir, authorizationDir + "\n"},
		{"runtime NUL", runtimeDir + "\x00", authorizationDir},
		{"relative runtime", "runtime", authorizationDir},
		{"wrong runtime leaf", filepath.Join(filepath.Dir(runtimeDir), "data"), authorizationDir},
		{"runtime whitespace", runtimeDir + " ", authorizationDir},
		{"UNC layout", `\\server\share\root\runtime`, `\\server\share\root\hook-guardian-state`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(managed.HookGuardianAuthorizationDirEnv, tc.authDir)
			if path := PathForDataDir(tc.dataDir); path != "" {
				t.Fatalf("invalid layout returned state path %q", path)
			}
			if got := ReadState(PathForDataDir(tc.dataDir)); got != StateUnknown {
				t.Fatalf("invalid layout reported state %q", got)
			}
		})
	}
}

func TestPathForDataDirWindowsUnpinnedFallback(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(managed.WindowsServiceAccountEnv, "")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, filepath.Join(t.TempDir(), "custom-auth"))
	stateDir := filepath.Join(dataDir, StateDirName)
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(PathForStateRoot(stateDir), StateReady); err != nil {
		t.Fatal(err)
	}
	if got := ReadState(PathForDataDir(dataDir)); got != StateReady {
		t.Fatalf("standalone fallback state = %q", got)
	}
}

func TestPathForDataDirWindowsLayoutIsCaseInsensitive(t *testing.T) {
	runtimeDir, authorizationDir, actualState := installedStateFixture(t)
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, strings.ToUpper(authorizationDir))
	if err := WriteState(actualState, StateReady); err != nil {
		t.Fatal(err)
	}
	if got := ReadState(PathForDataDir(strings.ToUpper(runtimeDir))); got != StateReady {
		t.Fatalf("case-insensitive installed state = %q", got)
	}
}

func readinessSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skip("Windows symbolic-link privilege is unavailable")
		}
		t.Fatal(err)
	}
}

func TestPathForDataDirWindowsRejectsReparseLayout(t *testing.T) {
	for _, leaf := range []string{"runtime", "hook-guardian-state", StateDirName} {
		t.Run(leaf, func(t *testing.T) {
			runtimeDir, _, actualState := installedStateFixture(t)
			root := filepath.Dir(runtimeDir)
			target := t.TempDir()
			if err := WriteState(PathForStateRoot(target), StateReady); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, leaf)
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			readinessSymlink(t, target, link)
			if path := PathForDataDir(runtimeDir); path != "" {
				t.Fatalf("reparse layout returned state path %q (guardian %q)", path, actualState)
			}
		})
	}
}

func TestReadStateWindowsRejectsSignalReparseReplacement(t *testing.T) {
	runtimeDir, _, actualState := installedStateFixture(t)
	if err := WriteState(actualState, StateReady); err != nil {
		t.Fatal(err)
	}
	path := PathForDataDir(runtimeDir)
	if got := ReadState(path); got != StateReady {
		t.Fatalf("initial installed state = %q", got)
	}
	outsideSignal := filepath.Join(t.TempDir(), FileName)
	if err := WriteState(outsideSignal, StateReady); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(actualState); err != nil {
		t.Fatal(err)
	}
	readinessSymlink(t, outsideSignal, actualState)
	if got := ReadState(path); got != StateUnknown {
		t.Fatalf("reparse replacement reported state %q", got)
	}
	if resolved := PathForDataDir(runtimeDir); resolved != "" {
		t.Fatalf("state-leaf reparse returned path %q", resolved)
	}
}
