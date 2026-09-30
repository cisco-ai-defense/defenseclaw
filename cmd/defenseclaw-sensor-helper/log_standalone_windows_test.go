// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubStandaloneLog(t *testing.T, hosted bool, logDir string) *string {
	t.Helper()
	previousHosted, previousLayout, previousTrust, previousMaker := standaloneServiceHosted, standaloneWindowsLayout, standaloneLogDirTrustCheck, standaloneLogDirectoryMaker
	t.Cleanup(func() {
		standaloneServiceHosted, standaloneWindowsLayout, standaloneLogDirTrustCheck, standaloneLogDirectoryMaker = previousHosted, previousLayout, previousTrust, previousMaker
	})
	standaloneServiceHosted = func() (bool, error) { return hosted, nil }
	standaloneWindowsLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{GOOS: "windows", LogDir: logDir}, nil
	}
	standaloneLogDirTrustCheck = func(string) error { return nil }
	created := new(string)
	standaloneLogDirectoryMaker = func(directory string) error {
		*created = directory
		return os.Mkdir(directory, 0o700)
	}
	return created
}

func TestStandaloneSensorHelperServiceLogPath(t *testing.T) {
	logDir := t.TempDir()
	t.Setenv(windowsServiceLogEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "standalone")

	created := stubStandaloneLog(t, true, logDir)
	want := filepath.Join(logDir, "sensor-helper", "sensor-helper.log")
	if got := standaloneSensorHelperServiceLogPath(); got != want {
		t.Fatalf("standalone service log = %q, want %q", got, want)
	}
	if *created != filepath.Join(logDir, "sensor-helper") {
		t.Fatalf("log directory created at %q", *created)
	}
	// An existing directory is reused without re-creation.
	*created = ""
	if got := standaloneSensorHelperServiceLogPath(); got != want || *created != "" {
		t.Fatalf("reuse: path=%q created=%q", got, *created)
	}

	// Other helpers keep their log: the Secure Client helper, an explicit
	// service log, a console run and an untrusted log root derive none.
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if got := standaloneSensorHelperServiceLogPath(); got != "" {
		t.Fatalf("Secure Client helper got a derived log %q", got)
	}
	t.Setenv(managed.EnterpriseProfileEnv, "standalone")
	t.Setenv(windowsServiceLogEnv, `C:\explicit\sensor-helper.log`)
	if got := standaloneSensorHelperServiceLogPath(); got != "" {
		t.Fatalf("an explicit service log must win, got %q", got)
	}
	t.Setenv(windowsServiceLogEnv, "")
	stubStandaloneLog(t, false, logDir)
	if got := standaloneSensorHelperServiceLogPath(); got != "" {
		t.Fatalf("a console run got a derived log %q", got)
	}
	// A fresh root: the reused one already holds the helper directory.
	stubStandaloneLog(t, true, t.TempDir())
	standaloneLogDirTrustCheck = func(string) error { return errors.New("untrusted") }
	if got := standaloneSensorHelperServiceLogPath(); got != "" {
		t.Fatalf("an untrusted log root must fall back to stderr, got %q", got)
	}
}

func TestCreateStandaloneSensorHelperLogDirectoryIsAdministratorOnly(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sensor-helper")
	if err := createStandaloneSensorHelperLogDirectory(directory); err != nil {
		t.Fatalf("create: %v", err)
	}
	security, err := windows.GetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read DACL: %v", err)
	}
	control, _, err := security.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("log directory DACL must be protected (control=%#x err=%v)", control, err)
	}
	sddl := security.String()
	for _, want := range []string{"(A;OICI;FA;;;SY)", "(A;OICI;FA;;;BA)"} {
		if !strings.Contains(sddl, want) {
			t.Fatalf("log directory SDDL %q misses %s", sddl, want)
		}
	}
	if strings.Contains(sddl, ";;;BU)") || strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;AU)") {
		t.Fatalf("log directory SDDL %q grants a non-administrator", sddl)
	}
	// Creating again is idempotent.
	if err := createStandaloneSensorHelperLogDirectory(directory); err != nil {
		t.Fatalf("recreate: %v", err)
	}
}
