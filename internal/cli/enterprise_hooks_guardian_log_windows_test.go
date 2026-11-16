// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The guardian log is capped like the lifecycle log, while the services keep
// appending through handles they hold open: the file is copied to .1 and
// emptied in place, older generations move up, and the next line lands at the
// start of the emptied file.
func standaloneGuardianLogConfig(t *testing.T, profile string) {
	t.Helper()
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{Profile: profile}}
}

// The Secure Client guardian log is left alone: no rotation, whatever its size.
func TestCapWindowsGuardianLogLeavesTheSecureClientLogAlone(t *testing.T) {
	standaloneGuardianLogConfig(t, managed.ProfileSecureClient)
	dir := t.TempDir()
	path := filepath.Join(dir, "hook-guardian.log")
	t.Setenv(windowsGuardianServiceLogEnv, path)
	previous := windowsGuardianLogLimit
	windowsGuardianLogLimit = 16
	t.Cleanup(func() { windowsGuardianLogLimit = previous })
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	capWindowsGuardianLog(&stderr)
	if info, err := os.Stat(path); err != nil || info.Size() != 4096 || stderr.Len() != 0 {
		t.Fatalf("the Secure Client log was rotated: %v %v %q", info, err, stderr.String())
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("a generation was created: %v", err)
	}
	// The Secure Client guardian does not fold its lines either.
	if enterpriseHookFoldRepeats() {
		t.Fatal("the Secure Client guardian folds repeated lines")
	}
}

func TestCapWindowsGuardianLogRotatesAFileAServiceHoldsOpen(t *testing.T) {
	standaloneGuardianLogConfig(t, managed.ProfileStandalone)
	dir := t.TempDir()
	path := filepath.Join(dir, "hook-guardian.log")
	t.Setenv(windowsGuardianServiceLogEnv, path)
	previous := windowsGuardianLogLimit
	windowsGuardianLogLimit = 256
	t.Cleanup(func() { windowsGuardianLogLimit = previous })

	// The service handle: append-only, kept open across the rotation.
	service, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	write := func(text string) {
		t.Helper()
		if _, err := service.WriteString(text); err != nil {
			t.Fatal(err)
		}
	}
	var stderr bytes.Buffer

	write("short\n")
	capWindowsGuardianLog(&stderr)
	if stderr.Len() != 0 {
		t.Fatalf("a log under the cap was rotated: %q", stderr.String())
	}

	for generation := 1; generation <= windowsEnterpriseLogGenerates+2; generation++ {
		write(strings.Repeat("g", 300) + "\n")
		write("generation " + strconv.Itoa(generation) + "\n")
		capWindowsGuardianLog(&stderr)
		write("after rotation " + strconv.Itoa(generation) + "\n")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "after rotation "+strconv.Itoa(generation)+"\n" {
			t.Fatalf("generation %d: the log after the rotation holds %q", generation, body)
		}
		moved, err := os.ReadFile(path + ".1")
		if err != nil || !strings.Contains(string(moved), "generation "+strconv.Itoa(generation)) {
			t.Fatalf("generation %d: .1 does not hold the rotated lines: %v %q", generation, err, moved)
		}
	}
	if !strings.Contains(stderr.String(), "rotated") {
		t.Fatalf("the rotation was not logged: %q", stderr.String())
	}
	// The newest generations are kept and the oldest dropped: at most .1 to .4.
	for generation := 1; generation < windowsEnterpriseLogGenerates; generation++ {
		if _, err := os.Stat(path + "." + strconv.Itoa(generation)); err != nil {
			t.Fatalf("generation .%d is missing: %v", generation, err)
		}
	}
	if _, err := os.Stat(path + "." + strconv.Itoa(windowsEnterpriseLogGenerates)); !os.IsNotExist(err) {
		t.Fatalf("a generation beyond the cap exists: %v", err)
	}
}

func TestCapWindowsGuardianLogLeavesAProcessWithoutAServiceLogAlone(t *testing.T) {
	standaloneGuardianLogConfig(t, managed.ProfileStandalone)
	dir := t.TempDir()
	path := filepath.Join(dir, "hook-guardian.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := windowsGuardianLogLimit
	windowsGuardianLogLimit = 16
	t.Cleanup(func() { windowsGuardianLogLimit = previous })
	for _, value := range []string{"", "hook-guardian.log"} {
		t.Setenv(windowsGuardianServiceLogEnv, value)
		capWindowsGuardianLog(&bytes.Buffer{})
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 4096 {
		t.Fatalf("a log this process does not write was rotated: %v %v", info, err)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("a generation was created: %v", err)
	}
}
