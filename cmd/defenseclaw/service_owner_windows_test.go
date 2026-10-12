//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/svc"
)

// The LocalSystem gateway must own its files as its service SID before it
// creates the first one (the service log), and must not start when it
// cannot: its write-restricted token could not then secure its own audit
// database.
func TestRunWindowsServiceAdoptsGatewayFileOwnerBeforeItsFirstFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	t.Setenv(windowsServiceNameEnv, defaultGatewayServiceName)
	t.Setenv(windowsServiceLogEnv, logPath)
	originalDetector, originalRunner, originalAdopt := isWindowsService, runSCMService, adoptGatewayFileOwner
	originalStdout, originalStderr := os.Stdout, os.Stderr
	t.Cleanup(func() {
		isWindowsService, runSCMService, adoptGatewayFileOwner = originalDetector, originalRunner, originalAdopt
		os.Stdout, os.Stderr = originalStdout, originalStderr
	})
	isWindowsService = func() (bool, error) { return true, nil }
	runSCMService = func(string, svc.Handler) error {
		t.Error("the service ran after its file owner could not be set")
		return nil
	}
	adopted := 0
	adoptGatewayFileOwner = func() error {
		adopted++
		if _, err := os.Stat(logPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("service log existed before the file owner was set: %v", err)
		}
		return errors.New("owner refused")
	}

	handled, code := runWindowsService(func(context.Context) int {
		t.Error("the executor ran after its file owner could not be set")
		return 0
	})
	if !handled || code != 1 {
		t.Fatalf("result handled=%v code=%d, want handled failure", handled, code)
	}
	if adopted != 1 {
		t.Fatalf("file owner set %d times, want 1", adopted)
	}
	if _, err := os.Stat(logPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service log created after the file owner change failed: %v", err)
	}
}
