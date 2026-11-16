//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/svc"
)

// The LocalSystem gateway sets its file owner to its service SID before it
// creates the first file (the service log). When it cannot, it still starts
// and reports the degraded owner (26.8.4): the process never exits before
// SCM sees it.
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
	ran := 0
	runSCMService = func(string, svc.Handler) error {
		ran++
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

	handled, code := runWindowsService(func(context.Context) int { return 0 })
	if !handled || code != 0 {
		t.Fatalf("result handled=%v code=%d, want the service to run", handled, code)
	}
	if adopted != 1 || ran != 1 {
		t.Fatalf("file owner set %d times and service ran %d times, want 1 and 1", adopted, ran)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("service log: %v", err)
	}
	if !strings.Contains(string(raw), "default-owner") {
		t.Fatalf("service log does not report the degraded owner:\n%s", raw)
	}
}
