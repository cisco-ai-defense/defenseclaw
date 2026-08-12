// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"errors"
	"os"
	"sync"
	"testing"
)

func installLivePayloadTraversalTrap(t *testing.T, _ string, path string) func() {
	t.Helper()
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if err := os.Chmod(path, 0o700); err != nil {
				t.Errorf("restore test directory permissions: %v", err)
			}
		})
	}
	t.Cleanup(restore)
	if _, err := os.ReadDir(path); err == nil {
		restore()
		t.Skip("test process can bypass directory permissions")
	} else if !errors.Is(err, os.ErrPermission) {
		restore()
		t.Fatalf("inaccessible directory read error = %v, want permission denied", err)
	}
	return restore
}
