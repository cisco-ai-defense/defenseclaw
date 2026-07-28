// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"debug/pe"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRequireNativeWindowsX64(t *testing.T) {
	original := queryProcessMachines
	t.Cleanup(func() { queryProcessMachines = original })

	queryProcessMachines = func(_ windows.Handle, processMachine, nativeMachine *uint16) error {
		*processMachine = pe.IMAGE_FILE_MACHINE_UNKNOWN
		*nativeMachine = pe.IMAGE_FILE_MACHINE_AMD64
		return nil
	}
	if err := requireNativeWindowsX64(); err != nil {
		t.Fatalf("native x64 rejected: %v", err)
	}

	queryProcessMachines = func(_ windows.Handle, processMachine, nativeMachine *uint16) error {
		*processMachine = pe.IMAGE_FILE_MACHINE_AMD64
		*nativeMachine = pe.IMAGE_FILE_MACHINE_ARM64
		return nil
	}
	if err := requireNativeWindowsX64(); err == nil || !strings.Contains(err.Error(), "x64 emulation") {
		t.Fatalf("ARM64 emulation error = %v, want explicit rejection", err)
	}

	queryProcessMachines = func(_ windows.Handle, _, _ *uint16) error {
		return errors.New("query failed")
	}
	if err := requireNativeWindowsX64(); err == nil || !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("query error = %v, want fail-closed rejection", err)
	}
}
