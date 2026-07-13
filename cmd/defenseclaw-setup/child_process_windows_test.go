// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCapturedSetupCommandDoesNotCreateAConsoleWindow(t *testing.T) {
	cmd := newCapturedSetupCommand(context.Background(), "cmd.exe", "/c", "exit", "0")
	if cmd.SysProcAttr == nil {
		t.Fatal("captured setup command has no Windows process attributes")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("captured setup command does not hide its child window")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("captured setup command creation flags = %#x, missing CREATE_NO_WINDOW", cmd.SysProcAttr.CreationFlags)
	}
}
