// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"testing"
)

func TestServiceLogPathReadsProtectedServiceEnvironment(t *testing.T) {
	const path = `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\logs\sensor-helper\sensor-helper.log`
	t.Setenv(windowsServiceLogEnv, "  "+path+"  ")
	if got := serviceLogPath(); got != path {
		t.Fatalf("serviceLogPath() = %q, want %q", got, path)
	}
	t.Setenv(windowsServiceLogEnv, "")
	if got := serviceLogPath(); got != "" {
		t.Fatalf("serviceLogPath() = %q with the variable empty, want empty", got)
	}
}
