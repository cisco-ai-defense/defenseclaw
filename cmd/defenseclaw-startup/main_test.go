// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupPathsUseAdjacentGatewayAndUserData(t *testing.T) {
	root := t.TempDir()
	launcher := filepath.Join(root, "Program Files", "DefenseClaw", "bin", "defenseclaw-startup.exe")
	home := filepath.Join(root, "Users", "Jane Doe")

	gateway, dataRoot, err := startupPaths(launcher, home)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(filepath.Dir(launcher), "defenseclaw-gateway.exe"); gateway != want {
		t.Fatalf("gateway path = %q, want %q", gateway, want)
	}
	if want := filepath.Join(home, ".defenseclaw"); dataRoot != want {
		t.Fatalf("data root = %q, want %q", dataRoot, want)
	}
}

func TestWithDefenseClawHomeReplacesInheritedValueCaseInsensitively(t *testing.T) {
	got := withDefenseClawHome([]string{
		"Path=C:\\Windows",
		"defenseclaw_home=C:\\hostile-project",
		"OTHER=value",
	}, `C:\Users\Jane Doe\.defenseclaw`)
	joined := strings.Join(got, "\n")
	if strings.Contains(strings.ToLower(joined), "hostile-project") {
		t.Fatalf("inherited DEFENSECLAW_HOME survived: %v", got)
	}
	if !strings.Contains(joined, `DEFENSECLAW_HOME=C:\Users\Jane Doe\.defenseclaw`) {
		t.Fatalf("managed DEFENSECLAW_HOME missing: %v", got)
	}
}
