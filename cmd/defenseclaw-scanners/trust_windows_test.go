//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestScannerLaunchRejectsWritablePythonImportFolder(t *testing.T) {
	_, root := testenv.CiscoRuntimeTree(t, "DefenseClaw-ScannerRuntime")
	python := filepath.Join(root, "runtime-digest", "python")
	site := filepath.Join(python, "Lib", "site-packages")
	testenv.WriteAdminOnlyFile(t, filepath.Join(python, "python.exe"), []byte("python"))
	testenv.WriteAdminOnlyFile(t, filepath.Join(site, "sitecustomize.py"), []byte("pass"))
	previous := runtimeCodeRoot
	runtimeCodeRoot = func() (string, error) { return root, nil }
	t.Cleanup(func() { runtimeCodeRoot = previous })
	if err := validateRuntimeCodeTree(); err != nil {
		t.Fatalf("trusted runtime refused: %v", err)
	}
	testenv.SetSecurity(t, site, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1200ab;;;BU)")
	if err := validateRuntimeCodeTree(); err == nil || !strings.Contains(err.Error(), site) {
		t.Fatalf("writable import folder = %v, want refusal naming %s", err, site)
	}
}
