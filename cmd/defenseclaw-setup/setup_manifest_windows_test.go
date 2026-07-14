// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSetupManifestIsEmbeddedAndNormalUserCanRunHelp(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "DefenseClawSetup-x64.exe")
	build := exec.Command("go", "build", "-o", executable, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build setup probe: %v\n%s", err, output)
	}

	manifest := filepath.Join(repoRoot, "cmd", "defenseclaw-setup", "setup.manifest")
	manifestTool := filepath.Join(repoRoot, "scripts", "set-windows-application-manifest.ps1")
	pwsh, err := exec.LookPath("pwsh.exe")
	if err != nil {
		t.Fatalf("locate PowerShell 7: %v", err)
	}
	for _, args := range [][]string{
		{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", manifestTool, "-Executable", executable, "-Manifest", manifest},
		{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", manifestTool, "-Executable", executable, "-Manifest", manifest, "-VerifyOnly"},
	} {
		command := exec.Command(pwsh, args...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("manifest tool failed: %v\n%s", err, output)
		}
	}

	module, err := windows.LoadLibraryEx(
		executable,
		0,
		windows.LOAD_LIBRARY_AS_DATAFILE|windows.LOAD_LIBRARY_AS_IMAGE_RESOURCE,
	)
	if err != nil {
		t.Fatalf("load setup executable as resource: %v", err)
	}
	defer windows.FreeLibrary(module)
	resource, err := windows.FindResource(
		module,
		windows.CREATEPROCESS_MANIFEST_RESOURCE_ID,
		windows.RT_MANIFEST,
	)
	if err != nil {
		t.Fatalf("find setup RT_MANIFEST/1: %v", err)
	}
	embedded, err := windows.LoadResourceData(module, resource)
	if err != nil {
		t.Fatalf("load setup manifest resource: %v", err)
	}
	want, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(embedded, want) {
		t.Fatal("embedded RT_MANIFEST/1 does not byte-match setup.manifest")
	}

	help := exec.Command(executable, "/quiet", "/?")
	output, err := help.CombinedOutput()
	if err != nil {
		t.Fatalf("normal current-user help failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "INSTALLSCOPE=user") {
		t.Fatalf("normal current-user help output was incomplete: %q", output)
	}
}
