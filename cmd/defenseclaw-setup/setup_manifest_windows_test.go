// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/windowsresources"
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

	icon := filepath.Join(repoRoot, filepath.FromSlash(windowsresources.IconSource))
	resourceTool := filepath.Join(t.TempDir(), "windowsresources.exe")
	resourceBuild := exec.Command("go", "build", "-o", resourceTool, "./internal/tools/windowsresources")
	resourceBuild.Dir = repoRoot
	if output, err := resourceBuild.CombinedOutput(); err != nil {
		t.Fatalf("build resource tool: %v\n%s", err, output)
	}
	for _, args := range [][]string{
		{"-target", "windows_amd64", "-executable", executable, "-component", "setup", "-version", "1.2.3", "-icon", icon},
		{"-target", "windows_amd64", "-executable", executable, "-component", "setup", "-version", "1.2.3", "-icon", icon, "-verify-only"},
	} {
		command := exec.Command(resourceTool, args...)
		command.Dir = repoRoot
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("resource tool failed: %v\n%s", err, output)
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
	want, err := windowsresources.Manifest(windowsresources.ComponentSetup, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(embedded, want) {
		t.Fatal("embedded RT_MANIFEST/1 does not byte-match the canonical generated setup manifest")
	}
	const primaryResourceID windows.ResourceID = 1
	for _, resourceType := range []windows.ResourceID{windows.RT_GROUP_ICON, windows.RT_VERSION} {
		resource, err := windows.FindResource(module, primaryResourceID, resourceType)
		if err != nil {
			t.Fatalf("find setup resource type %d: %v", resourceType, err)
		}
		contents, err := windows.LoadResourceData(module, resource)
		if err != nil || len(contents) == 0 {
			t.Fatalf("load setup resource type %d: bytes=%d err=%v", resourceType, len(contents), err)
		}
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
