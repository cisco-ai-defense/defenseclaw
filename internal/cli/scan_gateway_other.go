// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Seams for tests.
var (
	managedScanUnixLayout   = func() (managed.StandaloneLayout, error) { return managed.StandaloneLayoutFor(runtime.GOOS) }
	managedScanUnixReadFile = os.ReadFile
	managedScanUnixRecord   = func() bool { _, present := managedHostUnixRecord(nil); return present }
	managedScanUnixRuntime  = func() error { _, _, err := managed.InstalledUnixScannerRuntime(); return err }
	managedScanUnixGOOS     = runtime.GOOS
)

// managedScanUnixAdministratorOnly answers a standard account: the managed
// gateway's token is readable only by root.
const managedScanUnixAdministratorOnly = "on this managed computer a scan runs through the DefenseClaw gateway, whose token only an administrator can read; " +
	"run it with sudo, or ask your administrator to run it. Nothing was scanned"

// managedScanGatewayEndpoint binds the scan commands of a managed Linux or
// macOS computer to the managed gateway: its loopback API and the gateway
// token in its data folder (root only). The root CLI used to read
// /root/.defenseclaw/config.yaml and found no gateway (GAP-1234).
func managedScanGatewayEndpoint() (string, string, bool, error) {
	if !managedScanUnixRecord() {
		return "", "", false, nil
	}
	layout, err := managedScanUnixLayout()
	if err != nil {
		return "", "", true, err
	}
	body, err := managedScanUnixReadFile(filepath.Join(layout.DataDir, ".env"))
	if errors.Is(err, fs.ErrPermission) {
		return "", "", true, errors.New(managedScanUnixAdministratorOnly)
	}
	if err != nil {
		return "", "", true, fmt.Errorf("read the managed gateway token: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		name, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if ok && strings.TrimSpace(name) == "DEFENSECLAW_GATEWAY_TOKEN" && strings.TrimSpace(value) != "" {
			return "http://" + layout.APIAddr, strings.Trim(strings.TrimSpace(value), `"'`), true, nil
		}
	}
	return "", "", true, errors.New("the managed gateway token is not provisioned")
}

// managedScanUnavailable answers `scan skill|mcp|plugin` on a managed Linux
// or macOS computer that cannot run the scan: one whose packages installed
// no scanner runtime (a deployment from the payload archive), one whose
// runtime is no longer trusted, or a folder the gateway service cannot read.
// The managed packages install the runtime (GAP-1527), so the scan runs
// through the managed gateway, as on a managed Windows computer.
func managedScanUnavailable(kind, target string) error {
	if !managedScanUnixRecord() {
		return nil
	}
	scanner := "skill"
	switch kind {
	case "mcp":
		scanner = "MCP"
	case "plugin":
		scanner = "plugin"
	}
	if err := managedScanUnixRuntime(); errors.Is(err, managed.ErrNoScannerRuntime) {
		return withExitCode(fmt.Errorf("scan %s: this DefenseClaw deployment has no %s scanner: the managed defenseclaw-enterprise package "+
			"(rpm, deb or macOS pkg) installs the scanner runtime, a deployment from the payload archive does not. Install the package "+
			"to run this scan. Nothing was scanned", kind, scanner), 3)
	} else if err != nil {
		return withExitCode(fmt.Errorf("scan %s: the scanner runtime the package installed is not trusted (%v); reinstall the "+
			"defenseclaw-enterprise package to restore it. Nothing was scanned", kind, err), 3)
	}
	if kind == "mcp" {
		return nil
	}
	return managedScanTargetReadable(kind, target)
}

// managedScanTargetReadable refuses a folder the managed gateway service
// cannot read, with the step that works, instead of a "not found" from the
// service. On Linux its unit hides home folders (ProtectHome) and gives it a
// private /tmp and /var/tmp (PrivateTmp); on macOS the service account
// cannot read inside user folders.
func managedScanTargetReadable(kind, target string) error {
	resolved := target
	if real, err := filepath.EvalSymlinks(target); err == nil {
		resolved = real
	}
	hidden := []string{"/home", "/root", "/tmp", "/var/tmp", "/run/user"}
	if managedScanUnixGOOS == "darwin" {
		hidden = []string{"/Users", "/var/root", "/private/var/root"}
	}
	for _, dir := range hidden {
		if resolved == dir || strings.HasPrefix(resolved, dir+"/") {
			return withExitCode(fmt.Errorf("scan %s: %s is inside %s, which the managed DefenseClaw gateway service cannot read. "+
				"Copy the folder outside home and temporary folders, readable by all accounts (for example `sudo mkdir -p /opt/defenseclaw-scan && "+
				"sudo cp -R %s /opt/defenseclaw-scan/`), and scan that copy. Nothing was scanned", kind, target, dir, target), 3)
		}
	}
	return nil
}
