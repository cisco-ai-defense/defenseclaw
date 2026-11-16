// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The lifecycle tests in this package drive runWindowsEnterpriseLifecycle on
// arbitrary CI hosts, so the host preflight is stubbed out package-wide; the
// tests below exercise it explicitly.
func init() {
	windowsEnterprisePrerequisiteChecker = func(windowsEnterprisePrereqInput) error { return nil }
}

func TestRunWindowsEnterpriseLifecyclePrerequisiteFailureStopsBeforePowerShell(t *testing.T) {
	originalChecker := windowsEnterprisePrerequisiteChecker
	originalRunner := windowsEnterpriseCommandRunner
	originalScriptFinder := windowsEnterpriseScriptFinder
	t.Cleanup(func() {
		windowsEnterprisePrerequisiteChecker = originalChecker
		windowsEnterpriseCommandRunner = originalRunner
		windowsEnterpriseScriptFinder = originalScriptFinder
	})
	first := newWindowsEnterprisePrereq(prereqCheckLoopbackPort, map[string]string{
		"addr": "127.0.0.1:18970", "reason": "excluded port range", "remedy": "r",
	})
	second := newWindowsEnterprisePrereq(prereqCheckNTFS, map[string]string{"path": `D:\`, "reason": "x", "remedy": "y"})
	var seen windowsEnterprisePrereqInput
	windowsEnterprisePrerequisiteChecker = func(input windowsEnterprisePrereqInput) error {
		seen = input
		return errors.Join(first, second)
	}
	scriptLookedUp := false
	windowsEnterpriseScriptFinder = func(string) (string, error) {
		scriptLookedUp = true
		return `C:\trusted\install-enterprise.ps1`, nil
	}
	windowsEnterpriseCommandRunner = func(context.Context, *cobra.Command, string, []string) error {
		t.Fatal("PowerShell ran after a failed prerequisite")
		return nil
	}
	// Main reads --config for its profile before the host preflight, so the
	// config exists, and the computer's own deployment records are kept out.
	stubWindowsEnterpriseRecords(t, nil, nil, func(string) error { return nil }, true)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	err := runWindowsEnterpriseLifecycle(context.Background(), cmd, "install", &windowsEnterpriseLifecycleOptions{
		jsonOutput:  true,
		configPath:  configPath,
		installRoot: `C:\root`,
		stateRoot:   `C:\state`,
	})
	if err == nil || scriptLookedUp {
		t.Fatalf("err=%v scriptLookedUp=%t", err, scriptLookedUp)
	}
	if seen.Action != "install" || seen.ConfigPath != configPath ||
		seen.InstallRoot != `C:\root` || seen.StateRoot != `C:\state` {
		t.Fatalf("preflight input = %#v", seen)
	}
	var report windowsEnterpriseLifecyclePreflightFailure
	if err := json.Unmarshal([]byte(output.String()), &report); err != nil {
		t.Fatalf("preflight output is not one JSON document: %v\n%s", err, output.String())
	}
	if report.OK || report.Action != "install" || len(report.Errors) != 2 ||
		report.Errors[0] != first.Error() || report.Errors[1] != second.Error() ||
		!strings.HasPrefix(report.Error, `defenseclaw_prereq addr="127.0.0.1:18970" check="gateway_loopback_port"`) {
		t.Fatalf("preflight report = %#v", report)
	}
	if code := windowsEnterpriseFailureExitCode; code != 1603 {
		t.Fatalf("failure exit code = %d", code)
	}
}

func TestCheckWindowsEnterprisePrerequisitesNeverFailsReadOnlyActions(t *testing.T) {
	for _, action := range []string{"status", "verify", "reconcile", "uninstall"} {
		if err := checkWindowsEnterprisePrerequisites(windowsEnterprisePrereqInput{Action: action}); err != nil {
			t.Fatalf("%s: read-only action failed the host preflight: %v", action, err)
		}
	}
}

func TestWindowsEnterpriseBindAndConnectDetectsBusyPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()
	excluded, inUse, bindErr, _ := windowsEnterpriseBindAndConnect(addr)
	if excluded || bindErr == nil {
		t.Fatalf("busy port: excluded=%t inUse=%t bindErr=%v", excluded, inUse, bindErr)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	excluded, inUse, bindErr, connectErr := windowsEnterpriseBindAndConnect("127.0.0.1:" + strconv.Itoa(port))
	if excluded || inUse || bindErr != nil || connectErr != nil {
		t.Fatalf("free port: excluded=%t inUse=%t bindErr=%v connectErr=%v", excluded, inUse, bindErr, connectErr)
	}
}

// The port preflight admits only the installed gateway as the listener. A
// standalone gateway runs from Cisco\DefenseClaw, so the image and config it
// reads must follow the profile, or ensure, upgrade and repair of a running
// standalone deployment fail with its own gateway named as a foreign owner.
func TestWindowsEnterprisePrereqRootsFollowTheProfile(t *testing.T) {
	programFiles, programData := t.TempDir(), t.TempDir()
	previousFiles, previousData := windowsEnterpriseProgramFilesResolver, windowsEnterpriseProgramDataResolver
	t.Cleanup(func() {
		windowsEnterpriseProgramFilesResolver, windowsEnterpriseProgramDataResolver = previousFiles, previousData
	})
	windowsEnterpriseProgramFilesResolver = func() (string, error) { return programFiles, nil }
	windowsEnterpriseProgramDataResolver = func() (string, error) { return programData, nil }

	for _, tc := range []struct {
		name  string
		input windowsEnterprisePrereqInput
		image string
	}{
		{"secure client", windowsEnterprisePrereqInput{}, filepath.Join(programFiles, "Cisco", "Cisco Secure Client", "DefenseClaw", "bin", "defenseclaw-gateway.exe")},
		{"standalone", windowsEnterprisePrereqInput{Standalone: true}, filepath.Join(programFiles, "Cisco", "DefenseClaw", "bin", "defenseclaw-gateway.exe")},
		{"explicit root", windowsEnterprisePrereqInput{Standalone: true, InstallRoot: `C:\Scope`}, `C:\Scope\bin\defenseclaw-gateway.exe`},
	} {
		got, err := windowsEnterpriseGatewayImage(tc.input)
		if err != nil || !strings.EqualFold(got, tc.image) {
			t.Errorf("%s: gateway image = %q, %v; want %q", tc.name, got, err, tc.image)
		}
	}

	config := filepath.Join(programData, "Cisco", "DefenseClaw", "etc", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(config), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("gateway:\n  api_port: 19443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := windowsEnterpriseGatewayPort(windowsEnterprisePrereqInput{Standalone: true}); got != 19443 {
		t.Errorf("standalone gateway port = %d, want 19443 from the standalone config", got)
	}
	if got := windowsEnterpriseGatewayPort(windowsEnterprisePrereqInput{}); got != windowsEnterpriseGatewayPortFromConfig(nil) {
		t.Errorf("secure client gateway port = %d, read the standalone config", got)
	}
}
