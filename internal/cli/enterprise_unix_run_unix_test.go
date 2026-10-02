// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A standard account running `enterprise secret status` on a managed host
// got the raw "open /etc/defenseclaw/secrets: permission denied".
func TestEnterpriseSecretStatusAsStandardUserNamesAdministratorRights(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0000 directory")
	}
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	secrets := root + layout.SecretsDir
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secrets, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secrets, 0o700) })
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 1000 }}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })

	cmd := newEnterpriseSecretCommand("status", "")
	var out bytes.Buffer
	cmd.SetOut(&out)
	err = runEnterpriseSecret(cmd, "status", &enterpriseSecretOptions{})
	if err == nil {
		t.Fatal("secret status succeeded without access to the credentials directory")
	}
	if strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "administrator rights") ||
		!strings.Contains(err.Error(), "sudo "+layout.BinDir+"/defenseclaw-gateway enterprise secret status") {
		t.Fatalf("secret status error = %q", err)
	}
	if commandExitCode(err) != 1 {
		t.Fatalf("exit code %d", commandExitCode(err))
	}
}

// verify printed every failed target three times: as a "! <code>" warning,
// as a "✗ verify_failed" error and again in the final "Error: verify
// failed: ..." line. Each problem is printed once, with its specific code,
// and the headline of a result with warnings is not a green check.
func TestLifecycleOutputPrintsEachProblemOnce(t *testing.T) {
	target := "devin 3000.11.3 for user alice has no verified DefenseClaw hook contract, so it runs without DefenseClaw hooks"
	other := "com.cisco.defenseclaw.hook-enumerator is not active"
	result := enterprisestatus.New("verify", "standalone", "darwin", "1.0.0")
	result.AddWarning("hook_contract_unverified", target)
	result.AddError("verify_failed", other)
	result.AddError("verify_failed", target)
	result.Finish("darwin", 0)
	var out bytes.Buffer
	if err := printLifecycleResult(&out, result, false); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Count(text, target) != 1 || strings.Count(text, other) != 1 {
		t.Fatalf("each problem must be printed once:\n%s", text)
	}
	if !strings.Contains(text, "✗ hook_contract_unverified: "+target) {
		t.Fatalf("the problem lost its specific code:\n%s", text)
	}

	// The error line after the listing does not repeat the problems.
	previous := newUnixLifecycleEnv
	root := t.TempDir()
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 0 }}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	platform := "linux"
	if goos == "darwin" {
		platform = "macos"
	}
	cmd := &cobra.Command{}
	out.Reset()
	cmd.SetOut(&out)
	runErr := runUnixLifecycle(cmd, platform, "verify", &unixLifecycleOptions{})
	if runErr == nil {
		t.Fatal("verify of an empty host succeeded")
	}
	listed := 0
	for _, line := range strings.Split(out.String(), "\n") {
		message, ok := strings.CutPrefix(line, "  ✗ ")
		if !ok {
			continue
		}
		listed++
		if _, text, found := strings.Cut(message, ": "); found && strings.Contains(runErr.Error(), text) {
			t.Fatalf("the error line repeats a listed problem: %q", runErr)
		}
	}
	if listed == 0 {
		t.Fatalf("verify listed no problem:\n%s", out.String())
	}

	ok := enterprisestatus.New("status", "standalone", "linux", "1.0.0")
	ok.AddWarning("unit_failed", "defenseclaw-enterprise-apply.service failed")
	ok.Inspection.Local, ok.Inspection.AIDefense = "active", "unavailable:auth_failed"
	ok.Finish("linux", 0)
	out.Reset()
	if err := printLifecycleResult(&out, ok, false); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(out.String(), "✓") {
		t.Fatalf("a result with warnings got a green check:\n%s", out.String())
	}
	// Human status names the AI Defense state, not only the JSON.
	if !strings.Contains(out.String(), "inspection: local=active ai_defense=unavailable:auth_failed") {
		t.Fatalf("status hides the inspection state:\n%s", out.String())
	}
}

// A failed verify of an installed deployment ends with the repair command
// (GAP-1094); other failures and --json keep their line.
func TestLifecycleFailureOfAnInstalledVerifyNamesRepair(t *testing.T) {
	const repair = "/usr/bin/defenseclaw-gateway enterprise linux repair"
	result := enterprisestatus.New(enterpriseunix.ActionVerify, "standalone", "linux", "1.0.0")
	result.Installed = true
	result.AddError("verify_failed", "defenseclaw-sensor-helper.service is not active")
	result.AddError("verify_failed", "DefenseClaw hooks are not in place in vendor machine policy for claudecode")
	result.Finish("linux", 0)
	err := lifecycleFailure(result, false, repair)
	if want := "verify failed; see the 2 problems listed above. Run `" + repair + "` as root to fix them"; err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if commandExitCode(err) != result.ExitCode {
		t.Fatalf("exit code %d, want %d", commandExitCode(err), result.ExitCode)
	}
	if err := lifecycleFailure(result, true, repair); strings.Contains(err.Error(), "repair") {
		t.Fatalf("--json error line = %q, want the problems only", err)
	}
	result.Installed = false
	if err := lifecycleFailure(result, false, repair); strings.Contains(err.Error(), "repair") {
		t.Fatalf("not installed: %q, want no repair advice", err)
	}
}
