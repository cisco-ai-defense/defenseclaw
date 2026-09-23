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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	windowspayload "github.com/defenseclaw/defenseclaw/packaging/windows"
)

const windowsEnterpriseRestrictedStagingHelperEnv = "DEFENSECLAW_TEST_RESTRICTED_ENTERPRISE_STAGING"

func TestWindowsEnterpriseEmbeddedPayloadStagingWithRestrictedEnvironment(t *testing.T) {
	if os.Getenv(windowsEnterpriseRestrictedStagingHelperEnv) == "1" {
		if _, present := os.LookupEnv("ProgramData"); present {
			t.Fatal("restricted staging helper inherited ProgramData")
		}
		expectedParent, err := trustedWindowsEnterpriseProgramData()
		if err != nil {
			t.Fatalf("resolve ProgramData from fixed machine registration: %v", err)
		}
		script, cleanup, err := stageWindowsEnterprisePayload()
		if err != nil {
			t.Fatalf("stage embedded payload from restricted environment: %v", err)
		}
		payloadCleanupPending := true
		t.Cleanup(func() {
			if payloadCleanupPending {
				_ = cleanup()
			}
		})
		stagingDirectory := filepath.Dir(script)
		if !strings.EqualFold(filepath.Dir(stagingDirectory), expectedParent) {
			t.Fatalf(
				"embedded payload parent = %q, want trusted ProgramData %q",
				filepath.Dir(stagingDirectory),
				expectedParent,
			)
		}
		for name, want := range map[string][]byte{
			windowspayload.InstallerName: windowspayload.Installer(),
			windowspayload.ModuleName:    windowspayload.Module(),
		} {
			got, readErr := os.ReadFile(filepath.Join(stagingDirectory, name))
			if readErr != nil {
				t.Fatalf("read restricted staged %s: %v", name, readErr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("restricted staged %s differs from embedded bytes", name)
			}
		}
		if err := cleanup(); err != nil {
			t.Fatalf("clean up restricted embedded payload: %v", err)
		}
		payloadCleanupPending = false
		if _, err := os.Lstat(stagingDirectory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restricted staging directory survived cleanup: %v", err)
		}

		powerShellTemp, cleanupTemp, err := prepareWindowsEnterprisePowerShellTemp()
		if err != nil {
			t.Fatalf("prepare protected PowerShell temp from restricted environment: %v", err)
		}
		tempCleanupPending := true
		t.Cleanup(func() {
			if tempCleanupPending {
				_ = cleanupTemp()
			}
		})
		environment, err := trustedWindowsEnterpriseEnvironment(powerShellTemp)
		if err != nil {
			t.Fatalf("construct trusted child environment from restricted process: %v", err)
		}
		childValues := make(map[string]string, len(environment))
		for _, entry := range environment {
			name, value, found := strings.Cut(entry, "=")
			if found {
				childValues[strings.ToLower(name)] = value
			}
		}
		roots, err := resolveWindowsEnterpriseMachineRoots()
		if err != nil {
			t.Fatalf("resolve roots for trusted child environment assertion: %v", err)
		}
		for name, want := range map[string]string{
			"programdata":       roots.ProgramData,
			"programfiles":      roots.ProgramFiles,
			"programfiles(x86)": roots.ProgramFilesX86,
			"temp":              powerShellTemp,
			"tmp":               powerShellTemp,
		} {
			if !strings.EqualFold(childValues[name], want) {
				t.Fatalf("trusted child %s = %q, want %q", name, childValues[name], want)
			}
		}
		if err := cleanupTemp(); err != nil {
			t.Fatalf("clean up restricted protected PowerShell temp: %v", err)
		}
		tempCleanupPending = false
		if _, err := os.Lstat(powerShellTemp); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restricted protected PowerShell temp survived cleanup: %v", err)
		}
		return
	}

	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("embedded ProgramData payload staging requires an elevated process token")
	}
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatalf("resolve trusted Windows directory: %v", err)
	}
	system32 := filepath.Join(windowsDirectory, "System32")
	temporaryProfile := t.TempDir()
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestWindowsEnterpriseEmbeddedPayloadStagingWithRestrictedEnvironment$",
	)
	command.Env = []string{
		windowsEnterpriseRestrictedStagingHelperEnv + "=1",
		"ComSpec=" + filepath.Join(system32, "cmd.exe"),
		"PATH=" + strings.Join([]string{
			system32,
			windowsDirectory,
			filepath.Join(system32, "Wbem"),
			filepath.Join(system32, "WindowsPowerShell", "v1.0"),
		}, string(os.PathListSeparator)),
		"PSModulePath=" + filepath.Join(
			system32,
			"WindowsPowerShell",
			"v1.0",
			"Modules",
		),
		"SystemRoot=" + windowsDirectory,
		"TEMP=" + temporaryProfile,
		"TMP=" + temporaryProfile,
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("restricted embedded-payload staging helper: %v\n%s", err, output)
	}
}

func TestResolveWindowsEnterpriseMachineRootsIgnoresProcessEnvironment(t *testing.T) {
	poison := filepath.Join(t.TempDir(), "attacker-controlled")
	t.Setenv("ProgramData", poison)
	t.Setenv("ProgramFiles", poison)
	t.Setenv("ProgramFiles(x86)", poison)
	roots, err := resolveWindowsEnterpriseMachineRoots()
	if err != nil {
		t.Fatalf("resolve fixed machine roots: %v", err)
	}
	for label, root := range map[string]string{
		"ProgramData":       roots.ProgramData,
		"Program Files":     roots.ProgramFiles,
		"Program Files x86": roots.ProgramFilesX86,
	} {
		if strings.EqualFold(root, poison) || !filepath.IsAbs(root) {
			t.Fatalf("%s machine root = %q, want absolute non-environment value", label, root)
		}
	}
}

func TestValidateWindowsEnterpriseMachineRootRejectsUnsafeSyntaxAndMissingPath(t *testing.T) {
	for name, value := range map[string]string{
		"empty":               "",
		"relative":            `ProgramData`,
		"environment":         `%ProgramData%`,
		"UNC":                 `\\server\share`,
		"extended device":     `\\?\C:\ProgramData`,
		"DOS device":          `\\.\C:\ProgramData`,
		"alternate stream":    `C:\ProgramData:stream`,
		"noncanonical parent": `C:\ProgramData\..`,
		"forward slash":       `C:/ProgramData`,
		"padded":              ` C:\ProgramData`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateWindowsEnterpriseMachineRoot(value, "fixture"); err == nil {
				t.Fatalf("unsafe machine root %q was accepted", value)
			}
		})
	}
	missing := filepath.Join(t.TempDir(), "missing-machine-root")
	if _, err := validateWindowsEnterpriseMachineRoot(missing, "fixture"); err == nil {
		t.Fatalf("missing machine root %q was accepted", missing)
	}
}

func TestValidateWindowsEnterpriseMachineRootRejectsReparseRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(filepath.Dir(target), filepath.Base(target)+"-reparse")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("directory reparse fixture unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	if _, err := validateWindowsEnterpriseMachineRoot(link, "fixture"); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("reparse machine root error = %v, want explicit rejection", err)
	}
}

func TestWindowsEnterprisePayloadCarriesBothLifecycleScripts(t *testing.T) {
	if !windowspayload.Available() {
		t.Fatal("Windows builds must carry the lifecycle scripts")
	}
	for name, staged := range map[string][]byte{
		windowspayload.InstallerName: windowspayload.Installer(),
		windowspayload.ModuleName:    windowspayload.Module(),
	} {
		source, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(source, staged) {
			t.Fatalf("embedded %s does not match its source file", name)
		}
	}
}

func TestStageWindowsEnterprisePayloadWritesThePairAndCleansUp(t *testing.T) {
	originalValidator := windowsEnterpriseTrustValidator
	t.Cleanup(func() { windowsEnterpriseTrustValidator = originalValidator })

	directory := t.TempDir()
	validated := ""
	windowsEnterpriseTrustValidator = func(script string) error {
		validated = script
		return nil
	}

	script, cleanup, err := stageWindowsEnterprisePayloadIn(func() (string, error) {
		return directory, nil
	})
	if err != nil {
		t.Fatalf("stage embedded installer: %v", err)
	}
	if want := filepath.Join(directory, windowspayload.InstallerName); script != want {
		t.Fatalf("staged script = %q, want %q", script, want)
	}
	if validated != script {
		t.Fatalf("trust validation ran on %q, want the staged script %q", validated, script)
	}
	// The script imports its module by name from its own directory, so both
	// files have to be present before PowerShell starts.
	for name, want := range map[string][]byte{
		windowspayload.InstallerName: windowspayload.Installer(),
		windowspayload.ModuleName:    windowspayload.Module(),
	} {
		got, readErr := os.ReadFile(filepath.Join(directory, name))
		if readErr != nil {
			t.Fatalf("read staged %s: %v", name, readErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("staged %s does not match the embedded copy", name)
		}
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup staged installer: %v", err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging directory survived cleanup: %v", err)
	}
}

func TestStageWindowsEnterprisePayloadRemovesStagingWhenTrustFails(t *testing.T) {
	originalValidator := windowsEnterpriseTrustValidator
	t.Cleanup(func() { windowsEnterpriseTrustValidator = originalValidator })

	directory := filepath.Join(t.TempDir(), "staging")
	windowsEnterpriseTrustValidator = func(string) error {
		return errors.New("untrusted staging root")
	}

	_, _, err := stageWindowsEnterprisePayloadIn(func() (string, error) {
		if mkErr := os.Mkdir(directory, 0o700); mkErr != nil {
			return "", mkErr
		}
		return directory, nil
	})
	if err == nil {
		t.Fatal("staging into an untrusted root must fail closed")
	}
	if _, statErr := os.Stat(directory); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rejected staging survived: %v", statErr)
	}
}

func TestRunWindowsEnterpriseLifecycleStagesTheEmbeddedInstallerWhenDiscoveryFindsNone(
	t *testing.T,
) {
	originalRunner := windowsEnterpriseCommandRunner
	originalScriptFinder := windowsEnterpriseScriptFinder
	originalStager := windowsEnterprisePayloadStager
	t.Cleanup(func() {
		windowsEnterpriseCommandRunner = originalRunner
		windowsEnterpriseScriptFinder = originalScriptFinder
		windowsEnterprisePayloadStager = originalStager
	})
	t.Setenv(windowsEnterpriseInstallerEnv, "")

	staged := filepath.Join(t.TempDir(), windowspayload.InstallerName)
	cleaned := false
	windowsEnterpriseScriptFinder = func(string) (string, error) {
		return "", fmt.Errorf("%w; pass --installer", errWindowsEnterpriseInstallerNotFound)
	}
	windowsEnterprisePayloadStager = func() (string, func() error, error) {
		return staged, func() error {
			cleaned = true
			return nil
		}, nil
	}
	ran := ""
	windowsEnterpriseCommandRunner = func(
		_ context.Context,
		_ *cobra.Command,
		script string,
		_ []string,
	) error {
		ran = script
		return nil
	}

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := runWindowsEnterpriseLifecycle(
		context.Background(),
		cmd,
		"status",
		&windowsEnterpriseLifecycleOptions{},
	); err != nil {
		t.Fatalf("status with no installer on disk: %v", err)
	}
	if ran != staged {
		t.Fatalf("ran %q, want the staged embedded installer %q", ran, staged)
	}
	if !cleaned {
		t.Fatal("staged installer was left behind")
	}
}

func TestRunWindowsEnterpriseLifecycleFailsRatherThanStageOverAnExplicitInstaller(t *testing.T) {
	originalRunner := windowsEnterpriseCommandRunner
	originalScriptFinder := windowsEnterpriseScriptFinder
	originalStager := windowsEnterprisePayloadStager
	t.Cleanup(func() {
		windowsEnterpriseCommandRunner = originalRunner
		windowsEnterpriseScriptFinder = originalScriptFinder
		windowsEnterprisePayloadStager = originalStager
	})

	windowsEnterpriseScriptFinder = func(string) (string, error) {
		return "", fmt.Errorf("%w; pass --installer", errWindowsEnterpriseInstallerNotFound)
	}
	// The stager and runner stubs execute inside t.Run subtests, which run on
	// a different goroutine than the parent test. Calling t.Fatal on the
	// captured parent T from a foreign goroutine terminates that goroutine
	// with runtime.Goexit and leaves the subtest in an undefined state.
	// Record any invocation and assert inside each subtest instead.
	var stagerCalled, runnerCalled atomic.Bool
	windowsEnterprisePayloadStager = func() (string, func() error, error) {
		stagerCalled.Store(true)
		return "", nil, nil
	}
	windowsEnterpriseCommandRunner = func(
		context.Context,
		*cobra.Command,
		string,
		[]string,
	) error {
		runnerCalled.Store(true)
		return nil
	}

	for name, opts := range map[string]*windowsEnterpriseLifecycleOptions{
		"flag": {installerPath: filepath.Join(t.TempDir(), "missing.ps1")},
		"env":  {},
	} {
		t.Run(name, func(t *testing.T) {
			stagerCalled.Store(false)
			runnerCalled.Store(false)
			if name == "env" {
				t.Setenv(
					windowsEnterpriseInstallerEnv,
					filepath.Join(t.TempDir(), "missing.ps1"),
				)
			} else {
				t.Setenv(windowsEnterpriseInstallerEnv, "")
			}
			cmd := &cobra.Command{}
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			if err := runWindowsEnterpriseLifecycle(
				context.Background(),
				cmd,
				"status",
				opts,
			); err == nil {
				t.Fatal("a named installer that is missing must fail")
			}
			if stagerCalled.Load() {
				t.Fatal("an explicitly named installer must never fall back to the embedded copy")
			}
			if runnerCalled.Load() {
				t.Fatal("a missing explicit installer must not reach PowerShell")
			}
		})
	}
}
