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

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fleetpolicy "github.com/defenseclaw/defenseclaw/internal/fleet/policy"
)

func stagedCompiler(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, compilerArchiveDir, "tools", compilerFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func stagedFleetConfig(t *testing.T, h *testHost) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := append(DefaultConfig(h.env.Layout), []byte("\nfleet:\n  enabled: true\n")...)
	if err := os.WriteFile(path, body, 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func allowTestFleetPython(h *testHost) {
	h.env.MacFleetPythonCheck = func() (string, error) { return fleetpolicy.ManagedMacOSPythonCandidates()[0], nil }
	h.env.LinuxFleetPythonCheck = func() (string, error) { return "/usr/bin/python3", nil }
}

func packagedCompiler(t *testing.T, h *testHost, content string) string {
	t.Helper()
	canonical := packageCompilerSourcePath(h.env.Layout)
	path := h.env.P(canonical)
	for _, dir := range []string{filepath.Join(h.env.Layout.InstallRoot, "share"), filepath.Dir(canonical)} {
		rooted := h.env.P(dir)
		if err := os.MkdirAll(rooted, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(rooted, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := h.env.Lchown(rooted, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.env.writeFileAtomic(path, []byte(content), 0o644, rootOwner()); err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestPayloadCompilerInstalledVerifiedAndRolledBack(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			allowTestFleetPython(h)
			first := h.payload("1.0.0")
			stagedCompiler(t, first, "print('first')\n")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: first, ConfigFile: stagedFleetConfig(t, h)}))
			installed := compilerInstallPath(h.env.Layout)
			if got := h.read(installed); got != "print('first')\n" {
				t.Fatalf("installed compiler = %q", got)
			}
			if got := h.mode(installed); got != 0o644 {
				t.Fatalf("installed compiler mode = %04o", got)
			}
			record, err := h.env.loadDeployment()
			if err != nil || record.Files[installed] == "" {
				t.Fatalf("compiler is not digest-pinned in deployment: %v %+v", err, record)
			}
			writeFreshLedger(t, h)
			// The fake host cannot make the real files root-owned when the
			// tests run as a regular account. Check compiler-specific verify
			// findings; the privileged install lane exercises full verify.
			if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); strings.Contains(got, "installed compiler") || strings.Contains(got, installed+" was modified") {
				t.Fatalf("untouched compiler failed verify: %s", got)
			}
			unchanged := h.run(Options{Action: ActionEnsure})
			requireOK(t, unchanged)
			if !unchanged.Noop {
				t.Fatalf("unchanged compiler caused an apply: %+v", unchanged)
			}

			second := h.payload("2.0.0")
			stagedCompiler(t, second, "print('second')\n")
			h.healthy = false
			failed := h.run(Options{Action: ActionUpgrade, PayloadDir: second})
			requireError(t, failed, codeActivate)
			if !hasWarning(failed, codeRolledBack) {
				t.Fatalf("no rollback after failed activation: %+v", failed)
			}
			if got := h.read(installed); got != "print('first')\n" {
				t.Fatalf("compiler was not rolled back: %q", got)
			}
			record, err = h.env.loadDeployment()
			if err != nil || record.ProductVersion != "1.0.0" || record.Files[installed] != sha256Bytes([]byte("print('first')\n")) {
				t.Fatalf("deployment did not roll back compiler digest: %v %+v", err, record)
			}
		})
	}
}

func TestFleetOffPayloadDoesNotInstallOrValidateOptionalCompiler(t *testing.T) {
	h := newTestHost(t, "linux")
	payload := h.payload("1.0.0")
	compiler := stagedCompiler(t, payload, "print('unused')\n")
	if err := os.Chmod(compiler, 0o666); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
	active := compilerInstallPath(h.env.Layout)
	if _, err := os.Lstat(h.env.P(active)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Fleet-off install materialized compiler: %v", err)
	}
	record, err := h.env.loadDeployment()
	if err != nil || record.Files[active] != "" {
		t.Fatalf("Fleet-off deployment tracked optional compiler: %v %+v", err, record)
	}
	requireError(t, h.run(Options{Action: ActionEnsure, ConfigFile: stagedFleetConfig(t, h)}), codePayload)
}

func TestPayloadCompilerRejectsUntrustedPaths(t *testing.T) {
	for name, change := range map[string]func(*testing.T, string, string){
		"script symlink": func(t *testing.T, dir, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, binGateway), path); err != nil {
				t.Fatal(err)
			}
		},
		"parent symlink": func(t *testing.T, dir, path string) {
			if err := os.RemoveAll(filepath.Dir(path)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(dir, filepath.Dir(path)); err != nil {
				t.Fatal(err)
			}
		},
		"group writable script": func(t *testing.T, _, path string) {
			if err := os.Chmod(path, 0o664); err != nil {
				t.Fatal(err)
			}
		},
		"group writable parent": func(t *testing.T, _, path string) {
			if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"empty script": func(t *testing.T, _, path string) {
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}
		},
		"oversized script": func(t *testing.T, _, path string) {
			if err := os.Truncate(path, maxCompilerFileBytes+1); err != nil {
				t.Fatal(err)
			}
		},
		"missing script": func(t *testing.T, _, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			dir := h.payload("1.0.0")
			path := stagedCompiler(t, dir, "print('valid')\n")
			change(t, dir, path)
			requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: dir, ConfigFile: stagedFleetConfig(t, h)}), codePayload)
			if record, err := h.env.loadDeployment(); err != nil || record != nil {
				t.Fatalf("invalid compiler reached a committed deployment: %v %+v", err, record)
			}
		})
	}
}

func TestPayloadCompilerTamperFailsVerifyAndRepairRestores(t *testing.T) {
	h := newTestHost(t, "linux")
	allowTestFleetPython(h)
	staged := h.payload("1.0.0")
	stagedCompiler(t, staged, "print('trusted')\n")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: staged, ConfigFile: stagedFleetConfig(t, h)}))
	writeFreshLedger(t, h)
	installed := compilerInstallPath(h.env.Layout)
	if err := os.WriteFile(h.env.P(installed), []byte("print('tampered')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verify := h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, installed+" was modified after install") {
		t.Fatalf("verify did not identify compiler tampering: %s", got)
	}
	requireOK(t, h.run(Options{Action: ActionRepair, PayloadDir: staged}))
	if got := h.read(installed); got != "print('trusted')\n" {
		t.Fatalf("repair kept the tampered compiler: %q", got)
	}
	if err := os.Chmod(h.env.P(installed), 0o666); err != nil {
		t.Fatal(err)
	}
	requireError(t, h.run(Options{Action: ActionVerify}), codeVerify)
	requireOK(t, h.run(Options{Action: ActionRepair, PayloadDir: staged}))
	if got := h.mode(installed); got != 0o644 {
		t.Fatalf("repair kept a writable compiler mode %04o", got)
	}
}

func TestPackageCompilerRecordedWithoutLifecycleRewriting(t *testing.T) {
	h := packageHost(t, "1.0.0")
	allowTestFleetPython(h)
	if err := os.Chmod(h.env.P("/opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := packagedCompiler(t, h, "print('package')\n")
	installed := compilerInstallPath(h.env.Layout)
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package", ConfigFile: stagedFleetConfig(t, h)}))
	if got := h.read(source); got != "print('package')\n" {
		t.Fatalf("package source changed: %q", got)
	}
	writeFreshLedger(t, h)
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); strings.Contains(got, "installed compiler") || strings.Contains(got, installed+" was modified") {
		t.Fatalf("untouched package compiler failed verify: %s", got)
	}
	record, err := h.env.loadDeployment()
	if err != nil || record.Files[installed] != sha256Bytes([]byte("print('package')\n")) {
		t.Fatalf("package compiler was not recorded: %v %+v", err, record)
	}
	if result := h.run(Options{Action: ActionEnsure, FromPackage: true}); !result.OK || !result.Noop {
		t.Fatalf("unchanged package compiler should be a no-op: %+v", result)
	}
	if err := os.WriteFile(h.env.P(installed), []byte("print('tampered')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verify := h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, installed+" was modified") {
		t.Fatalf("verify omitted package compiler drift: %s", got)
	}
	requireError(t, h.run(Options{Action: ActionEnsure, FromPackage: true}), codePayload)
}

func TestFleetOffPackageLeavesCompilerInactiveUntilConfigEnable(t *testing.T) {
	h := packageHost(t, "1.0.0")
	allowTestFleetPython(h)
	if err := os.Chmod(h.env.P("/opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := packagedCompiler(t, h, "print('package')\n")
	active := compilerInstallPath(h.env.Layout)
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package"}))
	if _, err := os.Lstat(h.env.P(active)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Fleet-off package activated compiler: %v", err)
	}
	record, err := h.env.loadDeployment()
	if err != nil || record.Files[active] != "" {
		t.Fatalf("Fleet-off package recorded compiler: %v %+v", err, record)
	}
	if h.read(source) != "print('package')\n" {
		t.Fatal("package source disappeared")
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, ConfigFile: stagedFleetConfig(t, h)}))
	if got := h.read(active); got != "print('package')\n" {
		t.Fatalf("Fleet enable did not materialize compiler: %q", got)
	}
	configFile := filepath.Join(t.TempDir(), "disabled.yaml")
	if err := os.WriteFile(configFile, DefaultConfig(h.env.Layout), 0o640); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, ConfigFile: configFile}))
	if _, err := os.Lstat(h.env.P(active)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Fleet disable retained active compiler: %v", err)
	}
	if got := h.read(source); got != "print('package')\n" {
		t.Fatalf("Fleet disable changed package source: %q", got)
	}
}

// GAP-0722: a Fleet-on ensure from a package whose share/fleet folder has no
// policy_compiler.py says that the payload has no compiler and names the
// --payload route, not a raw lstat error, and changes nothing.
func TestFleetEnableWithoutPackageCompilerNamesTheFleetCause(t *testing.T) {
	h := packageHost(t, "1.0.0")
	allowTestFleetPython(h)
	if err := os.Chmod(h.env.P("/opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := packagedCompiler(t, h, "print('package')\n")
	if err := os.Remove(h.env.P(source)); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package"}))
	previous := h.read(h.env.Layout.ConfigPath)
	result := h.run(Options{Action: ActionEnsure, FromPackage: true, ConfigFile: stagedFleetConfig(t, h)})
	requireError(t, result, codePayload)
	got := messagesOf(result.Errors, codePayload)
	if !strings.Contains(got, "fleet.enabled is set but the managed payload has no policy_compiler.py") ||
		!strings.Contains(got, "--payload <dir>") || strings.Contains(got, "lstat") {
		t.Fatalf("Fleet-on ensure without the compiler = %q", got)
	}
	if h.read(h.env.Layout.ConfigPath) != previous {
		t.Fatal("the refused Fleet config changed the active config")
	}
}

func TestFleetEnableRejectsUntrustedPackageCompilerWithoutChangingConfig(t *testing.T) {
	h := packageHost(t, "1.0.0")
	allowTestFleetPython(h)
	if err := os.Chmod(h.env.P("/opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := packagedCompiler(t, h, "print('package')\n")
	path := h.env.P(source)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway)), path); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package"}))
	previous := h.read(h.env.Layout.ConfigPath)
	result := h.run(Options{Action: ActionEnsure, FromPackage: true, ConfigFile: stagedFleetConfig(t, h)})
	requireError(t, result, codePayload)
	if got := h.read(h.env.Layout.ConfigPath); got != previous {
		t.Fatal("untrusted optional compiler changed the active config")
	}
	if _, err := os.Lstat(h.env.P(compilerInstallPath(h.env.Layout))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted optional compiler became active: %v", err)
	}
}

func TestManagedMacFleetRequiresUsablePythonOnlyWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		name         string
		fleetEnabled bool
		compiler     bool
		probeFails   bool
		wantCode     string
	}{
		{name: "disabled ignores Python", compiler: true, probeFails: true},
		{name: "enabled rejects absent compiler", fleetEnabled: true, probeFails: true, wantCode: codePayload},
		{name: "enabled rejects missing PyYAML", fleetEnabled: true, compiler: true, probeFails: true, wantCode: codeConfig},
		{name: "enabled accepts usable Python", fleetEnabled: true, compiler: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			payload := h.payload("1.0.0")
			if tc.compiler {
				stagedCompiler(t, payload, "print('trusted')\n")
			}
			calls := 0
			h.env.MacFleetPythonCheck = func() (string, error) {
				calls++
				if tc.probeFails {
					return "", errors.New("isolated PyYAML import failed")
				}
				return fleetpolicy.ManagedMacOSPythonCandidates()[0], nil
			}
			opts := Options{Action: ActionInstall, PayloadDir: payload}
			if tc.fleetEnabled {
				opts.ConfigFile = stagedFleetConfig(t, h)
			}
			result := h.run(opts)
			if tc.wantCode != "" {
				requireError(t, result, tc.wantCode)
				if tc.wantCode == codeConfig && !strings.Contains(messagesOf(result.Errors, codeConfig), "PyYAML") {
					t.Fatalf("missing dependency in diagnostic: %+v", result.Errors)
				}
				if record, err := h.env.loadDeployment(); err != nil || record != nil {
					t.Fatalf("failed prerequisite committed deployment: %v %+v", err, record)
				}
				wantCalls := 0
				if tc.wantCode == codeConfig {
					wantCalls = 1
				}
				if calls != wantCalls {
					t.Fatalf("Python admission calls = %d, want %d", calls, wantCalls)
				}
				return
			}
			requireOK(t, result)
			wantCalls := 0
			if tc.fleetEnabled {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("Python admission calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestManagedMacFleetConfigEnsureKeepsPriorDeploymentOnPythonFailure(t *testing.T) {
	h := newTestHost(t, "darwin")
	payload := h.payload("1.0.0")
	stagedCompiler(t, payload, "print('trusted')\n")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
	previous := h.read(h.env.Layout.ConfigPath)
	configFile := filepath.Join(t.TempDir(), "fleet-enabled.yaml")
	if err := os.WriteFile(configFile, append([]byte(previous), []byte("\nfleet:\n  enabled: true\n")...), 0o640); err != nil {
		t.Fatal(err)
	}
	h.env.MacFleetPythonCheck = func() (string, error) { return "", errors.New("PyYAML unavailable") }
	result := h.run(Options{Action: ActionEnsure, PayloadDir: payload, ConfigFile: configFile})
	requireError(t, result, codeConfig)
	if got := h.read(h.env.Layout.ConfigPath); got != previous {
		t.Fatal("failed Fleet prerequisite changed the active config")
	}
	record, err := h.env.loadDeployment()
	if err != nil || record == nil || record.ConfigSHA256 != sha256Bytes([]byte(previous)) {
		t.Fatalf("failed Fleet prerequisite changed deployment metadata: %v %+v", err, record)
	}
}

func TestManagedLinuxFleetRequiresUsablePythonOnlyWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		name         string
		fleetEnabled bool
		compiler     bool
		pythonError  string
		wantCode     string
	}{
		{name: "disabled ignores Python", compiler: true, pythonError: "Python missing"},
		{name: "enabled rejects absent compiler", fleetEnabled: true, pythonError: "Python missing", wantCode: codePayload},
		{name: "enabled rejects missing Python", fleetEnabled: true, compiler: true, pythonError: "Python missing", wantCode: codeConfig},
		{name: "enabled rejects missing PyYAML", fleetEnabled: true, compiler: true, pythonError: "PyYAML missing", wantCode: codeConfig},
		{name: "enabled accepts usable Python", fleetEnabled: true, compiler: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			payload := h.payload("1.0.0")
			if tc.compiler {
				stagedCompiler(t, payload, "print('trusted')\n")
			}
			calls := 0
			h.env.LinuxFleetPythonCheck = func() (string, error) {
				calls++
				if tc.pythonError != "" {
					return "", errors.New(tc.pythonError)
				}
				return "/usr/bin/python3", nil
			}
			opts := Options{Action: ActionInstall, PayloadDir: payload}
			if tc.fleetEnabled {
				opts.ConfigFile = stagedFleetConfig(t, h)
			}
			result := h.run(opts)
			if tc.wantCode != "" {
				requireError(t, result, tc.wantCode)
				if tc.wantCode == codeConfig && !strings.Contains(messagesOf(result.Errors, codeConfig), tc.pythonError) {
					t.Fatalf("missing prerequisite detail in diagnostic: %+v", result.Errors)
				}
				if record, err := h.env.loadDeployment(); err != nil || record != nil {
					t.Fatalf("failed prerequisite committed deployment: %v %+v", err, record)
				}
			} else {
				requireOK(t, result)
			}
			wantCalls := 0
			if tc.fleetEnabled && tc.compiler {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("Python admission calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}
