//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

type installedSkillScannerFixture struct {
	root, gateway, scanner, marker string
	state                          map[string]any
}

func newInstalledSkillScannerFixture(t *testing.T) installedSkillScannerFixture {
	t.Helper()
	root := t.TempDir()
	commandDir := filepath.Join(root, "commands")
	dataRoot := filepath.Join(root, "custom-data")
	scriptsDir := filepath.Join(dataRoot, ".venv", "Scripts")
	for _, path := range []string{root, commandDir, dataRoot, filepath.Dir(scriptsDir), scriptsDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectDirectory(path); err != nil {
			t.Fatal(err)
		}
	}
	f := installedSkillScannerFixture{
		root: root, gateway: filepath.Join(commandDir, "defenseclaw-gateway.exe"),
		scanner: filepath.Join(scriptsDir, "skill-scanner.exe"),
		marker:  filepath.Join(commandDir, "defenseclaw-hook-state.json"),
		state: map[string]any{
			"schema_version": 1, "install_kind": "powershell-windows", "install_scope": "user",
			"install_root": commandDir, "command_dir": commandDir, "data_root": dataRoot,
		},
	}
	for _, path := range []string{f.gateway, f.scanner} {
		if err := safefile.WritePrivate(path, []byte("installed executable fixture")); err != nil {
			t.Fatal(err)
		}
	}
	f.writeState(t)
	original := skillScannerExecutable
	skillScannerExecutable = func() (string, error) { return f.gateway, nil }
	t.Cleanup(func() { skillScannerExecutable = original })
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	return f
}

func (f installedSkillScannerFixture) writeState(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(f.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(f.marker, data); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultSkillScannerUsesInstalledExecutableInsteadOfPATHShadow(t *testing.T) {
	f := newInstalledSkillScannerFixture(t)
	shadow := filepath.Join(filepath.Dir(f.gateway), "skill-scanner.exe")
	foreign := []byte("unrelated old scanner")
	if err := os.WriteFile(shadow, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(filepath.Dir(f.gateway), "skill-scanner.cmd")
	if err := os.WriteFile(shim, []byte("@echo off\r\n\""+f.scanner+"\" %*\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(shadow))
	t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
	if found, err := exec.LookPath("skill-scanner"); err != nil || found != shadow {
		t.Fatalf("fixture PATH resolves %q, %v; want foreign scanner %q", found, err, shadow)
	}
	for _, name := range []string{"skill-scanner", "skill-scanner.exe"} {
		if got, err := resolveDefaultSkillScanner(name, false); err != nil || got != f.scanner {
			t.Fatalf("resolve(%q) = %q, %v; want managed %q", name, got, err, f.scanner)
		}
	}
	if data, err := os.ReadFile(shadow); err != nil || string(data) != string(foreign) {
		t.Fatalf("unrelated scanner changed: %q, %v", data, err)
	}
}

func TestDefaultSkillScannerRefusesBrokenRecognizedInstallBeforeLaunching(t *testing.T) {
	for _, change := range []string{"malformed", "wrong-root", "relative-data", "missing-scanner", "oversized"} {
		t.Run(change, func(t *testing.T) {
			f := newInstalledSkillScannerFixture(t)
			switch change {
			case "malformed":
				if err := safefile.WritePrivate(f.marker, []byte("not JSON")); err != nil {
					t.Fatal(err)
				}
			case "wrong-root":
				f.state["command_dir"] = filepath.Dir(f.root)
				f.writeState(t)
			case "relative-data":
				f.state["data_root"] = "relative-data"
				f.writeState(t)
			case "missing-scanner":
				if err := os.Remove(f.scanner); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := safefile.WritePrivate(f.marker, []byte(strings.Repeat(" ", (64<<10)+1))); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(f.marker)
			if err != nil {
				t.Fatal(err)
			}
			s := NewSkillScannerFromLLM(config.SkillScannerConfig{}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
			result, err := s.Scan(context.Background(), t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "PATH fallback refused") || result == nil || result.ExitCode != -1 || result.ScanError == "" {
				t.Fatalf("Scan = %+v, %v; want repair refusal before launching a scanner", result, err)
			}
			if after, err := os.ReadFile(f.marker); err != nil || string(after) != string(before) {
				t.Fatalf("installer identity was repaired or changed: %v", err)
			}
		})
	}
}

func TestDefaultSkillScannerPreservesOtherDeploymentAndCommandRoutes(t *testing.T) {
	f := newInstalledSkillScannerFixture(t)
	if err := safefile.WritePrivate(f.marker, []byte("broken identity must never be read by these routes")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{filepath.Join(f.root, "custom.exe"), "custom-scanner"} {
		if got, err := resolveDefaultSkillScanner(command, false); err != nil || got != command {
			t.Fatalf("explicit command = %q, %v; want %q", got, err, command)
		}
	}
	if got, err := resolveDefaultSkillScanner("skill-scanner", true); err != nil || got != "skill-scanner" {
		t.Fatalf("Secure Client resolution = %q, %v", got, err)
	}
	for _, profile := range []string{managed.ProfileStandalone, managed.ProfileSecureClient} {
		t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
		t.Setenv(managed.EnterpriseProfileEnv, profile)
		if got, err := resolveDefaultSkillScanner("skill-scanner", false); err != nil || got != "skill-scanner" {
			t.Fatalf("managed profile %q resolution = %q, %v", profile, got, err)
		}
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	if err := os.Remove(f.marker); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveDefaultSkillScanner("skill-scanner", false); err != nil || got != "skill-scanner" {
		t.Fatalf("unmarked development layout = %q, %v", got, err)
	}
	if err := safefile.WritePrivate(f.marker, []byte("not used by a non-gateway process")); err != nil {
		t.Fatal(err)
	}
	skillScannerExecutable = func() (string, error) { return filepath.Join(f.root, "test-tool.exe"), nil }
	if got, err := resolveDefaultSkillScanner("skill-scanner", false); err != nil || got != "skill-scanner" {
		t.Fatalf("non-gateway process = %q, %v", got, err)
	}
}

func TestDefaultSkillScannerRefusesRedirectedManagedScripts(t *testing.T) {
	f := newInstalledSkillScannerFixture(t)
	scripts := filepath.Dir(f.scanner)
	outside := filepath.Join(f.root, "outside-scripts")
	if err := os.Rename(scripts, outside); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", scripts, outside).CombinedOutput(); err != nil {
		t.Fatalf("create disposable junction: %s: %v", output, err)
	}
	if got, err := resolveDefaultSkillScanner("skill-scanner", false); err == nil || got != "" || !strings.Contains(err.Error(), "redirected") {
		t.Fatalf("redirected managed scanner = %q, %v; want refusal", got, err)
	}
	if data, err := os.ReadFile(filepath.Join(outside, "skill-scanner.exe")); err != nil || string(data) != "installed executable fixture" {
		t.Fatalf("junction target changed: %q, %v", data, err)
	}
}

func TestDefaultSkillScannerPrefersJudgeCompatEntryOnWindows(t *testing.T) {
	f := newInstalledSkillScannerFixture(t)
	compat := filepath.Join(filepath.Dir(f.scanner), "defenseclaw-skill-scanner.exe")
	if err := safefile.WritePrivate(compat, []byte("compat entry fixture")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"skill-scanner", "skill-scanner.exe"} {
		if got, err := resolveDefaultSkillScanner(name, false); err != nil || got != compat {
			t.Fatalf("resolve(%q) = %q, %v; want judge-compat entry %q", name, got, err, compat)
		}
	}
	if got, err := resolveDefaultSkillScanner("skill-scanner", true); err != nil || got != "skill-scanner" {
		t.Fatalf("Secure Client resolution = %q, %v", got, err)
	}
}

func TestDefaultSkillScannerRefusesRedirectedJudgeCompatEntry(t *testing.T) {
	f := newInstalledSkillScannerFixture(t)
	compat := filepath.Join(filepath.Dir(f.scanner), "defenseclaw-skill-scanner.exe")
	target := filepath.Join(f.root, "elsewhere.exe")
	if err := safefile.WritePrivate(target, []byte("foreign")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, compat); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if got, err := resolveDefaultSkillScanner("skill-scanner", false); err == nil || got != "" || !strings.Contains(err.Error(), "PATH fallback refused") {
		t.Fatalf("redirected compat entry = %q, %v; want refusal", got, err)
	}
}
