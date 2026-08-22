// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"gopkg.in/yaml.v3"
)

func TestHookOnlyConnector_CapabilityMatrix(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), WorkspaceDir: t.TempDir()}
	cases := []struct {
		conn       *hookOnlyConnector
		canBlock   bool
		canAsk     bool
		failClosed bool
		scope      string
		configBase string
	}{
		{NewHermesConnector(), true, false, false, "user", "config.yaml"},
		{NewCursorConnector(), true, false, true, "user", "hooks.json"},
		{NewWindsurfConnector(), true, false, true, "user", "hooks.json"},
		{NewGeminiCLIConnector(), true, false, true, "user", "settings.json"},
		{NewCopilotConnector(), true, true, false, "user,workspace", "defenseclaw.json"},
		{NewOpenHandsConnector(), true, false, true, "user,workspace", "hooks.json"},
		{NewAntigravityConnector(), true, true, false, "user", "hooks.json"},
	}
	for _, tc := range cases {
		t.Run(tc.conn.Name(), func(t *testing.T) {
			caps := tc.conn.HookCapabilities(opts)
			if caps.CanBlock != tc.canBlock {
				t.Fatalf("CanBlock = %v, want %v", caps.CanBlock, tc.canBlock)
			}
			if caps.CanAskNative != tc.canAsk {
				t.Fatalf("CanAskNative = %v, want %v", caps.CanAskNative, tc.canAsk)
			}
			if caps.SupportsFailClosed != tc.failClosed {
				t.Fatalf("SupportsFailClosed = %v, want %v", caps.SupportsFailClosed, tc.failClosed)
			}
			if caps.Scope != tc.scope {
				t.Fatalf("Scope = %q, want %q", caps.Scope, tc.scope)
			}
			if filepath.Base(caps.ConfigPath) != tc.configBase {
				t.Fatalf("ConfigPath = %q, want basename %q", caps.ConfigPath, tc.configBase)
			}
		})
	}
}

func TestHardeningJQFallbackRejectsStructuredOutputWithoutParser(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	emptyPath := filepath.Join(dir, "empty-path")
	if err := os.Mkdir(emptyPath, 0o700); err != nil {
		t.Fatalf("create empty PATH: %v", err)
	}
	cmd := exec.Command("/bin/bash", "-c", `. "$1"; _dc_jq -c '.hook_output // empty'`, "bash", helperPath)
	cmd.Env = []string{"HOME=" + dir, "PATH=" + emptyPath}
	cmd.Stdin = strings.NewReader(`{"hook_output":{"permissionDecision":"deny"}}`)
	if err := cmd.Run(); err == nil {
		t.Fatal("structured output was accepted without jq or python3")
	}
}

func TestHardeningJQFallbackPreservesStringDefault(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	helperPath := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && { [ "$2" = "jq" ] || [ "$2" = "python3" ]; }; then
    return 1
  fi
  builtin command "$@"
}
printf '{}' | _dc_jq -r '.action//"allow"'
value="$(printf '{"reason":""}' | _dc_jq -r '.reason // "fallback"')"
printf '<%s>\n' "$value"
printf '{}' | _dc_jq -r '.reason // null'
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run shell fallback: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "allow\n<>\nnull" {
		t.Fatalf("fallback output = %q, want no-space default plus preserved empty string", got)
	}
}

func TestHardeningJQFallbackRejectsExplicitNonStringField(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	helperPath := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && { [ "$2" = "jq" ] || [ "$2" = "python3" ]; }; then
    return 1
  fi
  builtin command "$@"
}
printf '{"action":null}' | _dc_jq -r '.action // "allow"'
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("explicit non-string action used the allow default: %q", out)
	}
}

func TestHardeningJQFallbackEmptyProducesNoOutput(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	helperPath := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && { [ "$2" = "jq" ] || [ "$2" = "python3" ]; }; then
    return 1
  fi
  builtin command "$@"
}
printf '{}' | _dc_jq -r '.action // empty'
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run shell fallback: %v: %s", err, out)
	}
	if len(out) != 0 {
		t.Fatalf("empty fallback output = %q, want zero bytes", out)
	}
}

func TestHardeningJQFallbackOnlyReadsTopLevelFields(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	helperPath := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && { [ "$2" = "jq" ] || [ "$2" = "python3" ]; }; then
    return 1
  fi
  builtin command "$@"
}
printf '{"nested":{"action":"allow"},"action":"deny"}' | _dc_jq -r '.action // "allow"'
printf '{"nested":{"action":"deny"}}' | _dc_jq -r '.action // "allow"'
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run shell fallback: %v: %s", err, out)
	}
	if got := string(out); got != "deny\nallow\n" {
		t.Fatalf("top-level fallback output = %q, want deny then absent-field default", got)
	}
}

func TestHermesConfigPathHonorsHermesHomeAndExplicitOverride(t *testing.T) {
	hermesHome := filepath.Join(t.TempDir(), "Hermes Home")
	t.Setenv("HERMES_HOME", hermesHome)

	previous := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	if got, want := hermesConfigPath(SetupOpts{}), filepath.Join(hermesHome, "config.yaml"); got != want {
		t.Fatalf("hermesConfigPath() = %q, want %q", got, want)
	}
	caps := NewHermesConnector().Capabilities(SetupOpts{})
	if got, want := caps.Skills.ReadPaths, []string{filepath.Join(hermesHome, "skills")}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("Hermes skill paths = %v, want %v", got, want)
	}
	if !caps.Plugins.Supported || !caps.Plugins.DiscoveryOnly || len(caps.Plugins.WritePaths) != 0 {
		t.Fatalf("Hermes plugins must be read-only discovery: %+v", caps.Plugins)
	}

	explicit := filepath.Join(t.TempDir(), "explicit-config.yaml")
	HermesConfigPathOverride = explicit
	if got := hermesConfigPath(SetupOpts{}); got != explicit {
		t.Fatalf("HermesConfigPathOverride lost precedence: got %q, want %q", got, explicit)
	}
}

func TestHermesUnavailableConfigCapabilitiesKeepPluginsDiscoveryOnly(t *testing.T) {
	previousOverride := HermesConfigPathOverride
	previousResolver := hermesConfigPathResolver
	HermesConfigPathOverride = ""
	hermesConfigPathResolver = func() string { return "" }
	t.Cleanup(func() {
		HermesConfigPathOverride = previousOverride
		hermesConfigPathResolver = previousResolver
	})

	caps := NewHermesConnector().Capabilities(SetupOpts{})
	if !caps.Plugins.Supported || !caps.Plugins.DiscoveryOnly || len(caps.Plugins.WritePaths) != 0 {
		t.Fatalf("Hermes plugins must remain read-only discovery when config is unavailable: %+v", caps.Plugins)
	}
}

func TestHermesConfigPathUsesWindowsLocalAppData(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows Hermes path")
	}
	t.Setenv("HERMES_HOME", "")

	previous := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	want := hermesConfigPath(SetupOpts{})
	if want == "" {
		t.Fatal("current-token LocalAppData was not resolved")
	}
	t.Setenv("LOCALAPPDATA", filepath.Join(t.TempDir(), "poisoned Local AppData"))
	if got := hermesConfigPath(SetupOpts{}); got != want {
		t.Fatalf("hermesConfigPath() changed with inherited LOCALAPPDATA: got %q, want %q", got, want)
	}
}

func TestHermesSetupRejectsUnavailableOrRelativeWindowsConfigBeforeInspectionOrMutation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows fail-before-mutation path guard")
	}
	for _, test := range []struct {
		name        string
		configPath  string
		wantError   string
		useResolver bool
	}{
		{name: "unavailable current-token LocalAppData", wantError: "config path is unavailable", useResolver: true},
		{name: "relative returned config path", configPath: filepath.Join("relative-hermes", "config.yaml"), wantError: "absolute normalized Windows path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			cwd := filepath.Join(root, "cwd")
			if err := os.MkdirAll(cwd, 0o700); err != nil {
				t.Fatal(err)
			}
			// If profile validation reached cwd (the historical filepath.Dir("")
			// behavior), this sentinel would produce the named-profile error.
			activeProfile := filepath.Join(cwd, "active_profile")
			activeProfileBody := []byte("must-not-be-inspected\n")
			if err := os.WriteFile(activeProfile, activeProfileBody, 0o600); err != nil {
				t.Fatal(err)
			}
			allowlist := filepath.Join(cwd, hermesAllowlistFileName)
			allowlistBody := []byte("{\"approvals\":[],\"operator\":\"unchanged\"}\n")
			if err := os.WriteFile(allowlist, allowlistBody, 0o600); err != nil {
				t.Fatal(err)
			}
			expectedFiles := map[string][]byte{
				activeProfile: activeProfileBody,
				allowlist:     allowlistBody,
			}
			if test.configPath != "" {
				relativeHome := filepath.Join(cwd, filepath.Dir(test.configPath))
				if err := os.MkdirAll(relativeHome, 0o700); err != nil {
					t.Fatal(err)
				}
				relativeConfig := filepath.Join(cwd, test.configPath)
				relativeConfigBody := []byte("operator_literal: KEEP-CONFIG-BYTES\n")
				if err := os.WriteFile(relativeConfig, relativeConfigBody, 0o600); err != nil {
					t.Fatal(err)
				}
				relativeAllowlist := filepath.Join(relativeHome, hermesAllowlistFileName)
				relativeAllowlistBody := []byte("{\"approvals\":[],\"operator\":\"KEEP-ALLOWLIST-BYTES\"}\n")
				if err := os.WriteFile(relativeAllowlist, relativeAllowlistBody, 0o600); err != nil {
					t.Fatal(err)
				}
				expectedFiles[relativeConfig] = relativeConfigBody
				expectedFiles[relativeAllowlist] = relativeAllowlistBody
			}
			t.Chdir(cwd)

			previousOverride := HermesConfigPathOverride
			previousResolver := hermesConfigPathResolver
			resolverCalls := 0
			HermesConfigPathOverride = test.configPath
			if test.useResolver {
				HermesConfigPathOverride = ""
				hermesConfigPathResolver = func() string {
					resolverCalls++
					return ""
				}
			}
			t.Cleanup(func() {
				HermesConfigPathOverride = previousOverride
				hermesConfigPathResolver = previousResolver
			})

			dataDir := filepath.Join(root, "defenseclaw-data")
			err := NewHermesConnector().Setup(context.Background(), SetupOpts{DataDir: dataDir})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Setup error = %v, want %q", err, test.wantError)
			}
			if test.useResolver && resolverCalls != 1 {
				t.Fatalf("Setup resolved Hermes config %d times, want exactly once", resolverCalls)
			}
			if strings.Contains(err.Error(), "named profile") {
				t.Fatalf("Setup inspected cwd profile before path rejection: %v", err)
			}
			if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
				t.Fatalf("Setup mutated hook/backup/data state before path rejection: %v", statErr)
			}
			for path, want := range expectedFiles {
				got, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s mutated before path rejection: got %q want %q", path, got, want)
				}
			}
		})
	}
}

func TestHermesTeardownAndAgentPathsRejectUnavailableOrRelativeWindowsConfigBeforeMutation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows teardown fail-before-mutation path guard")
	}
	for _, test := range []struct {
		name        string
		configPath  string
		wantError   string
		useResolver bool
	}{
		{name: "unavailable current-token LocalAppData", wantError: "config path is unavailable", useResolver: true},
		{name: "relative returned config path", configPath: filepath.Join("relative-hermes", "config.yaml"), wantError: "absolute normalized Windows path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			cwd := filepath.Join(root, "cwd")
			dataDir := filepath.Join(root, "defenseclaw-data")
			if err := os.MkdirAll(cwd, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			dataSentinel := filepath.Join(dataDir, "operator-state.bin")
			dataSentinelBody := []byte("KEEP-DATA-BYTES\x00\x01\n")
			if err := os.WriteFile(dataSentinel, dataSentinelBody, 0o600); err != nil {
				t.Fatal(err)
			}
			cwdConfig := filepath.Join(cwd, "config.yaml")
			cwdConfigBody := []byte("operator_literal: KEEP-CWD-CONFIG-BYTES\n")
			cwdAllowlist := filepath.Join(cwd, hermesAllowlistFileName)
			cwdAllowlistBody := []byte("{\"approvals\":[],\"operator\":\"KEEP-CWD-ALLOWLIST-BYTES\"}\n")
			for path, body := range map[string][]byte{
				cwdConfig:    cwdConfigBody,
				cwdAllowlist: cwdAllowlistBody,
			} {
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			expectedFiles := map[string][]byte{
				dataSentinel: dataSentinelBody,
				cwdConfig:    cwdConfigBody,
				cwdAllowlist: cwdAllowlistBody,
			}
			if test.configPath != "" {
				relativeHome := filepath.Join(cwd, filepath.Dir(test.configPath))
				if err := os.MkdirAll(relativeHome, 0o700); err != nil {
					t.Fatal(err)
				}
				relativeConfig := filepath.Join(cwd, test.configPath)
				relativeConfigBody := []byte("operator_literal: KEEP-RELATIVE-CONFIG-BYTES\n")
				relativeAllowlist := filepath.Join(relativeHome, hermesAllowlistFileName)
				relativeAllowlistBody := []byte("{\"approvals\":[],\"operator\":\"KEEP-RELATIVE-ALLOWLIST-BYTES\"}\n")
				for path, body := range map[string][]byte{
					relativeConfig:    relativeConfigBody,
					relativeAllowlist: relativeAllowlistBody,
				} {
					if err := os.WriteFile(path, body, 0o600); err != nil {
						t.Fatal(err)
					}
					expectedFiles[path] = body
				}
			}
			t.Chdir(cwd)

			previousOverride := HermesConfigPathOverride
			previousResolver := hermesConfigPathResolver
			resolverCalls := 0
			HermesConfigPathOverride = test.configPath
			if test.useResolver {
				HermesConfigPathOverride = ""
				hermesConfigPathResolver = func() string {
					resolverCalls++
					return ""
				}
			}
			t.Cleanup(func() {
				HermesConfigPathOverride = previousOverride
				hermesConfigPathResolver = previousResolver
			})

			conn := NewHermesConnector()
			opts := SetupOpts{DataDir: dataDir}
			if paths := conn.AgentPaths(opts); len(paths.PatchedFiles) != 0 ||
				len(paths.BackupFiles) != 0 || len(paths.HookScripts) != 0 {
				t.Fatalf("AgentPaths returned relative/unavailable Hermes paths: %+v", paths)
			}
			if test.useResolver && resolverCalls != 1 {
				t.Fatalf("AgentPaths resolved Hermes config %d times, want exactly once", resolverCalls)
			}
			beforeTeardownResolve := resolverCalls
			err := conn.Teardown(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Teardown error = %v, want %q", err, test.wantError)
			}
			if test.useResolver && resolverCalls != beforeTeardownResolve+1 {
				t.Fatalf("Teardown resolved Hermes config %d times, want exactly once", resolverCalls-beforeTeardownResolve)
			}
			for path, want := range expectedFiles {
				got, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s mutated before path rejection: got %q want %q", path, got, want)
				}
			}
			for _, path := range []string{
				filepath.Join(dataDir, ".hermes-lifecycle.lock"),
				filepath.Join(dataDir, "hooks", hermesDirectNativeStateFileName),
				filepath.Join(dataDir, "hooks", "hermes-hook.sh"),
				managedFileBackupPath(dataDir, "hermes", "config"),
				managedFileBackupPath(dataDir, "hermes", "config.yaml"),
				managedFileBackupPath(dataDir, "hermes", hermesAllowlistLogicalName),
			} {
				if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
					t.Fatalf("Teardown created lifecycle artifact before path rejection at %s: %v", path, statErr)
				}
			}
		})
	}
}

func TestSetupHermesFilesRejectsInvalidWindowsPathBeforeAllowlistDerivation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows fail-before-mutation path guard")
	}
	root := testenv.PrivateTempDir(t)
	t.Chdir(root)
	cwdAllowlist := filepath.Join(root, hermesAllowlistFileName)
	cwdAllowlistBody := []byte("{\"approvals\":[],\"operator\":\"unchanged\"}\n")
	if err := os.WriteFile(cwdAllowlist, cwdAllowlistBody, 0o600); err != nil {
		t.Fatal(err)
	}
	relativeHome := filepath.Join(root, "relative-hermes")
	if err := os.MkdirAll(relativeHome, 0o700); err != nil {
		t.Fatal(err)
	}
	relativeConfig := filepath.Join(relativeHome, "config.yaml")
	relativeConfigBody := []byte("operator_literal: KEEP-CONFIG-BYTES\n")
	if err := os.WriteFile(relativeConfig, relativeConfigBody, 0o600); err != nil {
		t.Fatal(err)
	}
	relativeAllowlist := filepath.Join(relativeHome, hermesAllowlistFileName)
	relativeAllowlistBody := []byte("{\"approvals\":[],\"operator\":\"KEEP-ALLOWLIST-BYTES\"}\n")
	if err := os.WriteFile(relativeAllowlist, relativeAllowlistBody, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, configPath := range []string{"", filepath.Join("relative-hermes", "config.yaml")} {
		dataDir := filepath.Join(root, "data-"+strings.ReplaceAll(configPath, string(filepath.Separator), "-"))
		err := setupHermesFiles(SetupOpts{DataDir: dataDir}, configPath, "hook-command")
		if err == nil || (!strings.Contains(err.Error(), "unavailable") && !strings.Contains(err.Error(), "absolute normalized")) {
			t.Fatalf("setupHermesFiles(%q) error = %v, want path rejection", configPath, err)
		}
		if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
			t.Fatalf("setupHermesFiles(%q) mutated data state: %v", configPath, statErr)
		}
	}
	for path, want := range map[string][]byte{
		cwdAllowlist:      cwdAllowlistBody,
		relativeConfig:    relativeConfigBody,
		relativeAllowlist: relativeAllowlistBody,
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s changed after invalid path rejection: got %q want %q", path, got, want)
		}
	}
}

// TestHardeningPython3UsableRefusesMacosCLTStub pins the QA regression
// where a stock macOS host without Xcode Command Line Tools resolves
// python3 to the /usr/bin/python3 CLT launcher stub. A bare
// `command -v python3` treats that stub as usable; invoking it pops
// the "install command line developer tools" GUI dialog and returns
// no body, which then propagates as an empty payload / HTTP 400 into
// the codex hook and blocks the user's prompt.
//
// _dc_python3_usable must refuse the stub by cross-checking
// `xcode-select -p` (a safe macOS system call that does not trigger
// the installer dialog).
func TestHardeningPython3UsableRefusesMacosCLTStub(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	// Simulate stock macOS without CLT:
	//   - command -v python3 -> /usr/bin/python3 (the launcher stub)
	//   - uname -s -> Darwin
	//   - xcode-select -p -> exit 2 (CLT missing)
	// _dc_python3_usable must return non-zero. If it returns 0, the
	// caller would invoke /usr/bin/python3 and the QA popup returns.
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && [ "$2" = "python3" ]; then
    printf '/usr/bin/python3\n'
    return 0
  fi
  builtin command "$@"
}
uname() { printf 'Darwin\n'; }
xcode-select() { return 2; }
if _dc_python3_usable; then
  echo STUB_ACCEPTED
  exit 1
fi
echo STUB_REFUSED
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run stub-refusal probe: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "STUB_REFUSED" {
		t.Fatalf("_dc_python3_usable accepted the /usr/bin/python3 CLT stub without CLT installed: %q", got)
	}
}

// TestHardeningPython3UsableAcceptsMacosCLTInstalled asserts the other
// half of the contract: on macOS with CLT actually installed
// (xcode-select -p succeeds), _dc_python3_usable trusts
// /usr/bin/python3 as a real interpreter and returns 0 so the
// preferred tier-1 python3 path in defenseclaw_read_stdin_capped and
// the _dc_jq shim remain in use.
func TestHardeningPython3UsableAcceptsMacosCLTInstalled(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && [ "$2" = "python3" ]; then
    printf '/usr/bin/python3\n'
    return 0
  fi
  builtin command "$@"
}
uname() { printf 'Darwin\n'; }
xcode-select() { printf '/Library/Developer/CommandLineTools\n'; return 0; }
if _dc_python3_usable; then
  echo REAL_ACCEPTED
  exit 0
fi
echo REAL_REJECTED
exit 1
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("_dc_python3_usable refused python3 despite CLT installed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "REAL_ACCEPTED" {
		t.Fatalf("_dc_python3_usable did not accept real /usr/bin/python3 with CLT: %q", got)
	}
}

// TestHardeningPython3UsableAcceptsHomebrewPython covers the case
// where the operator has installed python3 outside the CLT-managed
// /usr/bin path (typical for homebrew, pyenv, asdf, etc.). Only
// /usr/bin/python3 on Darwin is a CLT launcher stub — everything
// else is trusted at face value regardless of xcode-select state.
func TestHardeningPython3UsableAcceptsHomebrewPython(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && [ "$2" = "python3" ]; then
    printf '/usr/local/bin/python3\n'
    return 0
  fi
  builtin command "$@"
}
uname() { printf 'Darwin\n'; }
xcode-select() { return 2; }
if _dc_python3_usable; then
  echo BREW_ACCEPTED
  exit 0
fi
echo BREW_REJECTED
exit 1
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("_dc_python3_usable refused non-/usr/bin python3: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "BREW_ACCEPTED" {
		t.Fatalf("_dc_python3_usable did not accept /usr/local/bin/python3 on Darwin: %q", got)
	}
}

// TestHardeningPython3UsableSkipsXcodeSelectOffDarwin asserts that
// the CLT stub check is Darwin-only. On Linux hosts we do not consult
// xcode-select at all — python3 is a first-class binary there and a
// failing (or missing) xcode-select must not gate the python3 tier.
func TestHardeningPython3UsableSkipsXcodeSelectOffDarwin(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && [ "$2" = "python3" ]; then
    printf '/usr/bin/python3\n'
    return 0
  fi
  builtin command "$@"
}
uname() { printf 'Linux\n'; }
xcode-select() { echo "xcode-select must not be consulted on Linux" >&2; return 127; }
if _dc_python3_usable; then
  echo LINUX_ACCEPTED
  exit 0
fi
echo LINUX_REJECTED
exit 1
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("_dc_python3_usable rejected python3 on Linux: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "LINUX_ACCEPTED" {
		t.Fatalf("_dc_python3_usable did not accept /usr/bin/python3 on Linux: %q", got)
	}
}

// TestHardeningPython3UsableRejectsAbsentPython3 asserts the base
// case: when python3 is not on PATH at all, _dc_python3_usable
// returns non-zero regardless of platform. This is the pre-existing
// contract for the tier-2 head(1) fallback in
// defenseclaw_read_stdin_capped and the string-only tail in _dc_jq.
func TestHardeningPython3UsableRejectsAbsentPython3(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	script := `. "$1"
command() {
  if [ "$1" = "-v" ] && [ "$2" = "python3" ]; then
    return 1
  fi
  builtin command "$@"
}
if _dc_python3_usable; then
  echo ACCEPTED_MISSING
  exit 1
fi
echo REJECTED_MISSING
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run absent-python3 probe: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "REJECTED_MISSING" {
		t.Fatalf("_dc_python3_usable accepted absent python3: %q", got)
	}
}

// TestHardeningReadStdinCappedSkipsPython3StubOnStockMacos is the
// integration guard: defenseclaw_read_stdin_capped must fall through
// to the head(1) tier (tier 2) when python3 resolves to the macOS
// CLT stub, instead of invoking the stub and returning an empty body.
//
// If this test regresses, the codex hook on stock macOS will post an
// empty payload to the gateway, get HTTP 400, and block the user's
// prompt with "codex hook error: gateway returned HTTP 400" — the
// exact QA-reported failure this fix addresses.
func TestHardeningReadStdinCappedSkipsPython3StubOnStockMacos(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	// A python3 impostor that would empty stdin and exit non-zero if
	// invoked — mirrors the macOS CLT stub's observed behaviour. If
	// _dc_python3_usable incorrectly says "yes", this stub runs and
	// the captured body is empty; the assertion below fails.
	stubDir := filepath.Join(dir, "stub-bin")
	if err := os.Mkdir(stubDir, 0o755); err != nil {
		t.Fatalf("mkdir stub-bin: %v", err)
	}
	stubPython := filepath.Join(stubDir, "python3")
	stubBody := "#!/bin/bash\n" +
		"# Behaves like the macOS CLT launcher stub: consumes nothing,\n" +
		"# prints the developer-tools note to stderr, exits non-zero.\n" +
		"echo 'xcode-select: note: No developer tools were found, requesting install.' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(stubPython, []byte(stubBody), 0o755); err != nil {
		t.Fatalf("write python3 stub: %v", err)
	}
	script := `. "$1"
# Point command -v python3 at the stub we control, and mask xcode-select
# so _dc_python3_usable classifies it as the CLT launcher.
command() {
  if [ "$1" = "-v" ] && [ "$2" = "python3" ]; then
    printf '/usr/bin/python3\n'
    return 0
  fi
  builtin command "$@"
}
uname() { printf 'Darwin\n'; }
xcode-select() { return 2; }
PATH="$2:$PATH"
BODY="$(defenseclaw_read_stdin_capped)"
printf 'BODY=<%s>\n' "$BODY"
`
	cmd := exec.Command("/bin/bash", "-c", script, "bash", helperPath, stubDir)
	cmd.Stdin = strings.NewReader("hello-world")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run stdin-capped probe: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "BODY=<hello-world>") {
		t.Fatalf("defenseclaw_read_stdin_capped invoked the CLT stub and lost the body:\n%s", out)
	}
}

func TestHookOnlyConnector_SurfaceCapabilities(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), WorkspaceDir: t.TempDir(), APIAddr: "127.0.0.1:18970"}
	cases := []struct {
		conn             *hookOnlyConnector
		codeGuardTargets []string
		nativeOTLP       bool
		pluginsSupported bool
		// mcpSupported is true for connectors that expose a documented
		// MCP install surface.
		mcpSupported bool
	}{
		{NewHermesConnector(), []string{"skill"}, false, true, true},
		{NewCursorConnector(), []string{"skill", "rule"}, false, true, true},
		{NewWindsurfConnector(), []string{"rule"}, false, false, true},
		{NewGeminiCLIConnector(), []string{"skill"}, true, true, true},
		{NewCopilotConnector(), []string{"skill", "rule"}, false, true, true},
		{NewOpenHandsConnector(), []string{"skill"}, runtime.GOOS == "darwin", false, true},
		{NewAntigravityConnector(), nil, false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.conn.Name(), func(t *testing.T) {
			caps := tc.conn.Capabilities(opts)
			if caps.MCP.Supported != tc.mcpSupported {
				t.Fatalf("MCP.Supported = %v, want %v", caps.MCP.Supported, tc.mcpSupported)
			}
			if caps.CodeGuard.Supported != (len(tc.codeGuardTargets) > 0) {
				t.Fatalf("CodeGuard.Supported = %v", caps.CodeGuard.Supported)
			}
			if strings.Join(caps.CodeGuard.InstallTargets, ",") != strings.Join(tc.codeGuardTargets, ",") {
				t.Fatalf("CodeGuard.InstallTargets = %v, want %v", caps.CodeGuard.InstallTargets, tc.codeGuardTargets)
			}
			if caps.CodeGuard.AutoInstall {
				t.Fatal("CodeGuard.AutoInstall = true, want explicit opt-in")
			}
			if caps.Telemetry.NativeOTLP != tc.nativeOTLP {
				t.Fatalf("Telemetry.NativeOTLP = %v, want %v", caps.Telemetry.NativeOTLP, tc.nativeOTLP)
			}
			if caps.Plugins.Supported != tc.pluginsSupported {
				t.Fatalf("Plugins.Supported = %v, want %v", caps.Plugins.Supported, tc.pluginsSupported)
			}
		})
	}
}

func TestWindsurfConnector_CascadeOnlyInventorySurfaces(t *testing.T) {
	t.Setenv("WINDSURF_USER_HOME", "")
	t.Setenv("WINDSURF_HOOK_CONFIG_PATH", "")
	home := filepath.Join(t.TempDir(), "bound-profile")
	workspace := filepath.Join(t.TempDir(), "repo")
	err := WithUserHomeDir(home, func() error {
		caps := NewWindsurfConnector().Capabilities(SetupOpts{WorkspaceDir: workspace})
		wantMCP := []string{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")}
		if !caps.MCP.Supported || !caps.MCP.DiscoveryOnly || !sameStrings(caps.MCP.ReadPaths, wantMCP) {
			return fmt.Errorf("Windsurf MCP capability = %+v, want bound legacy Cascade path %v", caps.MCP, wantMCP)
		}
		for _, path := range caps.MCP.ReadPaths {
			if filepath.Base(path) == "mcp.json" {
				return fmt.Errorf("undocumented guessed MCP path remains: %q", path)
			}
		}
		wantSkills := []string{
			filepath.Join(home, ".codeium", "windsurf", "skills"),
			filepath.Join(home, ".agents", "skills"),
			filepath.Join(workspace, ".windsurf", "skills"),
			filepath.Join(workspace, ".agents", "skills"),
		}
		if !caps.Skills.Supported || !caps.Skills.DiscoveryOnly || !sameStrings(caps.Skills.ReadPaths, wantSkills) {
			return fmt.Errorf("Windsurf skills capability = %+v, want %v", caps.Skills, wantSkills)
		}
		rulePaths := strings.Join(caps.Rules.ReadPaths, "\n")
		for _, want := range []string{"global_rules.md", ".devin", ".windsurf", ".windsurfrules", "AGENTS.md"} {
			if !strings.Contains(rulePaths, want) {
				return fmt.Errorf("Windsurf rule paths %v missing %q", caps.Rules.ReadPaths, want)
			}
		}
		notes := strings.Join(append(append([]string{}, caps.MCP.Notes...), caps.Rules.Notes...), " ")
		for _, want := range []string{"Devin Local", "ProgramData", "unverified"} {
			if !strings.Contains(notes, want) {
				return fmt.Errorf("Windsurf capability notes %q missing %q", notes, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWindsurfConnector_UsesOnePersistedProfileForHooksAndInventory(t *testing.T) {
	previousOverride := WindsurfHooksPathOverride
	WindsurfHooksPathOverride = ""
	t.Cleanup(func() { WindsurfHooksPathOverride = previousOverride })

	bound := filepath.Join(t.TempDir(), "windsurf-profile")
	hooks := filepath.Join(bound, ".codeium", "windsurf", "hooks.json")
	t.Setenv("WINDSURF_USER_HOME", bound)
	t.Setenv("WINDSURF_HOOK_CONFIG_PATH", hooks)
	conn := NewWindsurfConnector()
	opts := SetupOpts{WorkspaceDir: filepath.Join(t.TempDir(), "workspace")}

	if got := windsurfHooksPath(opts); got != hooks {
		t.Fatalf("hooks path = %q, want persisted binding %q", got, hooks)
	}
	caps := conn.Capabilities(opts)
	profilePaths := append([]string{}, caps.MCP.ReadPaths...)
	profilePaths = append(profilePaths, caps.Skills.ReadPaths[:2]...)
	profilePaths = append(profilePaths, caps.Rules.ReadPaths[0])
	for _, path := range profilePaths {
		if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(bound)+string(filepath.Separator)) {
			t.Fatalf("inventory path escaped persisted profile: %q", path)
		}
	}

	t.Setenv("WINDSURF_HOOK_CONFIG_PATH", filepath.Join(t.TempDir(), "other", "hooks.json"))
	if got := windsurfHooksPath(opts); got != "" {
		t.Fatalf("mismatched hook binding resolved to %q, want fail-closed empty path", got)
	}
	if err := conn.Setup(context.Background(), SetupOpts{DataDir: t.TempDir()}); err == nil ||
		!strings.Contains(err.Error(), "WINDSURF_HOOK_CONFIG_PATH does not match") {
		t.Fatalf("Setup path mismatch error = %v", err)
	}
}

func TestWindsurfOwnedHooksPresent_RequiresExactTwelveEventContract(t *testing.T) {
	for _, goos := range []string{"windows", "linux"} {
		t.Run(goos, func(t *testing.T) {
			previousOverride := WindsurfHooksPathOverride
			path := filepath.Join(t.TempDir(), "hooks.json")
			WindsurfHooksPathOverride = path
			t.Cleanup(func() { WindsurfHooksPathOverride = previousOverride })

			conn := NewWindsurfConnector()
			opts := SetupOpts{DataDir: t.TempDir()}
			command := conn.hookCommandForOS(goos, opts)
			entry := map[string]interface{}{"show_output": true}
			if goos == "windows" {
				entry["powershell"] = command
			} else {
				entry["command"] = shellWord(command)
			}
			hooks := make(map[string]interface{}, len(windsurfCascadeHookEvents))
			for _, event := range windsurfCascadeHookEvents {
				hooks[event] = []interface{}{
					map[string]interface{}{"command": "operator-hook"},
					maps.Clone(entry),
				}
			}
			cfg := map[string]interface{}{"hooks": hooks}
			writeFixture := func() {
				t.Helper()
				body, err := json.MarshalIndent(cfg, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeFixture()
			present, err := windsurfOwnedHooksPresentForOS(conn, opts, goos)
			if err != nil || !present {
				t.Fatalf("complete Cascade contract = %v, %v; want true", present, err)
			}

			delete(hooks, windsurfCascadeHookEvents[len(windsurfCascadeHookEvents)-1])
			writeFixture()
			present, err = windsurfOwnedHooksPresentForOS(conn, opts, goos)
			if err != nil || present {
				t.Fatalf("eleven-event Cascade contract = %v, %v; want false", present, err)
			}

			if goos == "windows" {
				hooks[windsurfCascadeHookEvents[len(windsurfCascadeHookEvents)-1]] = []interface{}{maps.Clone(entry)}
				managed := hooks[windsurfCascadeHookEvents[0]].([]interface{})[1].(map[string]interface{})
				managed["command"] = command
				writeFixture()
				present, err = windsurfOwnedHooksPresentForOS(conn, opts, goos)
				if err != nil || present {
					t.Fatalf("Windows fallback-bearing contract = %v, %v; want false", present, err)
				}

				delete(managed, "command")
				hooks[windsurfCascadeHookEvents[0]] = append(
					hooks[windsurfCascadeHookEvents[0]].([]interface{}),
					map[string]interface{}{"command": command, "show_output": true},
				)
				writeFixture()
				present, err = windsurfOwnedHooksPresentForOS(conn, opts, goos)
				if err != nil || present {
					t.Fatalf("separate Windows fallback contract = %v, %v; want false", present, err)
				}
			}
		})
	}
}

func TestCursorConnector_InventoryOnlyPluginAndSubagentCapabilities(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	workspace := filepath.Join(dir, "repo")
	testenv.SetHome(t, home)

	caps := NewCursorConnector().Capabilities(SetupOpts{WorkspaceDir: workspace})

	wantPlugins := []string{filepath.Join(home, ".cursor", "plugins", "local")}
	if !caps.Plugins.Supported || !caps.Plugins.DiscoveryOnly || !sameStrings(caps.Plugins.ReadPaths, wantPlugins) {
		t.Fatalf("Cursor plugin inventory capability drifted: %+v", caps.Plugins)
	}
	if len(caps.Plugins.WritePaths) != 0 || len(caps.Plugins.InstallTargets) != 0 {
		t.Fatalf("Cursor plugins must remain inventory-only: %+v", caps.Plugins)
	}

	wantAgents := []string{
		filepath.Join(workspace, ".cursor", "agents"),
		filepath.Join(workspace, ".claude", "agents"),
		filepath.Join(workspace, ".codex", "agents"),
		filepath.Join(home, ".cursor", "agents"),
		filepath.Join(home, ".claude", "agents"),
		filepath.Join(home, ".codex", "agents"),
	}
	if !caps.Agents.Supported || !caps.Agents.DiscoveryOnly || !sameStrings(caps.Agents.ReadPaths, wantAgents) {
		t.Fatalf("Cursor subagent inventory capability drifted: %+v", caps.Agents)
	}
	if len(caps.Agents.WritePaths) != 0 || len(caps.Agents.InstallTargets) != 0 {
		t.Fatalf("Cursor subagents must remain inventory-only: %+v", caps.Agents)
	}
}

func TestOpenHandsConnector_CapabilityContract(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	workspace := filepath.Join(dir, "repo")
	persistence := filepath.Join(dir, "openhands-persistence")
	testenv.SetHome(t, home)
	t.Setenv("OPENHANDS_PERSISTENCE_DIR", persistence)

	previousWorkspace := OpenHandsWorkspaceDirOverride
	OpenHandsWorkspaceDirOverride = ""
	t.Cleanup(func() { OpenHandsWorkspaceDirOverride = previousWorkspace })

	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "defenseclaw"),
		WorkspaceDir: workspace,
		APIAddr:      "127.0.0.1:18970",
	}
	caps := NewOpenHandsConnector().Capabilities(opts)

	wantMCP := []string{filepath.Join(persistence, "mcp.json")}
	if !caps.MCP.Supported || !sameStrings(caps.MCP.ConfigPaths, wantMCP) ||
		!sameStrings(caps.MCP.ReadPaths, wantMCP) || !sameStrings(caps.MCP.WritePaths, wantMCP) {
		t.Fatalf("OpenHands persistence-root MCP capability drifted: %+v", caps.MCP)
	}
	t.Setenv("OPENHANDS_PERSISTENCE_DIR", "")
	fallback := NewOpenHandsConnector().Capabilities(opts).MCP
	if want := []string{filepath.Join(home, ".openhands", "mcp.json")}; !sameStrings(fallback.ConfigPaths, want) {
		t.Fatalf("OpenHands default MCP path = %v, want %v", fallback.ConfigPaths, want)
	}

	wantRules := []string{
		filepath.Join(workspace, "AGENTS.md"),
		filepath.Join(workspace, "AGENT.md"),
		filepath.Join(workspace, "CLAUDE.md"),
		filepath.Join(workspace, "GEMINI.md"),
		filepath.Join(workspace, ".cursorrules"),
	}
	if !caps.Rules.Supported || !caps.Rules.DiscoveryOnly || !sameStrings(caps.Rules.ReadPaths, wantRules) ||
		len(caps.Rules.Notes) == 0 || !strings.Contains(caps.Rules.Notes[0], "case-insensitively") {
		t.Fatalf("OpenHands instruction discovery capability drifted: %+v", caps.Rules)
	}

	wantAgentWrites := []string{
		filepath.Join(workspace, ".agents", "agents"),
		filepath.Join(home, ".agents", "agents"),
	}
	wantAgentReads := append(append([]string{}, wantAgentWrites...),
		filepath.Join(home, ".openhands", "agents"),
		filepath.Join(workspace, ".openhands", "agents"),
	)
	if !caps.Agents.Supported || !caps.Agents.RequiresOptIn ||
		!sameStrings(caps.Agents.WritePaths, wantAgentWrites) || !sameStrings(caps.Agents.ReadPaths, wantAgentReads) ||
		!sameStrings(caps.Agents.InstallTargets, []string{"agent"}) {
		t.Fatalf("OpenHands subagent capability drifted: %+v", caps.Agents)
	}
	if caps.Plugins.Supported || len(caps.Plugins.Notes) == 0 || !strings.Contains(caps.Plugins.Notes[0], "N/A for the OpenHands CLI") {
		t.Fatalf("OpenHands plugin N/A boundary drifted: %+v", caps.Plugins)
	}
}

func TestCursorComponentTargetsDiscoverNestedSkillsAndRulesBoundedly(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	workspace := filepath.Join(dir, "repo")
	testenv.SetHome(t, home)
	nestedSkills := filepath.Join(workspace, "apps", "web", ".agents", "skills")
	nestedAgents := filepath.Join(workspace, "apps", "AGENTS.md")
	mdc := filepath.Join(workspace, ".cursor", "rules", "security", "secrets.mdc")
	ignored := filepath.Join(workspace, ".cursor", "rules", "ignored.md")
	for _, path := range []string{filepath.Join(nestedSkills, "deploy"), filepath.Dir(nestedAgents), filepath.Dir(mdc)} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{nestedAgents, mdc, ignored} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	targets := NewCursorConnector().ComponentTargets(workspace)
	if !stringInSlice(targets["skill"], nestedSkills) {
		t.Fatalf("Cursor skill targets missing nested root %q: %v", nestedSkills, targets["skill"])
	}
	for _, want := range []string{nestedAgents, mdc} {
		if !stringInSlice(targets["rule"], want) {
			t.Fatalf("Cursor rule targets missing %q: %v", want, targets["rule"])
		}
	}
	if stringInSlice(targets["rule"], ignored) {
		t.Fatalf("Cursor rule targets accepted non-.mdc file: %v", targets["rule"])
	}
}

func TestAntigravityConnector_CapabilityContract(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	workspace := filepath.Join(dir, "repo")
	testenv.SetHome(t, home)
	t.Setenv("ANTIGRAVITY_CONFIG_DIR", filepath.Join(dir, "vendor-looking-decoy"))
	t.Setenv("GEMINI_CONFIG_DIR", filepath.Join(dir, "gemini-decoy"))

	conn := NewAntigravityConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		WorkspaceDir: workspace,
		APIAddr:      "127.0.0.1:18970",
	}
	caps := conn.Capabilities(opts)

	if caps.Hooks.ConfigPath != filepath.Join(home, ".gemini", "config", "hooks.json") {
		t.Fatalf("Antigravity hook ConfigPath=%q", caps.Hooks.ConfigPath)
	}
	if caps.Hooks.Scope != "user" {
		t.Fatalf("Antigravity hook scope=%q want user", caps.Hooks.Scope)
	}
	if caps.Hooks.ConfigPath == filepath.Join(workspace, ".agents", "hooks.json") {
		t.Fatalf("Antigravity hook config must remain global-write only: %q", caps.Hooks.ConfigPath)
	}
	custodyHome := filepath.Join(dir, "legacy-custody")
	maintenanceCaps := conn.Capabilities(SetupOpts{
		DataDir:      opts.DataDir,
		WorkspaceDir: workspace,
		APIAddr:      opts.APIAddr,
		ConfigHome:   custodyHome,
	})
	if maintenanceCaps.Hooks.ConfigPath != filepath.Join(custodyHome, "hooks.json") {
		t.Fatalf("Antigravity hidden custody hook ConfigPath=%q", maintenanceCaps.Hooks.ConfigPath)
	}

	wantMCP := []string{
		filepath.Join(home, ".gemini", "config", "mcp_config.json"),
		filepath.Join(workspace, ".agents", "mcp_config.json"),
	}
	if !caps.MCP.Supported {
		t.Fatal("Antigravity MCP must be supported")
	}
	if !sameStrings(caps.MCP.ConfigPaths, wantMCP) || !sameStrings(caps.MCP.ReadPaths, wantMCP) || !sameStrings(caps.MCP.WritePaths, wantMCP) {
		t.Fatalf("Antigravity MCP paths drifted: config=%v read=%v write=%v want %v", caps.MCP.ConfigPaths, caps.MCP.ReadPaths, caps.MCP.WritePaths, wantMCP)
	}
	for _, path := range append(append([]string{}, caps.MCP.ConfigPaths...), append(caps.MCP.ReadPaths, caps.MCP.WritePaths...)...) {
		if strings.Contains(path, ".openclaw") || strings.Contains(path, "antigravity-cli") {
			t.Fatalf("Antigravity MCP path is not the contracted agy config path: %q", path)
		}
	}

	wantSkillWrites := []string{
		filepath.Join(home, ".gemini", "config", "skills"),
		filepath.Join(workspace, ".agents", "skills"),
	}
	if !caps.Skills.Supported || !sameStrings(caps.Skills.WritePaths, wantSkillWrites) {
		t.Fatalf("Antigravity skill write paths=%v supported=%v", caps.Skills.WritePaths, caps.Skills.Supported)
	}
	for _, want := range []string{
		filepath.Join(home, ".gemini", "antigravity-cli", "skills"),
		filepath.Join(workspace, ".agent", "skills"),
	} {
		if !stringInSlice(caps.Skills.ReadPaths, want) {
			t.Fatalf("Antigravity skill read paths missing discovery-only %q: %v", want, caps.Skills.ReadPaths)
		}
		if stringInSlice(caps.Skills.WritePaths, want) {
			t.Fatalf("Antigravity discovery-only skill path appeared as write target %q: %v", want, caps.Skills.WritePaths)
		}
	}

	if !caps.Rules.Supported || !caps.Rules.DiscoveryOnly || len(caps.Rules.WritePaths) != 0 {
		t.Fatalf("Antigravity rules should be discovery-only with no write paths: %+v", caps.Rules)
	}
	if caps.Rules.Scope != "workspace,user,plugin" {
		t.Fatalf("Antigravity rule scope = %q, want workspace,user,plugin", caps.Rules.Scope)
	}
	for _, want := range []string{
		filepath.Join(home, ".gemini", "GEMINI.md"),
		filepath.Join(workspace, ".agents", "rules"),
		filepath.Join(workspace, ".agent", "rules"),
		filepath.Join(home, ".gemini", "config", "plugins"),
		filepath.Join(home, ".gemini", "antigravity-cli", "plugins"),
		filepath.Join(workspace, ".agents", "plugins"),
		filepath.Join(workspace, "_agents", "plugins"),
	} {
		if !stringInSlice(caps.Rules.ReadPaths, want) {
			t.Fatalf("Antigravity rule read paths missing %q: %v", want, caps.Rules.ReadPaths)
		}
	}
	if !caps.Plugins.Supported || caps.Plugins.DiscoveryOnly || !caps.Plugins.RequiresOptIn {
		t.Fatalf("Antigravity plugins should expose explicit opt-in install support: %+v", caps.Plugins)
	}
	if len(caps.Plugins.InstallTargets) != 1 || caps.Plugins.InstallTargets[0] != "plugin" {
		t.Fatalf("Antigravity plugin install targets = %v, want [plugin]", caps.Plugins.InstallTargets)
	}
	if !caps.Agents.Supported || !caps.Agents.DiscoveryOnly || len(caps.Agents.WritePaths) != 0 {
		t.Fatalf("Antigravity agents should be discovery-only with no write paths: %+v", caps.Agents)
	}
	for _, want := range []string{
		filepath.Join(home, ".gemini", "config", "agents"),
		filepath.Join(workspace, ".agents", "agents"),
	} {
		if !stringInSlice(caps.Agents.ReadPaths, want) {
			t.Fatalf("Antigravity agent read paths missing %q: %v", want, caps.Agents.ReadPaths)
		}
	}
	for _, want := range []string{
		filepath.Join(home, ".gemini", "config", "plugins"),
		filepath.Join(home, ".gemini", "antigravity-cli", "plugins"),
		filepath.Join(workspace, ".agents", "plugins"),
		filepath.Join(workspace, "_agents", "plugins"),
	} {
		if !stringInSlice(caps.Plugins.ReadPaths, want) {
			t.Fatalf("Antigravity plugin read paths missing %q: %v", want, caps.Plugins.ReadPaths)
		}
	}
	for _, want := range []string{
		filepath.Join(home, ".gemini", "config", "plugins"),
		filepath.Join(workspace, ".agents", "plugins"),
		filepath.Join(workspace, "_agents", "plugins"),
	} {
		if !stringInSlice(caps.Plugins.WritePaths, want) {
			t.Fatalf("Antigravity plugin write paths missing %q: %v", want, caps.Plugins.WritePaths)
		}
	}
	if cliStaging := filepath.Join(home, ".gemini", "antigravity-cli", "plugins"); stringInSlice(caps.Plugins.WritePaths, cliStaging) {
		t.Fatalf("Antigravity CLI staging path must remain discovery-only: %v", caps.Plugins.WritePaths)
	}
}

func TestAntigravityAgentPathsDiscoverPluginComponents(t *testing.T) {
	root := t.TempDir()
	globalPlugins := filepath.Join(root, ".gemini", "config", "plugins")
	pluginAgents := filepath.Join(globalPlugins, "review-bundle", "agents")
	if err := os.MkdirAll(pluginAgents, 0o700); err != nil {
		t.Fatal(err)
	}
	var paths []string
	if err := WithUserHomeDir(root, func() error {
		paths = antigravityAgentPaths(SetupOpts{})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !stringInSlice(paths, filepath.Join(root, ".gemini", "config", "agents")) {
		t.Fatalf("global standalone agent path missing: %v", paths)
	}
	if !stringInSlice(paths, pluginAgents) {
		t.Fatalf("plugin agent component path missing: %v", paths)
	}
}

func TestHookOnlyConnector_SetupTeardown_BackupRestore(t *testing.T) {
	dir := t.TempDir()
	configDir := t.TempDir()
	overrides := map[string]*string{
		"hermes":      &HermesConfigPathOverride,
		"cursor":      &CursorHooksPathOverride,
		"devin":       &DevinHooksPathOverride,
		"copilot":     &CopilotHooksPathOverride,
		"openhands":   &OpenHandsHooksPathOverride,
		"antigravity": &AntigravityHooksPathOverride,
	}
	connectors := []*hookOnlyConnector{
		NewHermesConnector(),
		NewCursorConnector(),
		NewDevinConnector(),
		NewCopilotConnector(),
		NewOpenHandsConnector(),
		NewAntigravityConnector(),
	}
	for _, conn := range connectors {
		t.Run(conn.Name(), func(t *testing.T) {
			cfgPath := filepath.Join(configDir, conn.Name(), "config")
			if conn.Name() == "hermes" {
				cfgPath += ".yaml"
			} else {
				cfgPath += ".json"
			}
			ptr := overrides[conn.Name()]
			prev := *ptr
			*ptr = cfgPath
			t.Cleanup(func() { *ptr = prev })

			dataDir := filepath.Join(dir, conn.Name())
			if conn.Name() == "hermes" {
				dataDir = testenv.PrivateTempDir(t)
			}
			opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: t.TempDir()}
			if conn.Name() == "hermes" {
				opts = prepareHermesSetupAdmissionFixture(t, opts)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			data, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatalf("read config after setup: %v", err)
			}
			wantConfigNeedle := conn.scriptName
			if runtime.GOOS == "windows" {
				if conn.Name() == "cursor" {
					wantConfigNeedle = conn.Name() + "-hook.ps1"
				} else {
					wantConfigNeedle = nativeHookFlag + conn.Name()
				}
			}
			if runtime.GOOS == "windows" &&
				(conn.Name() == "antigravity" || conn.Name() == "copilot" || conn.Name() == "devin") {
				var cfg map[string]interface{}
				if err := json.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("parse %s config after setup: %v\n%s", conn.Name(), err, data)
				}
				ownedCommands := []string{conn.hookCommand(opts)}
				if conn.Name() == "antigravity" {
					ownedCommands = antigravityOwnedHookCommands(conn.hookCommand(opts))
					// The first entry is the generic pre-event command retained
					// only for legacy ownership cleanup. Current Antigravity
					// registration always carries one of its five trusted
					// --event bindings.
					ownedCommands = ownedCommands[1:]
				} else if conn.Name() == "copilot" {
					ownedCommands = make([]string, 0, len(copilotCurrentHookEvents))
					for _, event := range copilotCurrentHookEvents {
						ownedCommands = append(ownedCommands, copilotHookInvocationCommandForEvent(
							"windows", event, conn.hookCommand(opts),
						))
					}
				}
				for _, command := range ownedCommands {
					encodedCommand, err := json.Marshal(command)
					if err != nil {
						t.Fatalf("encode %s hook command: %v", conn.Name(), err)
					}
					if !strings.Contains(string(data), string(encodedCommand)) {
						t.Fatalf("config after setup does not reference safe %s command %q:\n%s",
							conn.Name(), command, string(data))
					}
				}
			} else if !strings.Contains(string(data), wantConfigNeedle) {
				t.Fatalf("config after setup does not reference %s:\n%s", wantConfigNeedle, string(data))
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if _, err := os.Stat(cfgPath); err == nil {
				t.Fatalf("config file still exists after teardown of previously missing config: %s", cfgPath)
			} else if !os.IsNotExist(err) {
				t.Fatalf("stat config after teardown: %v", err)
			}
		})
	}
}

// TestHermesSetup_WritesFullLifecycleAndScopedAllowlist pins the v0.19
// contract: Setup registers all 23 hooks and only their exact allowlist pairs;
// the operator's global hooks_auto_accept setting remains untouched.
func TestHermesSetup_WritesFullLifecycleAndScopedAllowlist(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	hermesHome := filepath.Join(dir, ".hermes")
	t.Setenv("HERMES_HOME", hermesHome)
	cfgPath := filepath.Join(hermesHome, "config.yaml")
	previousOverride := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() {
		HermesConfigPathOverride = previousOverride
	})

	conn := NewHermesConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(opts.DataDir, "hermes", "config.yaml")); err != nil {
		t.Fatalf("canonical Hermes config.yaml backup was not captured: %v", err)
	}
	if _, err := os.Stat(managedFileBackupPath(opts.DataDir, "hermes", "config")); !os.IsNotExist(err) {
		t.Fatalf("legacy Hermes config backup was created: %v", err)
	}

	cfg, err := readYAMLObject(cfgPath)
	if err != nil {
		t.Fatalf("read hermes config after setup: %v", err)
	}
	if value, present := cfg["hooks_auto_accept"]; present {
		t.Fatalf("hooks_auto_accept was introduced by Setup: %#v", value)
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks block missing or wrong type: %#v", cfg["hooks"])
	}
	for _, event := range []string{
		"pre_tool_call", "post_tool_call",
		"transform_terminal_output", "transform_tool_result", "transform_llm_output",
		"pre_llm_call", "post_llm_call", "pre_verify",
		"pre_api_request", "post_api_request", "api_request_error",
		"on_session_start", "on_session_end", "on_session_finalize", "on_session_reset",
		"subagent_start", "subagent_stop",
		"pre_gateway_dispatch", "pre_approval_request", "post_approval_response",
		"kanban_task_claimed", "kanban_task_completed", "kanban_task_blocked",
	} {
		if _, ok := hooks[event]; !ok {
			t.Errorf("hooks block missing lifecycle event %q; got keys %v", event, mapKeys(hooks))
		}
	}
	if len(hooks) != 23 {
		t.Errorf("Hermes hooks count = %d, want 23; got keys %v", len(hooks), mapKeys(hooks))
	}
	allowlistPath := filepath.Join(filepath.Dir(cfgPath), hermesAllowlistFileName)
	allowlist, err := readHermesAllowlist(allowlistPath)
	if err != nil {
		t.Fatalf("read Hermes allowlist: %v", err)
	}
	approvals := allowlist["approvals"].([]interface{})
	if len(approvals) != 23 {
		t.Fatalf("Hermes approvals count = %d, want 23", len(approvals))
	}
	wantCommand := hermesConfiguredHookCommand(conn.hookCommand(opts), opts.HookExecutable)
	seen := map[string]bool{}
	for _, raw := range approvals {
		entry := raw.(map[string]interface{})
		if entry["command"] != wantCommand || entry[hermesAllowlistOwnerField] != true {
			t.Fatalf("unexpected scoped approval: %#v", entry)
		}
		seen[entry["event"].(string)] = true
	}
	if len(seen) != 23 {
		t.Fatalf("Hermes approval events = %v, want 23 unique events", seen)
	}
	statePath := filepath.Join(opts.DataDir, "hooks", hermesDirectNativeStateFileName)
	if runtime.GOOS == "windows" {
		state, err := os.ReadFile(statePath)
		if err != nil || !bytes.Contains(state, []byte(`"status": "pending_reload"`)) {
			t.Fatalf("Hermes pending-reload state missing after setup: %s err=%v", state, err)
		}
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatalf("config still exists after teardown of previously-missing config")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat after teardown: %v", err)
	}
	if _, err := os.Stat(allowlistPath); !os.IsNotExist(err) {
		t.Fatalf("allowlist still exists after teardown of previously-missing file: %v", err)
	}
	if runtime.GOOS == "windows" {
		state, err := os.ReadFile(statePath)
		if err != nil || !bytes.Contains(state, []byte(`"status": "disabled_pending_reload"`)) {
			t.Fatalf("Hermes disabled tombstone missing after teardown: %s err=%v", state, err)
		}
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}

func TestOpenHandsSetupMigratesGlobalWorkspaceGlobalWithExactRestore(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	home := filepath.Join(root, "home")
	workspace := filepath.Join(root, "workspace")
	testenv.SetHome(t, home)
	globalPath := filepath.Join(home, ".openhands", "hooks.json")
	workspacePath := filepath.Join(workspace, ".openhands", "hooks.json")
	for _, path := range []string{globalPath, workspacePath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	globalOriginal := []byte("{\"session_start\":[{\"hooks\":[{\"command\":\"global-operator\"}]}]}\n")
	workspaceOriginal := []byte("{\"session_end\":[{\"hooks\":[{\"command\":\"workspace-operator\"}]}]}\n")
	if err := os.WriteFile(globalPath, globalOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspacePath, workspaceOriginal, 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewOpenHandsConnector()
	base := SetupOpts{DataDir: filepath.Join(root, "state"), APIAddr: "127.0.0.1:18970"}
	if err := conn.setup(context.Background(), base, ""); err != nil {
		t.Fatalf("global setup: %v", err)
	}
	workspaceOpts := base
	workspaceOpts.WorkspaceDir = workspace
	if err := conn.setup(context.Background(), workspaceOpts, ""); err != nil {
		t.Fatalf("workspace migration: %v", err)
	}
	if got, err := os.ReadFile(globalPath); err != nil || !bytes.Equal(got, globalOriginal) {
		t.Fatalf("global target not exactly restored: %q err=%v", got, err)
	}
	if err := conn.setup(context.Background(), base, ""); err != nil {
		t.Fatalf("global migration: %v", err)
	}
	if got, err := os.ReadFile(workspacePath); err != nil || !bytes.Equal(got, workspaceOriginal) {
		t.Fatalf("workspace target not exactly restored: %q err=%v", got, err)
	}
	if err := conn.teardown(context.Background(), base, ""); err != nil {
		t.Fatalf("global teardown: %v", err)
	}
	if got, err := os.ReadFile(globalPath); err != nil || !bytes.Equal(got, globalOriginal) {
		t.Fatalf("final global target not exactly restored: %q err=%v", got, err)
	}
}

func TestOpenHandsTargetMigrationSurgicallyPreservesOperatorEdits(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	home := filepath.Join(root, "home")
	workspace := filepath.Join(root, "workspace")
	testenv.SetHome(t, home)
	globalPath := filepath.Join(home, ".openhands", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(globalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalPath, []byte(`{"operator_extension":{"enabled":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewOpenHandsConnector()
	base := SetupOpts{DataDir: filepath.Join(root, "state"), APIAddr: "127.0.0.1:18970"}
	if err := conn.setup(context.Background(), base, ""); err != nil {
		t.Fatalf("global setup: %v", err)
	}
	configured, err := os.ReadFile(globalPath)
	if err != nil {
		t.Fatal(err)
	}
	var edited map[string]interface{}
	if err := json.Unmarshal(configured, &edited); err != nil {
		t.Fatal(err)
	}
	edited["operator_after_setup"] = map[string]interface{}{"enabled": true}
	editedBody, err := json.Marshal(edited)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalPath, editedBody, 0o600); err != nil {
		t.Fatal(err)
	}

	workspaceOpts := base
	workspaceOpts.WorkspaceDir = workspace
	if err := conn.setup(context.Background(), workspaceOpts, ""); err != nil {
		t.Fatalf("workspace migration: %v", err)
	}
	cleaned, err := os.ReadFile(globalPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cleaned, []byte("openhands-hook.sh")) {
		t.Fatalf("previous managed hook survived migration:\n%s", cleaned)
	}
	if !bytes.Contains(cleaned, []byte("operator_extension")) || !bytes.Contains(cleaned, []byte("operator_after_setup")) {
		t.Fatalf("migration clobbered operator edits:\n%s", cleaned)
	}
}

func TestHermesHookRepairReconcilesExactOwnedStateAndIsByteIdempotent(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	path := filepath.Join(root, "config.yaml")
	hookScript := filepath.Join(root, "hooks", "hermes-hook.sh")
	command := hermesConfiguredHookCommand(hookScript, "")
	hookFixture := map[string]interface{}{
		"hooks": map[string]interface{}{
			"pre_tool_call": []interface{}{
				map[string]interface{}{"command": "operator-hook", "timeout": 7},
				map[string]interface{}{"command": command, "timeout": 1, "matcher": "stale"},
				map[string]interface{}{"command": command, "timeout": 2, "matcher": "duplicate"},
			},
			"future_event": []interface{}{map[string]interface{}{"command": command, "timeout": 30}},
		},
	}
	hookBody, err := yaml.Marshal(hookFixture)
	if err != nil {
		t.Fatal(err)
	}
	prefix := []byte("# operator comment stays exact\noperator_literal: 'KEEP  UNRELATED  BYTES' # spacing stays\n")
	suffix := []byte("\n# operator tail stays exact\noperator_tail: {quoted: 'YES'}\n")
	body := append(append(append([]byte(nil), prefix...), hookBody...), suffix...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(path, hookScript, ""); err != nil {
		t.Fatalf("repair exact-owned Hermes hooks: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(first, prefix) || !bytes.HasSuffix(first, suffix) {
		t.Fatalf("unrelated operator bytes were not preserved exactly: %q", first)
	}
	if err := patchHermesHooks(path, hookScript, ""); err != nil {
		t.Fatalf("repeat Hermes repair: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("repeat Hermes repair changed config bytes")
	}
	config, err := readYAMLObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := config["hooks"].(map[string]interface{})
	if _, exists := hooks["future_event"]; exists {
		t.Fatal("stale exact-owned unexpected Hermes event was not removed")
	}
	entries := hooks["pre_tool_call"].([]interface{})
	if len(entries) != 2 || entries[0].(map[string]interface{})["command"] != "operator-hook" {
		t.Fatalf("foreign hook was not preserved around one repaired owned hook: %#v", entries)
	}
	repaired := entries[1].(map[string]interface{})
	if repaired["command"] != command || repaired["timeout"] != 30 || repaired["matcher"] != ".*" {
		t.Fatalf("owned hook was not reconciled exactly: %#v", repaired)
	}
}

func TestHermesSetupTamperedOwnedAllowlistRollsBackEveryFileExactly(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	configBody := []byte("operator_literal: KEEP-CONFIG-BYTES\n")
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	allowlistBody := []byte("{\n  \"approvals\": [{\"event\": \"pre_tool_call\", \"command\": \"tampered --connector hermes\", \"defenseclaw_managed\": true}],\n  \"operator_literal\": \"KEEP-ALLOWLIST-BYTES\"\n}\n")
	if err := os.WriteFile(allowlistPath, allowlistBody, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970"}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
	err := NewHermesConnector().Setup(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "tampered DefenseClaw command") {
		t.Fatalf("Setup error = %v, want exact-owned tamper refusal", err)
	}
	for path, want := range map[string][]byte{configPath: configBody, allowlistPath: allowlistBody} {
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s changed after refused Setup\n got %q\nwant %q", path, got, want)
		}
	}
}

func TestHermesAllowlistRepairIsByteIdempotent(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	path := filepath.Join(root, hermesAllowlistFileName)
	if err := os.WriteFile(path, []byte("{\n  \"approvals\": [],\n  \"operator_literal\": \"KEEP\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := hermesConfiguredHookCommand(filepath.Join(root, "hooks", "hermes-hook.sh"), "")
	if err := patchHermesAllowlist(path, command, filepath.Join(root, "hooks", "hermes-hook.sh")); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := patchHermesAllowlist(path, command, filepath.Join(root, "hooks", "hermes-hook.sh")); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("repeat Hermes allowlist repair changed bytes or approval timestamps")
	}
	document, err := readHermesAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	approvals := document["approvals"].([]interface{})
	if len(approvals) != len(hermesRequiredHooks) || document["operator_literal"] != "KEEP" {
		t.Fatalf("Hermes allowlist repair did not preserve unrelated data or exact event count: %#v", document)
	}
}

func TestHermesVerifyCleanDistinguishesFreshStateFromMissingTombstone(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Hermes direct-native tombstone is Windows-only")
	}
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	opts := SetupOpts{DataDir: filepath.Join(root, "dc")}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conn := NewHermesConnector()
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("fresh VerifyClean: %v", err)
	}

	lockPath := filepath.Join(opts.DataDir, ".hermes-lifecycle.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := conn.VerifyClean(opts)
	if err == nil || !strings.Contains(err.Error(), "disabled direct-native tombstone is unavailable") {
		t.Fatalf("VerifyClean after lifecycle marker = %v, want missing-tombstone refusal", err)
	}
}

// TestHermesSetup_PreservesExplicitAutoAcceptAndHealsUserConfig proves the
// global consent choice is never used as connector-owned state.
func TestHermesSetup_PreservesExplicitAutoAcceptAndHealsUserConfig(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	cfgPath := filepath.Join(dir, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pristine := "hooks_auto_accept: false\nhooks:\n  pre_tool_call:\n    - command: /usr/local/bin/my-own-hook.sh\n"
	if err := os.WriteFile(cfgPath, []byte(pristine), 0o600); err != nil {
		t.Fatalf("write pristine config: %v", err)
	}
	prev := HermesConfigPathOverride
	HermesConfigPathOverride = cfgPath
	t.Cleanup(func() { HermesConfigPathOverride = prev })

	conn := NewHermesConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	cfg, err := readYAMLObject(cfgPath)
	if err != nil {
		t.Fatalf("read after setup: %v", err)
	}
	if v, ok := cfg["hooks_auto_accept"].(bool); !ok || v {
		t.Fatalf("hooks_auto_accept was changed by Setup: %#v", cfg["hooks_auto_accept"])
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read after teardown: %v", err)
	}
	if string(got) != pristine {
		t.Fatalf("teardown did not heal config to pristine bytes\n got: %q\nwant: %q", string(got), pristine)
	}
}

func TestHermesTeardownMigratesLegacyBackupAndRestoresExactBytes(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configHome := filepath.Join(root, "custom-hermes-home")
	configPath := filepath.Join(configHome, "config.yaml")
	pristine := []byte("hooks_auto_accept: false\r\noperator_setting: keep-exact\r\n")
	if err := os.MkdirAll(configHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, pristine, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	conn := NewHermesConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := captureManagedFileBackup(opts.DataDir, "hermes", "config", configPath); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(configPath, conn.hookCommand(opts), opts.HookExecutable); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, "hermes", "config", configPath); err != nil {
		t.Fatal(err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pristine) {
		t.Fatalf("restored config.yaml bytes changed:\n got %q\nwant %q", got, pristine)
	}
	for _, logicalName := range []string{"config", "config.yaml"} {
		if _, err := os.Stat(managedFileBackupPath(opts.DataDir, "hermes", logicalName)); !os.IsNotExist(err) {
			t.Fatalf("%s backup survived exact restoration: %v", logicalName, err)
		}
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}

func TestHermesTeardownSurgicalCleanupPreservesOperatorAutoAccept(t *testing.T) {
	for _, test := range []struct {
		name                string
		pristine            string
		userAutoAccept      interface{}
		wantAutoAccept      interface{}
		wantAutoAcceptFound bool
	}{
		{
			name: "false",
			pristine: "hooks_auto_accept: false\noperator_setting: keep\nhooks:\n" +
				"  pre_tool_call:\n    - command: foreign-before-setup\n",
			wantAutoAccept:      false,
			wantAutoAcceptFound: true,
		},
		{
			name: "absent",
			pristine: "operator_setting: keep\nhooks:\n" +
				"  pre_tool_call:\n    - command: foreign-before-setup\n",
		},
		{
			name: "post-setup user edit survives",
			pristine: "operator_setting: keep\nhooks:\n" +
				"  pre_tool_call:\n    - command: foreign-before-setup\n",
			userAutoAccept:      false,
			wantAutoAccept:      false,
			wantAutoAcceptFound: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			configPath := filepath.Join(root, "hermes", "config.yaml")
			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte(test.pristine), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := HermesConfigPathOverride
			HermesConfigPathOverride = configPath
			t.Cleanup(func() { HermesConfigPathOverride = previous })

			conn := NewHermesConnector()
			opts := SetupOpts{
				DataDir:  filepath.Join(root, ".defenseclaw"),
				APIAddr:  "127.0.0.1:18970",
				APIToken: "tok-test",
			}
			opts = prepareHermesSetupAdmissionFixture(t, opts)
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}

			drifted, err := readYAMLObject(configPath)
			if err != nil {
				t.Fatal(err)
			}
			drifted["operator_edit"] = "after-setup"
			if test.userAutoAccept != nil {
				drifted["hooks_auto_accept"] = test.userAutoAccept
			}
			hooks := drifted["hooks"].(map[string]interface{})
			hooks["pre_tool_call"] = append(
				hooks["pre_tool_call"].([]interface{}),
				map[string]interface{}{"command": "foreign-after-setup"},
			)
			driftedBytes, err := yaml.Marshal(drifted)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, driftedBytes, 0o600); err != nil {
				t.Fatal(err)
			}

			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			cleaned, err := readYAMLObject(configPath)
			if err != nil {
				t.Fatal(err)
			}
			gotAutoAccept, gotAutoAcceptFound := cleaned["hooks_auto_accept"]
			if gotAutoAcceptFound != test.wantAutoAcceptFound ||
				(gotAutoAcceptFound && gotAutoAccept != test.wantAutoAccept) {
				t.Fatalf(
					"hooks_auto_accept = %#v, present=%t; want %#v, present=%t",
					gotAutoAccept,
					gotAutoAcceptFound,
					test.wantAutoAccept,
					test.wantAutoAcceptFound,
				)
			}
			if cleaned["operator_setting"] != "keep" || cleaned["operator_edit"] != "after-setup" {
				t.Fatalf("operator edits were not preserved: %#v", cleaned)
			}
			cleanedBytes, err := yaml.Marshal(cleaned)
			if err != nil {
				t.Fatal(err)
			}
			for _, foreign := range []string{"foreign-before-setup", "foreign-after-setup"} {
				if !bytes.Contains(cleanedBytes, []byte(foreign)) {
					t.Errorf("foreign hook %q was not preserved:\n%s", foreign, cleanedBytes)
				}
			}
			if bytes.Contains(cleanedBytes, []byte(conn.hookCommand(opts))) {
				t.Fatalf("DefenseClaw hook survived surgical cleanup:\n%s", cleanedBytes)
			}
			if _, err := os.Stat(managedFileBackupPath(opts.DataDir, "hermes", "config.yaml")); !os.IsNotExist(err) {
				t.Fatalf("canonical backup survived surgical cleanup: %v", err)
			}
		})
	}
}

func TestHermesAllowlistSurgicalCleanupPreservesForeignEntries(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("hooks_auto_accept: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	const pristineAllowlist = "{\n  \"approvals\": [{\"event\":\"pre_tool_call\",\"command\":\"operator-hook\"}],\n  \"operator\": \"keep\"\n}\n"
	if err := os.WriteFile(allowlistPath, []byte(pristineAllowlist), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	conn := NewHermesConnector()
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	drifted, err := readHermesAllowlist(allowlistPath)
	if err != nil {
		t.Fatal(err)
	}
	drifted["operator_after"] = "keep-too"
	drifted["approvals"] = append(drifted["approvals"].([]interface{}), map[string]interface{}{
		"event": "future_event", "command": "operator-after",
	})
	body, err := json.MarshalIndent(drifted, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowlistPath, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	cleaned, err := readHermesAllowlist(allowlistPath)
	if err != nil {
		t.Fatal(err)
	}
	if cleaned["operator"] != "keep" || cleaned["operator_after"] != "keep-too" {
		t.Fatalf("operator allowlist fields changed: %#v", cleaned)
	}
	approvals := cleaned["approvals"].([]interface{})
	if len(approvals) != 2 {
		t.Fatalf("approvals after surgical cleanup = %#v, want two foreign entries", approvals)
	}
	for _, raw := range approvals {
		if entry := raw.(map[string]interface{}); entry[hermesAllowlistOwnerField] == true {
			t.Fatalf("managed approval survived surgical cleanup: %#v", entry)
		}
	}
}

func TestHermesAllowlistTamperedOwnershipRefusesAmbiguousCleanup(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	conn := NewHermesConnector()
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	drifted, err := readHermesAllowlist(allowlistPath)
	if err != nil {
		t.Fatal(err)
	}
	first := drifted["approvals"].([]interface{})[0].(map[string]interface{})
	delete(first, hermesAllowlistOwnerField)
	drifted["operator_edit"] = true
	body, _ := json.MarshalIndent(drifted, "", "  ")
	if err := os.WriteFile(allowlistPath, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	err = conn.Teardown(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "lost its DefenseClaw ownership marker") {
		t.Fatalf("Teardown error = %v, want ambiguous ownership refusal", err)
	}
}

func TestHermesAllowlistTamperedOwnedCommandRefusesNonExactCleanup(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	conn := NewHermesConnector()
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	drifted, err := readHermesAllowlist(allowlistPath)
	if err != nil {
		t.Fatal(err)
	}
	first := drifted["approvals"].([]interface{})[0].(map[string]interface{})
	first["command"] = "operator-command --connector hermes"
	drifted["operator_edit"] = true
	body, _ := json.MarshalIndent(drifted, "", "  ")
	if err := os.WriteFile(allowlistPath, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	err = conn.Teardown(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "tampered DefenseClaw command") {
		t.Fatalf("Teardown error = %v, want non-exact owned-command refusal", err)
	}
	remaining, readErr := readHermesAllowlist(allowlistPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got := remaining["approvals"].([]interface{})[0].(map[string]interface{})["command"]; got != first["command"] {
		t.Fatalf("tampered entry changed after refused cleanup: got %v want %v", got, first["command"])
	}
}

func TestHermesSetupRejectsNamedAndMultiplexProfilesBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(t *testing.T, root string) string
	}{
		{"named HERMES_HOME", func(t *testing.T, root string) string {
			return filepath.Join(root, "profiles", "coder", "config.yaml")
		}},
		{"named profile directory", func(t *testing.T, root string) string {
			if err := os.MkdirAll(filepath.Join(root, "profiles", "coder"), 0o700); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, "config.yaml")
		}},
		{"active named profile", func(t *testing.T, root string) string {
			if err := os.WriteFile(filepath.Join(root, "active_profile"), []byte("coder\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, "config.yaml")
		}},
		{"multiplex config", func(t *testing.T, root string) string {
			path := filepath.Join(root, "config.yaml")
			if err := os.WriteFile(path, []byte("gateway:\n  multiplex_profiles: true\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"multiplex environment", func(t *testing.T, root string) string {
			t.Setenv("GATEWAY_MULTIPLEX_PROFILES", "yes")
			return filepath.Join(root, "config.yaml")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			configPath := test.build(t, root)
			previous := HermesConfigPathOverride
			HermesConfigPathOverride = configPath
			t.Cleanup(func() { HermesConfigPathOverride = previous })
			dataDir := filepath.Join(root, "dc")
			err := NewHermesConnector().Setup(context.Background(), SetupOpts{DataDir: dataDir})
			if err == nil || !strings.Contains(err.Error(), "unsupported by the single-HERMES_HOME connector") {
				t.Fatalf("Setup error = %v, want unsupported profile topology", err)
			}
			if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
				t.Fatalf("Setup mutated data dir before rejecting profile topology: %v", statErr)
			}
		})
	}
}

func TestHermesTeardownRejectsTamperedPristineCustodyBeforeSurgicalCleanup(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("hooks_auto_accept: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	conn := NewHermesConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	opts = prepareHermesSetupAdmissionFixture(t, opts)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	config, err := readYAMLObject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	config["operator_edit"] = "force-surgical-path"
	drifted, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, drifted, 0o600); err != nil {
		t.Fatal(err)
	}

	backupPath := managedFileBackupPath(opts.DataDir, "hermes", "config.yaml")
	backup, err := loadManagedFileBackupPath(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	backup.PristineBytes = []byte("hooks_auto_accept: true\n")
	if err := writeManagedFileBackup(backupPath, backup); err != nil {
		t.Fatal(err)
	}

	err = conn.Teardown(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "pristine custody hash") {
		t.Fatalf("Teardown error = %v, want pristine custody hash rejection", err)
	}
	got, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != string(drifted) {
		t.Fatalf("config changed after rejecting tampered custody:\n got %q\nwant %q", got, drifted)
	}
}

func mapKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestAntigravitySetup_WritesOfficialMixedSchema pins the documented
// matcher-group shape for tool events, direct handler shape for invocation/Stop
// events, and event-bound synchronous native command.
func TestAntigravitySetup_WritesOfficialMixedSchema(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".gemini", "config", "hooks.json")
	prev := AntigravityHooksPathOverride
	AntigravityHooksPathOverride = cfgPath
	t.Cleanup(func() { AntigravityHooksPathOverride = prev })

	conn := NewAntigravityConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read antigravity hooks.json: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("antigravity hooks.json is not valid JSON: %v\n%s", err, string(data))
	}
	for _, event := range []string{"PreInvocation", "PreToolUse", "PostToolUse", "PostInvocation", "Stop"} {
		outerKey := "defenseclaw-antigravity-" + strings.ToLower(event)
		eventEntry, ok := cfg[outerKey].(map[string]interface{})
		if !ok {
			t.Errorf("%s missing or wrong shape: %#v", outerKey, cfg[outerKey])
			continue
		}
		eventList, ok := eventEntry[event].([]interface{})
		if !ok {
			t.Errorf("%s[%q] is not an array: %#v", outerKey, event, eventEntry[event])
			continue
		}
		if len(eventList) != 1 {
			t.Errorf("%s[%q] must hold exactly one entry, got %d", outerKey, event, len(eventList))
			continue
		}
		var hookEntry map[string]interface{}
		if event == "PreToolUse" || event == "PostToolUse" {
			group, ok := eventList[0].(map[string]interface{})
			if !ok || group["matcher"] != "*" {
				t.Errorf("%s must use matcher group '*': %#v", event, eventList[0])
				continue
			}
			hooks, ok := group["hooks"].([]interface{})
			if !ok || len(hooks) != 1 {
				t.Errorf("%s nested handlers=%#v", event, group["hooks"])
				continue
			}
			hookEntry, ok = hooks[0].(map[string]interface{})
			if !ok {
				t.Errorf("%s handler=%#v", event, hooks[0])
				continue
			}
		} else {
			hookEntry, ok = eventList[0].(map[string]interface{})
			if !ok || hookEntry["matcher"] != nil || hookEntry["hooks"] != nil {
				t.Errorf("%s must use a direct handler: %#v", event, eventList[0])
				continue
			}
		}
		if !ok {
			continue
		}
		if hookEntry["type"] != "command" || hookEntry["timeout"] != float64(30) {
			t.Errorf("%s handler type/timeout=%#v/%#v", event, hookEntry["type"], hookEntry["timeout"])
		}
		eventCommand, ok := hookEntry["command"].(string)
		wantCommand := antigravityHookInvocationCommandForEvent(
			runtime.GOOS,
			event,
			filepath.Join(opts.DataDir, "hooks", "antigravity-hook.sh"),
		)
		if !ok || eventCommand != wantCommand {
			t.Errorf("%s command=%#v want %q", event, hookEntry["command"], wantCommand)
			continue
		}
		if strings.ContainsAny(eventCommand, `'"`) {
			t.Errorf("%s command contains visible quotes: %q", event, eventCommand)
		}
		if runtime.GOOS == "windows" {
			decoded := decodePowerShellEncodedCommandForTest(t, eventCommand)
			if !strings.Contains(decoded, "'--event','"+event+"'") ||
				!strings.Contains(decoded, powershellQuoteLiteral(defenseclawHookBinary())) {
				t.Errorf("%s encoded command is not event-bound:\n%s", event, decoded)
			}
		} else if !strings.HasSuffix(eventCommand, "antigravity-hook.sh "+event) {
			t.Errorf("%s Unix command is not event-bound: %q", event, eventCommand)
		}
	}
}

func TestAntigravityTeardownMigratesLegacyBackupAndRestoresExactBytes(t *testing.T) {
	root := t.TempDir()
	configHome := filepath.Join(root, "custom-antigravity-home")
	configPath := filepath.Join(configHome, "hooks.json")
	pristine := []byte("{\r\n  \"operator-hook\": {\"enabled\": true}\r\n}\r\n")
	if err := os.MkdirAll(configHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, pristine, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := AntigravityHooksPathOverride
	AntigravityHooksPathOverride = configPath
	t.Cleanup(func() { AntigravityHooksPathOverride = previous })

	conn := NewAntigravityConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := captureManagedFileBackup(opts.DataDir, "antigravity", "config", configPath); err != nil {
		t.Fatal(err)
	}
	if err := patchAntigravityHooks(configPath, conn.hookCommand(opts)); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, "antigravity", "config", configPath); err != nil {
		t.Fatal(err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pristine) {
		t.Fatalf("restored hooks.json bytes changed:\n got %q\nwant %q", got, pristine)
	}
	for _, logicalName := range []string{"config", "hooks.json"} {
		if _, err := os.Stat(managedFileBackupPath(opts.DataDir, "antigravity", logicalName)); !os.IsNotExist(err) {
			t.Fatalf("%s backup survived exact restoration: %v", logicalName, err)
		}
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}

func TestAntigravityManagedBackupMigrationCollapsesIdenticalRecords(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	target := filepath.Join(t.TempDir(), "antigravity-home", "hooks.json")
	base := managedFileBackup{
		Version:        managedBackupVersion,
		Connector:      "antigravity",
		Path:           target,
		Existed:        false,
		PristineSHA256: managedBackupMissingHash,
		PostSHA256:     managedBackupMissingHash,
		CapturedAt:     "2026-07-30T00:00:00Z",
	}
	legacy := base
	legacy.LogicalName = "config"
	canonical := base
	canonical.LogicalName = "hooks.json"
	legacyPath := managedFileBackupPath(dataDir, "antigravity", "config")
	canonicalPath := managedFileBackupPath(dataDir, "antigravity", "hooks.json")
	if err := writeManagedFileBackup(legacyPath, legacy); err != nil {
		t.Fatal(err)
	}
	if err := writeManagedFileBackup(canonicalPath, canonical); err != nil {
		t.Fatal(err)
	}

	conn := NewAntigravityConnector()
	if err := conn.migrateManagedBackup(SetupOpts{DataDir: dataDir}); err != nil {
		t.Fatalf("migrateManagedBackup: %v", err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("identical legacy backup survived migration: %v", err)
	}
	got, err := loadManagedFileBackupPath(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.LogicalName != "hooks.json" || !sameManagedTargetPath(got.Path, target) {
		t.Fatalf("canonical backup changed custody: %#v", got)
	}
}

func TestAntigravityManagedBackupMigrationRejectsConflictingCustody(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	legacy := managedFileBackup{
		Version:        managedBackupVersion,
		Connector:      "antigravity",
		LogicalName:    "config",
		Path:           filepath.Join(t.TempDir(), "legacy-home", "hooks.json"),
		PristineSHA256: managedBackupMissingHash,
		CapturedAt:     "2026-07-30T00:00:00Z",
	}
	canonical := legacy
	canonical.LogicalName = "hooks.json"
	canonical.Path = filepath.Join(t.TempDir(), "canonical-home", "hooks.json")
	legacyPath := managedFileBackupPath(dataDir, "antigravity", "config")
	canonicalPath := managedFileBackupPath(dataDir, "antigravity", "hooks.json")
	if err := writeManagedFileBackup(legacyPath, legacy); err != nil {
		t.Fatal(err)
	}
	if err := writeManagedFileBackup(canonicalPath, canonical); err != nil {
		t.Fatal(err)
	}

	conn := NewAntigravityConnector()
	err := conn.migrateManagedBackup(SetupOpts{DataDir: dataDir})
	if err == nil || !strings.Contains(err.Error(), "conflicting config and hooks.json managed backup custody") {
		t.Fatalf("migrateManagedBackup error = %v, want conflicting custody", err)
	}
	for _, path := range []string{legacyPath, canonicalPath} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("conflicting backup %q was modified or removed: %v", path, statErr)
		}
	}
}

func TestAntigravityRemoveConfigEntriesPrunesLegacyWindowsCommand(t *testing.T) {
	setHookBinaryOverride(t, `C:\Users\Jane Doe\.local\bin\defenseclaw-hook.exe`)
	current := hookInvocationCommandFor("windows", "antigravity", "")
	legacy := legacyAntigravityWindowsHookCommand()
	legacyNonWaiting := legacyAntigravityNonWaitingWindowsHookCommand()
	foreign := `foreign-hook.exe hook --connector antigravity`
	path := filepath.Join(t.TempDir(), "hooks.json")
	cfg := map[string]interface{}{
		"defenseclaw-antigravity-pretooluse": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": "*",
					"hooks": []interface{}{
						map[string]interface{}{"type": "command", "command": current},
						map[string]interface{}{"type": "command", "command": legacy},
						map[string]interface{}{"type": "command", "command": legacyNonWaiting},
					},
				},
			},
		},
		"operator-hook": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": "*",
					"hooks": []interface{}{
						map[string]interface{}{"type": "command", "command": foreign},
					},
				},
			},
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture hooks.json: %v", err)
	}

	conn := NewAntigravityConnector()
	if err := conn.removeConfigEntries(path, current, SetupOpts{}); err != nil {
		t.Fatalf("removeConfigEntries: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pruned hooks.json: %v", err)
	}
	var pruned map[string]interface{}
	if err := json.Unmarshal(after, &pruned); err != nil {
		t.Fatalf("parse pruned hooks.json: %v\n%s", err, after)
	}
	if structuredHookCommandReferences(pruned, []string{current, legacy, legacyNonWaiting}) {
		t.Fatalf("managed Antigravity command survived pruning:\n%s", after)
	}
	if !strings.Contains(string(after), foreign) {
		t.Fatalf("foreign hook was not preserved:\n%s", after)
	}
}

func TestOpenHandsSetup_PatchesDocumentedHookSchema(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenHands requires WSL and is unsupported on native Windows; platform rejection coverage remains active")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".openhands", "hooks.json")
	prev := OpenHandsHooksPathOverride
	OpenHandsHooksPathOverride = cfgPath
	t.Cleanup(func() { OpenHandsHooksPathOverride = prev })

	conn := NewOpenHandsConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		WorkspaceDir: dir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read OpenHands hooks.json: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("OpenHands hooks.json is not valid JSON: %v\n%s", err, string(data))
	}
	raw, ok := cfg["pre_tool_use"].([]interface{})
	if !ok || len(raw) == 0 {
		t.Fatalf("pre_tool_use missing from native top-level OpenHands hook schema: %#v", cfg)
	}
	group, ok := raw[0].(map[string]interface{})
	if !ok {
		t.Fatalf("pre_tool_use[0] = %#v, want object", raw[0])
	}
	if group["matcher"] != "*" {
		t.Fatalf("matcher=%#v want *", group["matcher"])
	}
	hooks, ok := group["hooks"].([]interface{})
	if !ok || len(hooks) == 0 {
		t.Fatalf("hooks missing from OpenHands group: %#v", group)
	}
	hook, ok := hooks[0].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks[0] = %#v, want object", hooks[0])
	}
	if hook["type"] != "command" {
		t.Fatalf("hook type=%#v want command", hook["type"])
	}
	command, _ := hook["command"].(string)
	if !strings.Contains(command, "openhands-hook.sh") {
		t.Fatalf("command=%q does not reference openhands-hook.sh", command)
	}
	if _, wrapped := cfg["hooks"]; wrapped {
		t.Fatalf("OpenHands native schema should not add Claude-compatible top-level hooks wrapper: %#v", cfg["hooks"])
	}
}

func newOpenHandsTokenLifecycleFixture(t *testing.T) (*hookOnlyConnector, SetupOpts, string) {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, ".openhands", "hooks.json")
	previous := OpenHandsHooksPathOverride
	OpenHandsHooksPathOverride = configPath
	t.Cleanup(func() { OpenHandsHooksPathOverride = previous })
	opts := SetupOpts{
		DataDir:      filepath.Join(root, "defenseclaw"),
		WorkspaceDir: root,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "gateway-token-must-not-be-published",
	}
	if runtime.GOOS == "darwin" {
		trustedDir := filepath.Join(root, "trusted")
		if err := os.MkdirAll(trustedDir, 0o700); err != nil {
			t.Fatal(err)
		}
		executable := filepath.Join(trustedDir, "openhands")
		if err := os.WriteFile(executable, []byte("OpenHands executable fixture\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		stablePath, digest, ok := setupSelectedAgentExecutableEvidence(executable)
		if !ok {
			t.Fatal("capture OpenHands setup-selected executable evidence")
		}
		now := time.Now().UTC().Truncate(time.Second)
		receipt := agentSelectionReceipt{
			SchemaVersion: agentSelectionSchemaVersion,
			UpdatedAt:     now.Format(time.RFC3339),
			Selections: map[string]agentSelectionEvidence{
				"openhands": {
					Connector:         "openhands",
					Source:            "setup-selected",
					Executable:        stablePath,
					RawVersion:        "OpenHands CLI 1.16.0",
					NormalizedVersion: "1.16.0",
					SHA256:            digest,
					SelectedAt:        now.Format(time.RFC3339),
					ExpiresAt:         now.Add(10 * time.Minute).Format(time.RFC3339),
				},
			},
		}
		body, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(opts.DataDir, agentSelectionFile), body, 0o600); err != nil {
			t.Fatal(err)
		}
		opts.AgentVersion = "OpenHands CLI 1.16.0"
		opts.AgentExecutable = stablePath
	}
	return NewOpenHandsConnector(), opts, configPath
}

func TestOpenHandsDarwinExporterTokenLifecycle(t *testing.T) {
	t.Run("clean teardown revokes token", func(t *testing.T) {
		conn, opts, _ := newOpenHandsTokenLifecycleFixture(t)
		if err := conn.setupOpenHandsWithTokenRollback(context.Background(), opts); err != nil {
			t.Fatalf("setupOpenHandsWithTokenRollback: %v", err)
		}
		if token, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeOpenHands); err != nil || token == "" {
			t.Fatalf("LoadOTLPPathToken after setup = %q, %v; want provisioned token", token, err)
		}
		if err := conn.teardownOpenHandsWithToken(context.Background(), opts); err != nil {
			t.Fatalf("teardownOpenHandsWithToken: %v", err)
		}
		if token, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeOpenHands); err != nil || token != "" {
			t.Fatalf("LoadOTLPPathToken after teardown = %q, %v; want revoked token", token, err)
		}
	})

	t.Run("failed setup revokes only a fresh token", func(t *testing.T) {
		for _, preexisting := range []bool{false, true} {
			name := "fresh"
			if preexisting {
				name = "preexisting"
			}
			t.Run(name, func(t *testing.T) {
				conn, opts, configPath := newOpenHandsTokenLifecycleFixture(t)
				before := ""
				if preexisting {
					var err error
					before, err = EnsureOTLPPathToken(opts.DataDir, OTLPScopeOpenHands)
					if err != nil {
						t.Fatalf("EnsureOTLPPathToken: %v", err)
					}
				}
				if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(configPath, []byte("{\n  \"pre_tool_use\": [\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := conn.setupOpenHandsWithTokenRollback(context.Background(), opts); err == nil {
					t.Fatal("setup succeeded despite malformed OpenHands hooks.json")
				}
				after, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeOpenHands)
				if err != nil {
					t.Fatalf("LoadOTLPPathToken after failed setup: %v", err)
				}
				if after != before {
					t.Fatalf("failed setup token = %q, want %q", after, before)
				}
			})
		}
	})
}

func TestOpenHandsConcurrentFailedSetupCannotRevokeSuccessfulToken(t *testing.T) {
	conn, opts, _ := newOpenHandsTokenLifecycleFixture(t)
	original := openHandsSetupOperation
	var calls atomic.Int32
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	openHandsSetupOperation = func(_ *hookOnlyConnector, _ context.Context, _ SetupOpts) error {
		if calls.Add(1) == 1 {
			close(firstEntered)
			<-releaseFirst
			return errors.New("injected first setup failure")
		}
		return nil
	}
	t.Cleanup(func() { openHandsSetupOperation = original })

	firstResult := make(chan error, 1)
	secondResult := make(chan error, 1)
	go func() { firstResult <- conn.setupOpenHandsWithTokenRollback(context.Background(), opts) }()
	<-firstEntered
	go func() { secondResult <- conn.setupOpenHandsWithTokenRollback(context.Background(), opts) }()
	select {
	case err := <-secondResult:
		t.Fatalf("second setup crossed the first setup/rollback transaction: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstResult; err == nil || !strings.Contains(err.Error(), "injected first setup failure") {
		t.Fatalf("first setup error = %v, want injected failure", err)
	}
	if err := <-secondResult; err != nil {
		t.Fatalf("second setup: %v", err)
	}
	if token, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeOpenHands); err != nil || token == "" {
		t.Fatalf("successful concurrent setup token = %q, %v; want live token", token, err)
	}
}

func TestGeminiSettingsPathHonorsLifecycleConfigHome(t *testing.T) {
	previous := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = ""
	t.Cleanup(func() { GeminiSettingsPathOverride = previous })

	profileRoot := filepath.Join(t.TempDir(), ".gemini")
	want := filepath.Join(profileRoot, "settings.json")
	if got := geminiSettingsPath(SetupOpts{ConfigHome: profileRoot}); got != want {
		t.Fatalf("bound Gemini settings path = %q, want %q", got, want)
	}
}

func TestGeminiPathsUsePrivateBindingAndRejectInvalidExplicitHome(t *testing.T) {
	previous := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = ""
	t.Cleanup(func() { GeminiSettingsPathOverride = previous })

	root := t.TempDir()
	bound := filepath.Join(root, "official", ".gemini")
	workspace := filepath.Join(root, "workspace")
	t.Setenv("DEFENSECLAW_GEMINI_CONFIG_HOME", bound)
	t.Setenv("GEMINI_CONFIG_DIR", filepath.Join(root, "hostile-vendor-home"))
	t.Setenv("GEMINI_CLI_HOME", filepath.Join(root, "hostile-official-root"))

	opts := SetupOpts{WorkspaceDir: workspace}
	if got := geminiSettingsPath(opts); got != filepath.Join(bound, "settings.json") {
		t.Fatalf("Gemini settings path = %q, want authenticated binding", got)
	}
	caps := NewGeminiCLIConnector().Capabilities(opts)
	for _, want := range []string{
		filepath.Join(bound, "skills"),
		filepath.Join(bound, "extensions"),
		filepath.Join(bound, "agents"),
	} {
		found := stringInSlice(caps.Skills.ReadPaths, want) ||
			stringInSlice(caps.Plugins.ReadPaths, want) ||
			stringInSlice(caps.Agents.ReadPaths, want)
		if !found {
			t.Fatalf("Gemini capabilities did not use bound path %q: %+v", want, caps)
		}
	}
	if !caps.Plugins.Supported || !caps.Plugins.DiscoveryOnly || len(caps.Plugins.WritePaths) != 0 {
		t.Fatalf("Gemini extension capability is not truthful discovery-only inventory: %+v", caps.Plugins)
	}
	workspaceSettings := filepath.Join(workspace, ".gemini", "settings.json")
	if !stringInSlice(caps.MCP.ConfigPaths, workspaceSettings) ||
		!stringInSlice(caps.MCP.ConfigPaths, filepath.Join(bound, "settings.json")) {
		t.Fatalf("Gemini MCP capability did not expose project-first and user settings: %+v", caps.MCP)
	}
	if stringInSlice(caps.Plugins.ReadPaths, filepath.Join(workspace, ".gemini", "extensions")) {
		t.Fatalf("Gemini capability invented a workspace extension root: %+v", caps.Plugins)
	}
	targets := NewGeminiCLIConnector().ComponentTargets(workspace)
	for kind, want := range map[string]string{
		"mcp":    filepath.Join(bound, "settings.json"),
		"skill":  filepath.Join(bound, "skills"),
		"plugin": filepath.Join(bound, "extensions"),
		"agent":  filepath.Join(bound, "agents"),
	} {
		if !stringInSlice(targets[kind], want) {
			t.Fatalf("Gemini %s targets = %v, missing %q", kind, targets[kind], want)
		}
	}
	if !stringInSlice(targets["mcp"], workspaceSettings) {
		t.Fatalf("Gemini MCP targets = %v, missing project settings %q", targets["mcp"], workspaceSettings)
	}
	if stringInSlice(targets["plugin"], filepath.Join(workspace, ".gemini", "extensions")) {
		t.Fatalf("Gemini plugin targets invented a workspace extension root: %v", targets["plugin"])
	}

	separator := string(os.PathSeparator)
	invalid := SetupOpts{ConfigHome: root + separator + "child" + separator + ".." + separator + ".gemini"}
	if got := geminiSettingsPath(invalid); got != "" {
		t.Fatalf("invalid explicit Gemini ConfigHome resolved to %q", got)
	}
}

func TestGeminiPathsUseOfficialCLIHomeForSourceInstalls(t *testing.T) {
	previousOverride := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = ""
	t.Cleanup(func() { GeminiSettingsPathOverride = previousOverride })
	previousPrivate, existed := os.LookupEnv("DEFENSECLAW_GEMINI_CONFIG_HOME")
	if err := os.Unsetenv("DEFENSECLAW_GEMINI_CONFIG_HOME"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv("DEFENSECLAW_GEMINI_CONFIG_HOME", previousPrivate)
		} else {
			_ = os.Unsetenv("DEFENSECLAW_GEMINI_CONFIG_HOME")
		}
	})

	root := filepath.Join(t.TempDir(), "gemini-home-root")
	t.Setenv("GEMINI_CLI_HOME", root)
	wantHome := filepath.Join(root, ".gemini")
	if got := geminiConfigHome(SetupOpts{}); got != wantHome {
		t.Fatalf("Gemini config home = %q, want official root child %q", got, wantHome)
	}
	if got := geminiSettingsPath(SetupOpts{}); got != filepath.Join(wantHome, "settings.json") {
		t.Fatalf("Gemini settings path = %q", got)
	}

	t.Setenv("GEMINI_CLI_HOME", "relative")
	if got := geminiConfigHome(SetupOpts{}); got != "" {
		t.Fatalf("invalid GEMINI_CLI_HOME resolved config home %q", got)
	}
}

func TestGeminiHookReconciliationMigratesExactWindowsCommandsAndPreservesForeignGroup(t *testing.T) {
	const hookBinary = `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`
	setHookBinaryOverride(t, hookBinary)

	root := t.TempDir()
	profileRoot := filepath.Join(root, ".gemini")
	opts := SetupOpts{DataDir: filepath.Join(root, "defenseclaw"), ConfigHome: profileRoot}
	settingsPath := filepath.Join(profileRoot, "settings.json")
	antigravityPath := filepath.Join(profileRoot, "config", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(antigravityPath), 0o700); err != nil {
		t.Fatal(err)
	}
	antigravityBefore := []byte(`{"operator-antigravity":{"PreToolUse":[]}}`)
	if err := os.WriteFile(antigravityPath, antigravityBefore, 0o600); err != nil {
		t.Fatal(err)
	}

	desired := hookInvocationCommandFor("windows", "geminicli", filepath.Join(opts.DataDir, "hooks", "geminicli-hook.sh"))
	legacyCallOperator := legacyWindowsGeminiCallOperatorHookCommandForBinary(hookBinary)
	legacyNonWaiting := legacyWindowsNativePowerShellHookCommandForBinary("geminicli", hookBinary)
	foreign := `C:\Operator\audit-hook.exe --gemini`
	fixture := map[string]interface{}{
		"operatorSetting": "keep",
		"hooks": map[string]interface{}{
			"BeforeTool": []interface{}{
				map[string]interface{}{
					"matcher":       "*",
					"sequential":    true,
					"operatorField": "keep",
					"hooks": []interface{}{
						map[string]interface{}{"name": "defenseclaw", "type": "command", "command": legacyCallOperator},
						map[string]interface{}{"name": "operator", "type": "command", "command": foreign},
					},
				},
				map[string]interface{}{
					"matcher": "*",
					"hooks": []interface{}{
						map[string]interface{}{"name": "defenseclaw", "type": "command", "command": legacyNonWaiting},
					},
				},
			},
		},
	}
	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	owned := geminiOwnedHookCommandsForOS("windows", opts, desired)
	if err := patchGeminiHooks(settingsPath, desired, owned...); err != nil {
		t.Fatalf("patchGeminiHooks: %v", err)
	}
	patched, err := readJSONObject(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range geminiCLIHookEvents {
		commands := geminiHookCommandsForTest(t, patched, event)
		currentCount := 0
		for _, command := range commands {
			if command == desired {
				currentCount++
			}
			if command != desired && stringInSlice(owned, command) {
				t.Errorf("event %s retained legacy managed command %q", event, command)
			}
		}
		if currentCount != 1 {
			t.Errorf("event %s has %d current Gemini handlers, want exactly 1: %v", event, currentCount, commands)
		}
	}
	if !geminiForeignGroupPreservedForTest(t, patched, "BeforeTool", foreign) {
		t.Fatal("mixed Gemini group did not preserve its foreign hook and operator fields")
	}
	conn := NewGeminiCLIConnector()
	if err := conn.verifyGeminiSettingsCleanForOS("windows", opts, settingsPath, desired, patched); err == nil {
		t.Fatal("Windows VerifyClean did not recognize the JSON-escaped encoded Gemini command")
	}

	if err := removeGeminiConfigEntries(settingsPath, desired, owned...); err != nil {
		t.Fatalf("removeGeminiConfigEntries: %v", err)
	}
	removed, err := readJSONObject(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range geminiCLIHookEvents {
		for _, command := range geminiHookCommandsForTest(t, removed, event) {
			if stringInSlice(owned, command) {
				t.Errorf("event %s retained exact managed command %q after teardown", event, command)
			}
		}
	}
	if !geminiForeignGroupPreservedForTest(t, removed, "BeforeTool", foreign) {
		t.Fatal("Gemini teardown removed or rewrote a foreign hook in a mixed group")
	}
	if removed["operatorSetting"] != "keep" {
		t.Fatalf("Gemini teardown changed unrelated settings: %#v", removed)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean rejected foreign-only Gemini settings after managed removal: %v", err)
	}
	afterAntigravity, err := os.ReadFile(antigravityPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterAntigravity, antigravityBefore) {
		t.Fatalf("Gemini settings reconciliation changed Antigravity's shared .gemini subtree:\n%s", afterAntigravity)
	}
}

func TestGeminiSetupTeardownDoesNotRestoreRecognizedLegacyHooks(t *testing.T) {
	const hookBinary = `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`
	setHookBinaryOverride(t, hookBinary)

	root := testenv.PrivateTempDir(t)
	profileRoot := filepath.Join(root, ".gemini")
	settingsPath := filepath.Join(profileRoot, "settings.json")
	previous := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = settingsPath
	t.Cleanup(func() { GeminiSettingsPathOverride = previous })

	opts := SetupOpts{
		DataDir:    filepath.Join(root, "defenseclaw"),
		ConfigHome: profileRoot,
		APIAddr:    "127.0.0.1:18970",
		APIToken:   "gateway-token-must-not-be-published",
	}
	legacyCommand := filepath.Join(opts.DataDir, "hooks", "geminicli-hook.sh")
	if runtime.GOOS == "windows" {
		legacyCommand = legacyWindowsGeminiCallOperatorHookCommandForBinary(hookBinary)
	}
	foreignCommand := "operator-audit-hook --gemini"
	fixture := map[string]interface{}{
		"operatorSetting": "keep",
		"hooks": map[string]interface{}{
			"BeforeTool": []interface{}{
				map[string]interface{}{
					"matcher":       "*",
					"sequential":    true,
					"operatorField": "keep",
					"hooks": []interface{}{
						map[string]interface{}{"name": "defenseclaw", "type": "command", "command": legacyCommand},
						map[string]interface{}{"name": "operator", "type": "command", "command": foreignCommand},
					},
				},
				map[string]interface{}{
					"matcher": "*",
					"hooks": []interface{}{
						map[string]interface{}{"name": "defenseclaw", "type": "command", "command": legacyCommand},
					},
				},
			},
		},
		"telemetry": map[string]interface{}{
			"enabled":      true,
			"target":       "otlp",
			"otlpEndpoint": "http://127.0.0.1:18790/otlp/geminicli/legacy-token",
			"protocol":     "http/json",
			"managedBy":    "defenseclaw",
		},
	}
	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(profileRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewGeminiCLIConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup over legacy Gemini hook: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown after legacy Gemini migration: %v", err)
	}

	restored, err := readJSONObject(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if restored["operatorSetting"] != "keep" {
		t.Fatalf("Gemini teardown changed unrelated settings: %#v", restored)
	}
	if _, ok := restored["telemetry"]; ok {
		t.Fatalf("Gemini teardown revived managed legacy telemetry: %#v", restored["telemetry"])
	}
	if !geminiForeignGroupPreservedForTest(t, restored, "BeforeTool", foreignCommand) {
		t.Fatal("Gemini teardown did not restore the foreign portion of the mixed hook group")
	}
	hooks, _ := restored["hooks"].(map[string]interface{})
	if len(hooks) != 1 {
		t.Fatalf("Gemini teardown restored unexpected managed hook events: %#v", hooks)
	}
	commands := geminiHookCommandsForTest(t, restored, "BeforeTool")
	if len(commands) != 1 || commands[0] != foreignCommand {
		t.Fatalf("Gemini teardown restored managed legacy hooks; commands=%v", commands)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean rejected the foreign-only restored Gemini settings: %v", err)
	}
	backupPath := managedFileBackupPath(opts.DataDir, "geminicli", conn.managedBackupLogicalName())
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("Gemini teardown retained managed backup receipt %s: %v", backupPath, err)
	}
}

func TestGeminiSetupTeardownMigratesExistingReceiptWithoutRestoringLegacyHooks(t *testing.T) {
	const hookBinary = `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`
	setHookBinaryOverride(t, hookBinary)

	root := testenv.PrivateTempDir(t)
	profileRoot := filepath.Join(root, ".gemini")
	settingsPath := filepath.Join(profileRoot, "settings.json")
	previous := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = settingsPath
	t.Cleanup(func() { GeminiSettingsPathOverride = previous })
	opts := SetupOpts{
		DataDir:    filepath.Join(root, "defenseclaw"),
		ConfigHome: profileRoot,
		APIAddr:    "127.0.0.1:18970",
		APIToken:   "gateway-token-must-not-be-published",
	}
	legacyCommand := filepath.Join(opts.DataDir, "hooks", "geminicli-hook.sh")
	if runtime.GOOS == "windows" {
		legacyCommand = legacyWindowsGeminiCallOperatorHookCommandForBinary(hookBinary)
	}
	foreignCommand := "operator-audit-hook --gemini"
	fixture := map[string]interface{}{
		"operatorSetting": "keep",
		"hooks": map[string]interface{}{
			"BeforeTool": []interface{}{
				map[string]interface{}{
					"matcher":       "*",
					"sequential":    true,
					"operatorField": "keep",
					"hooks": []interface{}{
						map[string]interface{}{"name": "defenseclaw", "type": "command", "command": legacyCommand},
						map[string]interface{}{"name": "operator", "type": "command", "command": foreignCommand},
					},
				},
			},
		},
		"telemetry": map[string]interface{}{
			"enabled":      true,
			"otlpEndpoint": "http://127.0.0.1:18790/otlp/geminicli/legacy-token",
			"managedBy":    "defenseclaw",
		},
	}
	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(profileRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewGeminiCLIConnector()
	logicalName := conn.managedBackupLogicalName()
	if err := captureManagedFileBackup(opts.DataDir, "geminicli", logicalName, settingsPath); err != nil {
		t.Fatalf("capture legacy generic receipt: %v", err)
	}
	currentCommand := conn.hookCommand(opts)
	owned := geminiOwnedHookCommands(opts, currentCommand)
	if err := patchGeminiHooks(settingsPath, currentCommand, owned...); err != nil {
		t.Fatalf("seed prior managed hooks: %v", err)
	}
	if err := patchGeminiTelemetry(settingsPath, opts); err != nil {
		t.Fatalf("seed prior managed telemetry: %v", err)
	}
	if err := updateManagedFileBackupPostHash(
		opts.DataDir,
		"geminicli",
		logicalName,
		settingsPath,
	); err != nil {
		t.Fatalf("finalize prior receipt: %v", err)
	}

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup over existing Gemini receipt: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown after existing receipt migration: %v", err)
	}
	restored, err := readJSONObject(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if restored["operatorSetting"] != "keep" ||
		!geminiForeignGroupPreservedForTest(t, restored, "BeforeTool", foreignCommand) {
		t.Fatalf("existing receipt migration did not preserve foreign Gemini state: %#v", restored)
	}
	if _, ok := restored["telemetry"]; ok {
		t.Fatalf("existing receipt migration restored managed telemetry: %#v", restored["telemetry"])
	}
	commands := geminiHookCommandsForTest(t, restored, "BeforeTool")
	if len(commands) != 1 || commands[0] != foreignCommand {
		t.Fatalf("existing receipt migration restored managed hooks: %v", commands)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean rejected migrated foreign-only Gemini state: %v", err)
	}
}

func geminiHookCommandsForTest(t *testing.T, cfg map[string]interface{}, event string) []string {
	t.Helper()
	hooks, _ := cfg["hooks"].(map[string]interface{})
	groups, _ := hooks[event].([]interface{})
	var commands []string
	for _, rawGroup := range groups {
		group, ok := rawGroup.(map[string]interface{})
		if !ok {
			continue
		}
		handlers, _ := group["hooks"].([]interface{})
		for _, rawHandler := range handlers {
			handler, ok := rawHandler.(map[string]interface{})
			if !ok {
				continue
			}
			if command, ok := handler["command"].(string); ok {
				commands = append(commands, command)
			}
		}
	}
	return commands
}

func geminiForeignGroupPreservedForTest(t *testing.T, cfg map[string]interface{}, event, foreign string) bool {
	t.Helper()
	hooks, _ := cfg["hooks"].(map[string]interface{})
	groups, _ := hooks[event].([]interface{})
	for _, rawGroup := range groups {
		group, ok := rawGroup.(map[string]interface{})
		if !ok || group["operatorField"] != "keep" || group["sequential"] != true {
			continue
		}
		handlers, _ := group["hooks"].([]interface{})
		for _, rawHandler := range handlers {
			handler, _ := rawHandler.(map[string]interface{})
			if handler["command"] == foreign {
				return true
			}
		}
	}
	return false
}

func newGeminiTokenLifecycleFixture(t *testing.T) (*hookOnlyConnector, SetupOpts, string) {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	configHome := filepath.Join(root, ".gemini")
	opts := SetupOpts{
		DataDir:    filepath.Join(root, "defenseclaw"),
		ConfigHome: configHome,
		APIAddr:    "127.0.0.1:18970",
		APIToken:   "gateway-token-must-not-be-published",
	}
	// Keep the effective-layer validation hermetic instead of consulting an
	// operator's real machine-wide Gemini policy during this lifecycle test.
	t.Setenv("GEMINI_CLI_SYSTEM_DEFAULTS_PATH", filepath.Join(root, "system", "defaults.json"))
	t.Setenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH", filepath.Join(root, "system", "settings.json"))
	return NewGeminiCLIConnector(), opts, filepath.Join(configHome, "settings.json")
}

func TestGeminiTeardownRevokesScopedOTLPTokenAfterCleanRestore(t *testing.T) {
	conn, opts, _ := newGeminiTokenLifecycleFixture(t)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if token, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI); err != nil || token == "" {
		t.Fatalf("LoadOTLPPathToken after setup = %q, %v; want a provisioned token", token, err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if token, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI); err != nil || token != "" {
		t.Fatalf("LoadOTLPPathToken after teardown = %q, %v; want revoked token", token, err)
	}
}

func TestGeminiTeardownRetainsScopedOTLPTokenWhenConfigCleanupFails(t *testing.T) {
	conn, opts, settingsPath := newGeminiTokenLifecycleFixture(t)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	before, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI)
	if err != nil || before == "" {
		t.Fatalf("LoadOTLPPathToken after setup = %q, %v; want a provisioned token", before, err)
	}
	// Force the surgical cleanup path to fail parsing. The changed digest
	// prevents pristine restore, and teardown must keep the still-referenced
	// token valid rather than revoke it underneath the broken settings file.
	if err := os.WriteFile(settingsPath, []byte("{\n  \"hooks\": [\n"), 0o600); err != nil {
		t.Fatalf("write malformed drifted settings: %v", err)
	}

	if err := conn.Teardown(context.Background(), opts); err == nil {
		t.Fatal("Teardown succeeded despite malformed drifted Gemini settings")
	}
	after, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken after failed teardown: %v", err)
	}
	if after != before {
		t.Fatalf("failed teardown changed scoped token: before=%q after=%q", before, after)
	}
}

func TestGeminiFailedSetupScopedOTLPTokenLifecycle(t *testing.T) {
	t.Run("fresh token is revoked", func(t *testing.T) {
		conn, opts, settingsPath := newGeminiTokenLifecycleFixture(t)
		if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(settingsPath, []byte("{\n  \"telemetry\": [\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := conn.Setup(context.Background(), opts); err == nil {
			t.Fatal("Setup succeeded despite malformed Gemini settings")
		}
		if token, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI); err != nil || token != "" {
			t.Fatalf("LoadOTLPPathToken after failed setup = %q, %v; want fresh token revoked", token, err)
		}
	})

	t.Run("preexisting token is preserved", func(t *testing.T) {
		conn, opts, settingsPath := newGeminiTokenLifecycleFixture(t)
		before, err := EnsureOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI)
		if err != nil {
			t.Fatalf("EnsureOTLPPathToken: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(settingsPath, []byte("{\n  \"telemetry\": [\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := conn.Setup(context.Background(), opts); err == nil {
			t.Fatal("Setup succeeded despite malformed Gemini settings")
		}
		after, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI)
		if err != nil {
			t.Fatalf("LoadOTLPPathToken after failed setup: %v", err)
		}
		if after != before {
			t.Fatalf("failed setup changed preexisting scoped token: before=%q after=%q", before, after)
		}
	})
}

func TestGeminiSetup_PatchesNativeTelemetryPathToken(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	cfgPath := filepath.Join(dir, "settings.json")
	prev := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = cfgPath
	t.Cleanup(func() { GeminiSettingsPathOverride = prev })
	if err := os.WriteFile(cfgPath, []byte(`{
  "telemetry": {
    "outfile": "operator-telemetry.jsonl",
    "useCliAuth": true
  }
}`), 0o600); err != nil {
		t.Fatalf("seed conflicting Gemini telemetry: %v", err)
	}

	conn := NewGeminiCLIConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read gemini settings: %v", err)
	}
	text := string(data)
	// Gemini CLI's settings.json schema only accepts target ∈
	// {"local","gcp"}. To forward telemetry to a custom (loopback)
	// OTLP collector we must set target=local + useCollector=true.
	// See https://geminicli.com/docs/reference/configuration/.
	if !strings.Contains(text, `"target": "local"`) {
		t.Fatalf("gemini settings missing managed telemetry target=local:\n%s", text)
	}
	if !strings.Contains(text, `"useCollector": true`) {
		t.Fatalf("gemini settings missing useCollector=true (required for external OTLP):\n%s", text)
	}
	if !strings.Contains(text, `"otlpProtocol": "http"`) {
		t.Fatalf("gemini settings missing otlpProtocol=http:\n%s", text)
	}
	if !strings.Contains(text, `"useCliAuth": false`) {
		t.Fatalf("gemini settings did not disable incompatible CLI telemetry auth:\n%s", text)
	}
	if !strings.Contains(text, `"outfile": ""`) {
		t.Fatalf("gemini settings did not neutralize outfile redirection:\n%s", text)
	}
	// Gemini's schema rejects unknown keys at load time, so we MUST
	// NOT write the legacy "managedBy" / "protocol" fields anymore —
	// otherwise `gemini` aborts with "Unrecognized key(s) in object".
	for _, banned := range []string{`"managedBy"`, `"protocol":`} {
		if strings.Contains(text, banned) {
			t.Fatalf("gemini settings contain key rejected by schema (%s):\n%s", banned, text)
		}
	}
	// H-4: settings.json must NOT contain the master gateway bearer
	// (opts.APIToken). The OTLP exporter authenticates via a scoped
	// per-source path-token instead — see EnsureOTLPPathToken /
	// patchGeminiTelemetry.
	if strings.Contains(text, "tok-test") {
		t.Fatalf("gemini settings leaked master gateway token (H4 regression):\n%s", text)
	}
	scoped, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken: %v", err)
	}
	if scoped == "" {
		t.Fatalf("setup did not mint a scoped OTLP token under %s", opts.DataDir)
	}
	if !strings.Contains(text, "/otlp/geminicli/"+scoped) {
		t.Fatalf("gemini settings missing scoped path-token config:\n%s", text)
	}
}

func TestGeminiSetup_MigratesLegacySchemaInPlace(t *testing.T) {
	// Regression: defenseclaw < 0.x wrote `target: "otlp"`,
	// `protocol: "http/json"`, and `managedBy: "defenseclaw"` —
	// all three are rejected by the current Gemini CLI schema, so
	// `gemini` refuses to start until the file is repaired. Running
	// `defenseclaw setup` against a stale settings.json must
	// migrate the keys (not just append).
	dir := testenv.PrivateTempDir(t)
	cfgPath := filepath.Join(dir, "settings.json")
	prev := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = cfgPath
	t.Cleanup(func() { GeminiSettingsPathOverride = prev })

	legacy := map[string]interface{}{
		"telemetry": map[string]interface{}{
			"enabled":      true,
			"target":       "otlp",
			"otlpEndpoint": "http://127.0.0.1:18790/otlp/geminicli/legacy-token",
			"protocol":     "http/json",
			"logPrompts":   true,
			"managedBy":    "defenseclaw",
		},
		"userSetting": "keep",
	}
	body, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy config: %v", err)
	}
	if err := os.WriteFile(cfgPath, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	conn := NewGeminiCLIConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup over legacy config: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	text := string(data)
	for _, banned := range []string{`"target": "otlp"`, `"protocol": "http/json"`, `"managedBy": "defenseclaw"`} {
		if strings.Contains(text, banned) {
			t.Fatalf("legacy schema key %q survived migration:\n%s", banned, text)
		}
	}
	for _, want := range []string{`"target": "local"`, `"otlpProtocol": "http"`, `"useCollector": true`, `"userSetting": "keep"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("migrated config missing %q:\n%s", want, text)
		}
	}
}

func TestGeminiTeardown_DriftedConfigRemovesManagedTelemetry(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	cfgPath := filepath.Join(dir, "settings.json")
	prev := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = cfgPath
	t.Cleanup(func() { GeminiSettingsPathOverride = prev })

	conn := NewGeminiCLIConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read setup config: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse setup config: %v", err)
	}
	cfg["userSetting"] = "keep"
	telemetry, _ := cfg["telemetry"].(map[string]interface{})
	if telemetry == nil {
		t.Fatal("setup did not create telemetry object")
	}
	telemetry["userTelemetrySetting"] = "keep"
	drifted, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal drifted config: %v", err)
	}
	if err := os.WriteFile(cfgPath, append(drifted, '\n'), 0o600); err != nil {
		t.Fatalf("write drifted config: %v", err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if token, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI); err != nil || token != "" {
		t.Fatalf("LoadOTLPPathToken after drifted teardown = %q, %v; want revoked token", token, err)
	}
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config after teardown: %v", err)
	}
	text := string(restored)
	for _, forbidden := range []string{"geminicli-hook.sh", "/otlp/geminicli/", `"managedBy": "defenseclaw"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("teardown left managed Gemini residue %q:\n%s", forbidden, text)
		}
	}
	for _, want := range []string{`"userSetting": "keep"`, `"userTelemetrySetting": "keep"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("teardown did not preserve user edit %q:\n%s", want, text)
		}
	}
	var cleaned map[string]interface{}
	if err := json.Unmarshal(restored, &cleaned); err != nil {
		t.Fatalf("parse config after teardown: %v", err)
	}
	cleanedTelemetry, _ := cleaned["telemetry"].(map[string]interface{})
	for _, managedKey := range []string{"enabled", "traces", "target", "otlpEndpoint", "otlpProtocol", "useCollector", "useCliAuth", "outfile", "logPrompts"} {
		if _, present := cleanedTelemetry[managedKey]; present {
			t.Fatalf("teardown left managed Gemini telemetry key %q: %#v", managedKey, cleanedTelemetry)
		}
	}
	if cleanedTelemetry["userTelemetrySetting"] != "keep" {
		t.Fatalf("teardown did not preserve foreign Gemini telemetry: %#v", cleanedTelemetry)
	}
}

func TestHookOnlyTeardown_UsesBackedUpConfigPathWhenWorkspaceChanges(t *testing.T) {
	dir := t.TempDir()
	prevHooks := CopilotHooksPathOverride
	prevWorkspace := CopilotWorkspaceDirOverride
	CopilotHooksPathOverride = ""
	CopilotWorkspaceDirOverride = ""
	t.Cleanup(func() {
		CopilotHooksPathOverride = prevHooks
		CopilotWorkspaceDirOverride = prevWorkspace
	})

	oldWorkspace := filepath.Join(dir, "old-workspace")
	newWorkspace := filepath.Join(dir, "new-workspace")
	conn := NewCopilotConnector()
	setupOpts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: oldWorkspace,
	}
	if err := conn.Setup(context.Background(), setupOpts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	oldPath := filepath.Join(oldWorkspace, ".github", "hooks", "defenseclaw.json")
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("expected old workspace hook config after setup: %v", err)
	}

	teardownOpts := setupOpts
	teardownOpts.WorkspaceDir = newWorkspace
	if err := conn.Teardown(context.Background(), teardownOpts); err != nil {
		t.Fatalf("Teardown with changed workspace: %v", err)
	}
	if _, err := os.Stat(oldPath); err == nil {
		t.Fatalf("old workspace hook config survived teardown: %s", oldPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat old workspace hook config: %v", err)
	}
}

func TestOpenHandsWorkspaceRootFallsBackToHomeWhenDaemonCwdIsDataDir(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	testenv.SetHome(t, home)

	prevHooks := OpenHandsHooksPathOverride
	prevWorkspace := OpenHandsWorkspaceDirOverride
	OpenHandsHooksPathOverride = ""
	OpenHandsWorkspaceDirOverride = ""
	t.Cleanup(func() {
		OpenHandsHooksPathOverride = prevHooks
		OpenHandsWorkspaceDirOverride = prevWorkspace
	})

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dataDir); err != nil {
		t.Fatalf("chdir data dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	got := openhandsHooksPath(SetupOpts{DataDir: dataDir})
	want := filepath.Join(home, ".openhands", "hooks.json")
	if got != want {
		t.Fatalf("OpenHands hooks path = %q, want SDK-reachable home fallback %q", got, want)
	}
}

func TestCopilotSetupDefaultsToGlobalWhenDaemonCwdIsDataDir(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	dataDir := filepath.Join(dir, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	testenv.SetHome(t, home)

	prevHooks := CopilotHooksPathOverride
	prevWorkspace := CopilotWorkspaceDirOverride
	CopilotHooksPathOverride = ""
	CopilotWorkspaceDirOverride = ""
	t.Cleanup(func() {
		CopilotHooksPathOverride = prevHooks
		CopilotWorkspaceDirOverride = prevWorkspace
	})

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dataDir); err != nil {
		t.Fatalf("chdir data dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	err = NewCopilotConnector().Setup(context.Background(), SetupOpts{
		DataDir:  dataDir,
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	if err != nil {
		t.Fatalf("Copilot setup with global home path failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".copilot", "hooks", "defenseclaw.json")); err != nil {
		t.Fatalf("stat global copilot hook config: %v", err)
	}

	err = NewCopilotConnector().Setup(context.Background(), SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: dataDir,
	})
	if err == nil {
		t.Fatal("Copilot setup succeeded with explicit data dir as workspace")
	}
	if !strings.Contains(err.Error(), "workspace must be outside DefenseClaw data dir") {
		t.Fatalf("Copilot setup error = %v, want clear workspace error", err)
	}
}

func TestCopilotHomeOverrideDrivesHooksAndInventory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "copilot-home")
	t.Setenv("COPILOT_HOME", root)
	opts := SetupOpts{}

	if got, want := copilotHooksPath(opts), filepath.Join(root, "hooks", "defenseclaw.json"); got != want {
		t.Fatalf("copilotHooksPath = %q, want %q", got, want)
	}
	caps := NewCopilotConnector().Capabilities(opts)
	for _, want := range []string{
		filepath.Join(root, "mcp-config.json"),
		filepath.Join(root, "skills"),
		filepath.Join(root, "agents"),
	} {
		found := false
		for _, paths := range [][]string{
			caps.MCP.ConfigPaths,
			caps.Skills.ReadPaths,
			caps.Agents.ReadPaths,
		} {
			if stringInSlice(paths, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Copilot capabilities do not contain COPILOT_HOME path %q: %+v", want, caps)
		}
	}
}

func TestCopilotInventoryReadsOfficialWorkspacePrecedence(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(repo, "packages", "service")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(t.TempDir(), "custom-skills")
	t.Setenv("COPILOT_SKILLS_DIRS", custom+",relative-skills")
	opts := SetupOpts{WorkspaceDir: workspace}
	caps := NewCopilotConnector().Capabilities(opts)

	wantSkillPrefix := []string{
		filepath.Join(workspace, ".github", "skills"),
		filepath.Join(workspace, ".agents", "skills"),
		filepath.Join(workspace, ".claude", "skills"),
		filepath.Join(filepath.Dir(workspace), ".github", "skills"),
		filepath.Join(repo, ".github", "skills"),
	}
	if len(caps.Skills.ReadPaths) < len(wantSkillPrefix) {
		t.Fatalf("Copilot skill read paths too short: %v", caps.Skills.ReadPaths)
	}
	for i, want := range wantSkillPrefix {
		if caps.Skills.ReadPaths[i] != want {
			t.Fatalf("Copilot skill read path %d=%q, want %q; all=%v", i, caps.Skills.ReadPaths[i], want, caps.Skills.ReadPaths)
		}
	}
	for _, want := range []string{custom, filepath.Join(workspace, "relative-skills")} {
		if !stringInSlice(caps.Skills.ReadPaths, want) {
			t.Fatalf("Copilot skill read paths missing %q: %v", want, caps.Skills.ReadPaths)
		}
	}
	if want := filepath.Join(workspace, ".claude", "commands"); caps.Skills.ReadPaths[len(caps.Skills.ReadPaths)-1] != want {
		t.Fatalf("Copilot command compatibility path=%q, want final low-priority path %q", caps.Skills.ReadPaths[len(caps.Skills.ReadPaths)-1], want)
	}
	for _, want := range []string{
		copilotHomePath("copilot-instructions.md"),
		copilotHomePath("instructions"),
		filepath.Join(repo, "AGENTS.md"),
		filepath.Join(repo, ".claude", "CLAUDE.md"),
		filepath.Join(repo, ".github", "instructions"),
		repo,
	} {
		if !stringInSlice(caps.Rules.ReadPaths, want) {
			t.Fatalf("Copilot instruction read paths missing %q: %v", want, caps.Rules.ReadPaths)
		}
	}
	if !caps.Rules.DiscoveryOnly || len(caps.Rules.WritePaths) != 0 {
		t.Fatalf("Copilot instructions must remain discovery-only: %+v", caps.Rules)
	}

	wantMCP := []string{
		filepath.Join(workspace, ".mcp.json"),
		filepath.Join(workspace, ".github", "mcp.json"),
		filepath.Join(filepath.Dir(workspace), ".mcp.json"),
		filepath.Join(filepath.Dir(workspace), ".github", "mcp.json"),
		filepath.Join(repo, ".mcp.json"),
		filepath.Join(repo, ".github", "mcp.json"),
		copilotHomePath("mcp-config.json"),
	}
	if !sameStrings(caps.MCP.ConfigPaths, wantMCP) {
		t.Fatalf("Copilot MCP read paths=%v, want %v", caps.MCP.ConfigPaths, wantMCP)
	}

	wantAgents := []string{
		filepath.Join(workspace, ".github", "agents"),
		filepath.Join(workspace, ".claude", "agents"),
		filepath.Join(filepath.Dir(workspace), ".github", "agents"),
		filepath.Join(filepath.Dir(workspace), ".claude", "agents"),
		filepath.Join(repo, ".github", "agents"),
		filepath.Join(repo, ".claude", "agents"),
	}
	for i, want := range wantAgents {
		if caps.Agents.ReadPaths[i] != want {
			t.Fatalf("Copilot agent read path %d=%q, want %q; all=%v", i, caps.Agents.ReadPaths[i], want, caps.Agents.ReadPaths)
		}
	}
	for _, forbidden := range []string{
		filepath.Join(workspace, ".claude", "skills"),
		filepath.Join(workspace, ".claude", "agents"),
		custom,
	} {
		if stringInSlice(caps.Skills.WritePaths, forbidden) || stringInSlice(caps.Agents.WritePaths, forbidden) {
			t.Fatalf("discovery-only Copilot path became writable: %q", forbidden)
		}
	}
}

func TestCopilotSettingsCascadePreservesEffectiveOperatorPolicy(t *testing.T) {
	home := filepath.Join(t.TempDir(), "copilot-home")
	repo := filepath.Join(t.TempDir(), "repo")
	workspace := filepath.Join(repo, "package")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".github", "copilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COPILOT_HOME", home)
	userSettings := append([]byte{0xEF, 0xBB, 0xBF}, []byte("{// user\n\"disableAllHooks\": true,}")...)
	if err := os.WriteFile(filepath.Join(home, "settings.json"), userSettings, 0o600); err != nil {
		t.Fatal(err)
	}
	claudeLocal := filepath.Join(repo, ".claude", "settings.local.json")
	if err := os.WriteFile(claudeLocal, []byte(`{"disableAllHooks": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(repo, ".github", "copilot", "settings.local.json")
	if err := os.WriteFile(local, []byte(`{"disableAllHooks": false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{WorkspaceDir: workspace}
	if err := validateCopilotHookPolicy(opts, filepath.Join(repo, "missing-hooks.json")); err != nil {
		t.Fatalf("higher-priority false did not override user true: %v", err)
	}
	if err := os.WriteFile(local, []byte(`{"disableAllHooks": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := validateCopilotHookPolicy(opts, filepath.Join(repo, "missing-hooks.json"))
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite operator policy") {
		t.Fatalf("effective disableAllHooks did not block setup: %v", err)
	}
	registration := filepath.Join(workspace, ".github", "hooks", "defenseclaw.json")
	err = NewCopilotConnector().patchConfig(opts, "unused")
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite operator policy") {
		t.Fatalf("Copilot Setup path did not preserve effective operator policy: %v", err)
	}
	if _, statErr := os.Stat(registration); !os.IsNotExist(statErr) {
		t.Fatalf("Copilot Setup mutated disabled registration %q: %v", registration, statErr)
	}
}

func TestCopilotSettingsCascadeRejectsMalformedJSONC(t *testing.T) {
	home := t.TempDir()
	t.Setenv("COPILOT_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "settings.json"), []byte(`{"disableAllHooks": "yes"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := validateCopilotHookPolicy(SetupOpts{}, filepath.Join(home, "hooks", "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "must be boolean") {
		t.Fatalf("malformed setting was not rejected: %v", err)
	}
}

func TestCopilotLifecycleHomeRejectsNonExactBinding(t *testing.T) {
	t.Setenv("COPILOT_HOME", " relative-home ")
	if err := validateCopilotLifecycleHome(SetupOpts{}); err == nil || !strings.Contains(err.Error(), "absolute normalized") {
		t.Fatalf("non-exact COPILOT_HOME accepted: %v", err)
	}
}

func TestCopilotShellBootstrapFailuresAlwaysOpen(t *testing.T) {
	script, err := hookFS.ReadFile("hooks/copilot-hook.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(script)
	if strings.Contains(body, "exit 2") {
		t.Fatalf("Copilot shell bootstrap contains a fail-closed exit: %s", body)
	}
	for _, required := range []string{
		`HOME="$(cd ~ 2>/dev/null && pwd)" || exit 0`,
		`HOOK_BASE="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 0`,
		`HOOK_DIR="$(cd -P -- "$HOOK_PARENT" 2>/dev/null && pwd)" || exit 0`,
		`if [ ! -r "${HOOK_DIR}/_hardening.sh" ]; then`,
		`if ! . "${HOOK_DIR}/_hardening.sh"; then`,
		`if ! defenseclaw_harden_resources; then`,
		`if ! defenseclaw_harden_env; then`,
	} {
		if !strings.Contains(body, required) {
			t.Errorf("Copilot shell bootstrap missing fail-open guard %q", required)
		}
	}
}

func TestCopilotWindowsHooksRepairAndTeardown(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Copilot selects the powershell hook field only on Windows")
	}
	const hookBinary = `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`
	setHookBinaryOverride(t, hookBinary)
	current := windowsCopilotPowerShellHookCommandForBinary(hookBinary)
	legacy := legacyWindowsCopilotPowerShellHookCommandForBinary(hookBinary)
	duplicated := legacyWindowsCopilotDoubleCallOperatorHookCommandForBinary(hookBinary)
	legacyEvent := legacyWindowsCopilotPowerShellHookCommandForEvent("preToolUse", hookBinary)
	historic := legacyWindowsCopilotDoubleCallOperatorHookCommandForBinary(
		filepath.Join(userHomeDir(), ".local", "bin", windowsHookBinaryName),
	)
	foreign := "Write-Output 'operator hook'"
	path := filepath.Join(t.TempDir(), "defenseclaw.json")
	cfg := map[string]interface{}{
		"version": 1,
		"hooks": map[string]interface{}{
			"preToolUse": []interface{}{
				map[string]interface{}{"type": "command", "powershell": legacyEvent, "timeoutSec": 30},
				map[string]interface{}{"type": "command", "powershell": duplicated, "timeoutSec": 30},
				map[string]interface{}{"type": "command", "powershell": legacy, "timeoutSec": 30},
				map[string]interface{}{"type": "command", "powershell": historic, "timeoutSec": 30},
				map[string]interface{}{"type": "command", "powershell": foreign, "timeoutSec": 10},
			},
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if err := patchCopilotHooks(path, current); err != nil {
		t.Fatalf("patchCopilotHooks: %v", err)
	}
	repaired, err := readJSONObject(path)
	if err != nil {
		t.Fatalf("read repaired hooks: %v", err)
	}
	hooks := repaired["hooks"].(map[string]interface{})
	for event, raw := range hooks {
		entries := raw.([]interface{})
		managed := 0
		wantEventCommand := windowsCopilotPowerShellHookCommandForEvent(event, hookBinary)
		for _, rawEntry := range entries {
			entry := rawEntry.(map[string]interface{})
			command, _ := entry["powershell"].(string)
			if command == wantEventCommand {
				managed++
				if entry["type"] != "command" || fmt.Sprint(entry["timeoutSec"]) != "30" {
					t.Errorf("%s canonical entry drifted: %#v", event, entry)
				}
			}
			if command == legacy || command == duplicated || command == historic || command == legacyEvent {
				t.Errorf("%s retained legacy Copilot command %q", event, command)
			}
		}
		if managed != 1 {
			t.Errorf("%s managed entry count = %d, want 1", event, managed)
		}
	}
	repairedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read repaired config: %v", err)
	}
	if !strings.Contains(string(repairedData), foreign) {
		t.Fatal("repair removed the operator-owned hook")
	}
	if err := patchCopilotHooks(path, current); err != nil {
		t.Fatalf("idempotent patchCopilotHooks: %v", err)
	}
	idempotentData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read idempotent config: %v", err)
	}
	if !bytes.Equal(idempotentData, repairedData) {
		t.Fatal("second Copilot migration changed the converged registration")
	}

	if err := removeJSONHookReferences(path, current); err != nil {
		t.Fatalf("removeJSONHookReferences: %v", err)
	}
	afterData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config after teardown: %v", err)
	}
	after := string(afterData)
	ownedCommands := []string{current, legacy, duplicated, historic, legacyEvent}
	for _, event := range copilotCurrentHookEvents {
		ownedCommands = append(ownedCommands, windowsCopilotPowerShellHookCommandForEvent(event, hookBinary))
	}
	for _, owned := range ownedCommands {
		if strings.Contains(after, owned) {
			t.Errorf("owned Copilot command survived teardown: %q", owned)
		}
	}
	if !strings.Contains(after, foreign) {
		t.Fatal("teardown removed the operator-owned hook")
	}
}

func TestCopilotHookContractReconciliationIsEventBoundAndVersionExact(t *testing.T) {
	const hookScript = `/opt/defenseclaw/hooks/copilot-hook.sh`
	path := filepath.Join(t.TempDir(), "defenseclaw.json")
	if err := os.WriteFile(path, []byte(`{
  "version": 1,
  "hooks": {
    "userPromptTransformed": [
      {"type":"command","bash":"/opt/operator/transform.sh","timeoutSec":15}
    ],
    "futureEvent": [
      {"type":"command","bash":"/opt/operator/future.sh","timeoutSec":15}
    ]
  }
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := patchCopilotHooksForOS(path, hookScript, copilotCurrentHookEvents, "linux"); err != nil {
		t.Fatalf("patch current contract: %v", err)
	}
	current, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := current["hooks"].(map[string]interface{})
	if len(hooks) != len(copilotCurrentHookEvents)+1 {
		t.Fatalf("current hook count=%d, want 14 managed event keys plus foreign future event: %v", len(hooks), mapKeys(hooks))
	}
	for _, event := range copilotCurrentHookEvents {
		entries := hooks[event].([]interface{})
		want := copilotHookInvocationCommandForEvent("linux", event, hookScript)
		found := false
		for _, raw := range entries {
			entry := raw.(map[string]interface{})
			if entry["bash"] == want {
				found = true
				if fmt.Sprint(entry["timeoutSec"]) != "30" {
					t.Fatalf("%s timeout=%#v, want 30", event, entry["timeoutSec"])
				}
			}
		}
		if !found {
			t.Fatalf("%s missing event-bound command %q: %#v", event, want, entries)
		}
	}

	if err := patchCopilotHooksForOS(path, hookScript, copilotLegacyHookEvents, "linux"); err != nil {
		t.Fatalf("reconcile legacy contract: %v", err)
	}
	legacy, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	legacyHooks := legacy["hooks"].(map[string]interface{})
	transformed := legacyHooks["userPromptTransformed"].([]interface{})
	if len(transformed) != 1 || transformed[0].(map[string]interface{})["bash"] != "/opt/operator/transform.sh" {
		t.Fatalf("v2-to-v1 reconciliation did not preserve only foreign transformed handler: %#v", transformed)
	}
	if future := legacyHooks["futureEvent"].([]interface{}); len(future) != 1 {
		t.Fatalf("unknown future event was changed: %#v", future)
	}
}

func TestCursorHooks_ActionIsFailClosedAndObserveRefreshIsFailOpen(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })

	conn := NewCursorConnector()
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, "dc"),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "tok-test",
		HookFailMode:  "closed",
		GuardrailMode: "action",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cursor hooks: %v", err)
	}
	if !strings.Contains(string(data), `"failClosed": true`) || strings.Contains(string(data), `"failClosed": false`) {
		t.Fatalf("Cursor action hooks must all be fail-closed:\n%s", string(data))
	}

	// Refreshing the same connector in observe mode must replace the
	// managed entries rather than retaining stale host-side enforcement.
	opts.GuardrailMode = "observe"
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("observe refresh Setup: %v", err)
	}
	cfg, err := readJSONObject(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	for event, raw := range hooks {
		entries, _ := raw.([]interface{})
		if len(entries) != 1 {
			t.Fatalf("Cursor %s entries = %d after refresh, want 1", event, len(entries))
		}
		entry, _ := entries[0].(map[string]interface{})
		if entry["failClosed"] != false {
			t.Fatalf("Cursor %s retained failClosed=true after observe refresh: %#v", event, entry)
		}
		if fmt.Sprint(entry["timeout"]) != "30" {
			t.Fatalf("Cursor %s timeout=%#v, want 30 seconds", event, entry["timeout"])
		}
	}
}

func TestCursorTeardownRestoresConfigAndRemovesOwnedRuntimes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".cursor", "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })

	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	const original = "{\n  \"version\": 1,\n  \"hooks\": {}\n}\n"
	if err := os.WriteFile(cfgPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := NewCursorConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		HookFailMode: "open",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	for _, name := range conn.HookScriptNames(opts) {
		if _, err := os.Stat(filepath.Join(opts.DataDir, "hooks", name)); err != nil {
			t.Fatalf("runtime %s missing after setup: %v", name, err)
		}
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Fatalf("Cursor config was not restored byte-for-byte:\n%s", restored)
	}
	for _, name := range []string{"cursor-hook.sh", "cursor-hook.ps1"} {
		if _, err := os.Stat(filepath.Join(opts.DataDir, "hooks", name)); !os.IsNotExist(err) {
			t.Fatalf("Cursor runtime %s remains after teardown: %v", name, err)
		}
	}
}

func TestCursorTeardownRefusesForeignRuntimeReplacement(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })

	conn := NewCursorConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	foreign := filepath.Join(opts.DataDir, "hooks", "cursor-hook.sh")
	if err := os.WriteFile(foreign, []byte("# operator-owned replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := conn.Teardown(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "without DefenseClaw ownership marker") {
		t.Fatalf("Teardown error = %v, want foreign-runtime refusal", err)
	}
	body, readErr := os.ReadFile(foreign)
	if readErr != nil || string(body) != "# operator-owned replacement\n" {
		t.Fatalf("foreign runtime was not preserved: body=%q err=%v", body, readErr)
	}
}

func TestCursorTeardownSurgicallyRemovesOnlyProvenOwnedCommands(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })

	opts := SetupOpts{DataDir: filepath.Join(dir, "dc")}
	owned := cursorOwnedHookCommands(opts)
	if len(owned) < 3 {
		t.Fatalf("owned Cursor commands = %v, want portable, adapter, and legacy native forms", owned)
	}
	foreignAdapter := "& " + powershellQuoteLiteral(filepath.Join(dir, "operator", "cursor-hook.ps1"))
	foreignNative := windowsQuoteExe(filepath.Join(dir, "operator", windowsGatewayBinaryName)) +
		" " + nativeHookFlag + "cursor"
	entries := make([]interface{}, 0, len(owned)+2)
	for _, command := range owned {
		entries = append(entries, map[string]interface{}{"type": "command", "command": command})
	}
	for _, command := range []string{foreignAdapter, foreignNative} {
		entries = append(entries, map[string]interface{}{"type": "command", "command": command})
	}
	fixture := map[string]interface{}{
		"version": 1,
		"hooks": map[string]interface{}{
			"preToolUse": entries,
		},
	}
	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewCursorConnector()
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	after, err := readJSONObject(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if structuredHookCommandReferences(after, owned) {
		t.Fatalf("managed Cursor command survived teardown: %#v", after)
	}
	for _, command := range []string{foreignAdapter, foreignNative} {
		if !structuredHookCommandReferences(after, []string{command}) {
			t.Fatalf("foreign Cursor command %q was removed: %#v", command, after)
		}
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean rejected foreign-only config: %v", err)
	}
}

func TestCursorHooks_RefreshMigratesNativeCommandAndUpdatesFailClosed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("direct-native to PowerShell adapter migration is Windows-specific")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })
	setHookBinaryOverride(t, filepath.Join(userHomeDir(), ".local", "bin", windowsHookBinaryName))

	legacyNative := windowsQuoteExe(defenseclawHookBinary()) + " " + nativeHookFlag + "cursor"
	foreign := `& 'C:\Tools\operator-hook.ps1'`
	seed := fmt.Sprintf(`{
  "version": 1,
  "hooks": {
    "beforeSubmitPrompt": [
      {"type":"command","command":%q,"failClosed":true},
      {"type":"command","command":%q,"failClosed":true}
    ]
  }
}`, legacyNative, foreign)
	if err := os.WriteFile(cfgPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewCursorConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		HookFailMode: "open",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("observe Setup: %v", err)
	}
	// A second setup must be idempotent rather than duplicating the adapter.
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repeated observe Setup: %v", err)
	}

	cfg, err := readJSONObject(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	entries, _ := hooks["beforeSubmitPrompt"].([]interface{})
	if len(entries) != 2 {
		t.Fatalf("beforeSubmitPrompt entries = %d, want one foreign and one DefenseClaw: %#v", len(entries), entries)
	}
	managedCount := 0
	foreignFound := false
	for _, raw := range entries {
		item, _ := raw.(map[string]interface{})
		command, _ := item["command"].(string)
		switch {
		case command == foreign:
			foreignFound = true
		case strings.Contains(command, "cursor-hook.ps1"):
			managedCount++
			if item["failClosed"] != false {
				t.Fatalf("observe adapter retained failClosed=true: %#v", item)
			}
		case command == legacyNative:
			t.Fatalf("legacy direct-native command survived refresh: %#v", item)
		}
	}
	if !foreignFound || managedCount != 1 {
		t.Fatalf("refresh did not preserve foreign hook and deduplicate adapter: %#v", entries)
	}
}

func TestCursorHookOwnershipMatcherKeepsConnectorBoundaryExact(t *testing.T) {
	ownedAdapter := `& 'C:\Users\tester\.defenseclaw\hooks\cursor-hook.ps1'`
	ownedPortable := `C:\Users\tester\.defenseclaw\hooks\cursor-hook.sh`
	owned := []string{ownedAdapter, ownedPortable}

	tests := []struct {
		name  string
		entry interface{}
		want  bool
	}{
		{name: "exact owned command", entry: map[string]interface{}{"command": ownedAdapter}, want: true},
		{name: "exact owned powershell", entry: map[string]interface{}{"powershell": ownedAdapter}, want: true},
		{name: "shell quoted owned portable", entry: map[string]interface{}{"bash": shellWord(ownedPortable)}, want: true},
		{name: "malformed entry", entry: map[string]interface{}{"command": json.Number("1")}, want: false},
		{name: "tampered owned command", entry: map[string]interface{}{"command": ownedAdapter + " -OperatorChanged"}, want: false},
		{
			name: "Copilot shaped command",
			entry: map[string]interface{}{
				"powershell": windowsCopilotPowerShellHookCommandForEvent("preToolUse", defenseclawHookBinary()),
			},
			want: false,
		},
		{
			name:  "foreign Cursor adapter",
			entry: map[string]interface{}{"command": `& 'C:\Operator\cursor-hook.ps1'`},
			want:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := managedCursorHookEntry(test.entry, owned)
			generic := false
			for _, command := range owned {
				if managedHookCommandEntry(test.entry, command) {
					generic = true
					break
				}
			}
			if got != generic {
				t.Fatalf("Cursor matcher = %v, generic ownership matcher = %v", got, generic)
			}
			if got != test.want {
				t.Fatalf("managedCursorHookEntry() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCursorHooksHighCardinalityForeignRegistrationsStayWithinLifecycleBudget(t *testing.T) {
	dataDir := `C:\Users\tester\.defenseclaw`
	legacyShellScript := filepath.Join(dataDir, "hooks", "cursor-hook.sh")
	hookScript := hookInvocationCommandFor("windows", "cursor", legacyShellScript)
	currentCommand := shellWord(hookScript)
	opts := SetupOpts{DataDir: dataDir}
	hooks := make(map[string]interface{}, len(cursorHookEvents))
	for _, event := range cursorHookEvents {
		entries := make([]interface{}, 0, 23)
		for index := 0; index < 22; index++ {
			foreignPath := fmt.Sprintf(`C:\stale-defenseclaw\%s\%02d\cursor-hook.ps1`, event, index)
			entries = append(entries, map[string]interface{}{
				"type":    "command",
				"command": "& " + powershellQuoteLiteral(foreignPath),
			})
		}
		hooks[event] = entries
	}

	started := time.Now()
	const iterations = 100
	for iteration := 0; iteration < iterations; iteration++ {
		patchMatcher := newCursorHookCommandMatcher(cursorManagedHookCommands(hookScript, legacyShellScript))
		for _, event := range cursorHookEvents {
			entry := map[string]interface{}{
				"type":       "command",
				"command":    currentCommand,
				"timeout":    json.Number("30"),
				"failClosed": false,
			}
			hooks[event] = replaceManagedCursorHooks(hooks[event], patchMatcher, entry)
		}
		verifyCommands := uniqueNonEmptyStrings(append(
			[]string{hookScript, currentCommand},
			cursorOwnedHookCommands(opts)...,
		))
		verifyMatcher := newCursorHookCommandMatcher(verifyCommands)
		// Exercise the exact post-write scan twice. Setup performs the first check;
		// the published-hook presence gate performs the same high-cardinality scan.
		if !cursorHookContractPresent(hooks, currentCommand, verifyMatcher, false) ||
			!cursorHookContractPresent(hooks, currentCommand, verifyMatcher, false) {
			t.Fatal("high-cardinality Cursor contract did not retain one exact managed entry per event")
		}
	}
	elapsed := time.Since(started)
	t.Logf("%d Cursor 21x23 patch plus two exact ownership-scan cycles completed in %s (average %s)", iterations, elapsed, elapsed/iterations)
	if elapsed > 15*time.Second {
		t.Fatalf("Cursor patch plus repeated ownership verification took %s, want <=15s within the fixed 2m lifecycle budget", elapsed)
	}

	for _, event := range cursorHookEvents {
		entries, _ := hooks[event].([]interface{})
		if len(entries) != 23 {
			t.Fatalf("Cursor %s entries = %d, want 22 preserved foreign entries plus one exact owned entry", event, len(entries))
		}
		ownedCount := 0
		staleCount := 0
		for _, raw := range entries {
			entry, _ := raw.(map[string]interface{})
			command, _ := entry["command"].(string)
			switch {
			case command == currentCommand:
				ownedCount++
			case strings.Contains(command, `C:\stale-defenseclaw\`):
				staleCount++
			}
		}
		if ownedCount != 1 || staleCount != 22 {
			t.Fatalf("Cursor %s preservation counts = owned:%d stale:%d, want 1/22", event, ownedCount, staleCount)
		}
	}
}

func TestHookOnlyHookScripts_RespectFailClosedCapability(t *testing.T) {
	cases := []struct {
		name          string
		connector     *hookOnlyConnector
		guardrailMode string
		wantFailMode  string
	}{
		{name: "cursor_action_forces_fail_closed", connector: NewCursorConnector(), guardrailMode: "action", wantFailMode: "closed"},
		{name: "cursor_observe_forces_fail_open", connector: NewCursorConnector(), guardrailMode: "observe", wantFailMode: "open"},
		{name: "devin_supports_fail_closed", connector: NewDevinConnector(), wantFailMode: "closed"},
		{name: "openhands_supports_fail_closed", connector: NewOpenHandsConnector(), wantFailMode: "closed"},
		{name: "hermes_downgrades_to_fail_open", connector: NewHermesConnector(), wantFailMode: "open"},
		{name: "copilot_downgrades_to_fail_open", connector: NewCopilotConnector(), wantFailMode: "open"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := SetupOpts{
				DataDir:       filepath.Join(dir, "dc"),
				APIAddr:       "127.0.0.1:18970",
				APIToken:      "tok-test",
				HookFailMode:  "closed",
				GuardrailMode: tc.guardrailMode,
				WorkspaceDir:  dir,
			}
			if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dir, "hooks"), opts, tc.connector); err != nil {
				t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
			}
			body, err := os.ReadFile(filepath.Join(dir, "hooks", tc.connector.scriptName))
			if err != nil {
				t.Fatalf("read hook script: %v", err)
			}
			want := `FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-` + tc.wantFailMode + `}"`
			if tc.connector.Name() == "copilot" {
				want = `FAIL_MODE="open"`
				if strings.Contains(string(body), "DEFENSECLAW_FAIL_MODE:-") {
					t.Fatalf("Copilot shell hook still accepts an inherited closed fail mode:\n%s", string(body))
				}
			}
			if !strings.Contains(string(body), want) {
				t.Fatalf("hook script missing %s:\n%s", want, string(body))
			}
		})
	}
}

func TestOpenHandsHookScript_BlockExitsTwo(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/openhands/hook" {
			t.Fatalf("path=%s want /api/v1/openhands/hook", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hook_output":{"decision":"deny","reason":"policy denied"}}`))
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	dir := t.TempDir()
	if err := WriteHookScriptsForConnectorObjectWithOpts(dir, SetupOpts{APIAddr: addr, APIToken: "tok-test", HookFailMode: "closed"}, NewOpenHandsConnector()); err != nil {
		t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
	}
	home := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(dir, "openhands-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"cat /etc/shadow"}}`)
	cmd.Env = append(os.Environ(), "DEFENSECLAW_HOME="+home)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("OpenHands deny hook exited 0, want exit 2; output=%s", string(out))
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("OpenHands deny hook exit=%v want code 2; output=%s", err, string(out))
	}
	if !strings.Contains(string(out), `"decision":"deny"`) {
		t.Fatalf("OpenHands deny hook did not print decision JSON; output=%s", string(out))
	}
}
