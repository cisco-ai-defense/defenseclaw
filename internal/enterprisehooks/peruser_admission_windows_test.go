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

//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePerUserAdmissionFixture(t *testing.T, home string, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{home}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("image"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWindowsStandalonePerUserAdmissionSelectsOnlyAdmissibleImages(t *testing.T) {
	home := t.TempDir()
	const ampVersion = "0.0.1785875347-gbc402f"

	if ok, reason := windowsStandalonePerUserAdmission(home, "amp", ampVersion); ok ||
		!strings.Contains(reason, "amp.exe") {
		t.Fatalf("amp without a native image: ok=%v reason=%q", ok, reason)
	}
	amp := writePerUserAdmissionFixture(t, home, windowsStandaloneManagedExecutableRelative["amp"][0]...)
	if ok, reason := windowsStandalonePerUserAdmission(home, "amp", ampVersion); !ok {
		t.Fatalf("amp with its native npm image refused: %s", reason)
	}
	if got, _ := windowsStandalonePerUserManagedExecutable(home, "amp"); got != amp {
		t.Fatalf("amp executable = %q, want %q", got, amp)
	}
	if ok, reason := windowsStandalonePerUserAdmission(home, "amp", "not-a-version"); ok ||
		!strings.Contains(reason, "known hook contract") {
		t.Fatalf("amp with unknown version: ok=%v reason=%q", ok, reason)
	}

	// npm OpenCode is admitted only when the opencode-ai package identity
	// checks out; the SST WinGet image wins when both exist.
	npmOpenCode := writePerUserAdmissionFixture(t, home, "AppData", "Roaming", "npm", "node_modules", "opencode-ai", "bin", "opencode.exe")
	if _, reason := windowsStandalonePerUserManagedExecutable(home, "opencode"); !strings.Contains(reason, "opencode-ai") {
		t.Fatalf("npm OpenCode without its package.json: reason = %q", reason)
	}
	manifest := filepath.Join(filepath.Dir(filepath.Dir(npmOpenCode)), "package.json")
	if err := os.WriteFile(manifest, []byte(`{"name":"not-opencode"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := windowsStandalonePerUserManagedExecutable(home, "opencode"); got != "" {
		t.Fatalf("npm OpenCode with a foreign package name was admitted: %q", got)
	}
	if err := os.WriteFile(manifest, []byte(`{"name":"opencode-ai","version":"1.18.32"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, reason := windowsStandalonePerUserManagedExecutable(home, "opencode"); got != npmOpenCode {
		t.Fatalf("npm OpenCode = %q (%s), want %q", got, reason, npmOpenCode)
	}
	winget := writePerUserAdmissionFixture(t, home, windowsStandaloneManagedExecutableRelative["opencode"][0]...)
	if got, _ := windowsStandalonePerUserManagedExecutable(home, "opencode"); got != winget {
		t.Fatalf("OpenCode with both installs = %q, want the WinGet image %q", got, winget)
	}

	// Hermes binds to the updater-managed image inside the target profile.
	if _, reason := windowsStandalonePerUserManagedExecutable(home, "hermes"); !strings.Contains(reason, "not present") {
		t.Fatalf("hermes without its image: reason = %q", reason)
	}
	hermes := writePerUserAdmissionFixture(t, home, "AppData", "Local", "hermes", "hermes-agent", "venv", "Scripts", "hermes.exe")
	if got, reason := windowsStandalonePerUserManagedExecutable(home, "hermes"); got != hermes {
		t.Fatalf("hermes = %q (%s), want %q", got, reason, hermes)
	}

	// Connectors without protected executable admission need no image.
	if exe, reason := windowsStandalonePerUserManagedExecutable(home, "copilot"); exe != "" || reason != "" {
		t.Fatalf("copilot selection = %q/%q, want none", exe, reason)
	}
}

// hermesBootstrapProfile lays out a Hermes 0.21.5 bootstrap install: the
// launcher in hermes\bin, the install stamp in hermes\hermes-agent and the
// leased virtual environment under hermes\installs, with no
// hermes-agent\venv.
func hermesBootstrapProfile(t *testing.T) (home, launcher string) {
	t.Helper()
	home = t.TempDir()
	root := filepath.Join(home, "AppData", "Local", "hermes")
	launcher = writePerUserAdmissionFixture(t, home, "AppData", "Local", "hermes", "bin", "hermes.exe")
	writePerUserAdmissionFixture(t, home, "AppData", "Local", "hermes", "installs", "04a441694ca8a16e",
		"environments", "401a1ded57e044b79c54bbb9cf9de7cf", "venv", "Scripts", "hermes.exe")
	stamp := filepath.Join(root, "hermes-agent", "install-stamp.json")
	if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stamp, []byte(`{"schemaVersion":2,"baseVersion":"0.21.5","payload":"bootstrap"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, launcher
}

func TestWindowsStandalonePerUserAdmissionSelectsTheHermesBootstrapLauncher(t *testing.T) {
	home, launcher := hermesBootstrapProfile(t)
	if got, reason := windowsStandalonePerUserManagedExecutable(home, "hermes"); got != launcher {
		t.Fatalf("hermes bootstrap install = %q (%s), want the launcher %q", got, reason, launcher)
	}
	if ok, reason := windowsStandaloneRowAdmission(home, "hermes", "0.21.5"); !ok {
		t.Fatalf("hermes 0.21.5 bootstrap install refused: %s", reason)
	}
}

func TestEnumerateWindowsStandaloneEnrollsHermesBootstrapInstalls(t *testing.T) {
	stubMachineWinGet(t, nil)
	previousStandalone := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previousStandalone })
	home, _ := hermesBootstrapProfile(t)
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("hermes"), EnumerateOptions{})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].AgentVersion != "0.21.5" {
		t.Fatalf("targets = %+v, want one hermes row at 0.21.5", manifest.Targets)
	}
}
