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

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// withoutMachineAgentPrefixes keeps the host's own agent installs out of the
// executable search.
func withoutMachineAgentPrefixes(t *testing.T) {
	t.Helper()
	previous := machinePrefixes
	machinePrefixes = func() []string { return nil }
	t.Cleanup(func() { machinePrefixes = previous })
}

// writeUVToolOpenHands lays out OpenHands the way `uv tool install` does: a
// link in ~/.local/bin to the entry point in the tool environment. It
// returns the entry point as the host resolves it.
func writeUVToolOpenHands(t *testing.T, home string) string {
	t.Helper()
	entry := filepath.Join(home, ".local", "share", "uv", "tools", "openhands", "bin", "openhands")
	writeTestExecutable(t, entry, 0o755)
	link := filepath.Join(home, ".local", "bin", "openhands")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(entry, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(entry)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func writeTestExecutable(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'OpenHands CLI 1.16.0'\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestUnixManagedAgentExecutableResolvesToolLauncherLink(t *testing.T) {
	withoutMachineAgentPrefixes(t)
	home := newTestHome(t)
	want := writeUVToolOpenHands(t, home)
	got, err := unixManagedAgentExecutable(home, "openhands")
	if err != nil {
		t.Fatalf("unixManagedAgentExecutable: %v", err)
	}
	if got != want {
		t.Fatalf("selected %q, want the tool entry point %q", got, want)
	}
}

func TestUnixManagedAgentExecutableSkipsInadmissibleCandidates(t *testing.T) {
	withoutMachineAgentPrefixes(t)
	home := newTestHome(t)
	if _, err := unixManagedAgentExecutable(home, "openhands"); err == nil ||
		!strings.Contains(err.Error(), "no openhands executable was found") {
		t.Fatalf("empty home error = %v, want not-found", err)
	}

	// A link to an image with another name, and a non-executable file,
	// cannot pass the connector's admission and are skipped.
	renamed := filepath.Join(home, "tools", "openhands-cli")
	writeTestExecutable(t, renamed, 0o755)
	link := filepath.Join(home, ".local", "bin", "openhands")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(renamed, link); err != nil {
		t.Fatal(err)
	}
	writeTestExecutable(t, filepath.Join(home, ".npm-global", "bin", "openhands"), 0o644)
	plain := filepath.Join(home, "bin", "openhands")
	writeTestExecutable(t, plain, 0o755)
	want, err := filepath.EvalSymlinks(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unixManagedAgentExecutable(home, "openhands")
	if err != nil {
		t.Fatalf("unixManagedAgentExecutable: %v", err)
	}
	if got != want {
		t.Fatalf("selected %q, want the first admissible image %q", got, want)
	}
}

func TestSelectManagedAgentExecutableLeavesUnprotectedConnectorsAlone(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	withoutMachineAgentPrefixes(t)
	home := newTestHome(t)
	writeUVToolOpenHands(t, home)
	dataDir := filepath.Join(home, ".defenseclaw")
	for _, name := range []string{"codex", "claudecode", "copilot"} {
		opts := connector.SetupOpts{DataDir: dataDir, AgentVersion: "1.0.0"}
		if err := selectManagedAgentExecutable(home, dataDir, name, &opts); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if opts.AgentExecutable != "" {
			t.Fatalf("%s: selected %q for a connector without protected admission", name, opts.AgentExecutable)
		}
	}
	if runtime.GOOS != "darwin" {
		opts := connector.SetupOpts{DataDir: dataDir, AgentVersion: "1.16.0"}
		if err := selectManagedAgentExecutable(home, dataDir, "openhands", &opts); err != nil || opts.AgentExecutable != "" {
			t.Fatalf("openhands off macOS: executable=%q err=%v, want no selection", opts.AgentExecutable, err)
		}
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("no selection may create the data dir or a receipt: %v", err)
	}
}

// On macOS the OpenHands connector admits only a protected, setup-selected
// executable. The managed per-user install records the user's own image and
// the hook contract lock binds to it.
func TestInstallOpenHandsRecordsTheUsersExecutableOnDarwin(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	if runtime.GOOS != "darwin" {
		t.Skip("OpenHands protected executable admission is macOS-only")
	}
	setStandaloneProfileForTest(t, true)
	withoutMachineAgentPrefixes(t)
	home := newTestHome(t)
	executable := writeUVToolOpenHands(t, home)
	if _, err := Install(context.Background(), InstallOptions{
		ConnectorName: "openhands",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		AgentVersion:  "1.16.0",
		GuardrailMode: "action",
		Registry:      connector.NewDefaultRegistry(),
	}); err != nil {
		t.Fatalf("Install OpenHands with the user's executable: %v", err)
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	info, err := os.Lstat(filepath.Join(dataDir, "agent_selection.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("selection receipt: info=%v err=%v, want a private file", info, err)
	}
	lock := connector.LoadHookContractLockEntry(dataDir, "openhands")
	if lock.AgentExecutable != executable || lock.AgentExecutableSource != "setup-selected" || lock.AgentExecutableSHA256 == "" {
		t.Fatalf("hook contract lock executable=%q source=%q digest=%q, want %q setup-selected",
			lock.AgentExecutable, lock.AgentExecutableSource, lock.AgentExecutableSHA256, executable)
	}
	data, err := os.ReadFile(filepath.Join(home, ".openhands", "hooks.json"))
	if err != nil || !strings.Contains(string(data), "openhands-hook") {
		t.Fatalf("OpenHands hooks file lacks the DefenseClaw hook: err=%v\n%s", err, data)
	}

	// A repair after the image changed binds the lock to the new digest.
	if err := os.WriteFile(executable, []byte("#!/bin/sh\necho 'OpenHands CLI 1.16.0 rebuilt'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), InstallOptions{
		ConnectorName: "openhands",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		AgentVersion:  "1.16.0",
		GuardrailMode: "action",
		Registry:      connector.NewDefaultRegistry(),
	}); err != nil {
		t.Fatalf("repair after the executable changed: %v", err)
	}
	repaired := connector.LoadHookContractLockEntry(dataDir, "openhands")
	if repaired.AgentExecutableSHA256 == "" || repaired.AgentExecutableSHA256 == lock.AgentExecutableSHA256 {
		t.Fatalf("repaired lock digest %q, want a new digest (was %q)", repaired.AgentExecutableSHA256, lock.AgentExecutableSHA256)
	}
}

func TestInstallOpenHandsWithoutExecutableIsRefusedOnDarwin(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	if runtime.GOOS != "darwin" {
		t.Skip("OpenHands protected executable admission is macOS-only")
	}
	setStandaloneProfileForTest(t, true)
	withoutMachineAgentPrefixes(t)
	home := newTestHome(t)
	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "openhands",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "test-token",
		AgentVersion:  "1.16.0",
		GuardrailMode: "action",
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be managed for this user") {
		t.Fatalf("Install without an OpenHands executable error = %v, want a refusal", err)
	}
	if lock := connector.LoadHookContractLockEntry(filepath.Join(home, ".defenseclaw"), "openhands"); lock.Connector != "" {
		t.Fatalf("refused install wrote a hook contract lock: %+v", lock)
	}
}

// The Secure Client macOS guardian never selected an OpenHands executable:
// outside the standalone profile nothing is selected and no receipt or data
// directory is written.
func TestSelectManagedAgentExecutableIsStandaloneOnly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("OpenHands protected executable admission is macOS-only")
	}
	setStandaloneProfileForTest(t, false)
	withoutMachineAgentPrefixes(t)
	home := newTestHome(t)
	writeUVToolOpenHands(t, home)
	dataDir := filepath.Join(home, ".defenseclaw")
	opts := connector.SetupOpts{DataDir: dataDir, AgentVersion: "1.16.0"}
	if err := selectManagedAgentExecutable(home, dataDir, "openhands", &opts); err != nil || opts.AgentExecutable != "" {
		t.Fatalf("Secure Client selection: executable=%q err=%v, want none", opts.AgentExecutable, err)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("Secure Client selection created the data dir or a receipt: %v", err)
	}
}
