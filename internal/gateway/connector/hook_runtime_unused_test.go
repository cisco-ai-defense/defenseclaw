// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// writeUnusedSharedHookRuntime lays out the shared hook runtime of an account
// whose last connector was removed: a lock naming no connector and the
// shared scripts, with no connector's runtime record.
func writeUnusedSharedHookRuntime(t *testing.T) (dataDir string, scripts []string) {
	t.Helper()
	dataDir = t.TempDir()
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, hookContractLockFile), []byte(`{"version":1,"connectors":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, genericHookScripts...), hookHelperScripts...) {
		path := filepath.Join(hookDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, path)
	}
	return dataDir, scripts
}

func TestRemoveUnusedSharedHookRuntimeRemovesAnUnusedRuntime(t *testing.T) {
	dataDir, scripts := writeUnusedSharedHookRuntime(t)
	hookDir := filepath.Join(dataDir, "hooks")
	record := filepath.Join(hookDir, ".gateway-helper")
	markers := filepath.Join(hookDir, ".outage-warnings")
	if err := os.WriteFile(record, []byte("helper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(markers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markers, "old-session"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveUnusedSharedHookRuntime(dataDir); err != nil {
		t.Fatalf("RemoveUnusedSharedHookRuntime: %v", err)
	}
	for _, path := range append(scripts, record, markers, filepath.Join(dataDir, hookContractLockFile)) {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived an unused runtime's removal: %v", path, err)
		}
	}
}

// A hooks/.hookcfg that cannot be read is not an unused one: the removal
// fails and keeps the shared scripts and the lock (W16 review). It went on
// and deleted them.
func TestRemoveUnusedSharedHookRuntimeKeepsTheRuntimeWhenTheSidecarIsUnreadable(t *testing.T) {
	dataDir, scripts := writeUnusedSharedHookRuntime(t)
	// A directory at the sidecar path fails every read, also as root.
	if err := os.Mkdir(filepath.Join(dataDir, "hooks", hookConfigSidecarName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveUnusedSharedHookRuntime(dataDir); err == nil {
		t.Fatal("RemoveUnusedSharedHookRuntime succeeded over an unreadable hook config sidecar")
	}
	for _, path := range append(scripts, filepath.Join(dataDir, hookContractLockFile)) {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was removed over an unreadable hook config sidecar: %v", path, err)
		}
	}
}

// r102 GAP-0430: with no connector left, Hermes' lifecycle lock, its setup
// record and its empty backup folder go too, and so does its disabled
// tombstone unless a Hermes process of the account may still have the
// fail-closed hook cached. A tombstone that blocks on purpose, a script that
// is not a tombstone and a backup folder with a receipt stay.
func TestRemoveUnusedSharedHookRuntimeRemovesIdleConnectorLeftovers(t *testing.T) {
	for _, running := range []bool{false, true} {
		dataDir, _ := writeUnusedSharedHookRuntime(t)
		hookDir := filepath.Join(dataDir, "hooks")
		files := map[string]string{
			filepath.Join(hookDir, "hermes-hook.sh"):                                 disabledHookTombstone("hermes"),
			filepath.Join(hookDir, "devin-hook.sh"):                                  "#!/bin/sh\n# defenseclaw-managed-hook v0 (disabled tombstone)\necho restart >&2\nexit 2\n",
			filepath.Join(hookDir, "user-hook.sh"):                                   "#!/bin/sh\nexit 0\n",
			filepath.Join(dataDir, ".hermes-lifecycle.lock"):                         "",
			filepath.Join(dataDir, hermesHomeSetUpFileName):                          `{"home":"/h/.hermes"}`,
			filepath.Join(dataDir, "connector_backups", "codex", "config.toml.json"): "{}",
		}
		if err := os.MkdirAll(filepath.Join(dataDir, "connector_backups", "hermes"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dataDir, "connector_backups", "codex"), 0o700); err != nil {
			t.Fatal(err)
		}
		files[filepath.Join(dataDir, "connector_backups", "hermes")] = ""
		for path, body := range files {
			if filepath.Base(path) == "hermes" {
				continue // the empty backup folder
			}
			if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		agentProcessMayRun = func(string, string) bool { return running }
		err := RemoveUnusedSharedHookRuntime(dataDir)
		agentProcessMayRun = accountAgentProcessMayRun
		if err != nil {
			t.Fatalf("RemoveUnusedSharedHookRuntime: %v", err)
		}
		for path := range files {
			var want bool // gone after the removal
			switch filepath.Base(path) {
			case "hermes-hook.sh":
				want = !running
			case ".hermes-lifecycle.lock", hermesHomeSetUpFileName, "hermes":
				want = true
			}
			_, statErr := os.Stat(path)
			if gone := os.IsNotExist(statErr); gone != want {
				t.Fatalf("hermes running=%t: %s gone=%t (%v)", running, path, gone, statErr)
			}
		}
	}
}

func TestAccountAgentProcessMayRunSeesTheAgentsProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the account's processes are read from /proc on Linux only")
	}
	dataDir := t.TempDir()
	if accountAgentProcessMayRun(dataDir, "dcagentprobe") {
		t.Fatal("a process was found for an agent nothing runs")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	link := filepath.Join(t.TempDir(), "dcagentprobe")
	if err := os.Symlink(sleep, link); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(link, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if !accountAgentProcessMayRun(dataDir, "dcagentprobe") {
		t.Fatal("the running agent process was not found")
	}
}
