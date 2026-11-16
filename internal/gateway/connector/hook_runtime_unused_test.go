// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
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
	lockSentinel := filepath.Join(hookDir, hookConfigSidecarName+".lock")
	markers := filepath.Join(hookDir, ".outage-warnings")
	if err := os.WriteFile(record, []byte("helper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockSentinel, nil, 0o600); err != nil {
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
	for _, path := range append(scripts, record, lockSentinel, markers, filepath.Join(dataDir, hookContractLockFile)) {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived an unused runtime's removal: %v", path, err)
		}
	}
}

func TestRemoveUnusedSharedHookRuntimeKeepsLinkedHookDirectory(t *testing.T) {
	dataDir := t.TempDir()
	outside := t.TempDir()
	script := filepath.Join(outside, "inspect-tool.sh")
	if err := os.WriteFile(script, []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dataDir, "hooks")); err != nil {
		t.Skipf("directory links are unavailable: %v", err)
	}
	if err := RemoveUnusedSharedHookRuntime(dataDir); err == nil {
		t.Fatal("linked hook directory was accepted for cleanup")
	}
	registry := NewDefaultRegistry()
	removed, _ := registry.Get("devin")
	if err := RemovePerUserConnectorHookFiles(SetupOpts{DataDir: dataDir}, removed, nil); err == nil {
		t.Fatal("linked hook directory was accepted for connector cleanup")
	}
	if body, err := os.ReadFile(script); err != nil || string(body) != "kept\n" {
		t.Fatalf("linked directory target changed: %q, %v", body, err)
	}
}

func TestRemoveUnusedSharedHookRuntimeWaitsForHookWriter(t *testing.T) {
	dataDir, scripts := writeUnusedSharedHookRuntime(t)
	path := filepath.Join(dataDir, "hooks", hookConfigSidecarName)
	held := make(chan struct{})
	release := make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		writer <- withFileLock(path, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	removed := make(chan error, 1)
	go func() { removed <- RemoveUnusedSharedHookRuntime(dataDir) }()
	select {
	case err := <-removed:
		t.Fatalf("cleanup returned while the hook writer held its lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	for _, script := range scripts {
		if _, err := os.Stat(script); err != nil {
			t.Fatalf("hook script changed while the writer held its lock: %v", err)
		}
	}
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
}

func TestRemovePerUserConnectorHookFilesWaitsForHookWriter(t *testing.T) {
	dataDir := t.TempDir()
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "test-token", HookAPIToken: "test-token", HookAPITokenScoped: true}
	registry := NewDefaultRegistry()
	removed, _ := registry.Get("devin")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, removed); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hookDir, "devin-hook.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("premise: setup did not write the connector hook: %v", err)
	}
	lockPath := filepath.Join(hookDir, hookConfigSidecarName)
	held := make(chan struct{})
	release := make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		writer <- withFileLock(lockPath, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	select {
	case <-held:
	case err := <-writer:
		t.Fatalf("hook writer did not take its lock: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("hook writer did not take its lock")
	}
	removedDone := make(chan error, 1)
	go func() { removedDone <- RemovePerUserConnectorHookFiles(opts, removed, nil) }()
	select {
	case err := <-removedDone:
		t.Fatalf("connector cleanup returned while the hook writer held its lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("connector hook changed while the writer held its lock: %v", err)
	}
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	if err := <-removedDone; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); !os.IsNotExist(err) {
		t.Fatalf("connector hook remained after cleanup: %v", err)
	}
}

func TestRemovePerUserConnectorHookFilesKeepsLiveTeardownTombstones(t *testing.T) {
	for _, name := range []string{"devin", "kiro"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			dataDir := t.TempDir()
			opts := SetupOpts{DataDir: dataDir, ConfigHome: t.TempDir(), APIAddr: "127.0.0.1:18970",
				APIToken: "test-token", HookAPIToken: "test-token", HookAPITokenScoped: true}
			registry := NewDefaultRegistry()
			removed, _ := registry.Get(name)
			owner := removed.(HookScriptOwner)
			hookDir := filepath.Join(dataDir, "hooks")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, removed); err != nil {
				t.Fatal(err)
			}
			if err := removed.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("real teardown: %v", err)
			}
			script := filepath.Join(hookDir, owner.HookScriptNames(opts)[0])
			before, err := os.ReadFile(script)
			if err != nil || !bytes.Contains(before, []byte("(disabled tombstone)")) {
				t.Fatalf("teardown tombstone = %q, %v", before, err)
			}
			original := agentProcessMayRun
			t.Cleanup(func() { agentProcessMayRun = original })
			agentProcessMayRun = func(string, string) bool { return true }
			if err := RemovePerUserConnectorHookFiles(opts, removed, nil); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(script)
			if err != nil || !bytes.Equal(after, before) {
				t.Fatalf("cached hook path changed: %q, %v", after, err)
			}
			agentProcessMayRun = func(string, string) bool { return false }
			if err := RemovePerUserConnectorHookFiles(opts, removed, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(script); !os.IsNotExist(err) {
				t.Fatalf("idle hook path remains: %v", err)
			}
		})
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
			filepath.Join(hookDir, "devin-hook.sh"):                                  devinDisabledHookTombstone(),
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
			case "hermes-hook.sh", "devin-hook.sh":
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
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	agent := "dcagentprobe-" + strconv.Itoa(os.Getpid()) + "-" + hex.EncodeToString(suffix)
	dataDir := t.TempDir()
	if accountAgentProcessMayRun(dataDir, agent) {
		t.Fatal("a process was found for an agent nothing runs")
	}
	sleep := testenv.NativeSleep(t)
	link := filepath.Join(t.TempDir(), agent)
	if err := os.Symlink(sleep, link); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(link, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if !accountAgentProcessMayRun(dataDir, agent) {
		t.Fatal("the running agent process was not found")
	}
}
