// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoworkPluginDistinguishesRemovalFromHookLoss(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "account data")
	script := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho '{\"continue\":true}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := CoworkPluginHooks(SetupOpts{DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	trailingRaw, err := CoworkPluginHooks(SetupOpts{DataDir: dataDir + string(os.PathSeparator)})
	if err != nil || !strings.Contains(string(trailingRaw), dataDir+coworkRemovalMarkerSuffix) {
		t.Fatalf("trailing data-directory separator changed the removal record: %v", err)
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	run := func(event string) (int, string) {
		t.Helper()
		cmd := exec.Command("/bin/sh", "-c", doc.Hooks[event][0].Hooks[0].Command)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return 0, string(out)
		}
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), string(out)
		}
		t.Fatal(err)
		return -1, ""
	}
	marker := dataDir + ".cowork-uninstalled"
	if err := os.WriteFile(marker, []byte("removed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := run("PreToolUse"); code != 0 || !strings.Contains(out, `"continue":true`) {
		t.Fatalf("installed: exit %d output %q", code, out)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'gateway unavailable' >&2\necho '{\"continue\":true}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if code, out := run("PreToolUse"); code != 0 || !strings.Contains(out, "gateway unavailable") || !strings.Contains(out, `"continue":true`) {
		t.Fatalf("installed outage: exit %d output %q", code, out)
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if code, _ := run("PreToolUse"); code != 2 {
		t.Fatalf("missing script with install record: exit %d, want 2", code)
	}
	if err := os.Symlink(filepath.Join(dataDir, "missing"), script); err != nil {
		t.Fatal(err)
	}
	if code, _ := run("PreToolUse"); code != 2 {
		t.Fatalf("dangling script link: exit %d, want 2", code)
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if code, _ := run("PreToolUse"); code != 2 {
		t.Fatalf("removed config without a completed-removal record: exit %d, want 2", code)
	}
	if err := os.WriteFile(marker, []byte("removed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := run("PreToolUse"); code != 0 || !strings.Contains(out, "Customize") {
		t.Fatalf("removed: exit %d output %q", code, out)
	}
	if code, out := run("PreToolUse"); code != 0 || out != "" {
		t.Fatalf("repeat notice: exit %d output %q", code, out)
	}
	if code, out := run("UserPromptSubmit"); code != 0 || !strings.Contains(out, "additionalContext") {
		t.Fatalf("removed prompt: exit %d output %q", code, out)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte("mode: observe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := run("PreToolUse"); code != 2 {
		t.Fatalf("stale marker with installed config: exit %d, want 2", code)
	}
	if err := os.Remove(filepath.Join(dataDir, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, hookContractLockFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := run("PreToolUse"); code != 2 {
		t.Fatalf("stale marker with partial install record: exit %d, want 2", code)
	}
	if err := os.Remove(filepath.Join(dataDir, hookContractLockFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := run("PreToolUse"); code != 2 {
		t.Fatalf("stale marker with gateway runtime record: exit %d, want 2", code)
	}
}
