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

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCoworkPluginHooksUseClaudeCodeExecFormOnWindows pins the literal argv of
// the Windows plugin handlers in the one-line install layout: every event,
// PreToolUse included, runs the cmd.exe guard of the launcher, whose missing
// branch exits 1 with the uninstalled sentence (a non-blocking failure),
// with onFailure "continue" where the field applies; no handler is the
// managed form or launcher-guard (GAP-0051).
func TestCoworkPluginHooksUseClaudeCodeExecFormOnWindows(t *testing.T) {
	dataDir := t.TempDir()
	bin := t.TempDir()
	launcher := filepath.Join(bin, "defenseclaw-hook.exe")
	guard := filepath.Join(bin, "defenseclaw-hook-guard.exe")
	opts := SetupOpts{DataDir: dataDir, HookExecutable: launcher}
	if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CoworkPluginHooks(opts); !errors.Is(err, ErrCoworkClaudeCodeNotSetUp) {
		t.Fatalf("missing launcher: err = %v, want ErrCoworkClaudeCodeNotSetUp", err)
	}
	for _, path := range []string{launcher, guard} {
		if err := os.WriteFile(path, []byte("MZ"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	doc := renderCoworkPluginForWindowsTest(t, opts)
	if len(doc.Hooks) != len(CoworkPluginHookEvents) {
		t.Fatalf("%d events, want %d", len(doc.Hooks), len(CoworkPluginHookEvents))
	}
	cmdGuard := append([]string{"/d", "/c", "if", "exist", launcher, "(", launcher, "hook", "--connector", "claudecode",
		")", "else", "(", "echo"}, strings.Fields(coworkUninstalledMessage)...)
	cmdGuard = append(cmdGuard, "1>&2", "&", "exit", "/b", "1", ")")
	for event, entries := range doc.Hooks {
		handler := entries[0].Hooks[0]
		got := strings.Join(handler.Args, "\x00")
		if !strings.EqualFold(filepath.Base(handler.Command), "cmd.exe") || !filepath.IsAbs(handler.Command) ||
			got != strings.Join(cmdGuard, "\x00") {
			t.Fatalf("%s: %q %q, want <system>\\cmd.exe %q", event, handler.Command, handler.Args, cmdGuard)
		}
		wantFailure := "continue"
		if event == "Stop" || event == "SubagentStop" || handler.Async {
			wantFailure = ""
		}
		if handler.OnFailure != wantFailure {
			t.Fatalf("%s: onFailure %q, want %q", event, handler.OnFailure, wantFailure)
		}
		if strings.Contains(got, "--enterprise-managed") || strings.Contains(got, "launcher-guard") {
			t.Fatalf("%s: per-user plugin handler is %q", event, got)
		}
	}
}

type coworkWindowsPluginDoc struct {
	Hooks map[string][]struct {
		Hooks []struct {
			Command   string   `json:"command"`
			Args      []string `json:"args"`
			OnFailure string   `json:"onFailure"`
			Async     bool     `json:"async"`
		} `json:"hooks"`
	} `json:"hooks"`
}

func renderCoworkPluginForWindowsTest(t *testing.T, opts SetupOpts) coworkWindowsPluginDoc {
	t.Helper()
	raw, err := CoworkPluginHooks(opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc coworkWindowsPluginDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestCoworkPluginHookAllowsOnceDefenseClawIsUninstalledOnWindows runs the
// rendered PreToolUse argv as Claude runs an exec-form hook (no shell), with a
// copy of this test binary as the launcher (testCoworkLauncherEnv), in a
// folder with a space. Present: the launcher verdicts and output pass through
// (deny exit 2, allow exit 0). Removed, as the per-user uninstall removes it:
// exit 1, a non-blocking failure that onFailure "continue" lets through, with
// the uninstalled sentence on the first stderr line and nothing on stdout.
func TestCoworkPluginHookAllowsOnceDefenseClawIsUninstalledOnWindows(t *testing.T) {
	dataDir := t.TempDir()
	bin := filepath.Join(t.TempDir(), "local bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(bin, "defenseclaw-hook.exe")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, body, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(dataDir, HookContractLockEntry{Connector: "claudecode", ContractID: "claudecode-test"}); err != nil {
		t.Fatal(err)
	}
	doc := renderCoworkPluginForWindowsTest(t, SetupOpts{DataDir: dataDir, HookExecutable: launcher})
	handler := doc.Hooks["PreToolUse"][0].Hooks[0]
	run := func(verdict string) (int, string, string) {
		t.Helper()
		cmd := exec.Command(handler.Command, handler.Args...)
		cmd.Env = append(os.Environ(), testCoworkLauncherEnv+"="+verdict)
		cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo between-check"}}`)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("deny"); code != 2 || stdout != "" || strings.TrimSpace(stderr) != "DefenseClaw denied this tool call" {
		t.Fatalf("deny: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if code, stdout, _ := run("allow"); code != 0 || !strings.Contains(stdout, `"permissionDecision":"allow"`) {
		t.Fatalf("allow: exit %d stdout %q", code, stdout)
	}
	if err := os.Remove(launcher); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("deny")
	firstLine := strings.TrimSpace(strings.SplitN(stderr, "\n", 2)[0])
	if code != 1 || strings.TrimSpace(stdout) != "" || firstLine != coworkUninstalledMessage {
		t.Fatalf("uninstalled: exit %d stdout %q stderr %q, want exit 1 and the sentence", code, stdout, stderr)
	}
}
