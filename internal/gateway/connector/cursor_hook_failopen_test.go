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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The Cursor hook is wired into hooks.json with "failClosed": true when
// the operator selects a fail-closed install. Cursor treats a
// failClosed:true hook that produces EMPTY stdout as a hook failure and
// blocks the tool. So every fail-OPEN path in cursor-hook.sh (gateway
// unreachable, missing token, disabled/absent install, observe-mode
// response with no hook_output) must emit an explicit allow envelope on
// stdout — never a silent exit 0. These tests pin that contract; a
// regression would silently invert a deliberate fail-open into a
// fail-closed lockout with no self-recovery path for the agent.

// runCursorHook renders cursor-hook.sh with the given fail mode and
// runs it against the supplied gateway address, returning stdout,
// stderr, and the exit error. tokenPresent=false deletes the generated
// .token file to exercise the missing-token branch.
func runCursorHook(t *testing.T, apiAddr, failMode string, tokenPresent bool, extraEnv ...string) (string, string, error) {
	t.Helper()
	return runCursorHookWithInput(
		t,
		apiAddr,
		failMode,
		tokenPresent,
		`{"hook_event_name":"beforeShellExecution"}`,
		extraEnv...,
	)
}

func runCursorHookWithInput(
	t *testing.T,
	apiAddr, failMode string,
	tokenPresent bool,
	input string,
	extraEnv ...string,
) (string, string, error) {
	t.Helper()
	dir := t.TempDir()
	if err := writeHookScriptsCommonWithFailMode(dir, apiAddr, "tok-test", failMode, []string{"cursor-hook.sh"}); err != nil {
		t.Fatalf("writeHookScriptsCommonWithFailMode: %v", err)
	}
	if !tokenPresent {
		if err := os.Remove(filepath.Join(dir, ".token")); err != nil {
			t.Fatalf("remove .token: %v", err)
		}
	}
	dcHome := t.TempDir()

	cmd := exec.Command("bash", filepath.Join(dir, "cursor-hook.sh"))
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(),
		"PATH="+os.Getenv("PATH"),
		"DEFENSECLAW_HOME="+dcHome,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// assertAllowEnvelope fails unless out is a single, non-empty JSON
// object with "permission":"allow".
func assertAllowEnvelope(t *testing.T, out string) {
	t.Helper()
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		t.Fatal("stdout is empty — Cursor fail-closes on empty stdout, so this would block the tool")
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\ngot: %q", err, trimmed)
	}
	if obj["permission"] != "allow" {
		t.Fatalf(`stdout permission = %v, want "allow"; got: %q`, obj["permission"], trimmed)
	}
}

func assertDenyEnvelope(t *testing.T, out string) {
	t.Helper()
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		t.Fatal("stdout is empty; fail-closed Cursor paths must emit an explicit deny")
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\ngot: %q", err, trimmed)
	}
	if obj["permission"] != "deny" {
		t.Fatalf(`stdout permission = %v, want "deny"; got: %q`, obj["permission"], trimmed)
	}
	if continued, ok := obj["continue"].(bool); !ok || continued {
		t.Fatalf(`stdout continue = %v, want false; got: %q`, obj["continue"], trimmed)
	}
}

func TestCursorHook_FailOpenOnUnreachableEmitsAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	stdout, stderr, err := runCursorHook(t, "127.0.0.1:1", "open", true)
	if err != nil {
		t.Fatalf("expected exit 0 (fail-open), got %v; stderr=%s", err, stderr)
	}
	assertAllowEnvelope(t, stdout)
}

func TestCursorHook_FailClosedOnUnreachableEmitsDeny(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	stdout, stderr, err := runCursorHook(t, "127.0.0.1:1", "closed", true)
	if err == nil {
		t.Fatalf("expected exit 2 (fail-closed), got exit 0; stdout=%s", stdout)
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit 2 (fail-closed), got %v; stderr=%s", err, stderr)
	}
	assertDenyEnvelope(t, stdout)
}

func TestCursorHook_DisabledMarkerEmitsAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	dir := t.TempDir()
	if err := writeHookScriptsCommonWithFailMode(dir, "127.0.0.1:1", "tok-test", "closed", []string{"cursor-hook.sh"}); err != nil {
		t.Fatalf("writeHookScriptsCommonWithFailMode: %v", err)
	}
	dcHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(dcHome, ".disabled"), []byte(""), 0o600); err != nil {
		t.Fatalf("write .disabled: %v", err)
	}

	cmd := exec.Command("bash", filepath.Join(dir, "cursor-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"beforeShellExecution"}`)
	cmd.Env = append(os.Environ(),
		"PATH="+os.Getenv("PATH"),
		"DEFENSECLAW_HOME="+dcHome,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("expected exit 0 when .disabled present, got %v; stderr=%s", err, stderr.String())
	}
	assertAllowEnvelope(t, stdout.String())
}

func TestCursorHook_MissingTokenFailsOpenWithAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	// No .token file and no DEFENSECLAW_GATEWAY_TOKEN, not strict =>
	// historical allow-and-warn, but must emit an explicit allow so a
	// fail-open entry never depends on Cursor's empty-output fallback.
	stdout, stderr, err := runCursorHook(t, "127.0.0.1:1", "open", false)
	if err != nil {
		t.Fatalf("expected exit 0 (fail-open on missing token), got %v; stderr=%s", err, stderr)
	}
	assertAllowEnvelope(t, stdout)
	if !strings.Contains(stderr, "allowing cursor tool") {
		t.Errorf("stderr should announce allowing on the fail-open path, got: %q", stderr)
	}
}

// TestCursorHook_StrictMissingTokenBlocks pins the other side of the
// contract: with DEFENSECLAW_STRICT_AVAILABILITY=1 a missing token
// still emits current main's explicit deny and exits 2.
func TestCursorHook_StrictMissingTokenBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on windows")
	}
	stdout, stderr, err := runCursorHook(t, "127.0.0.1:1", "open", false, "DEFENSECLAW_STRICT_AVAILABILITY=1")
	if err == nil {
		t.Fatalf("expected exit 2 under strict availability, got exit 0; stdout=%s", stdout)
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit 2 under strict availability, got %v; stderr=%s", err, stderr)
	}
	if !strings.Contains(stderr, "blocking cursor tool") {
		t.Errorf("stderr should announce blocking under strict availability, got: %q", stderr)
	}
	assertDenyEnvelope(t, stdout)
}
