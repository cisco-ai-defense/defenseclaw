// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

func TestPerUserShellPostKeepsJSONForFullCLIFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash hook bridge is Unix only")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hook := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(hook, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fullCLI := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.WriteFile(fullCLI, []byte("#!/bin/sh\ncat > \"$DC_POST_WIRE\"\nprintf '{\"action\":\"allow\"}\\n200'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	wire := filepath.Join(dir, "wire")
	const body = `{"tool_input":{"command":"echo \\\"quoted\\\""}}`
	script := `set -euo pipefail
. "$1"
API_ADDR=127.0.0.1:18960
DEFENSECLAW_AGENT_HOME="$2"
defenseclaw_api_listener_unproven() { return 1; }
_dc_hook_elapsed_ms() { _DC_ELAPSED_MS=0; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 "$3" -H 'Authorization: Bearer scoped-token'`
	cmd := exec.Command("bash", "-c", script, "bash", hook, home, body)
	cmd.Env = append(os.Environ(), "DC_POST_WIRE="+wire)
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "{\"action\":\"allow\"}\n200" {
		t.Fatalf("full CLI fallback: %v, output=%q", err, out)
	}
	data, err := os.ReadFile(wire)
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Path    string            `json:"path"`
		Body    string            `json:"body"`
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(data, &frame); err != nil {
		t.Fatalf("full CLI fallback input is not JSON: %v", err)
	}
	if frame.Path != "/api/v1/claude-code/hook" || frame.Body != body || frame.Headers["Authorization"] != "Bearer scoped-token" {
		t.Fatalf("full CLI fallback lost request fields: %+v", frame)
	}
}

func TestPerUserShellPostFramesWithoutEscapeProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash hook bridge is Unix only")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hook := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(hook, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fullCLI := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.WriteFile(fullCLI, []byte("#!/bin/sh\nexit 77\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "defenseclaw-hook-post")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s' \"$*\" > \"$DC_POST_ARGS\"\ncat > \"$DC_POST_WIRE\"\nprintf '{\"action\":\"allow\"}\\n200'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	wire := filepath.Join(dir, "wire")
	args := filepath.Join(dir, "args")
	const body = `{"tool_input":{"command":"echo quote \\\" and slash \\ and newline\\n"}}`
	script := `set -euo pipefail
. "$1"
API_ADDR=127.0.0.1:18960
DEFENSECLAW_AGENT_HOME="$2"
defenseclaw_api_listener_unproven() { return 1; }
_dc_hook_elapsed_ms() { _DC_ELAPSED_MS=0; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 "$3" -H 'Content-Type: application/json' -H 'X-DefenseClaw-Note: quote " and slash \\' -H 'Authorization: Bearer secret-token'`
	cmd := exec.Command("bash", "-c", script, "bash", hook, home, body)
	cmd.Env = append(os.Environ(), "DC_POST_WIRE="+wire, "DC_POST_ARGS="+args)
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "{\"action\":\"allow\"}\n200" {
		t.Fatalf("hook post: %v, output=%q", err, out)
	}
	data, err := os.ReadFile(wire)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DCPOST1", "/api/v1/claude-code/hook", body,
		"Content-Type", "application/json", "X-DefenseClaw-Note", `quote " and slash \\`,
		"Authorization", "Bearer secret-token", ""}
	parts := bytes.Split(data, []byte{0})
	if len(parts) != len(want) {
		t.Fatalf("wire has %d fields, want %d: %q", len(parts), len(want), data)
	}
	for i, part := range parts {
		if string(part) != want[i] {
			t.Errorf("field %d = %q, want %q", i, part, want[i])
		}
	}
	argumentBytes, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(argumentBytes), "secret-token") || strings.Contains(string(argumentBytes), body) {
		t.Fatalf("hook credential or body reached helper arguments: %q", argumentBytes)
	}
}

func TestPerUserShellPostUsesVerifiedInstallerRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash hook bridge is Unix only")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	// macOS /var is a root-owned link to /private/var. Use the physical
	// directory, as installed data paths do, when exercising every ancestor.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(hook, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	binDir := filepath.Join(home, ".local", "bin")
	installerDir := filepath.Join(home, ".defenseclaw", "installer")
	for _, path := range []string{binDir, installerDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fullMarker := filepath.Join(dir, "full-cli-ran")
	fullCLI := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.WriteFile(fullCLI, []byte("#!/bin/sh\nprintf used > \"$DC_POST_FULL_MARKER\"\nexit 77\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	recovery := filepath.Join(installerDir, "defenseclaw-hook-post")
	if err := os.WriteFile(recovery, []byte("#!/bin/sh\nprintf '{\"action\":\"allow\"}\\n200'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := `set -euo pipefail
. "$1"
API_ADDR=127.0.0.1:18960
DEFENSECLAW_AGENT_HOME="$2"
DEFENSECLAW_HOME="$2/.defenseclaw"
defenseclaw_api_listener_unproven() { return 1; }
_dc_hook_elapsed_ms() { _DC_ELAPSED_MS=0; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 '{}' -H 'Content-Type: application/json'`
	run := func() ([]byte, error) {
		cmd := exec.Command("bash", "-c", script, "bash", hook, home)
		cmd.Env = append(os.Environ(), "DC_POST_FULL_MARKER="+fullMarker)
		return cmd.CombinedOutput()
	}
	if out, err := run(); err != nil || string(out) != "{\"action\":\"allow\"}\n200" {
		t.Fatalf("verified recovery post: %v, output=%q", err, out)
	}
	if _, err := os.Stat(fullMarker); !os.IsNotExist(err) {
		t.Fatalf("full gateway CLI ran instead of the recovery helper: %v", err)
	}
	if err := os.Chmod(recovery, 0o722); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err == nil || len(out) != 0 {
		t.Fatalf("writable recovery helper was accepted: %v, output=%q", err, out)
	}
	if _, err := os.Stat(fullMarker); !os.IsNotExist(err) {
		t.Fatalf("an untrusted recovery helper fell back to the full CLI: %v", err)
	}
	if err := os.Chmod(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	realInstaller := installerDir + "-real"
	if err := os.Rename(installerDir, realInstaller); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realInstaller, installerDir); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err == nil || len(out) != 0 {
		t.Fatalf("symlinked recovery directory was accepted: %v, output=%q", err, out)
	}
	if _, err := os.Stat(fullMarker); !os.IsNotExist(err) {
		t.Fatalf("a symlinked recovery directory fell back to the full CLI: %v", err)
	}
}
