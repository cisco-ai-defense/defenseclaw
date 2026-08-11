// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCodexHookKeepsCredentialsAndPayloadOutOfCurlArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}

	const (
		scopedToken      = "codex-scoped-transport-token"
		genericToken     = "inherited-generic-token"
		inheritedAPI     = "inherited-exported-api-token"
		inheritedPayload = "inherited-exported-payload"
		payload          = `{"hook_event_name":"PreToolUse","tool_name":"Read","private":"payload-must-not-enter-argv"}`
	)

	hooksDir := t.TempDir()
	if err := WriteHookScriptsForConnectorObject(
		hooksDir,
		"127.0.0.1:18970",
		scopedToken,
		NewCodexConnector(),
	); err != nil {
		t.Fatalf("write Codex hook: %v", err)
	}

	stubDir := t.TempDir()
	argvPath := filepath.Join(stubDir, "argv.txt")
	headerPath := filepath.Join(stubDir, "header.txt")
	bodyPath := filepath.Join(stubDir, "body.txt")
	envPath := filepath.Join(stubDir, "env.txt")
	stubPath := filepath.Join(stubDir, "curl")
	stub := `#!/bin/sh
set -eu
: > "${CODEX_CURL_ARGV_CAPTURE}"
: > "${CODEX_CURL_HEADER_CAPTURE}"
: > "${CODEX_CURL_BODY_CAPTURE}"
printf '%s\n%s\n%s\n' "${DEFENSECLAW_GATEWAY_TOKEN-}" "${API_TOKEN-}" "${PAYLOAD-}" > "${CODEX_CURL_ENV_CAPTURE}"
want=""
for arg in "$@"; do
  printf '%s\n' "$arg" >> "${CODEX_CURL_ARGV_CAPTURE}"
  case "$want" in
    header)
      case "$arg" in
        @*) cat "${arg#@}" >> "${CODEX_CURL_HEADER_CAPTURE}" ;;
        *) printf '%s\n' "$arg" >> "${CODEX_CURL_HEADER_CAPTURE}" ;;
      esac
      want=""
      ;;
    body)
      case "$arg" in
        @*) cat "${arg#@}" >> "${CODEX_CURL_BODY_CAPTURE}" ;;
        *) printf '%s' "$arg" >> "${CODEX_CURL_BODY_CAPTURE}" ;;
      esac
      want=""
      ;;
  esac
  case "$arg" in
    -H|--header) want="header" ;;
    -d|--data|--data-binary) want="body" ;;
  esac
done
printf '%s\n%s\n' '{"action":"allow","codex_output":{"decision":"allow"}}' '200'
`
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Fatalf("write curl stub: %v", err)
	}

	hookPath := filepath.Join(hooksDir, "codex-hook.sh")
	bakeHookPathForTest(t, hookPath, stubDir+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	cmd := exec.Command("bash", hookPath)
	cmd.Env = append(os.Environ(),
		"DEFENSECLAW_HOME="+t.TempDir(),
		"DEFENSECLAW_GATEWAY_TOKEN="+genericToken,
		"API_TOKEN="+inheritedAPI,
		"PAYLOAD="+inheritedPayload,
		"CODEX_CURL_ARGV_CAPTURE="+argvPath,
		"CODEX_CURL_HEADER_CAPTURE="+headerPath,
		"CODEX_CURL_BODY_CAPTURE="+bodyPath,
		"CODEX_CURL_ENV_CAPTURE="+envPath,
	)
	cmd.Stdin = strings.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run Codex hook: %v\nstdout=%q\nstderr=%q", err, stdout.String(), stderr.String())
	}

	argv := readCodexHookTransportCapture(t, argvPath)
	for _, secret := range []string{scopedToken, genericToken, inheritedAPI, inheritedPayload, payload, "payload-must-not-enter-argv"} {
		if strings.Contains(argv, secret) {
			t.Fatalf("curl argv exposed private material %q:\n%s", secret, argv)
		}
	}
	header := strings.TrimSpace(readCodexHookTransportCapture(t, headerPath))
	if !strings.Contains(header, "Authorization: Bearer "+scopedToken) {
		t.Fatalf("transported headers = %q, want scoped token", header)
	}
	if strings.Contains(header, genericToken) {
		t.Fatalf("transported Authorization header retained inherited generic token: %q", header)
	}
	body := readCodexHookTransportCapture(t, bodyPath)
	if body != payload {
		t.Fatalf("transported request body = %q, want %q", body, payload)
	}
	childEnv := readCodexHookTransportCapture(t, envPath)
	if strings.Contains(childEnv, scopedToken) || strings.Contains(childEnv, genericToken) ||
		strings.Contains(childEnv, inheritedAPI) || strings.Contains(childEnv, inheritedPayload) ||
		strings.Contains(childEnv, payload) {
		t.Fatalf("curl inherited a gateway credential in its environment: %q", childEnv)
	}
	if !strings.Contains(stdout.String(), `"decision":"allow"`) || strings.TrimSpace(stderr.String()) != "" {
		t.Fatalf("hook protocol changed: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func readCodexHookTransportCapture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read transport capture %s: %v", filepath.Base(path), err)
	}
	return string(data)
}
