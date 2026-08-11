// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCodexNotifyBridgeKeepsCredentialAndPayloadOutOfCurlProcessState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Bash notify bridge is not installed on Windows")
	}

	const (
		initialToken  = "codex-notify-scoped-token-initial"
		rotatedToken  = "codex-notify-scoped-token-rotated"
		bakedSentinel = "token-must-not-be-baked-into-notify-bridge"
		genericToken  = "inherited-generic-gateway-token"
		inheritedAPI  = "inherited-exported-api-token"
		inheritedJSON = "inherited-exported-json-value"
		payload       = `{"type":"agent-turn-complete","private":"notify-payload-must-not-enter-curl-argv"}`
	)

	dataDir := t.TempDir()
	tokenPath, err := HookAPITokenFilePath(dataDir, "codex")
	if err != nil {
		t.Fatalf("HookAPITokenFilePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatalf("create hook token directory: %v", err)
	}
	if err := os.WriteFile(tokenPath, []byte(initialToken+"\n"), 0o600); err != nil {
		t.Fatalf("write scoped token: %v", err)
	}
	if err := writeCodexNotifyBridge(SetupOpts{
		DataDir:  dataDir,
		APIAddr:  "127.0.0.1:18970",
		APIToken: bakedSentinel,
	}); err != nil {
		t.Fatalf("writeCodexNotifyBridge: %v", err)
	}

	bridgePath := filepath.Join(dataDir, "notify-bridge.sh")
	bridge, err := os.ReadFile(bridgePath)
	if err != nil {
		t.Fatalf("read notify bridge: %v", err)
	}
	for _, secret := range []string{initialToken, bakedSentinel} {
		if strings.Contains(string(bridge), secret) {
			t.Fatalf("notify bridge embedded credential %q", secret)
		}
	}

	stubDir := t.TempDir()
	argvPath := filepath.Join(stubDir, "argv.txt")
	headerPath := filepath.Join(stubDir, "headers.txt")
	bodyPath := filepath.Join(stubDir, "body.txt")
	envPath := filepath.Join(stubDir, "env.txt")
	stubPath := filepath.Join(stubDir, "curl")
	stub := `#!/bin/sh
set -eu
: > "${CODEX_NOTIFY_ARGV_CAPTURE}"
: > "${CODEX_NOTIFY_HEADER_CAPTURE}"
: > "${CODEX_NOTIFY_BODY_CAPTURE}"
/usr/bin/env > "${CODEX_NOTIFY_ENV_CAPTURE}"
want=""
for arg in "$@"; do
  printf '%s\n' "$arg" >> "${CODEX_NOTIFY_ARGV_CAPTURE}"
  case "$want" in
    header)
      case "$arg" in
        @*) cat "${arg#@}" >> "${CODEX_NOTIFY_HEADER_CAPTURE}" ;;
        *) printf '%s\n' "$arg" >> "${CODEX_NOTIFY_HEADER_CAPTURE}" ;;
      esac
      want=""
      ;;
    body)
      case "$arg" in
        @*) cat "${arg#@}" >> "${CODEX_NOTIFY_BODY_CAPTURE}" ;;
        *) printf '%s' "$arg" >> "${CODEX_NOTIFY_BODY_CAPTURE}" ;;
      esac
      want=""
      ;;
  esac
  case "$arg" in
    -H|--header) want="header" ;;
    -d|--data|--data-binary) want="body" ;;
  esac
done
`
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Fatalf("write curl stub: %v", err)
	}

	runBridge := func(wantPayload string) {
		t.Helper()
		cmd := exec.Command("/bin/bash", bridgePath, wantPayload)
		cmd.Env = []string{
			"PATH=" + stubDir + ":/usr/bin:/bin",
			"CODEX_NOTIFY_ARGV_CAPTURE=" + argvPath,
			"CODEX_NOTIFY_HEADER_CAPTURE=" + headerPath,
			"CODEX_NOTIFY_BODY_CAPTURE=" + bodyPath,
			"CODEX_NOTIFY_ENV_CAPTURE=" + envPath,
			"DEFENSECLAW_GATEWAY_TOKEN=" + genericToken,
			"API_TOKEN=" + inheritedAPI,
			"JSON=" + inheritedJSON,
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run notify bridge: %v\noutput=%q", err, output)
		} else if len(output) != 0 {
			t.Fatalf("best-effort notify bridge emitted operator noise: %q", output)
		}
	}

	assertTransport := func(wantToken, oldToken, wantPayload string) {
		t.Helper()
		argv := readCodexNotifyCapture(t, argvPath)
		for _, secret := range []string{
			wantToken, oldToken, wantPayload, "notify-payload-must-not-enter-curl-argv",
			genericToken, inheritedAPI, inheritedJSON, "Authorization: Bearer",
		} {
			if secret != "" && strings.Contains(argv, secret) {
				t.Fatalf("curl argv exposed private material %q:\n%s", secret, argv)
			}
		}
		for _, fdArg := range []string{"@/dev/fd/8", "@/dev/fd/9"} {
			if !strings.Contains(argv, fdArg) {
				t.Fatalf("curl argv missing descriptor transport %q:\n%s", fdArg, argv)
			}
		}

		headers := readCodexNotifyCapture(t, headerPath)
		if !strings.Contains(headers, "Authorization: Bearer "+wantToken) {
			t.Fatalf("transported headers do not contain current scoped token: %q", headers)
		}
		for _, rejected := range []string{oldToken, genericToken, inheritedAPI} {
			if rejected != "" && strings.Contains(headers, rejected) {
				t.Fatalf("transported headers retained rejected credential %q: %q", rejected, headers)
			}
		}
		if body := readCodexNotifyCapture(t, bodyPath); body != wantPayload {
			t.Fatalf("transported notify body = %q, want %q", body, wantPayload)
		}
		childEnv := readCodexNotifyCapture(t, envPath)
		for _, secret := range []string{wantToken, oldToken, wantPayload, genericToken, inheritedAPI, inheritedJSON} {
			if secret != "" && strings.Contains(childEnv, secret) {
				t.Fatalf("curl inherited private material %q in its environment", secret)
			}
		}
	}

	runBridge(payload)
	assertTransport(initialToken, "", payload)

	// Credential rotation must take effect from the managed sidecar without
	// regenerating a script that could preserve the previous credential.
	if err := os.WriteFile(tokenPath, []byte(rotatedToken+"\n"), 0o600); err != nil {
		t.Fatalf("rotate scoped token: %v", err)
	}
	const rotatedPayload = `{"type":"agent-turn-complete","private":"rotated-payload"}`
	runBridge(rotatedPayload)
	assertTransport(rotatedToken, initialToken, rotatedPayload)
}

func TestCodexNotifyBridgeFailsOpenWithoutScopedToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Bash notify bridge is not installed on Windows")
	}

	dataDir := t.TempDir()
	if err := writeCodexNotifyBridge(SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}); err != nil {
		t.Fatalf("writeCodexNotifyBridge: %v", err)
	}
	stubDir := t.TempDir()
	invokedPath := filepath.Join(stubDir, "curl-invoked")
	stubPath := filepath.Join(stubDir, "curl")
	stub := "#!/bin/sh\n: > \"${CODEX_NOTIFY_INVOKED}\"\nexit 99\n"
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Fatalf("write curl stub: %v", err)
	}

	cmd := exec.Command("/bin/bash", filepath.Join(dataDir, "notify-bridge.sh"), `{"type":"agent-turn-complete"}`)
	cmd.Env = []string{
		"PATH=" + stubDir + ":/usr/bin:/bin",
		"CODEX_NOTIFY_INVOKED=" + invokedPath,
		"DEFENSECLAW_GATEWAY_TOKEN=inherited-token-must-not-be-used",
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("missing-token notify did not fail open: %v\noutput=%q", err, output)
	} else if len(output) != 0 {
		t.Fatalf("missing-token notify emitted operator noise: %q", output)
	}
	if _, err := os.Stat(invokedPath); !os.IsNotExist(err) {
		t.Fatalf("missing-token notify invoked curl: %v", err)
	}
}

func readCodexNotifyCapture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read notify transport capture %s: %v", filepath.Base(path), err)
	}
	return string(data)
}
