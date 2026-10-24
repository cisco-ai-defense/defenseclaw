// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const (
	managedACPFixtureToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	managedACPServerNonce  = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	managedACPHelperEnv    = "DC_TEST_MANAGED_ACP_GATEWAY"
)

// managedACPGateway answers the ACP challenge and evaluation the way the
// gateway does, and allows every frame it can open.
func managedACPGateway(evaluated *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		keyID, nonce := r.Header.Get(acp.AuthKeyIDHeader), r.Header.Get(acp.AuthNonceHeader)
		if !acp.VerifyHTTPRequestMAC(managedACPFixtureToken, keyID, nonce, r.Method, r.URL.Path, body, r.Header.Get(acp.AuthRequestMACHeader)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var payload []byte
		switch r.URL.Path {
		case "/api/v1/acp/challenge":
			payload, _ = json.Marshal(map[string]string{"server_nonce": managedACPServerNonce})
		case "/api/v1/acp/evaluate":
			plaintext, err := acp.OpenHTTPPayload(managedACPFixtureToken, keyID,
				r.Header.Get(acp.AuthChallengeNonceHeader), r.Header.Get(acp.AuthServerNonceHeader),
				nonce, r.Method, r.URL.Path, body)
			if err != nil || !bytes.Contains(plaintext, []byte(`"payload"`)) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			evaluated.Add(1)
			payload = []byte(`{"action":"allow","raw_action":"allow"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set(acp.AuthResponseMACHeader, acp.HTTPResponseMAC(managedACPFixtureToken, keyID, nonce, http.StatusOK, payload))
		_, _ = w.Write(payload)
	})
}

// initializeThroughManagedGuard runs the managed observe guard with a Zed
// initialize frame in front of a minimal ACP agent and returns what Zed
// would read.
func initializeThroughManagedGuard(t *testing.T, gatewayURL string) string {
	t.Helper()
	evaluator, err := acp.NewManagedHTTPEvaluator(gatewayURL, managedACPFixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	initialize := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{},"clientInfo":{"name":"zed","version":"1.25.2"}}}` + "\n"
	agent := `IFS= read -r frame; printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{},"authMethods":[]}}'`
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = acp.Run(ctx, acp.ProxyOptions{
		AgentID: "copilot", ClientID: "zed", Profile: "p-obs", Mode: acp.ModeObserve, Managed: true,
		Command: "/bin/sh", Args: []string{"-c", agent},
		Stdin: strings.NewReader(initialize), Stdout: &stdout, Stderr: &stderr, Evaluator: evaluator,
	})
	if err != nil {
		t.Fatalf("managed ACP initialize failed: %v (stdout %q, stderr %q)", err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func assertInitialized(t *testing.T, editor string, evaluated *atomic.Int32) {
	t.Helper()
	if !strings.Contains(editor, `"protocolVersion":1`) || strings.Contains(editor, `"error"`) {
		t.Fatalf("editor did not receive the agent's initialize result: %q", editor)
	}
	if evaluated != nil && evaluated.Load() == 0 {
		t.Fatal("the managed gateway evaluated no frame: the session was not governed")
	}
}

// A supported ACP client initializes, governed, against the verified managed
// gateway (GAP-1138). Zed and Copilot on managed RHEL failed here because the
// peer check read /proc/<pid>/exe of the gateway, which an ordinary user may
// not do. The first case keeps the gateway in this account, the second puts
// it in a second account as the packaged service account is.
func TestManagedACPInitializeAgainstTheVerifiedGatewayService(t *testing.T) {
	if os.Getenv(managedACPHelperEnv) == "1" {
		serveManagedACPGatewayHelper(t)
		return
	}
	t.Run("gateway in this account", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var evaluated atomic.Int32
		server := &http.Server{Handler: managedACPGateway(&evaluated), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { _ = server.Close() })
		hookexec.UseManagedLinuxGatewayUnitForTest(t, os.Getpid(), os.Geteuid())
		assertInitialized(t, initializeThroughManagedGuard(t, "http://"+listener.Addr().String()), &evaluated)
	})
	t.Run("gateway in the service account", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads every process; this case proves an ordinary user")
		}
		if err := exec.Command("sudo", "-n", "-u", "nobody", "true").Run(); err != nil {
			t.Skipf("passwordless second-account execution is unavailable: %v", err)
		}
		binary := copyTestBinaryForSecondAccount(t)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		helper := exec.CommandContext(ctx, "sudo", "-n", "-u", "nobody", "/usr/bin/env", managedACPHelperEnv+"=1",
			binary, "-test.run=^TestManagedACPInitializeAgainstTheVerifiedGatewayService$")
		stdin, err := helper.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := helper.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		helper.Stderr = &stderr
		if err := helper.Start(); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewScanner(stdout)
		if !reader.Scan() || !strings.HasPrefix(reader.Text(), "GATEWAY=") {
			t.Fatalf("service-account gateway did not start: %q, stderr=%q", reader.Text(), stderr.String())
		}
		fields := strings.Fields(strings.TrimPrefix(reader.Text(), "GATEWAY="))
		if len(fields) != 3 {
			t.Fatalf("service-account gateway line = %q", reader.Text())
		}
		pid, pidErr := strconv.Atoi(fields[1])
		uid, uidErr := strconv.Atoi(fields[2])
		if pidErr != nil || uidErr != nil {
			t.Fatalf("service-account gateway line = %q", reader.Text())
		}
		hookexec.UseManagedLinuxGatewayUnitForTest(t, pid, uid)
		editor := initializeThroughManagedGuard(t, "http://"+fields[0])
		_ = stdin.Close()
		var counted string
		if reader.Scan() {
			counted = reader.Text()
		}
		if err := helper.Wait(); err != nil {
			t.Errorf("service-account gateway: %v, stderr=%q", err, stderr.String())
		}
		assertInitialized(t, editor, nil)
		if counted == "" || counted == "EVALUATED=0" {
			t.Fatalf("service-account gateway evaluated no frame (%q): the session was not governed", counted)
		}
	})
}

// serveManagedACPGatewayHelper is the gateway in the second account. It
// serves until the test closes its stdin, then prints how many frames it
// evaluated.
func serveManagedACPGatewayHelper(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var evaluated atomic.Int32
	server := &http.Server{Handler: managedACPGateway(&evaluated), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	fmt.Printf("GATEWAY=%s %d %d\n", listener.Addr(), os.Getpid(), os.Geteuid())
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(25 * time.Second):
	}
	_ = server.Close()
	fmt.Printf("EVALUATED=%d\n", evaluated.Load())
}

func copyTestBinaryForSecondAccount(t *testing.T) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "defenseclaw-managed-acp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "hookexec.test")
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return target
}
