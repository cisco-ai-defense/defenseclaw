// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const restartBracketListenerEnv = "DC_TEST_RESTART_BRACKET_LISTENER"

// TestRestartBracketListener is a second process that owns the new gateway's
// port. The parent closes the old listener after its call has begun.
func TestRestartBracketListener(t *testing.T) {
	addr := os.Getenv(restartBracketListenerEnv)
	if addr == "" {
		t.Skip("listener process only")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, _ = os.Stdout.WriteString("ready\n")
	time.Sleep(time.Minute)
}

// TestLinuxShellHookCallBracketingRestartFollowsOutageMode reproduces the
// loaded Linux timing: a benign call reaches this account's gateway before
// its restart, the old connection gives no answer, and the restart finishes
// before the call's answer budget expires. The rendered, installed Claude
// Code hook and its real hook-post helper decide the result. A held start
// lock without a changed listener remains a closed, unanswered call.
func TestLinuxShellHookCallBracketingRestartFollowsOutageMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		mode   string
		allow  bool
		swap   bool
		lock   bool
	}{
		{"default tier, restart", outageDefaultTierConfig, "open", true, true, true},
		{"strict tier, restart", outageStrictTierConfig, "closed", false, true, true},
		{"default tier, same slow gateway", outageDefaultTierConfig, "open", false, false, true},
		{"default tier, replacement without a start lock", outageDefaultTierConfig, "open", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			hookDir := filepath.Join(dataDir, "hooks")
			entered := make(chan struct{})
			stopHandler := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				select {
				case <-r.Context().Done():
				case <-stopHandler:
				}
			}))
			defer server.Close()
			defer server.CloseClientConnections()
			defer close(stopHandler)
			addr := strings.TrimPrefix(server.URL, "http://")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, SetupOpts{
				DataDir: dataDir, APIAddr: addr, APIToken: "scoped-test-token", HookFailMode: tc.mode,
			}, NewClaudeCodeConnector()); err != nil {
				t.Fatal(err)
			}
			installNativeGatewayForHookTest(t, home, hookDir)
			installNativeHookPostForHookTest(t, home)
			writeOutageTierConfig(t, dataDir, tc.config)
			if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("bash", filepath.Join(hookDir, "claude-code-hook.sh"))
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+dataDir, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
			cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"ordinary.txt"}}`)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			finished := make(chan error, 1)
			go func() { finished <- cmd.Wait() }()
			select {
			case <-entered:
			case err := <-finished:
				t.Fatalf("hook ended before its gateway took the call: %v, stdout %q stderr %q", err, stdout.String(), stderr.String())
			case <-time.After(20 * time.Second):
				t.Fatal("hook did not reach the gateway")
			}

			lock, err := os.OpenFile(filepath.Join(dataDir, "gateway.start.lock"), os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if tc.lock {
				if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			}
			if tc.swap {
				if err := server.Listener.Close(); err != nil {
					t.Fatal(err)
				}
				newGateway := exec.Command(os.Args[0], "-test.run=^TestRestartBracketListener$")
				newGateway.Env = append(sanitizedTestEnv(), restartBracketListenerEnv+"="+addr)
				ready, err := newGateway.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := newGateway.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = newGateway.Process.Kill(); _ = newGateway.Wait() })
				if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || line != "ready\n" {
					t.Fatalf("replacement gateway did not listen: %q, %v", line, err)
				}
				if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), []byte(strconv.Itoa(newGateway.Process.Pid)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// The down window ends while the first call is still waiting for an
			// answer. The timer defines that window; the channel above orders it
			// after the call reached the old gateway.
			<-time.After(750 * time.Millisecond)
			select {
			case runErr := <-finished:
				t.Fatalf("hook finished inside the restart window: %v, stdout %q stderr %q", runErr, stdout.String(), stderr.String())
			default:
			}
			if tc.lock {
				if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
					t.Fatal(err)
				}
			}
			var runErr error
			select {
			case runErr = <-finished:
			case <-time.After(15 * time.Second):
				t.Fatal("hook outlasted its answer budget")
			}
			blocked := hookCallBlocked(runErr, stdout.String())
			if blocked == tc.allow {
				t.Fatalf("blocked=%v, want %v; exit %d stdout %q stderr %q", blocked, !tc.allow, exitCodeOf(runErr), stdout.String(), stderr.String())
			}
			if !tc.swap && !strings.Contains(stdout.String(), "the gateway is running but did not answer") {
				t.Fatalf("same gateway has no restart proof: stdout %q stderr %q", stdout.String(), stderr.String())
			}
			rows := hookFailureRecords(t, dataDir)
			want := "fail_closed"
			if tc.allow {
				want = "fail_open"
			}
			if len(rows) != 1 || rows[0]["category"] != "transport" || rows[0]["outcome"] != want || rows[0]["reason"] != "gateway unreachable" {
				t.Fatalf("hook-failures rows %+v, want one transport %s row", rows, want)
			}
		})
	}
}
