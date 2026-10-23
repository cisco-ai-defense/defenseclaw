// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package systemd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A process launchd did not start for a job with sockets gets no socket:
// the libSystem call answers through the trampoline (no cgo) instead of
// crashing, and Listener reports "not activated".
func TestLaunchdActivationOutsideAJobIsNotActivated(t *testing.T) {
	if os.Getenv(launchdSocketHelperEnv) != "" {
		t.Skip("helper process")
	}
	if _, err := launchdActivateSocket("api"); !errors.Is(err, errLaunchdNoSocket) {
		t.Fatalf("launch_activate_socket outside a job = %v, want the no-socket answer", err)
	}
	if listener, ok, err := Listener("dc-test-no-such-socket"); ok || err != nil || listener != nil {
		t.Fatalf("Listener outside a job = %v, %t, %v; want not activated", listener, ok, err)
	}
}

const launchdSocketHelperEnv = "DC_TEST_LAUNCHD_SOCKET_HELPER"

// TestLaunchdSocketHelper is the daemon TestLaunchdHoldsTheGatewayPortAcrossRestarts
// loads: it serves one request on the plist's "api" socket with its pid,
// then exits, so launchd starts it again.
func TestLaunchdSocketHelper(t *testing.T) {
	if os.Getenv(launchdSocketHelperEnv) != "1" {
		t.Skip("run by launchd only")
	}
	listener, ok, err := Listener("api")
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "not activated: ok=%t err=%v\n", ok, err)
		os.Exit(3)
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	served := make(chan struct{})
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, strconv.Itoa(os.Getpid()))
		select {
		case <-served:
		default:
			close(served)
		}
	})
	go func() { _ = server.Serve(listener) }()
	select {
	case <-served:
	case <-time.After(2 * time.Minute):
	}
	time.Sleep(200 * time.Millisecond)
	os.Exit(0)
}

// GAP-0963: launchd holds the gateway's API socket while the gateway is
// down, so no other process can bind the port, and a request sent then is
// answered by the next gateway instead of by another account. Needs root
// (launchctl bootstrap system); run it on a macOS host with
// DC_TEST_LAUNCHD_SOCKET=1.
func TestLaunchdHoldsTheGatewayPortAcrossRestarts(t *testing.T) {
	if os.Getenv("DC_TEST_LAUNCHD_SOCKET") != "1" || os.Geteuid() != 0 {
		t.Skip("set DC_TEST_LAUNCHD_SOCKET=1 and run as root on macOS")
	}
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/private/tmp", "dc-launchd-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	helper := filepath.Join(dir, "helper.test")
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, data, 0o755); err != nil {
		t.Fatal(err)
	}
	label := fmt.Sprintf("com.cisco.defenseclaw.test.launchd-socket.%d", os.Getpid())
	plist := filepath.Join(dir, label+".plist")
	if err := os.WriteFile(plist, []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key><array><string>%s</string><string>-test.run=^TestLaunchdSocketHelper$</string></array>
	<key>EnvironmentVariables</key><dict><key>%s</key><string>1</string></dict>
	<key>KeepAlive</key><true/>
	<key>RunAtLoad</key><true/>
	<key>ThrottleInterval</key><integer>2</integer>
	<key>StandardErrorPath</key><string>%s</string>
	<key>Sockets</key><dict><key>api</key><dict>
		<key>SockFamily</key><string>IPv4</string>
		<key>SockNodeName</key><string>127.0.0.1</string>
		<key>SockServiceName</key><string>%d</string>
		<key>SockType</key><string>stream</string>
	</dict></dict>
</dict>
</plist>
`, label, helper, launchdSocketHelperEnv, filepath.Join(dir, "helper.err"), port)), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", plist).CombinedOutput(); err != nil {
		t.Fatalf("launchctl bootstrap: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/launchctl", "bootout", "system/"+label).Run() })
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	get := func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", nil)
		if err != nil {
			return "", err
		}
		resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(body)), err
	}
	first, err := get()
	if err != nil {
		log, _ := os.ReadFile(filepath.Join(dir, "helper.err"))
		t.Fatalf("first request: %v; helper log: %s", err, log)
	}
	// The helper exits after that answer. Until launchd starts it again,
	// the port stays bound: nobody else can listen there.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if out, err := exec.Command("/bin/launchctl", "print", "system/"+label).Output(); err == nil &&
			!strings.Contains(string(out), "pid = ") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if peer, err := net.Listen("tcp4", addr); err == nil {
		_ = peer.Close()
		t.Fatalf("another process bound %s while the daemon was down", addr)
	}
	second, err := get()
	if err != nil {
		log, _ := os.ReadFile(filepath.Join(dir, "helper.err"))
		t.Fatalf("request sent while the daemon was down: %v; helper log: %s", err, log)
	}
	if first == "" || second == "" || first == second {
		t.Fatalf("answers came from pids %q and %q, want two daemon starts", first, second)
	}
}
