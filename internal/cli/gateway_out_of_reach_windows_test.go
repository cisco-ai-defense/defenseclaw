// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// TestGAP1212OutOfReachGatewayHelper is the stand-in gateway of
// TestLifecycleNamesThisAccountsGatewayOutOfReach: it holds a loopback port,
// closes every connection, and writes the port to a file.
func TestGAP1212OutOfReachGatewayHelper(t *testing.T) {
	path := os.Getenv("DC_GAP1212_PORT_FILE")
	if path == "" {
		t.Skip("helper process only")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if err := os.WriteFile(path+".tmp", []byte(port), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Minute)
}

// rel-1-0-10:GAP-1212, black box with the commands only: this account's
// gateway that runs where this shell cannot open it (started elevated in
// another logon session: its process DACL grants only Administrators, SYSTEM
// and that session) holds the API port, and its private gateway-api.json
// names it with its creation time. The stand-in is a child whose process DACL
// grants only SYSTEM. status reports it as this account's running gateway,
// start says it is already running and changes nothing, stop and restart
// refuse with a non-zero exit and change nothing (never "not running").
func TestLifecycleNamesThisAccountsGatewayOutOfReach(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	portFile := filepath.Join(t.TempDir(), "port")
	child := exec.Command(os.Args[0], "-test.run=^TestGAP1212OutOfReachGatewayHelper$")
	child.Env = append(os.Environ(), "DC_GAP1212_PORT_FILE="+portFile)
	child.SysProcAttr = &syscall.SysProcAttr{ProcessAttributes: &syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: uintptr(unsafe.Pointer(sd)),
	}}
	err = child.Start()
	// sd is referenced only through a uintptr while CreateProcess reads it.
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	pid := child.Process.Pid
	var created windows.Filetime
	var timesErr error
	if err := child.Process.WithHandle(func(h uintptr) {
		var exit, kernel, user windows.Filetime
		timesErr = windows.GetProcessTimes(windows.Handle(h), &created, &exit, &kernel, &user)
	}); err != nil || timesErr != nil {
		t.Fatalf("creation time from the CreateProcess handle: %v %v", err, timesErr)
	}
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); err == nil {
		_ = windows.CloseHandle(h)
		t.Skip("the child opens for this caller (SeDebugPrivilege?): not the out-of-reach shape")
	}
	var port int
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if raw, err := os.ReadFile(portFile); err == nil {
			if port, err = strconv.Atoi(string(raw)); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the stand-in gateway never reported its port")
		}
	}

	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	configText := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_bind: 127.0.0.1\n  api_port: %d\n  token: disposable-test-token\nobservability: {}\n", home, port)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(home, "gateway-api.json")
	body := fmt.Sprintf(`{"pid":%d,"host":"127.0.0.1","port":%d,"start_identity":"%d"}`, pid, port, created.Nanoseconds())
	if err := os.WriteFile(record, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(record); err != nil {
		t.Fatal(err)
	}
	oldHost, oldPort := sidecarHost, sidecarPort
	sidecarHost, sidecarPort = "", 0
	t.Cleanup(func() { sidecarHost, sidecarPort = oldHost, oldPort })
	listing := func() string {
		entries, _ := os.ReadDir(home)
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	}

	t.Run("status", func(t *testing.T) {
		previousConfig, previousJSON := cfg, gatewayStatusJSON
		t.Cleanup(func() { cfg, gatewayStatusJSON = previousConfig, previousJSON })
		cfg = &config.Config{DataDir: home}
		cfg.Gateway.APIBind = "127.0.0.1"
		cfg.Gateway.APIPort = port
		gatewayStatusJSON = true
		var runErr error
		out := captureStdout(t, func() { runErr = runSidecarStatus(nil, nil) })
		var doc gatewayStatusDocument
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("status --json is not JSON (%v):\n%s", err, out)
		}
		if !doc.Running || strings.Contains(doc.Error, "not by this account") || strings.Contains(doc.Error, "another account") {
			t.Fatalf("status of this account's out-of-reach gateway = %+v (err %v), want it running and this account's", doc, runErr)
		}
	})
	t.Run("start", func(t *testing.T) {
		before := listing()
		var runErr error
		out := captureStdout(t, func() { runErr = runStart(startCmd, nil) })
		if runErr != nil || strings.Contains(out, "not by this account") {
			t.Fatalf("start = %v, output:\n%s\nwant already running", runErr, out)
		}
		if after := listing(); strings.Contains(after, "gateway.pid") {
			t.Fatalf("start launched a gateway: home %s -> %s", before, after)
		}
	})
	t.Run("stop", func(t *testing.T) {
		before := listing()
		var runErr error
		out := captureStdout(t, func() { runErr = runStop(stopCmd, nil) })
		if runErr == nil || strings.Contains(out, "not running") {
			t.Fatalf("stop = %v, output:\n%s\nwant a refusal (this shell cannot stop it), never not running", runErr, out)
		}
		if after := listing(); after != before {
			t.Fatalf("a refused stop changed the home: %s -> %s", before, after)
		}
	})
	t.Run("restart", func(t *testing.T) {
		var runErr error
		out := captureStdout(t, func() { runErr = runRestart(restartCmd, nil) })
		if runErr == nil || strings.Contains(runErr.Error(), "not by this account") || strings.Contains(out, "Starting gateway") {
			t.Fatalf("restart = %v, output:\n%s\nwant a refusal naming this account's gateway", runErr, out)
		}
	})
	var code uint32
	if err := child.Process.WithHandle(func(h uintptr) { _ = windows.GetExitCodeProcess(windows.Handle(h), &code) }); err != nil || code != 259 {
		t.Fatalf("the stand-in gateway did not survive: exit code %d, %v", code, err)
	}
}
