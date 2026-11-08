// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

const realGatewayAddrFileEnv = "DEFENSECLAW_TEST_REAL_GATEWAY_ADDR_FILE"

// TestRealGatewayChildProbe is the process internal/daemon starts as the
// gateway in the tests below: it holds one listener and takes no accept.
func TestRealGatewayChildProbe(t *testing.T) {
	file := os.Getenv(realGatewayAddrFileEnv)
	if file == "" || !daemon.IsDaemonChild() {
		t.Skip("started only by the daemon in the tests that need a real gateway process")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(listener.Addr().String()), 0o600); err != nil || os.Rename(tmp, file) != nil {
		os.Exit(2)
	}
	for {
		time.Sleep(time.Second)
	}
}

// startRealGateway starts a gateway through the code the product uses
// (daemon.Start, which writes gateway.pid) and returns its listener address,
// its data folder and its pid. The process is stopped when the test ends.
func startRealGateway(t *testing.T) (addr, dataDir string, pid int) {
	t.Helper()
	dataDir = t.TempDir()
	file := filepath.Join(t.TempDir(), "addr")
	t.Setenv(realGatewayAddrFileEnv, file)
	d := daemon.New(dataDir)
	pid, err := d.Start([]string{"-test.run=^TestRealGatewayChildProbe$"})
	if err != nil {
		t.Fatalf("start the gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGCONT)
		_ = d.Stop(3 * time.Second)
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		raw, err := os.ReadFile(file)
		if err == nil && len(raw) > 0 {
			return string(raw), dataDir, pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("the gateway process never opened its listener: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// freezeProcess stops pid (SIGSTOP) and waits until the kernel reports it
// stopped, so a connection to its listener is queued and never accepted.
func freezeProcess(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGCONT) })
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err == nil {
			stat := string(raw)
			if fields := strings.Fields(stat[strings.LastIndexByte(stat, ')')+1:]); len(fields) > 0 && fields[0] == "T" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d did not stop", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The record that daemon.Start writes names the gateway in the text the hook
// reads back: the hook finds the recorded process by its pid and start.
func TestHookReadsBackTheRecordTheGatewayWrote(t *testing.T) {
	_, dataDir, pid := startRealGateway(t)
	record, ok := readGatewayRecord(dataDir)
	if !ok {
		t.Fatal("the hook cannot read the gateway.pid the gateway wrote")
	}
	if record.PID != pid {
		t.Fatalf("record names pid %d, the gateway is %d", record.PID, pid)
	}
	if got, ok := recordedGatewayPID(dataDir); !ok || got != pid {
		t.Fatalf("recordedGatewayPID = %d, %v; want the gateway %d (start_identity %q)", got, ok, pid, record.StartIdentity)
	}
	if lockText, _ := procidentity.Of(pid); lockText == record.StartIdentity {
		t.Fatal("the test no longer tells the gateway text from the install-lock text")
	}
}

// A frozen (SIGSTOP) gateway that daemon.Start launched and recorded is this
// account's gateway that does not answer: an outage that follows the fail
// mode, not a listener the hook cannot place. The same turn against a record
// of a different process, and against a record whose process was replaced,
// stays refused.
func TestFrozenGatewayTheDaemonStartedFollowsTheOutageMode(t *testing.T) {
	addr, dataDir, pid := startRealGateway(t)
	freezeProcess(t, pid)
	assertFrozenGatewayFollowsOutageMode(t, addr, dataDir)

	shortConnectedWait(t, 150*time.Millisecond)
	decoy := otherProcess(t)
	for name, dir := range map[string]string{
		"record names another process": recordGateway(t, decoy, nil),
		"record of a replaced process": recordGateway(t, pid, func(r *gatewayRecord) { r.StartIdentity += "0" }),
	} {
		_, err := PostPerUserHook(WithPerUserGatewayDataDir(context.Background(), dir), addr, "/api/v1/claude-code/hook", nil, []byte("{}"))
		if err == nil || PerUserPostListenerUnanswered(err) || !PerUserPostPeerUnverified(err) {
			t.Fatalf("%s: a listener the record does not name was not refused as unverified: %v", name, err)
		}
	}
}
