// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

const freshListenerHelperEnv = "DC_TEST_FRESH_LISTENER_PROCESS"

// TestGAP0295FreshListenerHelper is a gateway that takes connections and
// never answers.
func TestGAP0295FreshListenerHelper(t *testing.T) {
	if os.Getenv(freshListenerHelperEnv) != "1" {
		t.Skip("helper process only")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(3)
	}
	_, _ = fmt.Fprintln(os.Stdout, listener.Addr().String())
	var held []net.Conn
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		held = append(held, conn)
	}
}

// TestGAP0295FreshGatewayHoldsCallProof runs the real Linux proof: the
// connection is held by the process the account's fresh gateway record
// names, and that process has answered nothing. A recorded first answer, a
// connection held by another process and a stale record are no proof.
func TestGAP0295FreshGatewayHoldsCallProof(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP0295FreshListenerHelper$")
	cmd.Env = append(os.Environ(), freshListenerHelperEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("listener helper not ready: %q, %v", line, err)
	}
	addr := strings.TrimSpace(line)
	pid := cmd.Process.Pid
	identity, ok := procidentity.Of(pid)
	if !ok {
		t.Fatal("helper identity unavailable")
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	writeRecord := func(started time.Time) {
		t.Helper()
		b, err := json.Marshal(map[string]any{
			"pid": pid, "executable": strings.TrimSuffix(executable, " (deleted)"), "data_dir": dataDir,
			"start_time": started.Unix(), "start_identity": identity,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checkFor := func(conn net.Conn) *perUserPeerCheck {
		check := &perUserPeerCheck{}
		check.ends.Store(&perUserConnEnds{local: conn.LocalAddr(), remote: conn.RemoteAddr()})
		return check
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	check := checkFor(conn)
	writeRecord(time.Now().Add(-time.Second))
	if !perUserGatewayRecentlyStarted(dataDir) {
		t.Fatal("a just-written gateway record is not recent")
	}
	// The helper accept()s the connection after the dial returns.
	proven := false
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end) && !proven; time.Sleep(10 * time.Millisecond) {
		proven = perUserFreshGatewayHoldsCall(dataDir, check)
	}
	if !proven {
		t.Fatal("a connection held by the fresh, unanswered gateway is not proven")
	}
	if perUserFreshGatewayHoldsCall(dataDir, &perUserPeerCheck{}) {
		t.Fatal("a try with no proven connection is proven")
	}

	// A stale record: its recorded start is far older than the process.
	writeRecord(time.Now().Add(-time.Minute))
	if perUserFreshGatewayHoldsCall(dataDir, check) {
		t.Fatal("a stale gateway record is proven fresh")
	}
	writeRecord(time.Now().Add(-time.Second))
	if !perUserFreshGatewayHoldsCall(dataDir, check) {
		t.Fatal("the restored record is not proven")
	}

	// A connection held by another process (this test's own listener).
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := other.Accept()
		accepted <- c
	}()
	otherConn, err := net.Dial("tcp", other.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer otherConn.Close()
	if c := <-accepted; c != nil {
		defer c.Close()
	}
	if perUserFreshGatewayHoldsCall(dataDir, checkFor(otherConn)) {
		t.Fatal("a connection another process holds is proven")
	}

	// The gateway's first answer ends its window.
	if err := recordPerUserGatewayAnswer(dataDir, perUserPeerProcess{pid: pid, identity: identity}); err != nil {
		t.Fatal(err)
	}
	if perUserFreshGatewayHoldsCall(dataDir, check) {
		t.Fatal("a gateway that answered a call is proven fresh")
	}
}

// TestGAP0295FirstTryOutageModeNotReadyStaysClosed (review N2): when the
// first try connects straight to a fresh gateway, the outage answer is
// prepared in the background because it reads the outage mode. If that read
// is not done by the deadline the call keeps the closed no-answer answer:
// never an allow without the account's mode.
func TestGAP0295FirstTryOutageModeNotReadyStaysClosed(t *testing.T) {
	previousLogWait := answerWatchdogLogWait
	answerWatchdogLogWait = time.Minute
	t.Cleanup(func() { answerWatchdogLogWait = previousLogWait })
	stubRestartWindowProof(t, true)
	sp, _ := specFor("claudecode")
	home := t.TempDir()
	writeFreshGatewayRecordStub(t, home)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
	exited := make(chan int, 1)
	opts := perUserRestartOptions(home, "open", false, stdout, stderr, func(code int) { exited <- code })
	opts.OutageFailModeNow = func() string { <-release; return "open" }
	w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
	w.noDecisionPending()
	w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
	code, shown := fireAnswerDeadline(t, w, exited, stdout, stderr)
	if !nativeAnswerBlocks(code, stdout.String()) || !strings.Contains(shown, "did not answer in time") {
		t.Fatalf("exit %d answer %q, want the closed no-answer while the outage mode is unread", code, shown)
	}
}
