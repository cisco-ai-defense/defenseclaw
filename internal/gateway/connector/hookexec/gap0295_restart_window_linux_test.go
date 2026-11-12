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
const freshListenerCloseAcceptedEnv = "DC_TEST_FRESH_LISTENER_CLOSE_ACCEPTED"

func perUserFreshGatewayHoldsCall(dataDir string, check *perUserPeerCheck) bool {
	return perUserFreshGatewayProof(dataDir, check).ok
}

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
	// Hold every accepted connection open until the helper ends.
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	}()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if os.Getenv(freshListenerCloseAcceptedEnv) == "1" {
			_, _ = fmt.Fprintln(os.Stdout, "accepted")
			// Closed when the test says so, once it has what it needs from the
			// open connection; an ended stdin closes it too.
			_, _ = bufio.NewReader(os.Stdin).ReadString(0x0a)
			_ = conn.Close()
			_, _ = fmt.Fprintln(os.Stdout, "closed")
			continue
		}
		held = append(held, conn)
	}
}

// TestGAP0295FreshOwnerSurvivesSocketClose covers a verified connection
// whose accepted socket closes as its answer deadline ends. The owner proof
// captured while it was open is still valid for that call.
func TestGAP0295FreshOwnerSurvivesSocketClose(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP0295FreshListenerHelper$")
	cmd.Env = append(os.Environ(), freshListenerHelperEnv+"=1", freshListenerCloseAcceptedEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	closeAccepted, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := bufio.NewReader(stdout)
	line, err := lines.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	executable, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	clock, start := freshGatewayClock(t, pid)
	dataDir := t.TempDir()
	record, err := json.Marshal(map[string]any{
		"pid": pid, "executable": strings.TrimSuffix(executable, " (deleted)"), "data_dir": dataDir,
		"start_time": start.Add(-time.Second).Unix(), "start_identity": recordedStart(t, pid),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), record, 0o600); err != nil {
		t.Fatal(err)
	}
	dateGatewayRecord(t, dataDir, start.Add(500*time.Millisecond))
	conn, err := net.Dial("tcp", strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if line, err := lines.ReadString('\n'); err != nil || strings.TrimSpace(line) != "accepted" {
		t.Fatalf("accept signal = %q, %v", line, err)
	}
	check := &perUserPeerCheck{}
	check.ends.Store(&perUserConnEnds{local: conn.LocalAddr(), remote: conn.RemoteAddr(), at: time.Now()})
	sp, _ := specFor("claudecode")
	w := &answerWatchdog{restart: &perUserRestartAnswer{mode: "open"}}
	w.restartWindowContact(Options{Home: dataDir}, sp, "open", check)
	awaitOwnerRead(t, clock)
	owner := check.owner.Load()
	if owner == nil {
		t.Fatal("the read of the connection owner ended without naming it")
	}
	if owner.pid != pid {
		t.Fatalf("captured owner = %+v, want the fresh gateway", owner)
	}
	// The read asked for the product wait, and it was not spent.
	if got := clock.Requested(); len(got) != 1 || got[0] != freshOwnerCaptureWait {
		t.Fatalf("owner read timers = %v, want one of %v", got, freshOwnerCaptureWait)
	}
	// Only now does the gateway close the accepted socket.
	if _, err := fmt.Fprintln(closeAccepted, "close"); err != nil {
		t.Fatal(err)
	}
	if line, err := lines.ReadString('\n'); err != nil || strings.TrimSpace(line) != "closed" {
		t.Fatalf("close signal = %q, %v", line, err)
	}
	if result := perUserFreshGatewayProof(dataDir, check); !result.ok {
		t.Fatalf("captured connection proof = %+v", result)
	}
	uncaptured := &perUserPeerCheck{}
	uncaptured.ends.Store(check.ends.Load())
	if result := perUserFreshGatewayProof(dataDir, uncaptured); result.ok || result.reason != "no_holder" {
		t.Fatalf("closed connection without its owner proof = %+v", result)
	}
}

// TestGAP0295FreshGatewayHoldsCallProof runs the real Linux proof: the
// connection is held by the process the account's fresh gateway record
// names, and that process had answered nothing when the connection reached
// it. A first answer recorded before the connection, a connection held by
// another process and a stale record are no proof; a sibling call answered
// after this connection was made does not end this call's window (v108k).
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
	clock, start := freshGatewayClock(t, pid)
	dataDir := t.TempDir()
	writeRecord := func(started time.Time) {
		t.Helper()
		b, err := json.Marshal(map[string]any{
			"pid": pid, "executable": strings.TrimSuffix(executable, " (deleted)"), "data_dir": dataDir,
			"start_time": started.Unix(), "start_identity": recordedStart(t, pid),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		dateGatewayRecord(t, dataDir, start.Add(500*time.Millisecond))
	}
	checkFor := func(conn net.Conn) *perUserPeerCheck {
		check := &perUserPeerCheck{}
		check.ends.Store(&perUserConnEnds{local: conn.LocalAddr(), remote: conn.RemoteAddr(), at: time.Now()})
		return check
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	check := checkFor(conn)
	writeRecord(start.Add(-time.Second))
	if !perUserGatewayRecentlyStarted(dataDir) {
		t.Fatal("a just-written gateway record is not recent")
	}
	// The helper accept()s the connection after the dial returns.
	eventuallyWithin(t, "the helper holding the connection", 5*time.Second, func() bool { return perUserFreshGatewayHoldsCall(dataDir, check) })
	// The limits are the product ones, read on the clock of the test: the
	// record is recent up to the window and two seconds of slack past the
	// modification time, and the gateway process is fresh up to 12 s.
	recordedAt := start.Add(500 * time.Millisecond)
	clock.Set(recordedAt.Add(perUserFreshGatewayWindow + 2*time.Second))
	if !perUserGatewayRecentlyStarted(dataDir) {
		t.Fatal("a gateway record at the end of its window is not recent")
	}
	clock.Set(recordedAt.Add(perUserFreshGatewayWindow + 2*time.Second + time.Millisecond))
	if perUserGatewayRecentlyStarted(dataDir) {
		t.Fatal("a gateway record past its window is recent")
	}
	clock.Set(start.Add(perUserFreshGatewayWindow))
	if !perUserFreshGatewayHoldsCall(dataDir, check) {
		t.Fatal("a gateway process at the end of its 12 s window is not fresh")
	}
	clock.Set(start.Add(perUserFreshGatewayWindow + time.Millisecond))
	if perUserFreshGatewayHoldsCall(dataDir, check) {
		t.Fatal("a gateway process past its 12 s window is proven fresh")
	}
	if got := perUserFreshGatewayProof(dataDir, check).reason; got != "not_fresh" {
		t.Fatalf("old gateway reason = %q", got)
	}
	clock.Set(start.Add(time.Second))
	if perUserFreshGatewayHoldsCall(dataDir, &perUserPeerCheck{}) {
		t.Fatal("a try with no proven connection is proven")
	}
	if got := perUserFreshGatewayProof(dataDir, &perUserPeerCheck{}).reason; got != "no_verified_connection" {
		t.Fatalf("missing connection reason = %q", got)
	}

	// A stale record: its recorded start is far older than the process.
	writeRecord(start.Add(-time.Minute))
	if perUserFreshGatewayHoldsCall(dataDir, check) {
		t.Fatal("a stale gateway record is proven fresh")
	}
	if got := perUserFreshGatewayProof(dataDir, check).reason; got != "not_fresh" {
		t.Fatalf("stale record reason = %q", got)
	}
	writeRecord(start.Add(-time.Second))
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
	if got := perUserFreshGatewayProof(dataDir, checkFor(otherConn)).reason; got != "no_holder" {
		t.Fatalf("other holder reason = %q", got)
	}

	// A sibling call that reached the gateway with this one is answered
	// first: this call, connected before that answer, stays in the window.
	time.Sleep(50 * time.Millisecond)
	if err := recordPerUserGatewayAnswer(dataDir, perUserPeerProcess{pid: pid, identity: identity}); err != nil {
		t.Fatal(err)
	}
	if !perUserFreshGatewayHoldsCall(dataDir, check) {
		t.Fatal("a call connected before the gateway's first answer left the window")
	}
	// A connection without its proof time is no proof once an answer exists.
	untimed := &perUserPeerCheck{}
	untimed.ends.Store(&perUserConnEnds{local: conn.LocalAddr(), remote: conn.RemoteAddr()})
	if perUserFreshGatewayHoldsCall(dataDir, untimed) {
		t.Fatal("a connection with no proof time is proven after an answer")
	}

	// A call that reaches the gateway after its first answer met a serving
	// gateway: no proof, the no-decision deny stands.
	time.Sleep(50 * time.Millisecond)
	late, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	lateCheck := checkFor(late)
	client, server := late.LocalAddr().(*net.TCPAddr), late.RemoteAddr().(*net.TCPAddr)
	eventuallyWithin(t, "the helper accepting the late connection", 5*time.Second, func() bool {
		owner, unique := perUserConnectedPeerPID(client, server)
		return unique && owner == pid
	})
	if perUserFreshGatewayHoldsCall(dataDir, lateCheck) {
		t.Fatal("a call that reached the gateway after its first answer is proven fresh")
	}
	if got := perUserFreshGatewayProof(dataDir, lateCheck).reason; got != "answered_before" {
		t.Fatalf("answer before connection reason = %q", got)
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
