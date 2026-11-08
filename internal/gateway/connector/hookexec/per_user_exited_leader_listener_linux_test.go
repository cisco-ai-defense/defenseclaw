// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// init turns the test binary into the helper process of
// TestListenerHeldByAWorkerOfAProcessWhoseLeaderExitedStaysUnverified: it
// inherits a listening socket as descriptor 3, then ends its main thread (the
// process leader) with the exit system call, which ends one thread only, so a
// worker thread keeps the process and the socket alive and the leader folder
// of the process is unreadable. The worker exits the process when the parent
// closes its stdin.
func init() {
	if os.Getenv("DC_TEST_EXITED_LEADER") != "1" {
		return
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		fmt.Println("LEADER_GONE")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}()
	// Syscall (not RawSyscall) so the runtime hands the processor on.
	time.Sleep(50 * time.Millisecond)
	syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0)
}

// A listener that a live worker of another process of the account keeps open
// after that process leader exited is still a second holder of the accept
// queue: the unreadable descriptor folder of the dead leader must not hide
// the readable folder of the live worker, so the recorded gateway does not
// hold the port alone and the call stays refused as unverified.
func TestListenerHeldByAWorkerOfAProcessWhoseLeaderExitedStaysUnverified(t *testing.T) {
	shortConnectedWait(t, 150*time.Millisecond)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	file, err := listener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(source, "-test.run=^$")
	cmd.Env = append(os.Environ(), "DC_TEST_EXITED_LEADER=1")
	cmd.ExtraFiles = []*os.File{file}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("no second process: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	reader := bufio.NewScanner(stdout)
	if !reader.Scan() || strings.TrimSpace(reader.Text()) != "LEADER_GONE" {
		t.Skipf("the helper could not end its leader thread: %q", reader.Text())
	}
	// The case under test: the leader folder is refused while a live worker
	// holds the listening socket.
	if _, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", cmd.Process.Pid)); err == nil {
		t.Skip("the leader folder of the helper is still readable")
	}
	held, err := socketInodesOf("/proc", cmd.Process.Pid)
	if err != nil {
		t.Fatalf("a live worker folder was hidden by the dead leader folder: %v", err)
	}
	if len(held) == 0 {
		t.Fatal("the live worker of the helper holds no socket")
	}
	ctx := WithPerUserGatewayDataDir(t.Context(), recordGateway(t, os.Getpid(), nil))
	_, err = PostPerUserHook(ctx, listener.Addr().String(), "/api/v1/claude-code/hook", nil, []byte("{}"))
	if err == nil {
		t.Fatal("a listener that accepts nothing answered")
	}
	if PerUserPostListenerUnanswered(err) || !PerUserPostPeerUnverified(err) {
		t.Fatalf("a listener held by a worker of an exited leader was not refused as unverified: %v", err)
	}
}
