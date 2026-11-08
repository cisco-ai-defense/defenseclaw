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
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestPrivateThreadListenerChild is the helper process of
// TestListenerHeldByAThreadWithItsOwnDescriptorTableStaysUnverified: it
// inherits a listening socket as descriptor 3, gives one thread a private copy
// of the descriptor table, then closes its own descriptor 3, so only that
// thread still holds the socket and the process leader folder does not list
// it. It exits when the parent closes its stdin.
func TestPrivateThreadListenerChild(t *testing.T) {
	if os.Getenv("DC_TEST_PRIVATE_THREAD") != "1" {
		t.Skip("helper process of the private descriptor table test")
	}
	// The thread that takes the private table must not be the process leader
	// (the main thread), whose table is the one /proc/<pid>/fd lists. Several
	// goroutines each hold a thread of their own, then one that is not the
	// leader is told to take the private table.
	type holder struct {
		tid  int
		take chan bool
	}
	holders := make(chan holder)
	done := make(chan error, 1)
	for range 8 {
		go func() {
			runtime.LockOSThread()
			h := holder{tid: syscall.Gettid(), take: make(chan bool)}
			holders <- h
			if !<-h.take {
				return
			}
			if _, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, syscall.CLONE_FILES, 0, 0); errno != 0 {
				done <- errno
				return
			}
			done <- nil
			select {}
		}()
	}
	chosen := false
	for range 8 {
		h := <-holders
		if !chosen && h.tid != os.Getpid() {
			chosen = true
			h.take <- true
			continue
		}
		h.take <- false
	}
	if !chosen {
		fmt.Println("PRIVATE_ERR=no thread other than the leader")
		return
	}
	if err := <-done; err != nil {
		fmt.Printf("PRIVATE_ERR=%v\n", err)
		return
	}
	if err := syscall.Close(3); err != nil {
		fmt.Printf("PRIVATE_ERR=%v\n", err)
		return
	}
	fmt.Println("PRIVATE_READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// A listener that a thread of another process of the account keeps open in a
// descriptor table of its own (the process leader closed its copy) is still a
// second holder of the accept queue: the recorded gateway does not hold it
// alone, so it stays refused as unverified in every fail mode, as it is when
// the second process holds it in its ordinary table.
func TestListenerHeldByAThreadWithItsOwnDescriptorTableStaysUnverified(t *testing.T) {
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
	cmd := exec.Command(source, "-test.run=^TestPrivateThreadListenerChild$")
	cmd.Env = append(os.Environ(), "DC_TEST_PRIVATE_THREAD=1")
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
	if !reader.Scan() || strings.TrimSpace(reader.Text()) != "PRIVATE_READY" {
		t.Skipf("the helper could not give a thread a private descriptor table: %q", reader.Text())
	}
	// The leader folder of the helper must not list the socket: that is the
	// case the thread folders exist to cover.
	leader, err := socketInodesOfLeader(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	threads, err := socketInodesOf("/proc", cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	private := false
	for held := range threads {
		private = private || !leader[held]
	}
	if !private {
		t.Fatal("the helper thread does not hold a socket its leader lacks")
	}
	ctx := WithPerUserGatewayDataDir(t.Context(), recordGateway(t, os.Getpid(), nil))
	_, err = PostPerUserHook(ctx, listener.Addr().String(), "/api/v1/claude-code/hook", nil, []byte("{}"))
	if err == nil {
		t.Fatal("a listener that accepts nothing answered")
	}
	if PerUserPostListenerUnanswered(err) || !PerUserPostPeerUnverified(err) {
		t.Fatalf("a listener held by a private descriptor table was not refused as unverified: %v", err)
	}
}

// socketInodesOfLeader lists the sockets in the process leader folder alone.
func socketInodesOfLeader(pid int) (map[string]bool, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	held := make(map[string]bool)
	for _, entry := range entries {
		target, err := os.Readlink(dir + "/" + entry.Name())
		if err != nil {
			continue
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			held[strings.TrimSuffix(inode, "]")] = true
		}
	}
	return held, nil
}
