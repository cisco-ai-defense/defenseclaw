// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// TestPerUserGatewayStartInProgressReadsTheStartLock pins the signal hook-post
// uses for rel-1-0-6 GAP-0295: only this account's regular start lock held by
// a start or restart counts.
func TestPerUserGatewayStartInProgressReadsTheStartLock(t *testing.T) {
	dir := t.TempDir()
	if PerUserGatewayStartInProgress(dir) {
		t.Fatal("no lock file: reported a start")
	}
	lock := filepath.Join(dir, perUserGatewayStartLockName)
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if PerUserGatewayStartInProgress(dir) {
		t.Fatal("lock nobody holds: reported a start")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if !PerUserGatewayStartInProgress(dir) {
		t.Fatal("held start lock: no start reported")
	}
	if PerUserGatewayStartInProgress("relative/dir") || PerUserGatewayStartInProgress("") {
		t.Fatal("a relative or empty data directory reported a start")
	}
	linked := t.TempDir()
	if err := os.Symlink(lock, filepath.Join(linked, perUserGatewayStartLockName)); err != nil {
		t.Fatal(err)
	}
	if PerUserGatewayStartInProgress(linked) {
		t.Fatal("a symlinked start lock reported a start")
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if PerUserGatewayStartInProgress(dir) {
		t.Fatal("released lock: still reported a start")
	}
	// A directory of that name can be flocked on Linux: it is no start lock.
	dirLock := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirLock, perUserGatewayStartLockName), 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(filepath.Join(dirLock, perUserGatewayStartLockName))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil && PerUserGatewayStartInProgress(dirLock) {
		t.Fatal("a held directory named like the start lock reported a start")
	}
}

func holdStartLock(t *testing.T, dir string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, perUserGatewayStartLockName), os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

// peerHelperEnv makes the test binary a process that listens on an address
// and waits (TestPerUserPeerHelperProcess).
const peerHelperEnv = "R107NA_PEER_HELPER_LISTEN"

// TestPerUserPeerHelperProcess is not a test: with peerHelperEnv set it is a
// second process of this account that listens on that address until killed.
func TestPerUserPeerHelperProcess(t *testing.T) {
	addr := os.Getenv(peerHelperEnv)
	if addr == "" {
		t.Skip("helper process only")
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		os.Exit(3)
	}
	defer l.Close()
	_, _ = os.Stdout.WriteString("ready\n")
	time.Sleep(time.Minute)
	os.Exit(0)
}

// startPeerHelper starts another process of this account listening on addr.
func startPeerHelper(t *testing.T, addr string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPerUserPeerHelperProcess$")
	cmd.Env = append(os.Environ(), peerHelperEnv+"="+addr)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper did not listen on %s: %q %v", addr, line, err)
	}
	return cmd
}

func knownPeer(pid int, identity string, server *net.TCPAddr) *PerUserPeerRecord {
	r := &PerUserPeerRecord{done: make(chan struct{}), ok: true, peer: perUserPeerProcess{pid: pid, identity: identity, server: server}}
	close(r.done)
	return r
}

// TestPerUserConnectedPeerIsTheProcessBehindTheSocket: the kernel names this
// process as the owner of the accepted server socket and of the listener.
func TestPerUserConnectedPeerIsTheProcessBehindTheSocket(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer func() {
		if s := <-accepted; s != nil {
			_ = s.Close()
		}
	}()
	var pid int
	var ok bool
	for i := 0; i < 50 && !ok; i++ {
		pid, ok = perUserConnectedPeerPID(c.LocalAddr().(*net.TCPAddr), c.RemoteAddr().(*net.TCPAddr))
		if !ok {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !ok || pid != os.Getpid() {
		t.Fatalf("connected peer = %d %v, want this process %d", pid, ok, os.Getpid())
	}
	owner, ok := perUserListenerOwner(l.Addr().(*net.TCPAddr))
	if !ok || owner.pid != os.Getpid() || owner.identity == "" {
		t.Fatalf("listener owner = %+v %v, want this process", owner, ok)
	}
	record := NewPerUserPeerRecord()
	record.capture(c.LocalAddr(), c.RemoteAddr())
	if got, ok := record.wait(5 * time.Second); !ok || got.pid != os.Getpid() {
		t.Fatalf("recorded peer = %+v %v, want this process", got, ok)
	}
}

// TestPerUserGatewayRestartProvenReadsTheConnectedPeer pins the lead ruling
// on rel-1-0-6 GAP-0295 (review r2): a no-answer is the restart outage only
// while the start lock is held and the process the kernel named behind the
// call's connection is gone, was replaced, or no longer owns the port.
// gateway.pid is not read at all, and an unknown peer is no proof.
func TestPerUserGatewayRestartProvenReadsTheConnectedPeer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := l.Addr().(*net.TCPAddr)
	self, ok := procidentity.Of(os.Getpid())
	if !ok {
		t.Skip("no process identity on this system")
	}
	unknown := NewPerUserPeerRecord()
	close(unknown.done)
	for _, tc := range []struct {
		name string
		lock bool
		peer *PerUserPeerRecord
		want bool
	}{
		{"lock held, same gateway up and slow", true, knownPeer(os.Getpid(), self, server), false},
		{"lock held, peer pid now names another process (XID)", true, knownPeer(os.Getpid(), self+"-other", server), true},
		{"lock held, peer exited", true, knownPeer(1<<22+12345, "1 2", server), true},
		{"lock held, peer unknown (XBEF)", true, unknown, false},
		{"lock held, no record", true, nil, false},
		{"no lock, peer exited", false, knownPeer(1<<22+12345, "1 2", server), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.lock {
				holdStartLock(t, dir)
			}
			if got := PerUserGatewayRestartProven(dir, tc.peer); got != tc.want {
				t.Fatalf("restart proven = %v, want %v", got, tc.want)
			}
		})
	}
	// Another process of this account owns the port by the deadline: the
	// gateway that took the call gave it up.
	t.Run("lock held, another process listens on the port", func(t *testing.T) {
		_ = l.Close()
		startPeerHelper(t, server.String())
		dir := t.TempDir()
		holdStartLock(t, dir)
		if !PerUserGatewayRestartProven(dir, knownPeer(os.Getpid(), self, server)) {
			t.Fatal("restart not proven with another process on the port")
		}
	})
}
