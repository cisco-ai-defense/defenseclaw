// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"bufio"
	"context"
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
	if os.Getenv(peerHoldHelperEnv) != "" {
		// Holds the descriptors it inherited (ExtraFiles) until killed.
		_, _ = os.Stdout.WriteString("ready\n")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
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

// peerHoldHelperEnv makes TestPerUserPeerHelperProcess a process that only
// holds the descriptors it inherited.
const peerHoldHelperEnv = "R107NA_PEER_HELPER_HOLD"

// startHoldHelper starts another process of this account that holds a dup
// of f (a listener or an accepted socket).
func startHoldHelper(t *testing.T, f *os.File) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPerUserPeerHelperProcess$")
	cmd.Env = append(os.Environ(), peerHoldHelperEnv+"=1")
	cmd.ExtraFiles = []*os.File{f}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("hold helper not ready: %q %v", line, err)
	}
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
	owners, ok := perUserListenerOwners(context.Background(), l.Addr().(*net.TCPAddr))
	if !ok || len(owners) != 1 || owners[0].pid != os.Getpid() || owners[0].identity == "" {
		t.Fatalf("listener owners = %+v %v, want this process", owners, ok)
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
	// A kill error other than "no such process" (EPERM: the pid now
	// belongs to another account) is no proof (review r3 finding 4).
	t.Run("lock held, peer pid unreadable (XPEERESRCH)", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can signal pid 1")
		}
		// A port nobody listens on, so only the peer read can decide.
		free, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		freeAddr := free.Addr().(*net.TCPAddr)
		_ = free.Close()
		dir := t.TempDir()
		holdStartLock(t, dir)
		if PerUserGatewayRestartProven(dir, knownPeer(1, "not-pid-1", freeAddr)) {
			t.Fatal("an unreadable peer pid read as a restart")
		}
	})
	// The proof that runs after the deadline has one budget: a proof not
	// done in it is no proof (review r3 finding 3).
	t.Run("lock held, proof budget spent", func(t *testing.T) {
		// Deterministic (review r4): the look at the start lock blocks until
		// the test ends, so only the outer budget can end the proof. The
		// peer would prove a restart if the proof ever finished.
		previous, previousOpen := perUserRestartProofBudget, perUserStartLockOpen
		perUserRestartProofBudget = 50 * time.Millisecond
		release := make(chan struct{})
		perUserStartLockOpen = func(path string) (*os.File, error) {
			<-release
			return previousOpen(path)
		}
		t.Cleanup(func() { close(release); perUserRestartProofBudget, perUserStartLockOpen = previous, previousOpen })
		dir := t.TempDir()
		holdStartLock(t, dir)
		got := make(chan bool, 1)
		start := time.Now()
		go func() { got <- PerUserGatewayRestartProven(dir, knownPeer(1<<22+12345, "1 2", server)) }()
		select {
		case ok := <-got:
			if ok {
				t.Fatal("a proof past its budget read as a restart")
			}
			if d := time.Since(start); d > time.Second {
				t.Fatalf("the proof took %v, want about its 50 ms budget", d)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the proof ran past its budget")
		}
	})
	// Another process holds a dup of the live gateway's listener (review r3
	// findings 1 and 2): the old peer is among the holders, so no change.
	t.Run("lock held, another process also holds the gateway listener", func(t *testing.T) {
		held, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		f, err := held.(*net.TCPListener).File()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		startHoldHelper(t, f)
		owners, ok := perUserListenerOwners(context.Background(), held.Addr().(*net.TCPAddr))
		if !ok || len(owners) != 2 {
			t.Fatalf("listener owners = %+v, want this process and the helper", owners)
		}
		dir := t.TempDir()
		holdStartLock(t, dir)
		if PerUserGatewayRestartProven(dir, knownPeer(os.Getpid(), self, held.Addr().(*net.TCPAddr))) {
			t.Fatal("a second holder of the live gateway's listener read as a restart")
		}
	})
	// More than one holder of the accepted socket is no known peer.
	t.Run("connected socket held by two processes is unknown", func(t *testing.T) {
		pl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pl.Close()
		accepted := make(chan net.Conn, 1)
		go func() { c, _ := pl.Accept(); accepted <- c }()
		c, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		sc := <-accepted
		if sc == nil {
			t.Fatal("no accepted connection")
		}
		defer sc.Close()
		f, err := sc.(*net.TCPConn).File()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		startHoldHelper(t, f)
		if pid, ok := perUserConnectedPeerPID(c.LocalAddr().(*net.TCPAddr), c.RemoteAddr().(*net.TCPAddr)); ok {
			t.Fatalf("connected peer = %d, want unknown with two holders", pid)
		}
	})
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

// TestPerUserGatewayStartInProgressDoesNotWaitOnAFIFO pins the O_NONBLOCK
// open of the start lock (review r4): a FIFO in the lock's place, which an
// open without O_NONBLOCK waits on until a writer appears, is no start and
// is answered at once.
func TestPerUserGatewayStartInProgressDoesNotWaitOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, perUserGatewayStartLockName)
	if err := syscall.Mkfifo(lock, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Frees a reader still waiting in the open (the old behavior).
		if f, err := os.OpenFile(lock, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	got := make(chan bool, 1)
	go func() { got <- PerUserGatewayStartInProgress(dir) }()
	select {
	case held := <-got:
		if held {
			t.Fatal("a FIFO in the start lock's place read as a start")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the look at the start lock waited on a FIFO")
	}
}
