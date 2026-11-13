// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sockdiag"
	"golang.org/x/sys/unix"
)

// The connected-peer proof reads the server end of its connection with the
// kernel's exact netlink lookup (exactAcceptedSocket) and reads the procfs
// tables only when that lookup gives no exact answer. These tests hold the
// two reads to one answer on the same live sockets: the same owner, the same
// inode, the same not-accepted and not-found results, the same refusal of
// another account and the same proof outcome.

type peerLookup struct {
	uid int
	err error
}

// bothLookups is findConnectedTCPUID on the live tables with the netlink
// lookup, then with the lookup failing (the procfs scan alone).
func bothLookups(t *testing.T, client, server *net.TCPAddr) (exact, scan peerLookup) {
	t.Helper()
	uid, err := findConnectedTCPUID(procSelfNet, client, server)
	exact = peerLookup{uid, err}
	withoutNetlink(t, func() {
		uid, err := findConnectedTCPUID(procSelfNet, client, server)
		scan = peerLookup{uid, err}
	})
	return exact, scan
}

func withoutNetlink(t *testing.T, run func()) {
	t.Helper()
	saved := exactEstablishedTCP
	exactEstablishedTCP = func(*net.TCPAddr, *net.TCPAddr) (sockdiag.Socket, error) {
		return sockdiag.Socket{}, errors.New("netlink unavailable (test)")
	}
	defer func() { exactEstablishedTCP = saved }()
	run()
}

func sameLookup(a, b peerLookup) bool {
	if a.uid != b.uid {
		return false
	}
	if a.err == nil || b.err == nil {
		return a.err == nil && b.err == nil
	}
	return errors.Is(a.err, errConnectedSocketNotAccepted) == errors.Is(b.err, errConnectedSocketNotAccepted) &&
		errors.Is(a.err, errConnectedSocketNotFound) == errors.Is(b.err, errConnectedSocketNotFound)
}

func socketInode(t *testing.T, conn net.Conn) uint32 {
	t.Helper()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	var statErr error
	if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &st) }); err != nil || statErr != nil {
		t.Fatal(err, statErr)
	}
	return uint32(st.Ino)
}

func dialPair(t *testing.T, listenNet, listenAddr, dialNet string, accept bool) (client, server *net.TCPAddr, accepted net.Conn, ln net.Listener, conn net.Conn) {
	t.Helper()
	ln, err := net.Listen(listenNet, listenAddr)
	if err != nil {
		t.Skipf("listen %s %s: %v", listenNet, listenAddr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	target := ln.Addr().String()
	if dialNet == "tcp4" {
		target = net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	}
	conn, err = net.Dial(dialNet, target)
	if err != nil {
		t.Skipf("dial %s: %v", target, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if accept {
		if accepted, err = ln.Accept(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = accepted.Close() })
	}
	return conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr), accepted, ln, conn
}

// settle waits for the kernel to list the server end of the tuple.
func settle(t *testing.T, client, server *net.TCPAddr) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if _, ok := exactAcceptedSocket(client, server); ok {
			return
		}
	}
	t.Fatalf("server end of %v -> %v never listed", client, server)
}

func TestExactPeerLookupMatchesProcScanOnLiveSockets(t *testing.T) {
	self := os.Geteuid()
	for _, tc := range []struct{ name, listenNet, listenAddr, dialNet string }{
		{"ipv4", "tcp4", "127.0.0.1:0", "tcp4"},
		{"ipv6", "tcp6", "[::1]:0", "tcp6"},
		{"dual-stack listener, ipv4 client", "tcp", "[::]:0", "tcp4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, accepted, _, _ := dialPair(t, tc.listenNet, tc.listenAddr, tc.dialNet, true)
			settle(t, client, server)
			sock, ok := exactAcceptedSocket(client, server)
			if !ok {
				t.Fatal("netlink gave no exact answer for an accepted socket")
			}
			if want := socketInode(t, accepted); sock.Inode != want {
				t.Fatalf("netlink inode %d, accepted descriptor %d", sock.Inode, want)
			}
			exact, scan := bothLookups(t, client, server)
			if exact.err != nil || exact.uid != self || !sameLookup(exact, scan) {
				t.Fatalf("netlink %+v, procfs scan %+v, want uid %d", exact, scan, self)
			}
			// The capture of the peer process reads the same inode both
			// ways: this test process is the sole holder.
			pid, unique := perUserConnectedPeerPID(client, server)
			var scanPID int
			var scanUnique bool
			withoutNetlink(t, func() { scanPID, scanUnique = perUserConnectedPeerPID(client, server) })
			if !unique || pid != os.Getpid() || pid != scanPID || unique != scanUnique {
				t.Fatalf("peer pid netlink (%d,%v), scan (%d,%v), want %d", pid, unique, scanPID, scanUnique, os.Getpid())
			}
			// Proof outcome: this account's accepted socket is proven.
			if err := verifyPerUserConnectedTupleIn(procSelfNet, self, time.Second, client, server); err != nil {
				t.Fatalf("own accepted socket not proven: %v", err)
			}
		})
	}
}

func TestExactPeerLookupUnacceptedAndClosedMatchProcScan(t *testing.T) {
	t.Run("not accepted", func(t *testing.T) {
		client, server, _, _, _ := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", false)
		settle(t, client, server)
		exact, scan := bothLookups(t, client, server)
		if !errors.Is(exact.err, errConnectedSocketNotAccepted) || !sameLookup(exact, scan) {
			t.Fatalf("netlink %+v, procfs scan %+v", exact, scan)
		}
		err := verifyPerUserConnectedTupleIn(procSelfNet, os.Geteuid(), 150*time.Millisecond, client, server)
		if !errors.Is(err, errPerUserNotAccepted) {
			t.Fatalf("unaccepted socket: %v", err)
		}
	})
	t.Run("closed between connect and lookup", func(t *testing.T) {
		client, server, accepted, ln, _ := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", true)
		settle(t, client, server)
		_ = accepted.Close()
		// The kernel lookup now falls back to the listener still on the
		// port, then to the closing entry: neither is the accepted socket.
		var exact, scan peerLookup
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			exact, scan = bothLookups(t, client, server)
			if exact.err != nil || time.Now().After(deadline) {
				break
			}
		}
		if !errors.Is(exact.err, errConnectedSocketNotFound) || !sameLookup(exact, scan) {
			t.Fatalf("closed server end: netlink %+v, procfs scan %+v", exact, scan)
		}
		if err := verifyPerUserConnectedTupleIn(procSelfNet, os.Geteuid(), 150*time.Millisecond, client, server); err == nil {
			t.Fatal("closed server end proven")
		}
		_ = ln.Close()
		exact, scan = bothLookups(t, client, server)
		if exact.err == nil || !sameLookup(exact, scan) {
			t.Fatalf("closed listener: netlink %+v, procfs scan %+v", exact, scan)
		}
	})
}

// Any netlink outcome that is not an exact answer reads the procfs tables,
// so the proof is the one it was before the lookup existed.
func TestExactPeerLookupFallsBackToProcScan(t *testing.T) {
	client, server, _, _, _ := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", true)
	settle(t, client, server)
	saved := exactEstablishedTCP
	t.Cleanup(func() { exactEstablishedTCP = saved })
	calls := 0
	for _, failure := range []error{
		errors.New("netlink socket refused"),
		fmt.Errorf("sockdiag: request refused: %w", unix.EPERM),
		errors.New("sockdiag: truncated reply"),
		errors.New("sockdiag: 2 messages in the reply, want 1"),
		sockdiag.ErrNoExactMatch,
	} {
		exactEstablishedTCP = func(*net.TCPAddr, *net.TCPAddr) (sockdiag.Socket, error) {
			calls++
			return sockdiag.Socket{}, failure
		}
		uid, err := findConnectedTCPUID(procSelfNet, client, server)
		if err != nil || uid != os.Geteuid() {
			t.Fatalf("%v: fallback gave uid=%d err=%v", failure, uid, err)
		}
		// A fallback whose tables cannot be read fails as before.
		if _, err := findConnectedTCPUID(filepath.Join(t.TempDir(), "missing"), client, server); err == nil {
			t.Fatalf("%v: unreadable tables proved the peer", failure)
		}
	}
	if calls != 5 {
		t.Fatalf("netlink lookup ran %d times, want 5 (fake tables never use it)", calls)
	}
	// Fake tables (tests, other namespaces) never use the live lookup.
	exactEstablishedTCP = func(*net.TCPAddr, *net.TCPAddr) (sockdiag.Socket, error) {
		t.Fatal("netlink lookup used for a procfs folder that is not the live one")
		return sockdiag.Socket{}, nil
	}
	_, _ = findConnectedTCPUID(t.TempDir(), client, server)
}

const exactPeerForeignEnv = "DC_TEST_EXACT_PEER_FOREIGN"

// The second account accepts the connection and holds it, then exits when
// told: the hook's lookups must name that account as the owner (refused),
// both ways, and find nothing once the holder has gone (refused).
func TestExactPeerLookupRefusesAnotherAccountAndExitedHolder(t *testing.T) {
	if os.Getenv(exactPeerForeignEnv) == "1" {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("ADDR=%s\n", ln.Addr())
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("ACCEPTED pid=%d\n", os.Getpid())
		_, _ = io.Copy(io.Discard, os.Stdin) // hold until told
		_ = conn.Close()
		_ = ln.Close()
		return
	}
	if err := exec.Command("sudo", "-n", "-u", "nobody", "true").Run(); err != nil {
		t.Skipf("passwordless second-account execution is unavailable: %v", err)
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip(err)
	}
	foreignUID, _ := strconv.Atoi(nobody.Uid)
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "defenseclaw-exact-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	_ = os.Chmod(root, 0o755)
	copyPath := filepath.Join(root, "hookexec.test")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "-u", "nobody", "/usr/bin/env", exactPeerForeignEnv+"=1",
		copyPath, "-test.run=^TestExactPeerLookupRefusesAnotherAccountAndExitedHolder$")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() || !strings.HasPrefix(lines.Text(), "ADDR=") {
		t.Fatalf("second-account listener did not start: %q", lines.Text())
	}
	conn, err := net.Dial("tcp4", strings.TrimPrefix(lines.Text(), "ADDR="))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !lines.Scan() || !strings.HasPrefix(lines.Text(), "ACCEPTED") {
		t.Fatalf("second account did not accept: %q", lines.Text())
	}
	client, server := conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr)
	exact, scan := bothLookups(t, client, server)
	if exact.err != nil || exact.uid != foreignUID || !sameLookup(exact, scan) {
		t.Fatalf("foreign accepted socket: netlink %+v, procfs scan %+v, want uid %d", exact, scan, foreignUID)
	}
	if _, ok := exactAcceptedSocket(client, server); !ok {
		t.Fatal("netlink gave no exact answer for the foreign socket")
	}
	self := os.Geteuid()
	err = verifyPerUserConnectedTupleIn(procSelfNet, self, time.Second, client, server)
	var scanErr error
	withoutNetlink(t, func() { scanErr = verifyPerUserConnectedTupleIn(procSelfNet, self, time.Second, client, server) })
	if err == nil || scanErr == nil || err.Error() != scanErr.Error() || !strings.Contains(err.Error(), "another account") {
		t.Fatalf("foreign socket: netlink proof %v, procfs proof %v", err, scanErr)
	}
	// The peer process of another account is never this account's peer.
	pid, unique := perUserConnectedPeerPID(client, server)
	var scanPID int
	var scanUnique bool
	withoutNetlink(t, func() { scanPID, scanUnique = perUserConnectedPeerPID(client, server) })
	if unique || pid != 0 || scanUnique || scanPID != 0 {
		t.Fatalf("foreign peer named: netlink (%d,%v), scan (%d,%v)", pid, unique, scanPID, scanUnique)
	}
	// The holder exits (its pid can now be reused by anyone): the server end
	// is gone and nothing is proven, both ways.
	_ = stdin.Close()
	_ = cmd.Wait()
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		exact, scan = bothLookups(t, client, server)
		if exact.err != nil || time.Now().After(deadline) {
			break
		}
	}
	if exact.err == nil || !sameLookup(exact, scan) {
		t.Fatalf("exited holder: netlink %+v, procfs scan %+v", exact, scan)
	}
	if err := verifyPerUserConnectedTupleIn(procSelfNet, self, 150*time.Millisecond, client, server); err == nil {
		t.Fatal("exited holder proven")
	}
}

// BenchmarkConnectedPeerLookup is the per-call cost of the peer proof's
// socket lookup with extra established loopback connections on the host:
// the netlink lookup stays flat, the procfs scan grows with the table.
func BenchmarkConnectedPeerLookup(b *testing.B) {
	for _, extra := range []int{0, 2000} {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		var held []net.Conn
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				held = append(held, c)
			}
		}()
		var dialed []net.Conn
		for i := 0; i < extra; i++ {
			c, err := net.Dial("tcp4", ln.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			dialed = append(dialed, c)
		}
		conn, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		client, server := conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr)
		time.Sleep(50 * time.Millisecond)
		b.Run(fmt.Sprintf("netlink/extra=%d", extra), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := findConnectedTCPUID(procSelfNet, client, server); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("procscan/extra=%d", extra), func(b *testing.B) {
			saved := exactEstablishedTCP
			exactEstablishedTCP = func(*net.TCPAddr, *net.TCPAddr) (sockdiag.Socket, error) {
				return sockdiag.Socket{}, errors.New("off")
			}
			defer func() { exactEstablishedTCP = saved }()
			for i := 0; i < b.N; i++ {
				if _, err := findConnectedTCPUID(procSelfNet, client, server); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("peerpid-walk/extra=%d", extra), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				perUserConnectedPeerPID(client, server)
			}
		})
		_ = conn.Close()
		for _, c := range dialed {
			_ = c.Close()
		}
		_ = ln.Close()
		for _, c := range held {
			_ = c.Close()
		}
	}
}
