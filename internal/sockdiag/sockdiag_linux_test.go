// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sockdiag

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fdInode(t *testing.T, conn net.Conn) uint32 {
	t.Helper()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	var statErr error
	if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &st) }); err != nil {
		t.Fatal(err)
	}
	if statErr != nil {
		t.Fatal(statErr)
	}
	return uint32(st.Ino)
}

// procRow is the uid and inode of the row of table whose local and remote
// addresses are local and remote, as /proc/self/net prints it.
func procRow(t *testing.T, table string, local, remote string) (uint32, uint32, bool) {
	t.Helper()
	f, err := os.Open("/proc/self/net/" + table)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan()
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 10 || fields[3] != "01" || !strings.EqualFold(fields[1], local) || !strings.EqualFold(fields[2], remote) {
			continue
		}
		uid, _ := strconv.ParseUint(fields[7], 10, 32)
		inode, _ := strconv.ParseUint(fields[9], 10, 32)
		return uint32(uid), uint32(inode), true
	}
	return 0, 0, false
}

func procKey(addr *net.TCPAddr, mapped bool) string {
	ip := addr.IP.To16()
	if v4 := addr.IP.To4(); v4 != nil && !mapped {
		ip = v4
	} else if v4 != nil {
		ip = make(net.IP, 16)
		ip[10], ip[11] = 0xff, 0xff
		copy(ip[12:], v4)
	}
	var b strings.Builder
	for off := 0; off < len(ip); off += 4 {
		for i := off + 3; i >= off; i-- {
			fmt.Fprintf(&b, "%02X", ip[i])
		}
	}
	return fmt.Sprintf("%s:%04X", b.String(), addr.Port)
}

type pair struct {
	listener       net.Listener
	client, server net.Conn
}

func connect(t *testing.T, listenNet, listenAddr, dialNet string, accept bool) pair {
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
	client, err := net.Dial(dialNet, target)
	if err != nil {
		t.Skipf("dial %s %s: %v", dialNet, target, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	p := pair{listener: ln, client: client}
	if accept {
		server, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		p.server = server
	}
	return p
}

// waitEstablished waits until the kernel lists the server end, which the
// handshake can finish a moment after connect returns.
func waitEstablished(t *testing.T, local, remote *net.TCPAddr) Socket {
	t.Helper()
	var last error
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		sock, err := EstablishedTCP(local, remote)
		if err == nil {
			return sock
		}
		last = err
	}
	t.Fatalf("no exact answer for %v <- %v: %v", local, remote, last)
	return Socket{}
}

func TestEstablishedTCPMatchesProcfsAndFile(t *testing.T) {
	cases := []struct {
		name, listenNet, listenAddr, dialNet, table string
		mapped                                      bool
	}{
		{"ipv4", "tcp4", "127.0.0.1:0", "tcp4", "tcp", false},
		{"ipv6", "tcp6", "[::1]:0", "tcp6", "tcp6", false},
		{"dual-stack listener, ipv4 client", "tcp", "[::]:0", "tcp4", "tcp6", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := connect(t, tc.listenNet, tc.listenAddr, tc.dialNet, true)
			client := p.client.LocalAddr().(*net.TCPAddr)
			server := p.client.RemoteAddr().(*net.TCPAddr)
			sock := waitEstablished(t, server, client)
			if sock.UID != uint32(os.Geteuid()) {
				t.Errorf("uid %d, want %d", sock.UID, os.Geteuid())
			}
			if want := fdInode(t, p.server); sock.Inode != want {
				t.Errorf("inode %d, accepted descriptor has %d", sock.Inode, want)
			}
			uid, inode, ok := procRow(t, tc.table, procKey(server, tc.mapped), procKey(client, tc.mapped))
			if !ok || uid != sock.UID || inode != sock.Inode {
				t.Errorf("procfs row uid=%d inode=%d found=%v, netlink uid=%d inode=%d", uid, inode, ok, sock.UID, sock.Inode)
			}
			// The client end is found too, with the client's own inode.
			if own, err := EstablishedTCP(client, server); err != nil || own.Inode != fdInode(t, p.client) {
				t.Errorf("client end: %+v, %v", own, err)
			}
		})
	}
}

func TestEstablishedTCPUnacceptedHasNoInode(t *testing.T) {
	p := connect(t, "tcp4", "127.0.0.1:0", "tcp4", false)
	client := p.client.LocalAddr().(*net.TCPAddr)
	server := p.client.RemoteAddr().(*net.TCPAddr)
	sock := waitEstablished(t, server, client)
	if sock.Inode != 0 {
		t.Fatalf("unaccepted socket has inode %d", sock.Inode)
	}
	if _, inode, ok := procRow(t, "tcp", procKey(server, false), procKey(client, false)); !ok || inode != 0 {
		t.Fatalf("procfs row inode=%d found=%v", inode, ok)
	}
}

// A tuple whose server end has closed is no answer, even while the kernel's
// lookup can fall back to the listener on the port or to a TIME_WAIT entry.
func TestEstablishedTCPClosedServerEndIsNoMatch(t *testing.T) {
	p := connect(t, "tcp4", "127.0.0.1:0", "tcp4", true)
	client := p.client.LocalAddr().(*net.TCPAddr)
	server := p.client.RemoteAddr().(*net.TCPAddr)
	waitEstablished(t, server, client)
	_ = p.server.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := EstablishedTCP(server, client)
		if err != nil {
			if !errors.Is(err, ErrNoExactMatch) && !errors.Is(err, unix.ENOENT) {
				t.Fatalf("closed server end: %v", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed server end still found as ESTABLISHED")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = p.listener.Close()
	_ = p.client.Close()
	if _, err := EstablishedTCP(server, client); err == nil {
		t.Fatal("closed connection found")
	}
}

func TestEstablishedTCPUnknownTupleIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	_, err = EstablishedTCP(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	if err == nil {
		t.Fatal("a tuple with no socket was found")
	}
	if _, err := EstablishedTCP(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}, &net.TCPAddr{IP: net.IPv6loopback, Port: 80}); err == nil {
		t.Fatal("mixed families accepted")
	}
	if _, err := EstablishedTCP(nil, nil); err == nil {
		t.Fatal("nil endpoints accepted")
	}
}

// reply builds one kernel answer to request number for the IPv4 tuple.
func reply(number uint32, kind uint16, flags uint16, family, state uint8, sport, dport int, src, dst [16]byte, uid, inode uint32) []byte {
	ne := binary.NativeEndian
	b := make([]byte, unix.SizeofNlMsghdr+sizeofMsg+8)
	ne.PutUint32(b[0:], uint32(len(b)))
	ne.PutUint16(b[4:], kind)
	ne.PutUint16(b[6:], flags)
	ne.PutUint32(b[8:], number)
	d := b[unix.SizeofNlMsghdr:]
	d[0], d[1] = family, state
	putSockID(d[4:], sport, dport, src, dst)
	tail := d[4+sizeofSockID:]
	ne.PutUint32(tail[12:], uid)
	ne.PutUint32(tail[16:], inode)
	return b
}

func TestDecodeReplyTakesOnlyAnExactAnswer(t *testing.T) {
	var src, dst [16]byte
	copy(src[:4], []byte{127, 0, 0, 1})
	copy(dst[:4], []byte{127, 0, 0, 2})
	good := reply(7, unix.SOCK_DIAG_BY_FAMILY, 0, unix.AF_INET, tcpEstablished, 9000, 40000, src, dst, 1000, 42)
	if sock, err := decodeReply(good, 7, unix.AF_INET, 9000, 40000, src, dst); err != nil || sock != (Socket{UID: 1000, Inode: 42}) {
		t.Fatalf("exact answer: %+v, %v", sock, err)
	}
	mapped := reply(7, unix.SOCK_DIAG_BY_FAMILY, 0, unix.AF_INET6, tcpEstablished, 9000, 40000, v4Mapped(src), v4Mapped(dst), 1000, 42)
	if _, err := decodeReply(mapped, 7, unix.AF_INET, 9000, 40000, src, dst); err != nil {
		t.Fatalf("dual-stack answer: %v", err)
	}
	errReply := make([]byte, unix.SizeofNlMsghdr+4+unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(errReply[0:], uint32(len(errReply)))
	binary.NativeEndian.PutUint16(errReply[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint32(errReply[8:], 7)
	code := -int32(unix.ENOENT)
	binary.NativeEndian.PutUint32(errReply[16:], uint32(code))
	ack := append([]byte(nil), errReply...)
	binary.NativeEndian.PutUint32(ack[16:], 0)
	other := dst
	other[3] = 9
	bad := map[string][]byte{
		"listener fallback": reply(7, unix.SOCK_DIAG_BY_FAMILY, 0, unix.AF_INET, 10, 9000, 0, src, [16]byte{}, 1000, 42),
		"time wait":         reply(7, unix.SOCK_DIAG_BY_FAMILY, 0, unix.AF_INET, 6, 9000, 40000, src, dst, 0, 0),
		"other peer":        reply(7, unix.SOCK_DIAG_BY_FAMILY, 0, unix.AF_INET, tcpEstablished, 9000, 40000, src, other, 1000, 42),
		"other port":        reply(7, unix.SOCK_DIAG_BY_FAMILY, 0, unix.AF_INET, tcpEstablished, 9000, 40001, src, dst, 1000, 42),
		"other request":     reply(8, unix.SOCK_DIAG_BY_FAMILY, 0, unix.AF_INET, tcpEstablished, 9000, 40000, src, dst, 1000, 42),
		"multipart":         reply(7, unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_MULTI, unix.AF_INET, tcpEstablished, 9000, 40000, src, dst, 1000, 42),
		"wrong family":      reply(7, unix.SOCK_DIAG_BY_FAMILY, 0, unix.AF_INET6, tcpEstablished, 9000, 40000, src, dst, 1000, 42),
		"wrong type":        reply(7, unix.NLMSG_DONE, 0, unix.AF_INET, tcpEstablished, 9000, 40000, src, dst, 1000, 42),
		"two messages":      append(append([]byte(nil), good...), good...),
		"truncated":         good[:len(good)-30],
		"short header":      good[:8],
		"error":             errReply,
		"bare ack":          ack,
	}
	for name, b := range bad {
		if sock, err := decodeReply(b, 7, unix.AF_INET, 9000, 40000, src, dst); err == nil {
			t.Errorf("%s: accepted as %+v", name, sock)
		}
	}
	if _, err := decodeReply(errReply, 7, unix.AF_INET, 9000, 40000, src, dst); !errors.Is(err, unix.ENOENT) {
		t.Errorf("error reply: %v", err)
	}
}
