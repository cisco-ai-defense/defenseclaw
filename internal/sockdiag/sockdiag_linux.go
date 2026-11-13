// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package sockdiag finds one TCP socket of this network namespace by its exact
// four-tuple with a single NETLINK_SOCK_DIAG request (inet_diag,
// SOCK_DIAG_BY_FAMILY without NLM_F_DUMP), the kernel hash lookup that ss -K
// and the socket-destroy path use. It replaces a read of every row of
// /proc/self/net/tcp{,6}, whose cost grows with the sockets of the host, by a
// constant-time lookup that reports the same owner (sock_i_uid) and inode
// (sock_i_ino) the procfs row prints.
//
// A caller takes only a positive answer as fact: an ESTABLISHED socket whose
// family, ports and addresses are exactly the ones asked for, in the one
// message the kernel sent for this request. Every other outcome (no such
// socket, a listener or TIME_WAIT entry the kernel's lookup fell back to,
// netlink unavailable, a refused request, a short, truncated, foreign or
// extra message) is an error, and the caller reads the procfs table as it
// did before.
package sockdiag

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Socket is the owner and inode of one socket as the kernel reports them.
// Inode 0 is a socket that has no file yet (accept() has not run).
type Socket struct {
	UID   uint32
	Inode uint32
}

// ErrNoExactMatch is a well-formed kernel answer that names no ESTABLISHED
// socket with exactly the asked tuple.
var ErrNoExactMatch = errors.New("sockdiag: no established socket with this exact tuple")

const (
	tcpEstablished = 1
	// sizeofSockID is struct inet_diag_sockid: sport, dport, src[4], dst[4],
	// if, cookie[2].
	sizeofSockID = 2 + 2 + 16 + 16 + 4 + 8
	// sizeofReqV2 is struct inet_diag_req_v2.
	sizeofReqV2 = 8 + sizeofSockID
	// sizeofMsg is struct inet_diag_msg: family, state, timer, retrans, id,
	// expires, rqueue, wqueue, uid, inode.
	sizeofMsg = 4 + sizeofSockID + 5*4
	// recvTimeout bounds the receive. The kernel answers a non-dump request
	// inside sendto (sock_diag_rcv runs synchronously), so the reply is
	// queued before the receive starts; the bound only guards that.
	recvTimeout = 250 * time.Millisecond
)

var seq atomic.Uint32

// EstablishedTCP returns the owner and inode of the ESTABLISHED TCP socket
// whose local end is local and whose remote end is remote. An IPv4 tuple
// (including an IPv4-mapped IPv6 one) also finds the accepted socket of a
// dual-stack IPv6 listener, which the kernel hashes by its IPv4 addresses.
func EstablishedTCP(local, remote *net.TCPAddr) (Socket, error) {
	family, src, dst, err := tuple(local, remote)
	if err != nil {
		return Socket{}, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return Socket{}, fmt.Errorf("sockdiag: socket: %w", err)
	}
	defer unix.Close(fd)
	tv := unix.NsecToTimeval(recvTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return Socket{}, fmt.Errorf("sockdiag: receive timeout: %w", err)
	}
	number := seq.Add(1)
	request := encodeRequest(number, family, local.Port, remote.Port, src, dst)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return Socket{}, fmt.Errorf("sockdiag: send: %w", err)
	}
	buf := make([]byte, 8192)
	n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, 0)
	if err != nil {
		return Socket{}, fmt.Errorf("sockdiag: receive: %w", err)
	}
	if flags&unix.MSG_TRUNC != 0 {
		return Socket{}, errors.New("sockdiag: truncated reply")
	}
	if sender, ok := from.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
		return Socket{}, errors.New("sockdiag: reply not from the kernel")
	}
	return decodeReply(buf[:n], number, family, local.Port, remote.Port, src, dst)
}

// tuple is the request family and the 16-byte source (local) and destination
// (remote) address fields of an exact lookup.
func tuple(local, remote *net.TCPAddr) (uint8, [16]byte, [16]byte, error) {
	var src, dst [16]byte
	if local == nil || remote == nil || local.Port < 1 || local.Port > 65535 || remote.Port < 1 || remote.Port > 65535 {
		return 0, src, dst, errors.New("sockdiag: invalid endpoint")
	}
	l4, r4 := local.IP.To4(), remote.IP.To4()
	switch {
	case l4 != nil && r4 != nil:
		copy(src[:4], l4)
		copy(dst[:4], r4)
		return unix.AF_INET, src, dst, nil
	case l4 == nil && r4 == nil && len(local.IP.To16()) == net.IPv6len && len(remote.IP.To16()) == net.IPv6len:
		copy(src[:], local.IP.To16())
		copy(dst[:], remote.IP.To16())
		return unix.AF_INET6, src, dst, nil
	}
	return 0, src, dst, errors.New("sockdiag: endpoints of different address families")
}

func encodeRequest(number uint32, family uint8, sport, dport int, src, dst [16]byte) []byte {
	b := make([]byte, unix.SizeofNlMsghdr+sizeofReqV2)
	ne := binary.NativeEndian
	ne.PutUint32(b[0:], uint32(len(b)))
	ne.PutUint16(b[4:], unix.SOCK_DIAG_BY_FAMILY)
	ne.PutUint16(b[6:], unix.NLM_F_REQUEST)
	ne.PutUint32(b[8:], number)
	ne.PutUint32(b[12:], 0)
	r := b[unix.SizeofNlMsghdr:]
	r[0] = family
	r[1] = unix.IPPROTO_TCP
	r[2] = 0 // no extensions
	ne.PutUint32(r[4:], 1<<tcpEstablished)
	putSockID(r[8:], sport, dport, src, dst)
	return b
}

// putSockID writes struct inet_diag_sockid with no interface and no cookie
// (INET_DIAG_NOCOOKIE), so the lookup is by tuple alone.
func putSockID(id []byte, sport, dport int, src, dst [16]byte) {
	binary.BigEndian.PutUint16(id[0:], uint16(sport))
	binary.BigEndian.PutUint16(id[2:], uint16(dport))
	copy(id[4:20], src[:])
	copy(id[20:36], dst[:])
	binary.NativeEndian.PutUint32(id[36:], 0)
	binary.NativeEndian.PutUint32(id[40:], ^uint32(0))
	binary.NativeEndian.PutUint32(id[44:], ^uint32(0))
}

// v4Mapped is the IPv4-mapped IPv6 form of the IPv4 address in the first four
// bytes of a.
func v4Mapped(a [16]byte) [16]byte {
	var m [16]byte
	m[10], m[11] = 0xff, 0xff
	copy(m[12:], a[:4])
	return m
}

func decodeReply(reply []byte, number uint32, family uint8, sport, dport int, src, dst [16]byte) (Socket, error) {
	ne := binary.NativeEndian
	// Exactly one message: its length covers the whole datagram, up to the
	// 4-byte alignment of a netlink message.
	if len(reply) < unix.SizeofNlMsghdr {
		return Socket{}, errors.New("sockdiag: short reply")
	}
	length := int(ne.Uint32(reply[0:4]))
	if length < unix.SizeofNlMsghdr || length > len(reply) || (length+3)&^3 < len(reply) {
		return Socket{}, errors.New("sockdiag: reply is not exactly one message")
	}
	kind, msgFlags, msgSeq := ne.Uint16(reply[4:6]), ne.Uint16(reply[6:8]), ne.Uint32(reply[8:12])
	data := reply[unix.SizeofNlMsghdr:length]
	if msgSeq != number {
		return Socket{}, errors.New("sockdiag: reply to another request")
	}
	switch kind {
	case unix.NLMSG_ERROR:
		if len(data) < 4 {
			return Socket{}, errors.New("sockdiag: short error reply")
		}
		code := int32(ne.Uint32(data[0:4]))
		if code == 0 {
			return Socket{}, errors.New("sockdiag: acknowledgement without an answer")
		}
		return Socket{}, fmt.Errorf("sockdiag: request refused: %w", unix.Errno(-code))
	case unix.SOCK_DIAG_BY_FAMILY:
	default:
		return Socket{}, fmt.Errorf("sockdiag: unexpected reply type %d", kind)
	}
	if msgFlags&unix.NLM_F_MULTI != 0 {
		return Socket{}, errors.New("sockdiag: multipart reply to an exact request")
	}
	d := data
	if len(d) < sizeofMsg {
		return Socket{}, errors.New("sockdiag: short reply")
	}
	id := d[4 : 4+sizeofSockID]
	gotFamily, state := d[0], d[1]
	if state != tcpEstablished ||
		int(binary.BigEndian.Uint16(id[0:])) != sport || int(binary.BigEndian.Uint16(id[2:])) != dport {
		return Socket{}, ErrNoExactMatch
	}
	gotSrc, gotDst := id[4:20], id[20:36]
	switch {
	case gotFamily == family && bytes.Equal(gotSrc, src[:]) && bytes.Equal(gotDst, dst[:]):
	case family == unix.AF_INET && gotFamily == unix.AF_INET6:
		// The accepted socket of a dual-stack IPv6 listener.
		ms, md := v4Mapped(src), v4Mapped(dst)
		if !bytes.Equal(gotSrc, ms[:]) || !bytes.Equal(gotDst, md[:]) {
			return Socket{}, ErrNoExactMatch
		}
	default:
		return Socket{}, ErrNoExactMatch
	}
	tail := d[4+sizeofSockID:]
	return Socket{UID: ne.Uint32(tail[12:16]), Inode: ne.Uint32(tail[16:20])}, nil
}
