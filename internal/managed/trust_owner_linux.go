// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package managed

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var trackedHostStatMu sync.Mutex

// hostOwnerUID recovers a managed file's host owner when a tracked scanner's
// user namespace reports the unmapped UID 65534. The trusted launcher checks
// the same inode outside that namespace. A missing, stale or mismatched reply
// uses an impossible owner UID, so even a service running as UID 65534 refuses.
func hostOwnerUID(path string, info os.FileInfo, mapped uint32) uint32 {
	if mapped != 65534 {
		return mapped
	}
	unknown := ^uint32(0)
	// An overflow UID can equal the service UID. Never trust it without the
	// launcher's host-inode evidence.
	if len(path) == 0 || len(path) > 4096 || !trackedHostStatChannel() {
		return unknown
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return unknown
	}
	var request [4096 + 26]byte
	binary.BigEndian.PutUint64(request[0:8], uint64(stat.Dev))
	binary.BigEndian.PutUint64(request[8:16], stat.Ino)
	if _, err := rand.Read(request[16:24]); err != nil {
		return unknown
	}
	binary.BigEndian.PutUint16(request[24:26], uint16(len(path)))
	copy(request[26:], path)
	trackedHostStatMu.Lock()
	defer trackedHostStatMu.Unlock()
	deadline := &unix.Timeval{Sec: 2}
	if unix.SetsockoptTimeval(5, unix.SOL_SOCKET, unix.SO_SNDTIMEO, deadline) != nil ||
		unix.SetsockoptTimeval(5, unix.SOL_SOCKET, unix.SO_RCVTIMEO, deadline) != nil {
		return unknown
	}
	if n, err := unix.SendmsgN(5, request[:26+len(path)], nil, nil, unix.MSG_NOSIGNAL); err != nil || n != 26+len(path) {
		return unknown
	}
	events := []unix.PollFd{{Fd: 5, Events: unix.POLLIN}}
	if n, err := unix.Poll(events, 2000); err != nil || n != 1 || events[0].Revents&unix.POLLIN == 0 {
		return unknown
	}
	var response [12]byte
	n, _, err := unix.Recvfrom(5, response[:], 0)
	if err != nil || n != len(response) || !bytes.Equal(response[:8], request[16:24]) {
		return unknown
	}
	uid := binary.BigEndian.Uint32(response[8:])
	if uid == ^uint32(0) {
		return unknown
	}
	return uid
}

// trackedHostStatChannel reports whether fd 5 is the scanner launcher's
// channel. The environment variable only names the descriptor; the process
// and the socket must prove it. This process runs below the scanner (its
// parent is the scanner's PID 1) in a PID namespace other than the host's,
// and fd 5 is a connected AF_UNIX SOCK_SEQPACKET socket whose peer runs as
// this user outside that namespace, so the kernel reports the peer's PID as 0.
// A host daemon reparented to PID 1, and every other socket on fd 5 (TCP, UDP,
// a stream or a socketpair of its own), fails before a request is sent.
func trackedHostStatChannel() bool {
	if os.Getenv("DEFENSECLAW_TRACKED_HOST_STAT_FD") != "5" || os.Getppid() != 1 || !inChildPIDNamespace() {
		return false
	}
	return hostStatPeerIsLauncher(5)
}

func hostStatPeerIsLauncher(fd int) bool {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil || domain != unix.AF_UNIX {
		return false
	}
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_SEQPACKET {
		return false
	}
	peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	return err == nil && peer.Pid == 0 &&
		peer.Uid == uint32(os.Geteuid()) && peer.Gid == uint32(os.Getegid())
}

// inChildPIDNamespace reports whether this process has a PID in more than one
// namespace, that is, it does not run in the host's PID namespace.
func inChildPIDNamespace() bool {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if ids, ok := strings.CutPrefix(line, "NSpid:"); ok {
			return len(strings.Fields(ids)) > 1
		}
	}
	return false
}
