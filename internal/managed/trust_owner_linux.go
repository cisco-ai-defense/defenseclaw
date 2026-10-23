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
	if os.Getenv("DEFENSECLAW_TRACKED_HOST_STAT_FD") != "5" {
		// An overflow UID can equal the service UID. Never trust it without
		// the launcher's host-inode evidence.
		return unknown
	}
	if os.Getppid() != 1 || len(path) == 0 || len(path) > 4096 {
		return unknown
	}
	// The peer is the launcher outside the scanner's PID namespace. The
	// kernel reports that peer as PID 0 from inside the scanner. A daemon
	// reparented to host PID 1 must never write to an incidental fd 5.
	peer, err := unix.GetsockoptUcred(5, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || peer.Pid != 0 {
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
