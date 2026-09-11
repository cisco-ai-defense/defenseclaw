// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package plane

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// cn_proc protocol constants. These are the netlink connector's ABI and are
// not exported by golang.org/x/sys.
const (
	cnIdxProc = 1
	cnValProc = 1

	procCNMcastListen = 1

	procEventNone = 0x00000000
	procEventFork = 0x00000001
	procEventExec = 0x00000002
	procEventUID  = 0x00000004
	procEventGID  = 0x00000040
	procEventExit = 0x80000000
)

// cnMsg header sizes, in bytes, for the packed netlink payload.
const (
	nlMsgHdrLen  = 16
	cnMsgHdrLen  = 20
	procEventHdr = 16
)

// linuxSource is Plane C on Linux: cn_proc for process events, fanotify for
// file events.
//
// The two halves are started independently and either can fail alone. cn_proc
// is unprivileged in the host namespace; fanotify needs CAP_SYS_ADMIN. An
// unprivileged host therefore gets the process half with the file half
// honestly reported absent, which is strictly better than losing the whole
// plane to one missing capability.
type linuxSource struct {
	buffer *Buffer

	procFD     int
	fanotifyFD int

	coverage Coverage
	mu       sync.Mutex
	closed   bool
	wg       sync.WaitGroup

	// credentialRoots are the directories fanotify marks. Marking a whole
	// mount would deliver every open on the system, which on a build host is
	// millions of events a minute for no gain.
	credentialRoots []string
}

// NewSource returns the Linux Plane C source.
func NewSource(homeDirs []string) Source {
	return &linuxSource{buffer: NewBuffer(), credentialRoots: credentialRoots(homeDirs)}
}

// credentialRoots are the directories worth watching for credential access and
// agent-config persistence. Chosen narrowly on purpose: fanotify has no path
// filter, so every additional root is delivered events the classifier then has
// to discard.
func credentialRoots(homeDirs []string) []string {
	roots := make([]string, 0, len(homeDirs)*6+2)
	for _, home := range homeDirs {
		home = strings.TrimSpace(home)
		if home == "" {
			continue
		}
		for _, suffix := range []string{
			".aws", ".ssh", ".config/gcloud", ".kube", ".docker",
			".claude", ".codex", ".cursor", ".openclaw",
		} {
			roots = append(roots, filepath.Join(home, suffix))
		}
	}
	return append(roots, "/etc/shadow", "/etc/sudoers.d")
}

func (s *linuxSource) Events() <-chan Event { return s.buffer.Events() }
func (s *linuxSource) Coverage() Coverage   { return s.coverage }

func (s *linuxSource) Start(ctx context.Context) error {
	procErr := s.startProcessConnector()
	fanErr := s.startFanotify()

	if procErr != nil && fanErr != nil {
		// Neither half came up. That is a real failure rather than degraded
		// coverage, and the caller needs both reasons to fix it.
		return fmt.Errorf("plane: linux plane C unavailable: cn_proc: %v; fanotify: %v", procErr, fanErr)
	}

	coverage := Coverage{}
	switch {
	case procErr == nil && fanErr == nil:
		coverage.Mechanism = "netlink process connector (cn_proc) + fanotify"
		coverage.Kinds = []Kind{KindExec, KindExit, KindFileRead, KindFileWrite, KindPrivilege}
	case procErr == nil:
		coverage.Mechanism = "netlink process connector (cn_proc) only"
		coverage.Kinds = []Kind{KindExec, KindExit, KindPrivilege}
		coverage.MissingKinds = []Kind{KindFileRead, KindFileWrite}
		coverage.Limitations = []string{
			"file events need fanotify, which needs CAP_SYS_ADMIN: " + fanErr.Error(),
		}
	default:
		coverage.Mechanism = "fanotify only"
		coverage.Kinds = []Kind{KindFileRead, KindFileWrite}
		coverage.MissingKinds = []Kind{KindExec, KindExit, KindPrivilege}
		coverage.Limitations = []string{
			"process events need the netlink connector: " + procErr.Error(),
		}
	}
	s.coverage = coverage

	if procErr == nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.readProcessConnector(ctx) }()
	}
	if fanErr == nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.readFanotify(ctx) }()
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return nil
}

func (s *linuxSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	procFD, fanFD := s.procFD, s.fanotifyFD
	s.procFD, s.fanotifyFD = -1, -1
	s.mu.Unlock()

	// Closing the descriptors is what unblocks the readers.
	if procFD > 0 {
		_ = unix.Close(procFD)
	}
	if fanFD > 0 {
		_ = unix.Close(fanFD)
	}
	s.wg.Wait()
	s.buffer.Close()
	return nil
}

// startProcessConnector opens the cn_proc netlink socket and subscribes.
func (s *linuxSource) startProcessConnector() error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid()),
	}); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("bind: %w", err)
	}
	if err := unix.Sendto(fd, listenMessage(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("subscribe: %w", err)
	}
	s.procFD = fd
	return nil
}

// listenMessage builds the PROC_CN_MCAST_LISTEN request.
func listenMessage() []byte {
	const payload = cnMsgHdrLen + 4
	message := make([]byte, nlMsgHdrLen+payload)
	binary.LittleEndian.PutUint32(message[0:], uint32(len(message))) // nlmsg_len
	binary.LittleEndian.PutUint16(message[4:], unix.NLMSG_DONE)      // nlmsg_type
	binary.LittleEndian.PutUint16(message[6:], 0)                    // nlmsg_flags
	binary.LittleEndian.PutUint32(message[8:], 0)                    // nlmsg_seq
	binary.LittleEndian.PutUint32(message[12:], uint32(os.Getpid())) // nlmsg_pid

	body := message[nlMsgHdrLen:]
	binary.LittleEndian.PutUint32(body[0:], cnIdxProc) // cb_id.idx
	binary.LittleEndian.PutUint32(body[4:], cnValProc) // cb_id.val
	binary.LittleEndian.PutUint32(body[8:], 0)         // seq
	binary.LittleEndian.PutUint32(body[12:], 0)        // ack
	binary.LittleEndian.PutUint16(body[16:], 4)        // len
	binary.LittleEndian.PutUint16(body[18:], 0)        // flags
	binary.LittleEndian.PutUint32(body[20:], procCNMcastListen)
	return message
}

func (s *linuxSource) readProcessConnector(ctx context.Context) {
	buffer := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		fd := s.procFD
		s.mu.Unlock()
		if fd <= 0 {
			return
		}
		read, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			// EBADF is the ordinary shutdown path: Close() closed the socket
			// out from under this read.
			return
		}
		s.decodeProcessMessages(buffer[:read])
	}
}

// decodeProcessMessages walks the netlink messages in one datagram.
func (s *linuxSource) decodeProcessMessages(data []byte) {
	for len(data) >= nlMsgHdrLen {
		length := int(binary.LittleEndian.Uint32(data[0:]))
		if length < nlMsgHdrLen || length > len(data) {
			return
		}
		body := data[nlMsgHdrLen:length]
		if len(body) >= cnMsgHdrLen+procEventHdr {
			s.decodeProcessEvent(body[cnMsgHdrLen:])
		}
		// Netlink messages are 4-byte aligned.
		aligned := (length + 3) &^ 3
		if aligned >= len(data) {
			return
		}
		data = data[aligned:]
	}
}

// decodeProcessEvent decodes one proc_event.
//
// The layout is: what(u32) cpu(u32) timestamp_ns(u64) then a union. Only the
// members this sensor uses are read; every other `what` is skipped rather than
// guessed at.
func (s *linuxSource) decodeProcessEvent(body []byte) {
	if len(body) < procEventHdr {
		return
	}
	what := binary.LittleEndian.Uint32(body[0:])
	union := body[procEventHdr:]
	now := time.Now()

	switch what {
	case procEventNone:
		return
	case procEventExec:
		// exec_proc_event: process_pid(u32) process_tgid(u32)
		if len(union) < 8 {
			return
		}
		pid := int(binary.LittleEndian.Uint32(union[0:]))
		s.pushProcess(KindExec, pid, now)
	case procEventFork:
		// fork_proc_event: parent_pid parent_tgid child_pid child_tgid
		if len(union) < 16 {
			return
		}
		child := int(binary.LittleEndian.Uint32(union[8:]))
		s.pushProcess(KindExec, child, now)
	case procEventExit:
		if len(union) < 8 {
			return
		}
		pid := int(binary.LittleEndian.Uint32(union[0:]))
		s.buffer.Push(Event{Kind: KindExit, PID: pid, At: now})
	case procEventUID, procEventGID:
		// id_proc_event: process_pid process_tgid r{ruid|rgid} e{euid|egid}
		if len(union) < 16 {
			return
		}
		pid := int(binary.LittleEndian.Uint32(union[0:]))
		effective := binary.LittleEndian.Uint32(union[12:])
		kind, label := "uid", "euid"
		if what == procEventGID {
			kind, label = "gid", "egid"
		}
		event := s.describe(pid)
		event.Kind = KindPrivilege
		event.At = now
		event.Detail = fmt.Sprintf("%s change: %s=%d", kind, label, effective)
		s.buffer.Push(event)
	}
}

// pushProcess enriches a bare pid from /proc and queues it.
//
// The read races the process: a short-lived `cat` can exit before this runs.
// A partially-read event is still worth delivering -- the pid and the exec
// itself are the lineage fact -- so missing fields are left zero rather than
// dropping the event.
func (s *linuxSource) pushProcess(kind Kind, pid int, at time.Time) {
	event := s.describe(pid)
	event.Kind = kind
	event.At = at
	s.buffer.Push(event)
}

func (s *linuxSource) describe(pid int) Event {
	event := Event{PID: pid}
	base := filepath.Join("/proc", strconv.Itoa(pid))
	if raw, err := os.ReadFile(filepath.Join(base, "stat")); err == nil {
		if open, closeIdx := bytes.IndexByte(raw, '('), bytes.LastIndexByte(raw, ')'); open >= 0 && closeIdx > open {
			event.Name = string(raw[open+1 : closeIdx])
			if fields := strings.Fields(string(raw[closeIdx+1:])); len(fields) > 1 {
				event.PPID, _ = strconv.Atoi(fields[1])
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil && len(raw) > 0 {
		parts := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
		words := make([]string, 0, len(parts))
		for _, part := range parts {
			if len(part) > 0 {
				words = append(words, string(part))
			}
		}
		event.Cmdline = strings.Join(words, " ")
	}
	event.ResponsiblePID = event.PPID
	return event
}

// startFanotify opens a notification-class fanotify group and marks the
// credential roots.
func (s *linuxSource) startFanotify() error {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("fanotify_init: %w", err)
	}
	marked := 0
	for _, root := range s.credentialRoots {
		if _, statErr := os.Stat(root); statErr != nil {
			continue
		}
		// FAN_OPEN and the modify/close-write pair cover the read and write
		// halves. FAN_EVENT_ON_CHILD extends a directory mark to its entries,
		// which is what makes marking ~/.aws catch ~/.aws/credentials.
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD,
			unix.FAN_OPEN|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE|unix.FAN_EVENT_ON_CHILD,
			unix.AT_FDCWD, root); err != nil {
			continue
		}
		marked++
	}
	if marked == 0 {
		_ = unix.Close(fd)
		return fmt.Errorf("no credential root could be marked")
	}
	s.fanotifyFD = fd
	return nil
}

func (s *linuxSource) readFanotify(ctx context.Context) {
	buffer := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		fd := s.fanotifyFD
		s.mu.Unlock()
		if fd <= 0 {
			return
		}
		read, err := unix.Read(fd, buffer)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				// Non-blocking group with nothing pending. Poll rather than
				// spin, so an idle host costs nothing.
				if !s.waitReadable(ctx, fd) {
					return
				}
				continue
			}
			return
		}
		s.decodeFanotify(buffer[:read])
	}
}

// waitReadable blocks until the group has data, the context ends, or the
// descriptor closes. Returns false when the reader should stop.
func (s *linuxSource) waitReadable(ctx context.Context, fd int) bool {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if ctx.Err() != nil {
			return false
		}
		count, err := unix.Poll(fds, 500)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return false
		}
		if count > 0 {
			return true
		}
	}
}

// decodeFanotify walks the fanotify_event_metadata records in one read.
func (s *linuxSource) decodeFanotify(data []byte) {
	const metadataLen = 24 // sizeof(struct fanotify_event_metadata)
	now := time.Now()
	for len(data) >= metadataLen {
		length := int(binary.LittleEndian.Uint32(data[0:]))
		if length < metadataLen || length > len(data) {
			return
		}
		mask := binary.LittleEndian.Uint64(data[8:])
		fd := int32(binary.LittleEndian.Uint32(data[16:]))
		pid := int(binary.LittleEndian.Uint32(data[20:]))

		if fd >= 0 {
			path := resolveFD(int(fd))
			// The descriptor must be closed even when the path is unresolvable,
			// or the group leaks one per event and eventually stops delivering.
			_ = unix.Close(int(fd))
			if path != "" && pid != os.Getpid() {
				kind := KindFileRead
				if mask&(unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE) != 0 {
					kind = KindFileWrite
				}
				event := s.describe(pid)
				event.Kind = kind
				event.Path = path
				event.At = now
				s.buffer.Push(event)
			}
		}
		data = data[length:]
	}
}

func resolveFD(fd int) string {
	link, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(fd)))
	if err != nil {
		return ""
	}
	return link
}
