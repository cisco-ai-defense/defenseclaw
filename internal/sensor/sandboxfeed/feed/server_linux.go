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

package feed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/ipc"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// Server bounds. A per-user gateway holds one connection and a status
// command opens one for a moment, so one account never needs many; the cap
// keeps one from using up the others'.
const (
	maxConnections = 64
	maxPerUID      = 8
	requestTimeout = 5 * time.Second
	writeTimeout   = 10 * time.Second
)

// Server serves the feed socket.
type Server struct {
	// Socket is the socket path (sandboxfeed.DefaultSocketPath when empty).
	Socket string
	// GID is the group whose members may read the feed: docker. The socket
	// and its directory get it, and every connection's credentials are
	// checked for it again at accept.
	GID int
	// Hub is the stream to serve.
	Hub *Hub
	// Build is the release named in the header.
	Build  string
	Logger *slog.Logger

	mu     sync.Mutex
	conns  int
	perUID map[int]int
}

// Serve listens until ctx ends.
func (s *Server) Serve(ctx context.Context) error {
	if s.Hub == nil {
		return errors.New("sandbox feed: no stream to serve")
	}
	if s.GID < 0 {
		return errors.New("sandbox feed: no group to serve")
	}
	if s.Logger == nil {
		s.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	path := s.Socket
	if path == "" {
		path = sandboxfeed.DefaultSocketPath
	}
	listener, err := ipc.ListenSecured(ctx, ipc.ListenSpec{
		Path: path, BaseName: filepath.Base(path), SocketMode: 0o660, DirMode: 0o750,
		OwnerUID: os.Getuid(), OwnerGID: s.GID,
	})
	if err != nil {
		return err
	}
	s.Logger.Info("sandbox kernel feed listening", "socket", path, "gid", s.GID, "build", s.Build)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var transient interface{ Timeout() bool }
			if errors.As(err, &transient) && transient.Timeout() {
				continue
			}
			return err
		}
		if !s.admit() {
			s.Logger.Warn("sandbox kernel feed refused a connection: too many readers", "limit", maxConnections)
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.release()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) admit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns >= maxConnections {
		return false
	}
	s.conns++
	return true
}

func (s *Server) release() {
	s.mu.Lock()
	s.conns--
	s.mu.Unlock()
}

func (s *Server) admitUID(uid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perUID == nil {
		s.perUID = map[int]int{}
	}
	if s.perUID[uid] >= maxPerUID {
		return false
	}
	s.perUID[uid]++
	return true
}

func (s *Server) releaseUID(uid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perUID[uid]--; s.perUID[uid] <= 0 {
		delete(s.perUID, uid)
	}
}

// handle serves one connection: the peer check, the request, the header and
// the reader's frames until either side ends.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	peer, err := peerOf(conn)
	if err != nil {
		s.Logger.Warn("sandbox kernel feed refused a connection", "error", err)
		return
	}
	if !peer.member(s.GID) {
		s.Logger.Warn("sandbox kernel feed refused a reader outside its group", "uid", peer.uid, "pid", peer.pid, "gid", s.GID)
		return
	}
	if !s.admitUID(peer.uid) {
		s.Logger.Warn("sandbox kernel feed refused a reader: too many connections of its account", "uid", peer.uid, "limit", maxPerUID)
		return
	}
	defer s.releaseUID(peer.uid)
	_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
	var request sandboxfeed.Request
	if err := sandboxfeed.ReadLine(sandboxfeed.NewLineScanner(conn), &request); err != nil {
		return
	}
	header := sandboxfeed.Header{Protocol: sandboxfeed.ProtocolVersion, Build: s.Build}
	switch {
	case request.Op != sandboxfeed.OpSandboxExecs:
		header.Error = sandboxfeed.HeaderErrorUnknownOp
	case request.Version < sandboxfeed.MinProtocolVersion:
		header.Error = sandboxfeed.HeaderErrorVersionSkew
	}
	header.Tetragon, header.Reason = s.Hub.Tetragon()
	_ = conn.SetDeadline(time.Now().Add(writeTimeout))
	if err := sandboxfeed.WriteLine(conn, header); err != nil || header.Error != "" {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	sub := s.Hub.Subscribe(peer.uid)
	defer sub.Close()
	s.Logger.Info("sandbox kernel feed reader connected", "uid", peer.uid, "pid", peer.pid)
	defer s.Logger.Info("sandbox kernel feed reader left", "uid", peer.uid, "pid", peer.pid)
	// The reader sends nothing after its request: any byte, or its close,
	// ends the stream.
	gone := make(chan struct{})
	go func() {
		var one [1]byte
		_, _ = conn.Read(one[:])
		close(gone)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-gone:
			return
		case frame := <-sub.Frames():
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := sandboxfeed.WriteLine(conn, frame); err != nil {
				return
			}
			if dropped := sub.TakeDropped(); dropped > 0 {
				state, reason := s.Hub.Tetragon()
				status := sandboxfeed.Frame{Kind: sandboxfeed.FrameStatus, At: time.Now(), Tetragon: state, Reason: reason, Dropped: dropped}
				if err := sandboxfeed.WriteLine(conn, status); err != nil {
					return
				}
			}
		}
	}
}

// peer is the kernel's account of who connected.
type peer struct {
	uid, gid, pid int
	groups        []int
}

// member reports whether the peer may read the feed: root, or a process
// holding gid as its group or a supplementary group when it connected.
func (p peer) member(gid int) bool {
	return p.uid == 0 || p.gid == gid || slices.Contains(p.groups, gid)
}

// peerOf reads SO_PEERCRED and SO_PEERGROUPS: the credentials the peer held
// when it connected, which it cannot change afterwards.
func peerOf(conn net.Conn) (peer, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return peer{}, errors.New("not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return peer{}, err
	}
	var out peer
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credErr = fmt.Errorf("SO_PEERCRED: %w", err)
			return
		}
		out.uid, out.gid, out.pid = int(cred.Uid), int(cred.Gid), int(cred.Pid)
		out.groups, credErr = peerGroups(int(fd))
	}); err != nil {
		return peer{}, err
	}
	return out, credErr
}

// peerGroups reads SO_PEERGROUPS (Linux 4.13): the peer's supplementary
// groups at connect time. The option fills a gid_t array and answers ERANGE
// with the size it needs when the buffer is short.
func peerGroups(fd int) ([]int, error) {
	buffer := make([]uint32, 64)
	for range 4 {
		size := uint32(len(buffer) * 4)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_SOCKET), uintptr(unix.SO_PEERGROUPS),
			uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch errno {
		case 0:
			out := make([]int, 0, size/4)
			for _, gid := range buffer[:size/4] {
				out = append(out, int(gid))
			}
			return out, nil
		case unix.ERANGE:
			buffer = make([]uint32, size/4+1)
		default:
			return nil, fmt.Errorf("SO_PEERGROUPS: %w", errno)
		}
	}
	return nil, errors.New("SO_PEERGROUPS: the group list keeps growing")
}
