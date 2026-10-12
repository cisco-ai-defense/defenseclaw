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
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// connPair is a connected unix socket pair: the server's end and the
// reader's. Both ends carry this process's credentials.
func connPair(t *testing.T) (server, reader net.Conn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	open := func(fd int, name string) net.Conn {
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		conn, err := net.FileConn(file)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	server, reader = open(fds[0], "server"), open(fds[1], "reader")
	t.Cleanup(func() { _ = server.Close(); _ = reader.Close() })
	return server, reader
}

// notMyGroup is a gid this process does not hold.
func notMyGroup(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for gid := 60000; gid < 65000; gid++ {
		if gid != os.Getgid() && !slices.Contains(groups, gid) {
			return gid
		}
	}
	t.Skip("no free gid")
	return -1
}

// A reader outside the feed's group is refused at accept: no header, no
// frame, whatever it asks.
func TestServerRefusesAReaderOutsideItsGroup(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root may read the feed")
	}
	hub := NewHub(nil)
	s := &Server{GID: notMyGroup(t), Hub: hub, Logger: quietLogger()}
	server, reader := connPair(t)
	done := make(chan struct{})
	go func() { s.handle(context.Background(), server); close(done) }()
	_ = sandboxfeed.WriteLine(reader, sandboxfeed.Request{Version: sandboxfeed.ProtocolVersion, Op: sandboxfeed.OpSandboxExecs})
	<-done
	_ = reader.SetReadDeadline(time.Now().Add(time.Second))
	if data, _ := io.ReadAll(reader); len(data) != 0 {
		t.Fatalf("a refused reader got %q", data)
	}
	if hub.Subscribers() != 0 {
		t.Fatal("a refused reader subscribed")
	}
}

// A member reads the header and its own uid's frames only, and is told what
// it missed.
func TestServerServesAMemberItsOwnFrames(t *testing.T) {
	hub := NewHub(nil)
	hub.SetTetragon(sandboxfeed.TetragonConnected, "")
	s := &Server{GID: os.Getgid(), Hub: hub, Build: "1.2.3", Logger: quietLogger()}
	server, reader := connPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.handle(ctx, server)
	if err := sandboxfeed.WriteLine(reader, sandboxfeed.Request{Version: sandboxfeed.ProtocolVersion, Op: sandboxfeed.OpSandboxExecs}); err != nil {
		t.Fatal(err)
	}
	scanner := sandboxfeed.NewLineScanner(reader)
	var header sandboxfeed.Header
	if err := sandboxfeed.ReadLine(scanner, &header); err != nil || header.Protocol != sandboxfeed.ProtocolVersion ||
		header.Build != "1.2.3" || header.Tetragon != sandboxfeed.TetragonConnected || header.Error != "" {
		t.Fatalf("header = %+v, %v", header, err)
	}
	waitFor(t, func() bool { return hub.Subscribers() == 1 })
	hub.Publish(Item{Owner: os.Getuid() + 1, Frame: sandboxfeed.Frame{Kind: sandboxfeed.FrameExec, ExecID: "theirs"}})
	hub.Publish(Item{Owner: os.Getuid(), Frame: sandboxfeed.Frame{Kind: sandboxfeed.FrameExec, ExecID: "mine"}})
	hub.Lost(3)
	var frames []sandboxfeed.Frame
	for len(frames) < 2 {
		var f sandboxfeed.Frame
		if err := sandboxfeed.ReadLine(scanner, &f); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
	}
	if frames[0].ExecID != "mine" || frames[1].Kind != sandboxfeed.FrameStatus || frames[1].Dropped != 3 {
		t.Fatalf("frames = %+v", frames)
	}
	// The reader sends nothing after its request: closing ends the stream.
	_ = reader.Close()
	waitFor(t, func() bool { return hub.Subscribers() == 0 })
}

// An unknown operation, and a request older than the feed reads, are refused
// in the header.
func TestServerRefusesInTheHeader(t *testing.T) {
	for want, request := range map[string]sandboxfeed.Request{
		sandboxfeed.HeaderErrorUnknownOp:   {Version: sandboxfeed.ProtocolVersion, Op: "dump_everything"},
		sandboxfeed.HeaderErrorVersionSkew: {Version: sandboxfeed.MinProtocolVersion - 1, Op: sandboxfeed.OpSandboxExecs},
	} {
		hub := NewHub(nil)
		s := &Server{GID: os.Getgid(), Hub: hub, Logger: quietLogger()}
		server, reader := connPair(t)
		go s.handle(context.Background(), server)
		_ = sandboxfeed.WriteLine(reader, request)
		var header sandboxfeed.Header
		if err := sandboxfeed.ReadLine(sandboxfeed.NewLineScanner(reader), &header); err != nil || header.Error != want {
			t.Fatalf("%+v: header = %+v, %v", request, header, err)
		}
		if hub.Subscribers() != 0 {
			t.Fatalf("%+v subscribed", request)
		}
	}
}

// Serve end to end: the socket gets the feed's group and modes, and a
// reader's stream ends when the feed stops.
func TestServeListensWithItsGroup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	path := filepath.Join(dir, "feed.sock")
	hub := NewHub(nil)
	s := &Server{Socket: path, GID: os.Getgid(), Hub: hub, Build: "1.2.3", Logger: quietLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx) }()
	waitFor(t, func() bool { _, err := os.Stat(path); return err == nil })
	for p, mode := range map[string]os.FileMode{dir: 0o750, path: 0o660} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s mode = %v, %v; want %v", p, info.Mode().Perm(), err, mode)
		}
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = sandboxfeed.WriteLine(conn, sandboxfeed.Request{Version: sandboxfeed.ProtocolVersion, Op: sandboxfeed.OpSandboxExecs})
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || len(line) < 10 {
		t.Fatalf("header line %q, %v", line, err)
	}
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestPeerGroupsAreTheProcesss(t *testing.T) {
	server, _ := connPair(t)
	p, err := peerOf(server)
	if err != nil {
		t.Fatal(err)
	}
	groups, _ := os.Getgroups()
	if p.uid != os.Getuid() || p.gid != os.Getgid() || p.pid != os.Getpid() {
		t.Fatalf("peer = %+v", p)
	}
	for _, gid := range groups {
		if !slices.Contains(p.groups, gid) {
			t.Fatalf("SO_PEERGROUPS %v lacks %d (process groups %v)", p.groups, gid, groups)
		}
	}
	if !p.member(os.Getgid()) || (os.Getuid() != 0 && p.member(notMyGroup(t))) {
		t.Fatalf("membership of %+v", p)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// One account cannot hold every connection.
func TestServerCapsConnectionsPerAccount(t *testing.T) {
	s := &Server{GID: os.Getgid(), Hub: NewHub(nil), Logger: quietLogger()}
	for range maxPerUID {
		if !s.admitUID(1000) {
			t.Fatal("refused under the cap")
		}
	}
	if s.admitUID(1000) {
		t.Fatal("admitted over the cap")
	}
	if !s.admitUID(1001) {
		t.Fatal("another account was refused")
	}
	s.releaseUID(1000)
	if !s.admitUID(1000) {
		t.Fatal("a released slot was not reusable")
	}
}
