// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The peer proof first asks the gateway its record names whether it holds the
// accepted socket (perUserGatewayPeerPID, S8 DESIGN section 15). These tests
// pin the rules of the walk of every process of this account, which still
// decides every doubtful case, and show when the walk does not run.

// countWalks counts the process walks of the peer proof until the test ends.
func countWalks(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	saved := socketHolderWalk
	socketHolderWalk = func(ctx context.Context, inode string) []int {
		n.Add(1)
		return procSocketHolders(ctx, inode)
	}
	t.Cleanup(func() { socketHolderWalk = saved })
	return &n
}

// selfGatewayRecord is a record naming this test process as the gateway.
func selfGatewayRecord(t *testing.T) string {
	t.Helper()
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	return recordGateway(t, os.Getpid(), func(r *gatewayRecord) { r.Executable = exe })
}

// startSocketHolder starts another process of this account that holds the
// descriptors in files (TestPerUserPeerHelperProcess) and returns its pid.
func startSocketHolder(t *testing.T, files ...*os.File) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPerUserPeerHelperProcess$")
	cmd.Env = append(os.Environ(), peerHoldHelperEnv+"=1")
	cmd.ExtraFiles = files
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
	return cmd.Process.Pid
}

func acceptedFile(t *testing.T, accepted net.Conn) *os.File {
	t.Helper()
	f, err := accepted.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestA2RecordedGatewayHoldingTheSocketIsThePeerWithoutAWalk(t *testing.T) {
	client, server, _, _, _ := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", true)
	settle(t, client, server)
	home := selfGatewayRecord(t)
	walks := countWalks(t)
	homes := []string{t.TempDir(), home} // a folder with no record is skipped
	if pid, ok := perUserGatewayPeerPID(context.Background(), homes, client, server); !ok || pid != os.Getpid() {
		t.Fatalf("peer = (%d,%v), want this process", pid, ok)
	}
	// A doubtful netlink reply reads the inode from the procfs tables; the
	// recorded gateway still answers.
	withoutNetlink(t, func() {
		if pid, ok := perUserGatewayPeerPID(context.Background(), homes, client, server); !ok || pid != os.Getpid() {
			t.Fatalf("peer without netlink = (%d,%v), want this process", pid, ok)
		}
	})
	if n := walks.Load(); n != 0 {
		t.Fatalf("%d process walks, want none", n)
	}
	// No record named: the walk, as before.
	if pid, ok := perUserConnectedPeerPID(client, server); !ok || pid != os.Getpid() || walks.Load() != 1 {
		t.Fatalf("walk peer = (%d,%v), walks %d", pid, ok, walks.Load())
	}
	// An ended context names no peer.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pid, ok := perUserGatewayPeerPID(ctx, homes, client, server); ok {
		t.Fatalf("ended read named %d", pid)
	}
}

// Every record that cannot prove the holder leaves the answer to the walk: it
// names the real holder (this process), never the process the record names.
func TestA2DoubtfulRecordWalksAndTheWalkDecides(t *testing.T) {
	client, server, _, _, _ := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", true)
	settle(t, client, server)
	other := otherProcess(t)
	exited := exec.Command("true")
	if err := exited.Run(); err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name string
		home func(t *testing.T) string
	}{
		{"no record", func(t *testing.T) string { return t.TempDir() }},
		{"relative folder", func(*testing.T) string { return "relative" }},
		{"record of another process of this account", func(t *testing.T) string { return recordGateway(t, other, nil) }},
		{"reused pid (start identity differs)", func(t *testing.T) string {
			return recordGateway(t, os.Getpid(), func(r *gatewayRecord) { r.StartIdentity = "Mon Jan 1 00:00:00 2024" })
		}},
		{"exited process", func(t *testing.T) string {
			return recordGateway(t, os.Getpid(), func(r *gatewayRecord) { r.PID = exited.Process.Pid })
		}},
		{"record of another folder", func(t *testing.T) string {
			return recordGateway(t, os.Getpid(), func(r *gatewayRecord) { r.DataDir = "/elsewhere" })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := tc.home(t)
			walks := countWalks(t)
			pid, ok := perUserGatewayPeerPID(context.Background(), []string{home}, client, server)
			if !ok || pid != os.Getpid() || walks.Load() != 1 {
				t.Fatalf("peer = (%d,%v) after %d walks, want this process after one walk", pid, ok, walks.Load())
			}
		})
	}
}

// Two holders of the accepted socket: the walk names no peer, as today. The
// recorded gateway among them is the peer (the one case DESIGN 15 accepts as
// a change: a second holder needs the gateway's help or ptrace rights over
// it).
func TestA2SecondHolderOfTheAcceptedSocket(t *testing.T) {
	client, server, accepted, _, _ := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", true)
	settle(t, client, server)
	helper := startSocketHolder(t, acceptedFile(t, accepted))
	walks := countWalks(t)
	if pid, ok := perUserConnectedPeerPID(client, server); ok {
		t.Fatalf("walk named %d with two holders", pid)
	}
	neither := recordGateway(t, otherProcess(t), nil)
	if pid, ok := perUserGatewayPeerPID(context.Background(), []string{neither}, client, server); ok {
		t.Fatalf("record of a non-holder: walk named %d with two holders", pid)
	}
	if n := walks.Load(); n != 2 {
		t.Fatalf("%d walks, want 2", n)
	}
	if pid, ok := perUserGatewayPeerPID(context.Background(), []string{selfGatewayRecord(t)}, client, server); !ok || pid != os.Getpid() {
		t.Fatalf("recorded gateway among two holders = (%d,%v)", pid, ok)
	}
	if pid, ok := perUserGatewayPeerPID(context.Background(), []string{recordGateway(t, helper, nil)}, client, server); !ok || pid != helper {
		t.Fatalf("recorded helper among two holders = (%d,%v), want %d", pid, ok, helper)
	}
	if n := walks.Load(); n != 2 {
		t.Fatalf("%d walks after the recorded holders, want still 2", n)
	}
}

// A server end no process holds any more is no peer, with or without a record.
func TestA2ClosedServerEndIsNoPeer(t *testing.T) {
	client, server, accepted, _, _ := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", true)
	settle(t, client, server)
	_ = accepted.Close()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if _, ok := exactAcceptedSocket(client, server); !ok {
			break
		}
	}
	home := selfGatewayRecord(t)
	for _, homes := range [][]string{nil, {home}} {
		if pid, ok := perUserGatewayPeerPID(context.Background(), homes, client, server); ok {
			t.Fatalf("closed server end named %d (homes %v)", pid, homes)
		}
	}
}

// The holder of the socket alone is the peer when the record names it: a
// fresh gateway (the helper, just started) whose record names it, with this
// process's copy closed, passes the restart-window holder check by the first
// look; a record naming a fresh process that does not hold it fails closed.
func TestA2FreshGatewayProofUsesTheRecordedHolder(t *testing.T) {
	client, server, accepted, _, _ := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", true)
	settle(t, client, server)
	f := acceptedFile(t, accepted)
	helper := startSocketHolder(t, f)
	_ = f.Close()
	_ = accepted.Close()
	if pid, ok := perUserConnectedPeerPID(client, server); !ok || pid != helper {
		t.Fatalf("helper not the sole holder: (%d,%v)", pid, ok)
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	check := &perUserPeerCheck{}
	check.ends.Store(&perUserConnEnds{local: client, remote: server, at: time.Now()})
	home := recordGateway(t, helper, func(r *gatewayRecord) { r.Executable = exe })
	walks := countWalks(t)
	if got := perUserFreshGatewayProof(home, check); !got.ok {
		t.Fatalf("recorded fresh holder: %+v", got)
	}
	if n := walks.Load(); n != 0 {
		t.Fatalf("%d walks, want none", n)
	}
	// The capture during the call names the same owner without a walk.
	perUserCaptureFreshGatewayOwner(home, check)
	for deadline := time.Now().Add(2 * time.Second); check.owner.Load() == nil && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
	}
	if owner := check.owner.Load(); owner == nil || owner.pid != helper || walks.Load() != 0 {
		t.Fatalf("captured owner %+v after %d walks, want %d", owner, walks.Load(), helper)
	}
	// A fresh process of this account that does not hold the socket.
	notHolder := startSocketHolder(t)
	elsewhere := recordGateway(t, notHolder, func(r *gatewayRecord) { r.Executable = exe })
	fresh := &perUserPeerCheck{}
	fresh.ends.Store(&perUserConnEnds{local: client, remote: server, at: time.Now()})
	if got := perUserFreshGatewayProof(elsewhere, fresh); got.ok || got.reason != "no_holder" {
		t.Fatalf("record of a non-holder: %+v, want no_holder", got)
	}
	if n := walks.Load(); n != 1 {
		t.Fatalf("%d walks, want one for the non-holder record", n)
	}
}

// hook-post reads the peer of its call with the record folder the call named.
func TestA2PeerRecordAsksTheCallsRecordedGateway(t *testing.T) {
	if got := perUserCallHomes(context.Background()); got != nil {
		t.Fatalf("homes of a call that named none = %v", got)
	}
	home := selfGatewayRecord(t)
	ctx := WithPerUserGatewayDataDir(context.Background(), home)
	if got := perUserCallHomes(ctx); len(got) != 1 || got[0] != home {
		t.Fatalf("homes = %v, want [%s]", got, home)
	}
	client, server, _, _, conn := dialPair(t, "tcp4", "127.0.0.1:0", "tcp4", true)
	settle(t, client, server)
	walks := countWalks(t)
	record := NewPerUserPeerRecord()
	record.capture(perUserCallHomes(ctx), conn.LocalAddr(), conn.RemoteAddr())
	if peer, ok := record.wait(2 * time.Second); !ok || peer.pid != os.Getpid() || walks.Load() != 0 {
		t.Fatalf("peer %+v ok=%v after %d walks", peer, ok, walks.Load())
	}
}
