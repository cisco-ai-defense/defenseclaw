// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestGAP0295ShellFreshStartUsesConnectionTime covers hook-post's exit 10
// proof with a real accepted connection. A sibling's completed answer after
// this call connected does not end this call's restart window; a later call
// still sees the completed answer and stays closed.
func TestGAP0295ShellFreshStartUsesConnectionTime(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP0295FreshListenerHelper$")
	cmd.Env = append(os.Environ(), freshListenerHelperEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	address, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	address = strings.TrimSpace(address)
	pid := cmd.Process.Pid
	identity, ok := procidentity.Of(pid)
	if !ok {
		t.Fatal("helper identity unavailable")
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	record, err := json.Marshal(map[string]any{
		"pid": pid, "executable": strings.TrimSuffix(executable, " (deleted)"), "data_dir": dataDir,
		"start_time": time.Now().Add(-time.Second).Unix(), "start_identity": recordedStart(t, pid),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), record, 0o600); err != nil {
		t.Fatal(err)
	}
	connect := func() (net.Conn, *PerUserPeerRecord) {
		t.Helper()
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		client, server := conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr)
		owner, unique := 0, false
		// Both reads are bounded by 2 s of wall time. Only a read that missed
		// it is given the host (GAP-0889): the helper process and this one are
		// stretched alike by a host that is short of CPU (testenv.MaxStretch).
		began := time.Now()
		poll := func(limit time.Duration) {
			for ; time.Since(began) < limit && !unique; time.Sleep(10 * time.Millisecond) {
				owner, unique = perUserConnectedPeerPID(client, server)
			}
		}
		poll(2 * time.Second)
		if !unique {
			poll(testenv.Limit(2 * time.Second))
		}
		if !unique || owner != pid {
			t.Fatalf("accepted socket owner = %d %v, want the fresh gateway", owner, unique)
		}
		peer := NewPerUserPeerRecord()
		peer.capture(conn.LocalAddr(), conn.RemoteAddr())
		got, known := peer.wait(2 * time.Second)
		if !known {
			got, known = peer.wait(testenv.Limit(2*time.Second) - 2*time.Second)
		}
		if !known || got.pid != pid {
			t.Fatalf("recorded peer = %+v %v", got, known)
		}
		return conn, peer
	}
	firstConn, first := connect()
	defer firstConn.Close()
	if fresh, _ := PerUserGatewayFreshStartNoAnswer(dataDir, first); !fresh {
		t.Fatal("first connection did not enter the fresh-start window")
	}
	time.Sleep(50 * time.Millisecond)
	if err := recordPerUserGatewayAnswer(dataDir, perUserPeerProcess{pid: pid, identity: identity}); err != nil {
		t.Fatal(err)
	}
	if fresh, _ := PerUserGatewayFreshStartNoAnswer(dataDir, first); !fresh {
		t.Fatal("sibling answer after this connection ended its restart window")
	}
	lateConn, late := connect()
	defer lateConn.Close()
	if fresh, _ := PerUserGatewayFreshStartNoAnswer(dataDir, late); fresh {
		t.Fatal("connection after the completed answer entered the restart window")
	}
}
