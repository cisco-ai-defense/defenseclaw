// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

const freshPeerProcessHelperEnv = "DC_TEST_FRESH_PEER_PROCESS"

func TestGAP0295FreshPeerProcessHelper(t *testing.T) {
	if os.Getenv(freshPeerProcessHelperEnv) != "1" {
		t.Skip("helper process only")
	}
	_, _ = fmt.Fprintln(os.Stdout, "ready")
	time.Sleep(time.Minute)
}

func TestGAP0295FreshStartRequiresCurrentPeerIdentity(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP0295FreshPeerProcessHelper$")
	cmd.Env = append(os.Environ(), freshPeerProcessHelperEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("peer helper not ready: %q, %v", line, err)
	}
	identity, ok := procidentity.Of(cmd.Process.Pid)
	if !ok {
		t.Fatal("peer identity unavailable")
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	writeRecord := func(recordIdentity string) {
		t.Helper()
		b, err := json.Marshal(map[string]any{
			"pid": cmd.Process.Pid, "executable": executable, "data_dir": dataDir,
			"start_time": time.Now().Add(-time.Second).Unix(), "start_identity": recordIdentity,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, "gateway.pid"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	peer := &PerUserPeerRecord{done: make(chan struct{}), ok: true,
		peer: perUserPeerProcess{pid: cmd.Process.Pid, identity: identity}}
	close(peer.done)
	writeRecord(recordedStart(t, cmd.Process.Pid))
	if fresh, _ := PerUserGatewayFreshStartNoAnswer(dataDir, peer); !fresh {
		t.Fatal("current peer record not recognized")
	}
	peer.peer.identity = "different"
	writeRecord("different")
	if fresh, _ := PerUserGatewayFreshStartNoAnswer(dataDir, peer); fresh {
		t.Fatal("changed peer identity recognized")
	}
	peer.peer.identity = identity
	writeRecord(recordedStart(t, cmd.Process.Pid))
	peer.at = time.Now()
	time.Sleep(50 * time.Millisecond)
	if err := recordPerUserGatewayAnswer(dataDir, perUserPeerProcess{pid: cmd.Process.Pid, identity: identity}); err != nil {
		t.Fatal(err)
	}
	if fresh, _ := PerUserGatewayFreshStartNoAnswer(dataDir, peer); !fresh {
		t.Fatal("a call connected before the first completed answer lost its restart window")
	}
	peer.at = time.Now()
	if fresh, _ := PerUserGatewayFreshStartNoAnswer(dataDir, peer); fresh {
		t.Fatal("a call connected after the first completed answer entered the restart window")
	}
}
