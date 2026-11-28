// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package attach

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// GAP-1008: `npx ...` runs npx.cmd under cmd.exe, which starts node.exe.
// Ending only the direct process left node.exe running on close, on a relay
// error, on a second open, when the command ended by itself and when the
// launcher died. These helpers stand in for cmd.exe (treeparent) and for a
// node.exe that ignores stdin EOF (treestuck).
func init() {
	mcpHelperModes["treeparent"] = func() int { return mcpTreeParent(false) }
	mcpHelperModes["treeparentexit"] = func() int { return mcpTreeParent(true) }
	mcpHelperModes["treestuck"] = func() int {
		time.Sleep(60 * time.Second) // reads nothing; only a kill ends it early
		return 0
	}
	mcpHelperModes["treelauncher"] = mcpTreeLauncher
}

// mcpTreeParent prints its own started message, starts a grandchild on the
// same stdio, prints the grandchild's started message, then waits for it
// (exit: returns at once and leaves it running).
func mcpTreeParent(exit bool) int {
	fmt.Printf("{\"jsonrpc\":\"2.0\",\"method\":\"started\",\"params\":{\"pid\":%d}}\n", os.Getpid())
	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(), "DC_MCP_HELPER=treestuck")
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "helper: start grandchild:", err)
		return 4
	}
	fmt.Printf("{\"jsonrpc\":\"2.0\",\"method\":\"started\",\"params\":{\"pid\":%d}}\n", c.Process.Pid)
	if exit {
		return 0
	}
	_ = c.Wait()
	return 0
}

// mcpTreeLauncher is a launcher process: it serves one stream whose command
// is treeparent, opens it, prints the two started messages and blocks until
// the test kills it.
func mcpTreeLauncher() int {
	_ = os.Setenv("DC_MCP_HELPER", "treeparent")
	srvConn := make(chan *websocket.Conn, 1)
	up := websocket.Upgrader{Subprotocols: []string{relay.Subprotocol}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := up.Upgrade(w, r, nil); err == nil {
			srvConn <- c
		}
	}))
	defer srv.Close()
	d := websocket.Dialer{Subprotocols: []string{relay.Subprotocol}}
	c, _, err := d.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "launcher: dial:", err)
		return 5
	}
	s := <-srvConn
	go func() {
		_ = ServeMCP(context.Background(), c, MCPServe{Spec: MCPSpec{Name: "helper", Argv: []string{os.Args[0]}}})
	}()
	if err := s.WriteMessage(websocket.TextMessage, []byte(`{"type":"open"}`)); err != nil {
		return 6
	}
	for i := 0; i < 2; i++ {
		_, b, err := s.ReadMessage()
		if err != nil {
			return 7
		}
		fmt.Printf("%s\n", b)
	}
	select {}
}

// treePIDs reads the direct child's and the grandchild's started messages.
func treePIDs(t *testing.T, frames <-chan frame, what string) (child, grand int) {
	t.Helper()
	child = startedPID(t, next(t, frames, what+": child"))
	grand = startedPID(t, next(t, frames, what+": grandchild"))
	t.Cleanup(func() { killPID(child); killPID(grand) }) // a red run leaves no orphan behind
	return child, grand
}

// killPID ends pid through a handle (test cleanup only).
func killPID(pid int) {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return
	}
	_ = windows.TerminateProcess(h, 1)
	_ = windows.CloseHandle(h)
}

// treeGoneWithin fails unless every pid has exited within limit (handle check).
func treeGoneWithin(t *testing.T, limit time.Duration, what string, pids ...int) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for _, pid := range pids {
		for pidAlive(pid) {
			if time.Now().After(deadline) {
				t.Errorf("%s: process %d still runs %s later", what, pid, limit)
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

const treeLimit = 5 * time.Second

// TestMCPBridgeEndsTheWholeTree (GAP-1008): close, a relay error, a second
// open, a command that ends by itself and the end of the stream all end the
// grandchild too, and the presence record goes only once it is gone.
func TestMCPBridgeEndsTheWholeTree(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		end  func(t *testing.T, s *websocket.Conn, frames <-chan frame, done <-chan error) // returns once the bridge acted
	}{
		{"close", "treeparent", func(t *testing.T, s *websocket.Conn, _ <-chan frame, _ <-chan error) {
			sendCtl(t, s, "close")
		}},
		{"error", "treeparent", func(t *testing.T, s *websocket.Conn, _ <-chan frame, done <-chan error) {
			if err := s.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","code":"mcp_busy"}`)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("ServeMCP did not return after the error message")
			}
		}},
		{"second-open", "treeparent", func(t *testing.T, s *websocket.Conn, frames <-chan frame, _ <-chan error) {
			sendCtl(t, s, "open")
			treePIDs(t, frames, "second open")
		}},
		{"command-exits", "treeparentexit", func(*testing.T, *websocket.Conn, <-chan frame, <-chan error) {}},
		{"stream-end", "treeparent", func(t *testing.T, s *websocket.Conn, _ <-chan frame, done <-chan error) {
			_ = s.Close()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("ServeMCP did not return after the stream ended")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := helperSpec(t, tc.mode)
			f := newFakeStream(t)
			c, s := f.dial()
			frames := pump(s)
			var grandPID atomic.Int64
			var orphanAtRemove atomic.Bool
			removed := make(chan struct{}, 4)
			_, done := startServe(t, c, MCPServe{Spec: spec, KillGrace: 2 * time.Second,
				OnChild: func(int) func() {
					return func() {
						if g := grandPID.Load(); g != 0 && pidAlive(int(g)) {
							orphanAtRemove.Store(true)
						}
						removed <- struct{}{}
					}
				}})
			sendCtl(t, s, "open")
			child, grand := treePIDs(t, frames, "open")
			grandPID.Store(int64(grand))
			tc.end(t, s, frames, done)
			treeGoneWithin(t, treeLimit, tc.name, child, grand)
			select {
			case <-removed:
			case <-time.After(treeLimit):
				t.Errorf("%s: the presence record was not removed", tc.name)
			}
			if orphanAtRemove.Load() {
				t.Errorf("%s: the presence record was removed while the grandchild %d still ran", tc.name, grand)
			}
		})
	}
}

// TestMCPBridgeLauncherDeathEndsTheTree (GAP-1008): when the launcher itself
// is killed (no Close, no deferred cleanup), Windows closes its job handle
// and kill-on-close ends the command and its grandchild.
func TestMCPBridgeLauncherDeathEndsTheTree(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "DC_MCP_HELPER=treelauncher")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := make(chan string, 2)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	var pids []int
	for len(pids) < 2 {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("the launcher helper ended after %d started messages", len(pids))
			}
			var m struct {
				Method string `json:"method"`
				Params struct {
					PID int `json:"pid"`
				} `json:"params"`
			}
			if json.Unmarshal([]byte(l), &m) != nil || m.Method != "started" || m.Params.PID == 0 {
				t.Fatalf("launcher helper printed %q", l)
			}
			pids = append(pids, m.Params.PID)
		case <-time.After(15 * time.Second):
			t.Fatal("the launcher helper printed no started messages")
		}
	}
	t.Cleanup(func() { killPID(pids[0]); killPID(pids[1]) })
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	treeGoneWithin(t, treeLimit, "launcher killed", pids...)
}
