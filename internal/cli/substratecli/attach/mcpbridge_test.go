// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// TestMain lets the test binary act as a tiny MCP server (DC_MCP_HELPER), so
// the lifecycle test runs the same on Windows, which has no /bin/cat.
func TestMain(m *testing.M) {
	if mode := os.Getenv("DC_MCP_HELPER"); mode != "" {
		os.Exit(mcpHelper(mode))
	}
	os.Exit(m.Run())
}

// mcpHelperModes holds the helper modes a platform test file adds.
var mcpHelperModes = map[string]func() int{}

func mcpHelper(mode string) int {
	if f := mcpHelperModes[mode]; f != nil {
		return f()
	}
	switch mode {
	case "exit":
		fmt.Fprintln(os.Stderr, "helper: failing on purpose")
		return 3
	case "flood":
		w := bufio.NewWriter(os.Stdout)
		fmt.Fprintf(w, "%s\n", strings.Repeat("x", MCPLineMax+2))
		fmt.Fprintf(w, "{\"jsonrpc\":\"2.0\",\"method\":\"after-long\"}\n")
		for i := 0; i < 100; i++ {
			fmt.Fprintf(os.Stderr, "noise %d\n", i)
		}
		w.Flush()
		select {}
	}
	fmt.Printf("{\"jsonrpc\":\"2.0\",\"method\":\"started\",\"params\":{\"pid\":%d}}\n", os.Getpid())
	fmt.Fprintln(os.Stderr, "helper: ready")
	r := bufio.NewReader(os.Stdin)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			b, _ := json.Marshal(line)
			fmt.Printf("{\"got\":%s}\n", b)
		}
		if err != nil {
			select {} // a stuck server: only a kill ends it
		}
	}
}

// fakeStream is the relay and gateway side of one stream: the test sends
// open/close and frames and reads what the launcher sends back.
type fakeStream struct {
	t     *testing.T
	srv   *httptest.Server
	conn  chan *websocket.Conn
	pings atomic.Int32
	pongs atomic.Int32
}

func newFakeStream(t *testing.T) *fakeStream {
	t.Helper()
	f := &fakeStream{t: t, conn: make(chan *websocket.Conn, 1)}
	up := websocket.Upgrader{Subprotocols: []string{relay.Subprotocol}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.SetPingHandler(func(string) error { f.pings.Add(1); return nil })
		c.SetPongHandler(func(string) error { f.pongs.Add(1); return nil })
		f.conn <- c
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// dial returns the launcher's end and the test's end.
func (f *fakeStream) dial() (client, server *websocket.Conn) {
	f.t.Helper()
	d := websocket.Dialer{Subprotocols: []string{relay.Subprotocol}}
	c, _, err := d.Dial("ws"+strings.TrimPrefix(f.srv.URL, "http"), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	select {
	case s := <-f.conn:
		f.t.Cleanup(func() { _ = s.Close() })
		return c, s
	case <-time.After(5 * time.Second):
		f.t.Fatal("no stream")
		return nil, nil
	}
}

type frame struct {
	kind int
	b    []byte
}

// pump reads server-side frames into a channel.
func pump(s *websocket.Conn) <-chan frame {
	ch := make(chan frame, 64)
	go func() {
		defer close(ch)
		for {
			k, b, err := s.ReadMessage()
			if err != nil {
				return
			}
			ch <- frame{k, b}
		}
	}()
	return ch
}

func next(t *testing.T, ch <-chan frame, what string) frame {
	t.Helper()
	select {
	case fr, ok := <-ch:
		if !ok {
			t.Fatalf("%s: stream closed", what)
		}
		return fr
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no frame", what)
		return frame{}
	}
}

func helperSpec(t *testing.T, mode string) MCPSpec {
	t.Setenv("DC_MCP_HELPER", mode)
	return MCPSpec{Name: "helper", Argv: []string{os.Args[0]}}
}

func startedPID(t *testing.T, fr frame) int {
	t.Helper()
	var m struct {
		Method string `json:"method"`
		Params struct {
			PID int `json:"pid"`
		} `json:"params"`
	}
	if fr.kind != websocket.BinaryMessage || json.Unmarshal(fr.b, &m) != nil || m.Method != "started" || m.Params.PID == 0 {
		t.Fatalf("want the started message as a binary frame, got kind %d %q", fr.kind, fr.b)
	}
	return m.Params.PID
}

func waitGone(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for pidAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("%s: process %d still runs", what, pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func sendCtl(t *testing.T, s *websocket.Conn, typ string) {
	t.Helper()
	if err := s.WriteMessage(websocket.TextMessage, []byte(`{"type":"`+typ+`"}`)); err != nil {
		t.Fatal(err)
	}
}

// startServe runs ServeMCP on the launcher's end.
func startServe(t *testing.T, c *websocket.Conn, o MCPServe) (cancel func(), done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	fin := make(chan struct{})
	go func() { ch <- ServeMCP(ctx, c, o); close(fin) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-fin:
		case <-time.After(15 * time.Second):
		}
	})
	return cancel, ch
}

// TestMCPBridgeChildLifecycle: open starts the command, its stdout lines are
// binary frames, binary frames reach its stdin with a newline, close kills
// it, a frame with no command is dropped and a second open starts a fresh
// one (and kills a running one first).
func TestMCPBridgeChildLifecycle(t *testing.T) {
	spec := helperSpec(t, "echo")
	f := newFakeStream(t)
	c, s := f.dial()
	frames := pump(s)
	var notes syncNotes
	var presMu sync.Mutex
	present := map[int]bool{}
	cancel, done := startServe(t, c, MCPServe{Spec: spec, Note: notes.add, KillGrace: 2 * time.Second,
		OnChild: func(pid int) func() {
			presMu.Lock()
			present[pid] = true
			presMu.Unlock()
			return func() { presMu.Lock(); delete(present, pid); presMu.Unlock() }
		}})
	_ = cancel

	// Before open there is no process: a frame is dropped.
	if err := s.WriteMessage(websocket.BinaryMessage, []byte(`{"jsonrpc":"2.0","id":0,"method":"dropped"}`)); err != nil {
		t.Fatal(err)
	}
	sendCtl(t, s, "open")
	pid1 := startedPID(t, next(t, frames, "first start"))

	// A line from the stream reaches stdin as one line with a newline, and
	// comes back as one frame; the dropped frame never did.
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	if err := s.WriteMessage(websocket.BinaryMessage, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Got string `json:"got"`
	}
	fr := next(t, frames, "echo")
	if fr.kind != websocket.BinaryMessage || json.Unmarshal(fr.b, &got) != nil || got.Got != msg+"\n" {
		t.Fatalf("stdin line: kind %d %q (want %q + newline)", fr.kind, fr.b, msg)
	}
	// A frame with a newline inside is compacted to one line.
	if err := s.WriteMessage(websocket.BinaryMessage, []byte("{\"a\":\n1}")); err != nil {
		t.Fatal(err)
	}
	fr = next(t, frames, "compacted")
	if json.Unmarshal(fr.b, &got) != nil || got.Got != "{\"a\":1}\n" {
		t.Fatalf("a frame with a newline arrived as %q", got.Got)
	}
	presMu.Lock()
	if !present[pid1] {
		t.Errorf("no presence record for the child %d", pid1)
	}
	presMu.Unlock()

	// A second open while it runs kills the old one and starts a fresh one.
	sendCtl(t, s, "open")
	pid2 := startedPID(t, next(t, frames, "second start"))
	if pid2 == pid1 {
		t.Fatalf("second open reused process %d", pid1)
	}
	waitGone(t, pid1, "second open")

	// close kills it; a frame after close is dropped, and a new open starts
	// a third process.
	sendCtl(t, s, "close")
	waitGone(t, pid2, "close")
	if err := s.WriteMessage(websocket.BinaryMessage, []byte(`{"jsonrpc":"2.0","id":2,"method":"late"}`)); err != nil {
		t.Fatal(err)
	}
	sendCtl(t, s, "open")
	pid3 := startedPID(t, next(t, frames, "third start"))
	if pid3 == pid2 || pid3 == pid1 {
		t.Fatalf("third open reused a process: %d %d %d", pid1, pid2, pid3)
	}
	if !strings.Contains(notes.all(), "[mcp helper] helper: ready") {
		t.Errorf("stderr not shown with its prefix: %q", notes.all())
	}

	// The stream ends: the child dies, nothing is left behind.
	_ = s.Close()
	if err := <-done; err != nil {
		t.Fatalf("ServeMCP after the stream closed: %v", err)
	}
	waitGone(t, pid3, "stream end")
	presMu.Lock()
	defer presMu.Unlock()
	if len(present) != 0 {
		t.Errorf("presence records left: %v", present)
	}
}

// A command that cannot start or that exits ends the shim's connection: the
// launcher sends the error control message.
func TestMCPBridgeCommandFailed(t *testing.T) {
	for name, spec := range map[string]MCPSpec{
		"exits":     helperSpec(t, "exit"),
		"not-found": {Name: "gone", Argv: []string{"/no/such/dc-mcp-tool"}},
	} {
		f := newFakeStream(t)
		c, s := f.dial()
		frames := pump(s)
		var notes syncNotes
		startServe(t, c, MCPServe{Spec: spec, Note: notes.add})
		sendCtl(t, s, "open")
		fr := next(t, frames, name)
		var m struct{ Type, Code string }
		if fr.kind != websocket.TextMessage || json.Unmarshal(fr.b, &m) != nil || m.Type != "error" || m.Code != "mcp_command_failed" {
			t.Fatalf("%s: got kind %d %q; want the mcp_command_failed control message", name, fr.kind, fr.b)
		}
		if notes.all() == "" {
			t.Errorf("%s: the person is told nothing", name)
		}
	}
}

// A line past the cap is dropped with one warning and the next line still
// goes; stderr past its burst is skipped, not shown in full.
func TestMCPBridgeLongLineAndNoise(t *testing.T) {
	spec := helperSpec(t, "flood")
	f := newFakeStream(t)
	c, s := f.dial()
	frames := pump(s)
	var notes syncNotes
	startServe(t, c, MCPServe{Spec: spec, Note: notes.add, KillGrace: time.Second})
	sendCtl(t, s, "open")
	fr := next(t, frames, "after the long line")
	if !strings.Contains(string(fr.b), "after-long") {
		t.Fatalf("first frame %d bytes, want the line after the long one", len(fr.b))
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(notes.all(), "dropped one line longer than") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := strings.Count(notes.all(), "dropped one line longer than"); n != 1 {
		t.Errorf("long-line warnings: %d (%q)", n, notes.all())
	}
	if n := strings.Count(notes.all(), "noise "); n > mcpStderrBurst+5 {
		t.Errorf("%d noise lines shown; the burst is %d", n, mcpStderrBurst)
	}
}

// TestMCPBridgeNoPings: idle close counts bytes, so the launcher writes no
// ping and answers none with a pong.
func TestMCPBridgeNoPings(t *testing.T) {
	spec := helperSpec(t, "echo")
	f := newFakeStream(t)
	c, s := f.dial()
	frames := pump(s)
	startServe(t, c, MCPServe{Spec: spec, Note: func(string) {}})
	// The server pings: the launcher must not answer.
	for i := 0; i < 3; i++ {
		if err := s.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case fr := <-frames:
		t.Fatalf("idle stream sent a frame: kind %d %q", fr.kind, fr.b)
	default:
	}
	if f.pings.Load() != 0 || f.pongs.Load() != 0 {
		t.Fatalf("idle launcher wrote %d pings and %d pongs", f.pings.Load(), f.pongs.Load())
	}
}

// A control error from the relay (mcp_busy) ends the stream with its code.
func TestMCPBridgeStreamError(t *testing.T) {
	f := newFakeStream(t)
	c, s := f.dial()
	_, done := startServe(t, c, MCPServe{Spec: MCPSpec{Name: "web", Argv: []string{os.Args[0]}}, Note: func(string) {}})
	if err := s.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","code":"mcp_busy"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		se, ok := err.(*MCPStreamError)
		if !ok || se.Code != "mcp_busy" {
			t.Fatalf("ServeMCP ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end")
	}
}

// mcpRelay is a gateway that refuses mcp streams with a reason, or serves
// them and keeps them open.
type mcpRelay struct {
	mu     sync.Mutex
	paths  []string
	refuse map[string]refusal // by server name
	fails  map[string]int     // refusals to give before serving, by name
	conns  chan *websocket.Conn
}

type refusal struct {
	status int
	reason string
}

func (m *mcpRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	m.mu.Lock()
	m.paths = append(m.paths, r.URL.Path)
	ref, refused := m.refuse[name]
	if m.fails[name] > 0 {
		m.fails[name]--
		ref, refused = refusal{http.StatusBadGateway, "relay_unreachable"}, true
	}
	m.mu.Unlock()
	if refused {
		routeRefusal(w, ref.status, ref.reason)
		return
	}
	up := websocket.Upgrader{Subprotocols: []string{relay.Subprotocol}}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	if m.conns != nil {
		m.conns <- conn
	}
}

// TestMCPBridgeRefusalsPrinted: each gateway reason prints its line (with the
// server's name) and the others go on.
func TestMCPBridgeRefusalsPrinted(t *testing.T) {
	for _, tc := range []struct {
		status int
		reason string
	}{
		{403, "mcp_bridge_off"}, {403, "mcp_server_blocked"}, {403, "not_your_agent"}, {409, "relay_too_old"}, {400, "websocket_required"}, {429, "too_many_streams"},
		{404, "not_found"}, {502, "relay_unreachable"}, {403, "relay_tls_required"},
	} {
		mr := &mcpRelay{refuse: map[string]refusal{"bad": {tc.status, tc.reason}}, conns: make(chan *websocket.Conn, 4)}
		r := newRig(t, mr)
		tun, err := NewTunnel(context.Background(), r.admin.gateway(r.caFile), r.bearer.token, testTarget)
		if err != nil {
			t.Fatal(err)
		}
		var notes syncNotes
		b := StartMCPBridges(context.Background(), MCPBridgeOptions{Tunnel: tun, Note: notes.add,
			Specs: []MCPSpec{{Name: "bad", Argv: []string{os.Args[0]}}, {Name: "good", Argv: []string{os.Args[0]}}}})
		if b.Opened != 1 || b.Refused != 1 {
			t.Errorf("%s: opened %d refused %d; want 1 and 1", tc.reason, b.Opened, b.Refused)
		}
		want := "[mcp bad] " + MCPLine(tc.reason, "bad")
		if MCPLine(tc.reason, "bad") == "" || !strings.Contains(notes.all(), want) {
			t.Errorf("%s: notes %q; want %q", tc.reason, notes.all(), want)
		}
		if strings.Contains(notes.all(), "[mcp good]") {
			t.Errorf("%s: the good server printed %q", tc.reason, notes.all())
		}
		b.Close()
		mr.mu.Lock()
		defer mr.mu.Unlock()
		if len(mr.paths) != 2 || mr.paths[0] != relay.Path(relay.RouteMCP+"/bad") || mr.paths[1] != relay.Path(relay.RouteMCP+"/good") {
			t.Errorf("%s: relay paths %v", tc.reason, mr.paths)
		}
	}
	// Anything else falls back to the attach wording of the status.
	mr := &mcpRelay{refuse: map[string]refusal{"x": {401, ""}}}
	r := newRig(t, mr)
	tun, _ := NewTunnel(context.Background(), r.admin.gateway(r.caFile), r.bearer.token, testTarget)
	var notes syncNotes
	b := StartMCPBridges(context.Background(), MCPBridgeOptions{Tunnel: tun, Note: notes.add, Specs: []MCPSpec{{Name: "x", Argv: []string{os.Args[0]}}}})
	if b.Refused != 1 || !strings.Contains(notes.all(), "did not accept your sign-in") {
		t.Errorf("sign-in refusal: %d %q", b.Refused, notes.all())
	}
}

// A relay that is not up yet (a new agent) is waited for; a reason that a
// wait cannot cure is not.
func TestMCPBridgeWaitsForARelayThatIsStarting(t *testing.T) {
	mr := &mcpRelay{fails: map[string]int{"web": 2}, refuse: map[string]refusal{"off": {403, "mcp_bridge_off"}}, conns: make(chan *websocket.Conn, 4)}
	r := newRig(t, mr)
	tun, _ := NewTunnel(context.Background(), r.admin.gateway(r.caFile), r.bearer.token, testTarget)
	var slept []time.Duration
	var notes syncNotes
	b := StartMCPBridges(context.Background(), MCPBridgeOptions{Tunnel: tun, Note: notes.add, Wait: time.Minute,
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil },
		Specs: []MCPSpec{{Name: "off", Argv: []string{os.Args[0]}}, {Name: "web", Argv: []string{os.Args[0]}}}})
	defer b.Close()
	if b.Opened != 1 || b.Refused != 1 || len(slept) != 2 {
		t.Fatalf("opened %d refused %d slept %v; want 1, 1 and two waits (none for mcp_bridge_off)", b.Opened, b.Refused, slept)
	}
	// With no Wait there is no retry.
	mr2 := &mcpRelay{fails: map[string]int{"web": 1}}
	r2 := newRig(t, mr2)
	tun2, _ := NewTunnel(context.Background(), r2.admin.gateway(r2.caFile), r2.bearer.token, testTarget)
	b2 := StartMCPBridges(context.Background(), MCPBridgeOptions{Tunnel: tun2, Note: func(string) {}, Specs: []MCPSpec{{Name: "web", Argv: []string{os.Args[0]}}}})
	if b2.Refused != 1 {
		t.Fatalf("no wait: refused %d", b2.Refused)
	}
}

// Close kills every child of every stream.
func TestMCPBridgesCloseKillsChildren(t *testing.T) {
	spec := helperSpec(t, "echo")
	mr := &mcpRelay{conns: make(chan *websocket.Conn, 4)}
	r := newRig(t, mr)
	tun, _ := NewTunnel(context.Background(), r.admin.gateway(r.caFile), r.bearer.token, testTarget)
	var notes syncNotes
	b := StartMCPBridges(context.Background(), MCPBridgeOptions{Tunnel: tun, Note: notes.add, KillGrace: 2 * time.Second, Specs: []MCPSpec{spec}})
	if b.Opened != 1 {
		t.Fatalf("opened %d: %q", b.Opened, notes.all())
	}
	s := <-mr.conns
	frames := pump(s)
	sendCtl(t, s, "open")
	pid := startedPID(t, next(t, frames, "start"))
	b.Close()
	waitGone(t, pid, "Close")
}

type syncNotes struct {
	mu sync.Mutex
	b  strings.Builder
}

func (n *syncNotes) add(s string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.b.WriteString(s + "\n")
}

func (n *syncNotes) all() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.b.String()
}
