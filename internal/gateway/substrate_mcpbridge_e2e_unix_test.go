// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// scopedSessions is gatewaySessions with the token's dc.scope and jti, as
// the actor's relay reads them, so a real relay serves mcp:NAME.
type scopedSessions struct{ f *substrateFixture }

func (g scopedSessions) Verify(_ context.Context, r *http.Request) (relay.Session, error) {
	s, err := g.f.sessions.Verify(relay.TokenFrom(r))
	if err != nil {
		return relay.Session{}, relay.ErrNoToken
	}
	return relay.Session{Person: s.Person, Actor: s.ActorRef, ActorUID: s.ActorUID, Expires: s.Expires,
		TokenID: s.TokenID, Scope: s.Scope}, nil
}

// TestMCPBridgeEndToEnd (B3.3 S4b): a fake laptop stdio MCP server behind
// the launcher's WebSocket, the gateway's bridge, a REAL relay (mcp/NAME,
// the agent's socket) and the real mcp-stdio shim as the agent's client.
// A tools/call the guard blocks is answered mcp_call_denied and never
// reaches the laptop; an allowed call reaches it byte for byte and its
// answer comes back to the agent byte for byte.
func TestMCPBridgeEndToEnd(t *testing.T) {
	b := newTixgBridge(t, false)
	st := b.fixture.api.substrateState()

	home, err := os.MkdirTemp("", "mcpe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	cfg := kit.DefaultConfig()
	cfg.Relay.Connector = "claudecode"
	cfg.Relay.ClaudeStateFile = filepath.Join(home, ".claude.json")
	rs := relay.NewServer(relay.Options{Config: cfg, Verifier: scopedSessions{b.fixture},
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warm: func(context.Context, string) error { return nil }})
	key, csr, err := relaytls.NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	pemCert, err := st.cfg.RelayCA.Sign(csr, subUID1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kp, err := relaytls.KeyPair(pemCert, key)
	if err != nil {
		t.Fatal(err)
	}
	// The relay's own listener behind the HTTP-parsing worker ingress
	// (GAP-1067).
	st.cfg.Relays = &dialRelay{addr: tixRelayBehindIngress(t, rs.Handler(), kp)}

	// The laptop: the launcher's WebSocket and a stdio MCP server behind it
	// (one message per line, as the launcher runs it).
	d := websocket.Dialer{Subprotocols: []string{relay.Subprotocol}, HandshakeTimeout: 10 * time.Second}
	laptop, resp, err := d.Dial("ws"+strings.TrimPrefix(b.srv.URL, "http")+"/api/v1/substrate/actors/eng-web/alice-1/attach/mcp/notes",
		http.Header{"Authorization": {"Bearer p-alice"}})
	if err != nil {
		t.Fatalf("bridge refused: %+v %v", resp, err)
	}
	t.Cleanup(func() { _ = laptop.Close() })
	answer := "{\"result\":{\"content\":[{\"text\":\"\\u00e9 \xc3\xa9 <&> \\u2028\",\"type\":\"text\"}]},  \"jsonrpc\":\"2.0\",\"id\":2}"
	srvIn, toSrv := io.Pipe()
	fromSrv, srvOut := io.Pipe()
	seen := make(chan string, 8)
	go func() { // the laptop's stdio MCP server
		r := bufio.NewReader(srvIn)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			seen <- l
			var m struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.Unmarshal([]byte(l), &m) == nil && m.Method == "tools/call" && string(m.ID) == "2" {
				_, _ = io.WriteString(srvOut, answer+"\n")
			}
		}
	}()
	go func() { // launcher: laptop server -> gateway
		r := bufio.NewReader(fromSrv)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if laptop.WriteMessage(websocket.BinaryMessage, []byte(strings.TrimSuffix(l, "\n"))) != nil {
				return
			}
		}
	}()
	go func() { // launcher: gateway -> laptop server
		defer toSrv.Close()
		for {
			kind, p, err := laptop.ReadMessage()
			if err != nil {
				return
			}
			if kind == websocket.BinaryMessage {
				_, _ = toSrv.Write(append(p, '\n'))
			}
		}
	}()

	// The agent: its MCP client starts the shim the relay configured.
	sock := filepath.Join(home, relay.MCPSocketDir, "notes.sock")
	deadline := time.Now().Add(10 * time.Second)
	// The relay makes the socket, then names the shim in the agent's MCP
	// configuration; the agent's client starts from that entry.
	for {
		_, err := os.Stat(sock)
		raw, _ := os.ReadFile(cfg.Relay.ClaudeStateFile)
		if err == nil && strings.Contains(string(raw), `"mcp-stdio"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay never made the agent's socket and MCP entry: %v %s", err, raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
	agentIn, toShim := io.Pipe()
	fromShim, agentOut := io.Pipe()
	var shimErr bytes.Buffer
	exited := make(chan int, 1)
	go func() { exited <- relay.MCPStdio("notes", agentIn, agentOut, &shimErr); _ = agentOut.Close() }()
	t.Cleanup(func() { _ = toShim.Close() })
	lines := bufio.NewReader(fromShim)
	readAgent := func() string {
		got := make(chan string, 1)
		go func() { l, _ := lines.ReadString('\n'); got <- l }()
		select {
		case l := <-got:
			return l
		case <-time.After(10 * time.Second):
			t.Fatalf("the agent got no answer (shim stderr %q)", shimErr.String())
			return ""
		}
	}

	blocked := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":` + tixgBlockedArgs + `}}`
	allowed := `{"id":2,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"id":"a b"},"name":"read_note"}}`
	if _, err := io.WriteString(toShim, blocked+"\n"+allowed+"\n"); err != nil {
		t.Fatal(err)
	}
	var denied struct {
		ID    int `json:"id"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	l := readAgent()
	if err := json.Unmarshal([]byte(l), &denied); err != nil || denied.ID != 1 ||
		!strings.HasPrefix(denied.Error.Message, "mcp_call_denied: The guard denied tool notes.exec: ") {
		t.Fatalf("blocked call answer %q, want mcp_call_denied for id 1", l)
	}
	if got := readAgent(); got != answer+"\n" {
		t.Fatalf("the agent got %q, want the laptop's answer byte for byte %q", got, answer+"\n")
	}
	select {
	case got := <-seen:
		if got != allowed+"\n" {
			t.Fatalf("the laptop server got %q, want the allowed call byte for byte %q", got, allowed+"\n")
		}
	default:
		t.Fatal("the laptop server never got the allowed call")
	}
	select {
	case extra := <-seen:
		t.Fatalf("the laptop server got another message %q (the blocked call?)", extra)
	default:
	}
	b.mu.Lock()
	var deniedRows int
	for _, a := range b.audits {
		if a["event"] == "substrate.mcp.denied" {
			deniedRows++
		}
	}
	b.mu.Unlock()
	if deniedRows != 1 {
		t.Fatalf("audit %v, want one substrate.mcp.denied", b.audits)
	}

	// The laptop goes: the relay ends the stream, the shim exits and the
	// agent's socket and MCP entry go.
	_ = laptop.Close()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the shim did not exit when the bridge ended")
	}
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		_, err := os.Lstat(sock)
		raw, _ := os.ReadFile(cfg.Relay.ClaudeStateFile)
		if os.IsNotExist(err) && !strings.Contains(string(raw), "mcp-stdio") {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("after the bridge ended: socket %v, entry %s", err, raw)
		}
	}
}
