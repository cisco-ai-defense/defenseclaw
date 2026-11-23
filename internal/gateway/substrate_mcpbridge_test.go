// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/calloutapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

const tixgBlockedArgs = `{"command":"rm -rf / --no-preserve-root"}`

type tixgBridge struct {
	srv     *httptest.Server
	agent   chan *websocket.Conn // the relay side, as the agent's shim
	scopes  []string
	mu      sync.Mutex
	audits  []map[string]any
	reg     registry.Registration
	fixture *substrateFixture
}

// newTixgBridge wires the admin listener to a fake relay that serves
// mcp/NAME as the agent end of the bridge.
func newTixgBridge(t *testing.T, managed bool) *tixgBridge {
	t.Helper()
	f := newSubstrateFixture(t)
	b := &tixgBridge{agent: make(chan *websocket.Conn, 1), fixture: f}
	up := websocket.Upgrader{Subprotocols: []string{relay.Subprotocol}}
	fake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := f.sessions.Verify(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err != nil || r.URL.Path != relay.Path(relay.RouteMCP+"/notes") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b.mu.Lock()
		b.scopes = append(b.scopes, s.Scope)
		b.mu.Unlock()
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		b.agent <- c
	}))
	// The relay end speaks relay TLS with a uid.<UID> certificate from the
	// gateway's relay CA, as a kit with relay.streams: tls does.
	ca := tixRelayCA(t)
	key, csr, err := relaytls.NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	pemCert, err := ca.Sign(csr, subUID1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kp, err := relaytls.KeyPair(pemCert, key)
	if err != nil {
		t.Fatal(err)
	}
	fake.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*kp}}
	fake.StartTLS()
	t.Cleanup(fake.Close)
	st := f.api.substrateState()
	st.cfg.Relays = &dialRelay{addr: strings.TrimPrefix(fake.URL, "https://")}
	st.cfg.RelayTLS, st.cfg.RelayCA = relaytls.ModeRequired, ca
	st.cfg.Managed = managed
	st.audit = func(_ context.Context, _, _ string, d map[string]any) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.audits = append(b.audits, d)
	}
	reg, ok, err := st.cfg.Registrations.Get(t.Context(), "eng-web", subUID1)
	if err != nil || !ok {
		t.Fatalf("fixture registration: %v %v", ok, err)
	}
	reg.RelayStreams = "mcp,port,tls"
	if err := st.cfg.Registrations.Put(t.Context(), reg); err != nil {
		t.Fatal(err)
	}
	b.reg = reg
	b.srv = httptest.NewServer(f.admin)
	t.Cleanup(b.srv.Close)
	return b
}

// open dials the bridge as the launcher (the laptop end) and returns both
// ends, or the HTTP refusal.
func (b *tixgBridge) open(t *testing.T) (laptop, agent *websocket.Conn, resp *http.Response) {
	t.Helper()
	d := websocket.Dialer{Subprotocols: []string{relay.Subprotocol}, HandshakeTimeout: 10 * time.Second}
	laptop, resp, err := d.Dial("ws"+strings.TrimPrefix(b.srv.URL, "http")+"/api/v1/substrate/actors/eng-web/alice-1/attach/mcp/notes",
		http.Header{"Authorization": {"Bearer p-alice"}})
	if err != nil {
		return nil, nil, resp
	}
	t.Cleanup(func() { _ = laptop.Close() })
	select {
	case agent = <-b.agent:
		t.Cleanup(func() { _ = agent.Close() })
	case <-time.After(10 * time.Second):
		t.Fatal("the gateway never dialed the relay's mcp route")
	}
	return laptop, agent, resp
}

func tixgRead(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, p, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(p, &m); err != nil {
		t.Fatalf("not one JSON-RPC object: %q", p)
	}
	return m
}

// TestMCPBridgeDenyByToolRule (B3.3 S4a): a tools/call over the bridge is
// judged by the same verdict as a direct MCP call in the actor. The one the
// guard blocks is answered with mcp_call_denied and never reaches the laptop
// server; an allowed call and non-call messages pass; the laptop sees the
// message the gateway judged, not a parser-ambiguous original.
func TestMCPBridgeDenyByToolRule(t *testing.T) {
	b := newTixgBridge(t, false)
	direct := b.fixture.api.substrateMCPVerdict(t.Context(), b.reg, substrateCalloutRequest{V: "1",
		MCP: calloutapi.MCP{Server: "notes", Tool: "exec", Transport: "stdio"}, Args: json.RawMessage(tixgBlockedArgs)})
	if direct.Verdict != "deny" {
		t.Fatalf("direct MCP verdict %+v, want deny (the test needs a blocked call)", direct)
	}
	laptop, agent, resp := b.open(t)
	if laptop == nil {
		t.Fatalf("bridge refused: %+v", resp)
	}
	send := func(s string) {
		if err := agent.WriteMessage(websocket.BinaryMessage, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":` + tixgBlockedArgs + `}}`)
	denied := tixgRead(t, agent)
	e, _ := denied["error"].(map[string]any)
	if denied["id"] != float64(2) || e == nil || !strings.HasPrefix(e["message"].(string), "mcp_call_denied: The guard denied tool notes.exec: ") ||
		!strings.Contains(e["message"].(string), direct.Reason) {
		t.Fatalf("blocked call answer %v, want mcp_call_denied with %q", denied, direct.Reason)
	}
	// A notification form of the same call is judged too, and gets no answer.
	send(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec","arguments":` + tixgBlockedArgs + `}}`)
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_note","arguments":{"id":"a"}}}`)
	// Duplicate keys: the laptop receives the one value that was judged.
	send(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec","name":"read_note","arguments":{"id":"b"}}}`)
	send(`[{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"exec","arguments":` + tixgBlockedArgs + `}}]`)
	if m := tixgRead(t, agent); m["id"] != nil || !strings.HasPrefix(m["error"].(map[string]any)["message"].(string), "invalid_message") {
		t.Fatalf("batch answer %v", m)
	}
	send(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_note","arguments":{"x":"` + strings.Repeat("a", 1<<20) + `"}}}`)
	if m := tixgRead(t, agent); !strings.HasPrefix(m["error"].(map[string]any)["message"].(string), "message_too_large") {
		t.Fatalf("oversize answer %v", m)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	var got []string
	for len(got) < 4 {
		m := tixgRead(t, laptop)
		p, _ := m["params"].(map[string]any)
		name, _ := p["name"].(string)
		got = append(got, m["method"].(string)+" "+name)
		if m["method"] == "tools/call" && strings.Contains(strings.ToLower(name), "exec") {
			t.Fatalf("a blocked call reached the laptop: %v", m)
		}
	}
	if want := "initialize |tools/call read_note|tools/call read_note|notifications/initialized "; strings.Join(got, "|") != want {
		t.Fatalf("laptop saw %q, want %q", strings.Join(got, "|"), want)
	}
	// The laptop's answer reaches the agent unchanged.
	if err := laptop.WriteMessage(websocket.BinaryMessage, []byte(`{"jsonrpc":"2.0","id":3,"result":{"content":[]}}`)); err != nil {
		t.Fatal(err)
	}
	if m := tixgRead(t, agent); m["id"] != float64(3) || m["result"] == nil {
		t.Fatalf("answer %v", m)
	}
	_ = laptop.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.mu.Lock()
		var denials, closes int
		for _, a := range b.audits {
			switch a["event"] {
			case "substrate.mcp.denied":
				denials++
			case "substrate.mcp.close":
				closes++
			}
		}
		scopes := append([]string(nil), b.scopes...)
		b.mu.Unlock()
		if denials == 4 && closes == 1 {
			if len(scopes) != 1 || scopes[0] != "mcp:notes" {
				t.Fatalf("relay token scopes %v", scopes)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit rows: %d denied, %d close (want 4, 1)", denials, closes)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMCPBridgeManagedDefaultOff (B3.3 S4a, D3-2): in a managed install the
// bridge is off until an admin sets mcp_bridge.enabled: on; the relay is
// never dialed.
func TestMCPBridgeManagedDefaultOff(t *testing.T) {
	b := newTixgBridge(t, true)
	laptop, _, resp := b.open(t)
	if laptop != nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("managed default: laptop %v resp %+v, want 403", laptop != nil, resp)
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Reason != "mcp_bridge_off" {
		t.Fatalf("refusal %q, want mcp_bridge_off", body.Reason)
	}
	if len(b.agent) != 0 || len(b.scopes) != 0 {
		t.Fatal("the relay was dialed with the bridge off")
	}
}

// TestSubstrateMCPCanonical: one JSON value, last duplicate wins, numbers
// kept as written, no trailing data.
func TestSubstrateMCPCanonical(t *testing.T) {
	for in, want := range map[string]string{
		`{"id":12345678901234567890,"method":"a","method":"tools/call"}`: `{"id":12345678901234567890,"method":"tools/call"}`,
		`{"m":"<&>"}`: `{"m":"<&>"}`,
	} {
		got, _, err := substrateMCPCanonical([]byte(in))
		if err != nil || string(got) != want {
			t.Fatalf("%s -> %s %v, want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{`{"a":1}{"b":2}`, `{"a":1} x`, `{`, ``} {
		if _, _, err := substrateMCPCanonical([]byte(bad)); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
}
