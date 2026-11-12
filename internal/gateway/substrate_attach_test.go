// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

type dialRelay struct {
	addr  string
	calls []string
}

func (d *dialRelay) DialRelay(ctx context.Context, atespace, name string) (net.Conn, error) {
	d.calls = append(d.calls, atespace+"/"+name)
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}

// GAP-0085/0086: the launcher attaches through the admin listener; the
// gateway mints the person-bound session token the relay checks, and only
// the actor's person (or an administrator) gets through.
func TestSubstrateAttachThroughTheAdminListener(t *testing.T) {
	var seen []string
	f := newSubstrateFixture(t)
	up := websocket.Upgrader{}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s, err := f.sessions.Verify(tok)
		if err != nil {
			w.WriteHeader(401)
			return
		}
		seen = append(seen, r.URL.Path+" "+s.Person+" "+s.ActorUID)
		if r.URL.Path == "/dcrelay/1/ws" {
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			_, msg, _ := c.ReadMessage()
			_ = c.WriteMessage(websocket.TextMessage, append([]byte("echo:"), msg...))
			_ = c.Close()
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer relay.Close()
	d := &dialRelay{addr: strings.TrimPrefix(relay.URL, "http://")}
	f.api.substrateState().cfg.Relays = d
	srv := httptest.NewServer(f.admin)
	defer srv.Close()

	get := func(tok, path string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := get("p-alice", "/api/v1/substrate/actors/eng-web/alice-1/attach/status"); c != 200 {
		t.Fatalf("own status %d", c)
	}
	if len(seen) != 1 || seen[0] != "/dcrelay/1/status "+alice.ID()+" "+subUID1 {
		t.Fatalf("relay saw %v", seen)
	}
	if c := get("p-bob", "/api/v1/substrate/actors/eng-web/alice-1/attach/status"); c != http.StatusNotFound {
		t.Fatalf("bob attaches to alice's actor: %d", c)
	}
	if c := get("p-admin", "/api/v1/substrate/actors/eng-web/alice-1/attach/status"); c != 200 {
		t.Fatalf("admin attach %d", c)
	}
	if !strings.Contains(seen[len(seen)-1], admin.ID()) {
		t.Fatalf("admin attach not as themselves: %v", seen)
	}
	if c := get("p-alice", "/api/v1/substrate/actors/eng-web/alice-1/attach/readyz"); c != http.StatusNotFound {
		t.Fatalf("unlisted relay path %d", c)
	}
	if c := get("", "/api/v1/substrate/actors/eng-web/alice-1/attach/status"); c != http.StatusUnauthorized {
		t.Fatalf("no sign-in %d", c)
	}
	// WebSocket through the proxy; a token the launcher sends is not
	// forwarded (only the gateway's).
	h := http.Header{"Authorization": {"Bearer p-alice"}, "Sec-WebSocket-Protocol": {"dcrelay.token.forged, dcrelay.v1"}}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/api/v1/substrate/actors/eng-web/alice-1/attach", h)
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	_ = ws.WriteMessage(websocket.TextMessage, []byte("hi"))
	_, msg, err := ws.ReadMessage()
	if err != nil || string(msg) != "echo:hi" {
		t.Fatalf("ws echo %q %v", msg, err)
	}
	_ = ws.Close()
	if len(d.calls) == 0 || d.calls[0] != "eng-web/alice-1" {
		t.Fatalf("dials %v", d.calls)
	}
}
