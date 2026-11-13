// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// The launcher's own attach client against the real admin handler (GAP-0085,
// GAP-0102, GAP-0134): the path mapping, the bearer, the client tag and the
// WebSocket go through the gateway's attach route to a relay stand-in that
// checks the session token the gateway mints.
func TestLauncherAttachesThroughTheRealAdminHandler(t *testing.T) {
	f := newSubstrateFixture(t)
	up := websocket.Upgrader{Subprotocols: []string{relay.Subprotocol}}
	var uploads int
	var uploaded int64
	var posts []string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, err := f.sessions.Verify(tok); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/dcrelay/1/status":
			_, _ = io.WriteString(w, `{"version":"dcrelay/1","tasks":{}}`)
		case "/dcrelay/1/files":
			uploads++
			n, _ := io.Copy(io.Discard, r.Body)
			uploaded += n
			w.WriteHeader(http.StatusNoContent)
		case "/dcrelay/1/task", "/dcrelay/1/poll", "/dcrelay/1/exec":
			posts = append(posts, r.Method+" "+r.URL.Path)
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "{}")
		case "/dcrelay/1/ws":
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.WriteMessage(websocket.BinaryMessage, relay.EncodeControl(relay.Control{Type: relay.CtlHello, Version: relay.Version, Session: "s-live"}))
			code := 0
			_ = c.WriteMessage(websocket.BinaryMessage, relay.Encode(relay.FrameData, []byte("hello from the relay\r\n")))
			_ = c.WriteMessage(websocket.BinaryMessage, relay.EncodeControl(relay.Control{Type: relay.CtlExit, Code: &code}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer peer.Close()
	f.api.substrateState().cfg.Relays = &dialRelay{addr: strings.TrimPrefix(peer.URL, "http://")}

	srv := httptest.NewTLSServer(f.admin)
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	gw := attach.Gateway{BaseURL: srv.URL, CAFile: ca}
	target := attach.Target{Atespace: "eng-web", Name: "alice-1"}
	bearer := func(context.Context) (string, error) { return "p-alice", nil }
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// Status goes through the route.
	st, err := attach.Status(ctx, attach.Options{Target: target, Gateway: gw, Bearer: bearer, NoBanner: true, NoAsks: true})
	if err != nil || st["version"] != "dcrelay/1" {
		t.Fatalf("status = %v, %v", st, err)
	}
	// Somebody else's agent is refused with the plain error.
	_, err = attach.Status(ctx, attach.Options{Target: target, Gateway: gw, Bearer: func(context.Context) (string, error) { return "p-bob", nil }, NoBanner: true, NoAsks: true})
	if !errors.Is(err, attach.ErrNoActor) {
		t.Fatalf("bob reached alice's agent: %v", err)
	}
	// The terminal: hello, output and the exit code.
	var out bytes.Buffer
	inR, inW, perr := os.Pipe() // a keyboard that stays quiet: the run ends with the agent
	if perr != nil {
		t.Fatal(perr)
	}
	defer inW.Close()
	defer inR.Close()
	res, err := attach.Attach(ctx, attach.Options{
		Target: target, Gateway: gw, Bearer: bearer, In: inR, Out: &out, Err: io.Discard,
		Transport: attach.TransportWebSocket, NoBanner: true, NoAsks: true,
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 || res.Session != "s-live" || !strings.Contains(out.String(), "hello from the relay") {
		t.Fatalf("attach = %+v, %q, %v", res, out.String(), err)
	}
	// A workspace upload is a PUT with a tar body, larger than the 1 MiB
	// cap of the JSON routes (GAP-0134).
	tun, err := attach.NewTunnel(ctx, gw, bearer, target)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	big := bytes.Repeat([]byte("t"), 2<<20)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, relay.RouteURL(tun.BaseURL(), relay.RouteFiles)+"?dir=/work", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := tun.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || uploads != 1 || uploaded != int64(len(big)) {
		t.Fatalf("upload answered %d; the relay saw %d uploads, %d bytes", resp.StatusCode, uploads, uploaded)
	}
	// run --task, the long-poll transport and exec are POSTs (GAP-0102):
	// through the tunnel they carry the client tag and pass the gate.
	for _, route := range []string{"task", "poll", "exec"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, relay.RouteURL(tun.BaseURL(), route), strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		resp, err := tun.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("POST %s through the tunnel answered %d", route, resp.StatusCode)
		}
	}
	if len(posts) != 3 {
		t.Errorf("the relay saw %v", posts)
	}
	// The gates stay: a write to the attach route without the client tag is
	// refused, and a JSON route still refuses a body that is not JSON.
	raw := func(method, path, contentType string, tag bool) int {
		req, _ := http.NewRequestWithContext(ctx, method, srv.URL+path, strings.NewReader("x"))
		req.Header.Set("Authorization", "Bearer p-alice")
		req.Header.Set("Content-Type", contentType)
		if tag {
			req.Header.Set("X-DefenseClaw-Client", "substrate-launcher")
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := raw(http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/attach/task", "application/json", false); code != http.StatusForbidden {
		t.Errorf("attach write without the client tag answered %d, want 403", code)
	}
	if code := raw(http.MethodPost, "/api/v1/substrate/actors", "application/x-tar", true); code != http.StatusUnsupportedMediaType {
		t.Errorf("a JSON route took a tar body: %d, want 415", code)
	}
}

// A gateway with no route to agents (no router address, GAP-0157) answers
// 503 attach_unavailable: the launcher stops at once and says what is
// missing, instead of waiting as for a full cluster.
func TestLauncherSaysWhenTheClusterHasNoAttachRoute(t *testing.T) {
	f := newSubstrateFixture(t)
	f.api.substrateState().cfg.Relays = nil
	srv := httptest.NewTLSServer(f.admin)
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := attach.Status(ctx, attach.Options{
		Target: attach.Target{Atespace: "eng-web", Name: "alice-1"}, Gateway: attach.Gateway{BaseURL: srv.URL, CAFile: ca},
		Bearer: func(context.Context) (string, error) { return "p-alice", nil }, NoBanner: true, NoAsks: true,
	})
	if !errors.Is(err, attach.ErrAttachOff) {
		t.Fatalf("err = %v, want ErrAttachOff", err)
	}
	if !strings.Contains(err.Error(), "attach is not set up") || strings.Contains(err.Error(), "full") {
		t.Errorf("message %q", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("the launcher waited %s for a refusal that does not change", time.Since(start))
	}
}
