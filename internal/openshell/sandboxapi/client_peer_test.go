// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type sandboxDialFails struct {
	next     http.RoundTripper
	failures int
	attempts int
}

func (t *sandboxDialFails) RoundTrip(req *http.Request) (*http.Response, error) {
	t.attempts++
	if t.attempts <= t.failures {
		return nil, errors.New("temporary verified gateway transport failure")
	}
	return t.next.RoundTrip(req)
}

// sandboxDialRefused refuses the first failures connections, as a listener
// that is not accepting yet does: none of the request goes out.
type sandboxDialRefused struct {
	next     http.RoundTripper
	failures int
	attempts int
}

func (t *sandboxDialRefused) RoundTrip(req *http.Request) (*http.Response, error) {
	t.attempts++
	if t.attempts <= t.failures {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}, Err: syscall.ECONNREFUSED}
	}
	return t.next.RoundTrip(req)
}

// GAP-1299, GAP-1549: a create whose connection was refused went out not at
// all, so it goes again; the daemon makes it once. One that still fails says
// why in plain words, without the loopback address or Go's dial text.
func TestARefusedConnectionIsTriedAgainAndSaidPlainly(t *testing.T) {
	var received atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer gateway.Close()
	u, err := url.Parse(gateway.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Gateway.Token = "sandbox-master-token"
	cfg.Gateway.APIPort = port
	for _, tc := range []struct {
		name               string
		failures, attempts int
		received           int32
		fails              bool
	}{
		{"refused once", 1, 2, 1, false},
		{"refused every time", 5, transportAttempts, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received.Store(0)
			client, err := ClientForConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			transport := &sandboxDialRefused{next: client.HTTP.Transport, failures: tc.failures}
			client.HTTP.Transport = transport
			_, err = client.Create(t.Context(), CreateRequest{Harness: "claudecode", Project: "/tmp"})
			if (err != nil) != tc.fails || transport.attempts != tc.attempts || received.Load() != tc.received {
				t.Fatalf("create: error=%v, attempts=%d, daemon requests=%d", err, transport.attempts, received.Load())
			}
			if tc.fails {
				e := AsError(err)
				if e.Code != CodeUnavailable || e.Detail != "nothing accepted the connection on its port" ||
					strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "dial") {
					t.Fatalf("unreachable daemon error = %+v", e)
				}
			}
		})
	}
}

// GAP-1551: a 1.0.4 daemon's strict decoder refuses the ready's new pack
// field; the client asks it again with the agent alone.
func TestReadyFallsBackForADaemonWithoutThePackField(t *testing.T) {
	var bodies []string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), `"pack"`) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":"invalid_request","error":"invalid JSON body: json: unknown field \"pack\""}`))
			return
		}
		_, _ = w.Write([]byte(`{"enabled":true}`))
	}))
	defer daemon.Close()
	st, err := NewClient(daemon.URL, "t").Ready(t.Context(), ReadyRequest{Harness: "codex", Pack: "codex-pack"})
	if err != nil || st == nil || !st.Enabled || len(bodies) != 2 || strings.Contains(bodies[1], "pack") || !strings.Contains(bodies[1], "codex") {
		t.Fatalf("ready = %+v, %v; bodies %q", st, err, bodies)
	}
}

func TestReadOnlySandboxRequestsRetryTransportWithoutReplayingCreate(t *testing.T) {
	var received atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("profile") == "blocked" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"policy_violation","message":"blocked"}`))
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer gateway.Close()
	u, err := url.Parse(gateway.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		request  func(*Client) error
		failures int
		attempts int
		received int32
		fails    bool
	}{
		{"status", func(c *Client) error { _, err := c.Status(t.Context()); return err }, 1, 2, 1, false},
		{"explain", func(c *Client) error {
			_, err := c.Explain(t.Context(), ExplainRequest{Harness: "claudecode"})
			return err
		}, 1, 2, 1, false},
		{"list", func(c *Client) error { _, err := c.List(t.Context()); return err }, 1, 2, 1, false},
		{"persistent outage", func(c *Client) error { _, err := c.Status(t.Context()); return err }, 3, 3, 0, true},
		{"policy refusal", func(c *Client) error {
			_, err := c.Explain(t.Context(), ExplainRequest{Harness: "claudecode", Profile: "blocked"})
			return err
		}, 0, 1, 1, true},
		{"create", func(c *Client) error {
			_, err := c.Create(t.Context(), CreateRequest{Harness: "claudecode", Project: "/tmp"})
			return err
		}, 1, 1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received.Store(0)
			cfg := &config.Config{}
			cfg.Gateway.Token = "sandbox-master-token"
			cfg.Gateway.APIPort = port
			client, err := ClientForConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			transport := &sandboxDialFails{next: client.HTTP.Transport, failures: tc.failures}
			client.HTTP.Transport = transport
			err = tc.request(client)
			if (err != nil) != tc.fails || transport.attempts != tc.attempts || received.Load() != tc.received {
				t.Fatalf("error=%v, attempts=%d, gateway requests=%d; want fails=%t, attempts=%d, gateway requests=%d",
					err, transport.attempts, received.Load(), tc.fails, tc.attempts, tc.received)
			}
		})
	}
}

func TestPerUserSandboxClientDoesNotForwardTheMasterTokenOnRedirect(t *testing.T) {
	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			foreignRequests.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+r.URL.Path, http.StatusFound)
	}))
	defer gateway.Close()
	u, err := url.Parse(gateway.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Gateway.Token = "sandbox-master-token"
	cfg.Gateway.APIPort = port
	client, err := ClientForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.Status(t.Context())
	if got := foreignRequests.Load(); got != 0 {
		t.Fatalf("a redirected sandbox request exposed the master token to %d other listeners", got)
	}
}

func TestPerUserSandboxClientRequiresConnectedPeerProof(t *testing.T) {
	previous := sandboxPeerClientFactory
	t.Cleanup(func() { sandboxPeerClientFactory = previous })
	address := ""
	sandboxPeerClientFactory = func(_ time.Duration, addr string) (*http.Client, error) {
		address = addr
		return nil, errors.New("connected sandbox gateway belongs to another account")
	}
	cfg := &config.Config{}
	cfg.Gateway.Token = "sandbox-master-token"
	cfg.Gateway.APIBind = "0.0.0.0"
	cfg.Gateway.APIPort = 18970
	client, err := ClientForConfig(cfg)
	if client != nil || err == nil || address != "127.0.0.1:18970" {
		t.Fatalf("sandbox client bypassed connected peer proof: client=%v address=%q error=%v", client, address, err)
	}
}
