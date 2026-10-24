// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// until 1.1: the retired OpenHands and OmniGent hook routes
// (retired_connector_hook.go). Delete with that file.

var retiredHookPaths = []string{"/api/v1/openhands/hook", "/api/v1/omnigent/hook"}

// requireRetiredBlock checks the answer is the block verdict both older
// clients read: action block (the OmniGent module and the OpenHands hook)
// and a deny hook_output (the OpenHands hook's Secure Client render), with
// the removal reason.
func requireRetiredBlock(t *testing.T, what string, response *httptest.ResponseRecorder) {
	t.Helper()
	requireRetiredBlockBody(t, what, response.Code, response.Body.Bytes())
}

func requireRetiredBlockBody(t *testing.T, what string, status int, body []byte) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("%s: status %d (%s); an older hook in fail mode open allows on any status but 2xx", what, status, body)
	}
	var verdict struct {
		Action     string `json:"action"`
		Reason     string `json:"reason"`
		HookOutput struct {
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		} `json:"hook_output"`
	}
	if err := json.Unmarshal(body, &verdict); err != nil {
		t.Fatalf("%s: body %q: %v", what, body, err)
	}
	if verdict.Action != "block" || verdict.HookOutput.Decision != "deny" ||
		!strings.Contains(verdict.Reason, "support was removed in DefenseClaw 1.0.4") || verdict.HookOutput.Reason != verdict.Reason {
		t.Fatalf("%s: verdict %+v, want a block with the removal reason", what, verdict)
	}
}

// retiredHookCall is one way an old hook, or anything else, calls a retired
// route: every credential state and caller.
type retiredHookCall struct {
	name, method, remote, header, value string
}

func retiredHookCalls(master string) []retiredHookCall {
	return []retiredHookCall{
		{"no token", http.MethodPost, "127.0.0.1:40000", "", ""},
		{"the revoked token", http.MethodPost, "127.0.0.1:40000", "Authorization", "Bearer " + strings.Repeat("a", 64)},
		{"a valid token", http.MethodPost, "127.0.0.1:40000", "Authorization", "Bearer " + master},
		{"a valid token in X-DC-Auth", http.MethodPost, "127.0.0.1:40000", "X-DC-Auth", master},
		{"a sandbox credential", http.MethodPost, "127.0.0.1:40000", "Authorization", "Bearer dcsb_" + strings.Repeat("b", 43)},
		{"a malformed header", http.MethodPost, "127.0.0.1:40000", "Authorization", "Basic Zm9vOmJhcg=="},
		{"GET", http.MethodGet, "127.0.0.1:40000", "", ""},
		{"ipv6 loopback", http.MethodPost, "[::1]:40000", "", ""},
		{"another address", http.MethodPost, "10.0.0.5:40000", "", ""},
	}
}

func (c retiredHookCall) request(path string) *http.Request {
	request := httptest.NewRequest(c.method, path, strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"bash"}`))
	request.RemoteAddr = c.remote
	request.Header.Set("Content-Type", "application/json")
	if c.header != "" {
		request.Header.Set(c.header, c.value)
	}
	return request
}

// Safety net: an OmniGent process that imported the 1.0.3 policy module
// before the upgrade, or an OpenHands hook the teardown could not reach,
// still posts to its old route. The gateway answers with a block before any
// credential check: with no token, the revoked one, a valid one, a sandbox
// credential, from any address, never the 401 an old hook in fail mode
// open turns into an allow. Other routes keep their authentication.
func TestRetiredConnectorHookRoutesBlockOverTCP(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.scannerCfg = &config.Config{}
	api.scannerCfg.Gateway.Token = "master-token"
	reached := false
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		http.NotFound(w, r)
	}))
	for _, path := range retiredHookPaths {
		for _, call := range retiredHookCalls("master-token") {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, call.request(path))
			requireRetiredBlock(t, path+" with "+call.name, response)
		}
	}
	if reached {
		t.Fatal("a retired hook request reached the routes behind authentication")
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(`{}`))
	request.RemoteAddr = "127.0.0.1:40000"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || reached {
		t.Fatalf("codex hook without a token: status %d, reached %v; want 401", response.Code, reached)
	}
}

// postRetired posts body to url and returns the answer; the server must keep
// the connection (no Connection: close), so the client reads the block and
// never a reset.
func postRetired(t *testing.T, client *http.Client, url string, body []byte) (int, []byte) {
	t.Helper()
	response, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s with %d bytes: %v", url, len(body), err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the answer to %s: %v", url, err)
	}
	if response.Close {
		t.Fatalf("POST %s with %d bytes: the server closed the connection after the answer", url, len(body))
	}
	return response.StatusCode, data
}

// A large hook body (the old hooks send up to 1 MiB) gets the block on a
// connection the server keeps: answering with most of the body unread made
// the server close the connection, and a client still sending sees a reset.
// The metrics middleware wraps the writer the retired routes answer on: it
// must let them set the drain deadline, or they skip the drain and the
// client sees the reset.
func TestRetiredConnectorHookRoutesKeepTheConnectionForTheBlock(t *testing.T) {
	large := append([]byte(`{"tool_input":"`), bytes.Repeat([]byte("x"), 2<<20)...)
	large = append(large, `"}`...)
	for name, server := range retiredHookTCPServers(t) {
		client := server.Client()
		for _, path := range retiredHookPaths {
			for _, body := range [][]byte{[]byte(`{}`), large} {
				status, data := postRetired(t, client, server.URL+path, body)
				requireRetiredBlockBody(t, path+" "+name, status, data)
			}
		}
	}
}

// retiredHookTCPServers serves the TCP API's authentication in front of a
// not-found handler, with the metrics middleware off and on.
func retiredHookTCPServers(t *testing.T) map[string]*httptest.Server {
	t.Helper()
	servers := map[string]*httptest.Server{}
	for _, metrics := range []bool{false, true} {
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
		api.scannerCfg = &config.Config{}
		api.scannerCfg.Gateway.Token = "master-token"
		name := "without metrics"
		if metrics {
			runtime, _ := newProxyGeneratedTraceRuntime(t)
			api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
			name = "with metrics"
		}
		server := httptest.NewServer(api.metricsMiddleware(api.tokenAuth(http.NotFoundHandler())))
		t.Cleanup(server.Close)
		servers[name] = server
	}
	return servers
}

// shortenRetiredDrain sets the retired routes' drain deadline for one test.
func shortenRetiredDrain(t *testing.T, d time.Duration) {
	t.Helper()
	restore := retiredConnectorDrainTimeout
	retiredConnectorDrainTimeout = d
	t.Cleanup(func() { retiredConnectorDrainTimeout = restore })
}

// stalledRetiredHookBodies are the ways a caller can declare a body to a
// retired route and not send it: nothing after the headers with a large or a
// small length (net/http itself discards up to 256 KiB of an unread body
// before it answers), part of the body, an unfinished chunked body, and one
// byte at a time for ever.
var stalledRetiredHookBodies = []struct {
	name, header, sent string
	trickle            bool
}{
	{"a 1 MiB body that never comes", "Content-Length: 1048576", "", false},
	{"a small body that never comes", "Content-Length: 4096", "", false},
	{"part of a body", "Content-Length: 1048576", strings.Repeat("x", 1000), false},
	{"an unfinished chunked body", "Transfer-Encoding: chunked", "10\r\n0123456789abcdef\r\n", false},
	{"a body one byte at a time", "Content-Length: 1048576", "", true},
}

// requireRetiredBlockForStalledBodies sends every stalled body to every
// retired route at address and requires the block within a few seconds. The
// routes answer before any credential check, so a caller with no credential
// must not hold the connection by never finishing its body.
func requireRetiredBlockForStalledBodies(t *testing.T, what, network, address string) {
	t.Helper()
	for _, path := range retiredHookPaths {
		for _, stall := range stalledRetiredHookBodies {
			status, body, err := stalledRetiredHookAnswer(network, address, path, stall.header, stall.sent, stall.trickle)
			if err != nil {
				t.Fatalf("%s %s with %s: no answer: %v; the route waits on the body without a bound", what, path, stall.name, err)
			}
			requireRetiredBlockBody(t, what+" "+path+" with "+stall.name, status, body)
		}
	}
}

func stalledRetiredHookAnswer(network, address, path, header, sent string, trickle bool) (int, []byte, error) {
	conn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	stop := make(chan struct{})
	defer close(stop)
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n%s\r\n\r\n%s", path, header, sent); err != nil {
		return 0, nil, err
	}
	if trickle {
		go func() {
			tick := time.NewTicker(20 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					if _, err := conn.Write([]byte("x")); err != nil {
						return
					}
				}
			}
		}()
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, body, err
}

// A caller that declares a body and stalls gets the block once the drain
// deadline passes, on the TCP API with and without the metrics middleware.
func TestRetiredConnectorHookRoutesBoundAStalledBodyOverTCP(t *testing.T) {
	shortenRetiredDrain(t, 200*time.Millisecond)
	for name, server := range retiredHookTCPServers(t) {
		requireRetiredBlockForStalledBodies(t, "TCP "+name, "tcp", server.Listener.Addr().String())
	}
}

// The drain deadline is the retired request's own: the next request on the
// same connection, sent after it passed, is read and answered.
func TestRetiredConnectorHookDrainDeadlineEndsWithTheRequest(t *testing.T) {
	shortenRetiredDrain(t, 100*time.Millisecond)
	for name, server := range retiredHookTCPServers(t) {
		conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			if i > 0 {
				time.Sleep(300 * time.Millisecond)
			}
			if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", retiredHookPaths[i]); err != nil {
				t.Fatalf("%s: request %d: %v", name, i+1, err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatalf("%s: request %d on a kept connection: %v", name, i+1, err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			requireRetiredBlockBody(t, name, response.StatusCode, body)
		}
		_ = conn.Close()
	}
}
