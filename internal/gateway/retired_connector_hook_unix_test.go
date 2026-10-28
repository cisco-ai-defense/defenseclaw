//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// until 1.1: the retired hook routes on the hook socket and across a
// gateway restart (retired_connector_hook.go). Delete with that file.

// On a managed Unix host the 1.0.3 OmniGent module posts over the hook
// socket with no token. The socket's handler answers the retired routes
// before its peer checks: a verified peer and one the kernel did not name
// both get the block, never the 403 an old hook in fail mode open allows on.
func TestRetiredConnectorHookRoutesBlockOverTheHookSocket(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	handler := api.managedHookSocketHandler(newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), func(h http.Handler) http.Handler { return h })
	for _, path := range retiredHookPaths {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"phase":"pre_tool"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "omnigent-policy/1.0")
		request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: 1001, Name: "alice"}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireRetiredBlock(t, path+" from a verified peer", response)

		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		requireRetiredBlock(t, path+" from an unverified peer", response)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(`{}`)))
	if response.Code != http.StatusForbidden {
		t.Fatalf("codex hook from an unverified peer: status %d, want 403", response.Code)
	}
}

// A gateway that starts again (an upgrade, a restart) answers the retired
// routes with the block on the TCP API and the hook socket at once: the
// routes need no state the start builds, and no token (the teardown revoked
// it). Both runs serve the same address and socket.
func TestRetiredConnectorHookRoutesBlockAcrossAGatewayRestart(t *testing.T) {
	addr := freeLoopbackAddr(t)
	socket := filepath.Join(shortGatewaySocketDir(t), "hook.sock")
	tcp := &http.Client{Timeout: 5 * time.Second}
	unix := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	large := append([]byte(`{"tool_input":"`), bytes.Repeat([]byte("y"), 2<<20)...)
	large = append(large, `"}`...)
	for run := 1; run <= 2; run++ {
		_, _, runErr, cancel := runHookSocketTestServerAt(t, true, addr, socket)
		deadline := time.Now().Add(10 * time.Second)
		for {
			response, tcpErr := tcp.Get("http://" + addr + "/health")
			if tcpErr == nil {
				_ = response.Body.Close()
			}
			if tcpErr == nil && hookSocketRoundTrip(socket) == nil {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("run %d: the gateway never served (tcp: %v)", run, tcpErr)
			}
			time.Sleep(20 * time.Millisecond)
		}
		for _, path := range retiredHookPaths {
			for _, body := range [][]byte{[]byte(`{}`), large} {
				status, data := postRetired(t, tcp, "http://"+addr+path, body)
				requireRetiredBlockBody(t, path+" over TCP", status, data)
				status, data = postRetired(t, unix, "http://127.0.0.1"+path, body)
				requireRetiredBlockBody(t, path+" over the hook socket", status, data)
			}
			request, err := http.NewRequest(http.MethodPost, "http://"+addr+path, strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+strings.Repeat("d", 64))
			response, err := tcp.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(response.Body)
			_ = response.Body.Close()
			requireRetiredBlockBody(t, path+" with the revoked token", response.StatusCode, buf.Bytes())
		}
		cancel()
		select {
		case err := <-runErr:
			if err != nil {
				t.Fatalf("run %d: Run after cancel = %v", run, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("run %d: Run did not return after cancel", run)
		}
	}
}

// The real gateway, which sets no read timeout on the TCP API or the hook
// socket, answers a retired route whose body never comes once the drain
// deadline passes, on both.
func TestRetiredConnectorHookRoutesBoundAStalledBodyOnTheGateway(t *testing.T) {
	shortenRetiredDrain(t, 200*time.Millisecond)
	addr := freeLoopbackAddr(t)
	socket := filepath.Join(shortGatewaySocketDir(t), "hook.sock")
	_, _, _, cancel := runHookSocketTestServerAt(t, true, addr, socket)
	defer cancel()
	tcp := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := tcp.Get("http://" + addr + "/health")
		if err == nil {
			_ = response.Body.Close()
		}
		if err == nil && hookSocketRoundTrip(socket) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the gateway never served (tcp: %v)", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	requireRetiredBlockForStalledBodies(t, "TCP API", "tcp", addr)
	requireRetiredBlockForStalledBodies(t, "hook socket", "unix", socket)
}

// The sandbox ingress bounds the drain by the same deadline, not by its
// two-minute read timeout.
func TestRetiredConnectorHookRoutesBoundAStalledBodyOnTheSandboxIngress(t *testing.T) {
	shortenRetiredDrain(t, 200*time.Millisecond)
	f := newSandboxIngressFixture(t)
	server := httptest.NewServer(f.handler)
	t.Cleanup(server.Close)
	requireRetiredBlockForStalledBodies(t, "sandbox ingress", "tcp", server.Listener.Addr().String())
}

// The sandbox ingress answers the retired routes with the block too, before
// the binding check: an old OpenShell OpenHands hook gets the removal
// reason, with its binding, a revoked one or none.
func TestRetiredConnectorHookRoutesBlockOnTheSandboxIngress(t *testing.T) {
	f := newSandboxIngressFixture(t)
	for _, path := range retiredHookPaths {
		for _, token := range []string{"", f.claudeTok, "dcsb_" + strings.Repeat("c", 43), "not-a-sandbox-token"} {
			requireRetiredBlock(t, path+" on the sandbox ingress", f.do(t, http.MethodPost, path, token, `{"hook_event_name":"PreToolUse"}`))
		}
	}
	if rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", "", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("claude-code hook on the ingress without a binding: status %d, want 401", rec.Code)
	}
}
