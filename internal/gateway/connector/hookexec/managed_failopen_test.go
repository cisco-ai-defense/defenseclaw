// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedInfrastructureFailuresHonorSelectedMode(t *testing.T) {
	type failureCase struct {
		name     string
		rt       func() *stubRT
		mutate   func(*testing.T, *Options)
		kind     string
		requests int
	}
	cases := []failureCase{
		{name: "connection-refused", rt: func() *stubRT { return &stubRT{err: errors.New("connection refused")} }, requests: 1},
		{name: "timeout", rt: func() *stubRT { return &stubRT{err: context.DeadlineExceeded} }, requests: 1},
		{name: "http-503", rt: func() *stubRT { return &stubRT{status: 503, body: "unavailable"} }, requests: 1},
		{name: "http-401", rt: func() *stubRT { return &stubRT{status: 401, body: "unauthorized"} }, kind: "response", requests: 1},
		{name: "invalid-json", rt: func() *stubRT { return ok("invalid JSON") }, kind: "response", requests: 1},
		{name: "unverified-peer", rt: func() *stubRT { return &stubRT{err: errManagedGatewayPeerUnverified} }, requests: 1},
		{name: "invalid-client-identity", mutate: func(t *testing.T, o *Options) { o.HTTPClient = nil; o.ManagedGatewayServiceName = "" }},
		{name: "resolver-failure", mutate: func(t *testing.T, o *Options) { o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid" }},
		{name: "missing-home", mutate: func(t *testing.T, o *Options) { o.Home = filepath.Join(o.Home, "missing") }},
		{name: "disabled-home", mutate: func(t *testing.T, o *Options) {
			if err := os.WriteFile(filepath.Join(o.Home, ".disabled"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "empty-snapshot-token", mutate: func(t *testing.T, o *Options) { token := ""; o.AuthenticatedManagedToken = &token }},
		{name: "missing-token", mutate: func(t *testing.T, o *Options) {
			o.AuthenticatedManagedToken = nil
			o.Token = ""
			o.HookDir = filepath.Join(o.Home, "empty")
		}},
		{name: "oversized-token", mutate: func(t *testing.T, o *Options) {
			o.AuthenticatedManagedToken = nil
			if err := os.WriteFile(filepath.Join(o.HookDir, ".hook-"+o.Connector+".token"), []byte(strings.Repeat("x", int(managedHookTokenMaxBytes+1))), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversized-payload", kind: "oversized", mutate: func(t *testing.T, o *Options) { o.MaxBody = 1 }},
	}
	for connectorName, sp := range specs {
		for _, mode := range []string{"open", "closed"} {
			for _, tc := range cases {
				t.Run(connectorName+"/"+mode+"/"+tc.name, func(t *testing.T) {
					rt := ok(`{"action":"allow"}`)
					if tc.rt != nil {
						rt = tc.rt()
					}
					result := run(t, connectorName, rt, func(o *Options) {
						o.ManagedEnterprise = true
						o.FailMode = mode
						o.StrictAvailability = false
						token := "authenticated-test-token"
						o.AuthenticatedManagedToken = &token
						if tc.mutate != nil {
							tc.mutate(t, o)
						}
					})
					want := sp.openAllow
					if mode == "closed" {
						want = sp.unreachableStrict
						if tc.kind == "response" {
							want = sp.responseClosed
						}
						if tc.kind == "oversized" {
							want = sp.oversizedClosed
						}
					}
					wantBody := want.body
					if wantBody != "" {
						wantBody += "\n"
					}
					if result.code != want.exit || result.stdout != wantBody {
						t.Fatalf("code=%d stdout=%q, want code=%d stdout=%q; stderr=%q", result.code, result.stdout, want.exit, wantBody, result.stderr)
					}
					if rt.requests != tc.requests {
						t.Fatalf("gateway requests=%d, want %d", rt.requests, tc.requests)
					}
				})
			}
		}
	}
}

func TestManagedCodexPolicyDecisionSurvivesFailOpen(t *testing.T) {
	for _, action := range []string{"block", "confirm"} {
		t.Run(action, func(t *testing.T) {
			body := `{"action":"` + action + `","codex_output":{"decision":"block","reason":"policy requires approval"}}`
			result := run(t, "codex", ok(body), func(o *Options) {
				o.ManagedEnterprise = true
				o.FailMode = "open"
				token := "authenticated-test-token"
				o.AuthenticatedManagedToken = &token
			})
			if !strings.Contains(result.stdout, `"decision":"block"`) {
				t.Fatalf("policy verdict disappeared: code=%d stdout=%q", result.code, result.stdout)
			}
		})
	}
}

func TestManagedCodexActualConnectionRefusedHonorsMode(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			result := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
				o.ManagedEnterprise = true
				o.FailMode = mode
				o.APIAddr = address
				o.HTTPClient = &http.Client{Timeout: time.Second}
				token := "authenticated-test-token"
				o.AuthenticatedManagedToken = &token
			})
			wantCode := 0
			if mode == "closed" {
				wantCode = blockExit
			}
			if result.code != wantCode {
				t.Fatalf("code=%d, want %d; stderr=%q", result.code, wantCode, result.stderr)
			}
			if !strings.Contains(result.stderr, "gateway unreachable") {
				t.Fatalf("missing outage diagnostic: %q", result.stderr)
			}
			t.Logf("mode=%s exit=%d stdout=%q stderr=%q", mode, result.code, result.stdout, result.stderr)
		})
	}
}
