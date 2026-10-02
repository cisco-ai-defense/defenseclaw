// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type foreignSessionRoundTrip func(*http.Request) (*http.Response, error)

func (f foreignSessionRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestExchangeForeignHookSessionUsesOnlyManagedTransportAuthority(t *testing.T) {
	for _, managedStandalone := range []bool{false, true} {
		name := "scoped token"
		if managedStandalone {
			name = "hook socket"
		}
		t.Run(name, func(t *testing.T) {
			token := "per-user-hook-token"
			opts := Options{ManagedEnterprise: true, ManagedStandalone: managedStandalone,
				APIAddr: "127.0.0.1:18970", AuthenticatedManagedToken: &token}
			opts.HTTPClient = &http.Client{Transport: foreignSessionRoundTrip(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api/v1/foreign-hook-session/claudecode" || req.Method != http.MethodPost {
					t.Fatalf("wrong scoped route: %s %s", req.Method, req.URL.Path)
				}
				wantAuth := "Bearer " + token
				if managedStandalone {
					wantAuth = ""
				}
				if got := req.Header.Get("Authorization"); got != wantAuth {
					t.Fatalf("authorization = %q, want %q", got, wantAuth)
				}
				body, err := io.ReadAll(req.Body)
				if err != nil || string(body) != `{"key":{"connector":"claudecode"}}` {
					t.Fatalf("update = %q, error %v", body, err)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"deny":false}`))}, nil
			})}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, err := ExchangeForeignHookSession(ctx, opts, "claudecode", []byte(`{"key":{"connector":"claudecode"}}`))
			if err != nil || string(response) != `{"deny":false}` {
				t.Fatalf("exchange = %q, error %v", response, err)
			}
		})
	}
}
