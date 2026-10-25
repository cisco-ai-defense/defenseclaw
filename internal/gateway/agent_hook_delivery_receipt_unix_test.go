// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A native managed hook uses HTTP/1 over the Unix hook socket. Exercise the
// receipt there, not only through the TCP fixture used by the other tests.
func TestManagedNativeAllowReceiptOverUnixSocket(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delay time.Duration
	}{
		{name: "fast peer lookup"},
		{name: "slow peer lookup", delay: 400 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) { testManagedNativeAllowReceiptOverUnixSocket(t, tc.delay) })
	}
}

func testManagedNativeAllowReceiptOverUnixSocket(t *testing.T, lookupDelay time.Duration) {
	f := newManagedHookAuditFixture(t, nil)
	dir, err := os.MkdirTemp("/tmp", "dc-h-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	handler := apiBodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.api.handleUnifiedConnectorHook("claudecode").ServeHTTP(&statusWriter{ResponseWriter: w}, r)
	}), apiRequestBodyMaxBytes, otlpRequestBodyMaxBytes)
	server := &http.Server{
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return withManagedHookConnPeer(ctx, func() managedHookPeer {
				time.Sleep(lookupDelay)
				return managedHookPeer{UID: os.Getuid()}
			})
		},
		Handler: managedHookEarlyReceipt(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The production peer middleware resolves the account on first use.
			// Preserve the fixture's token to isolate the receipt behavior.
			_, _ = managedHookRequestPeer(r.Context())
			handler.ServeHTTP(w, r)
		})),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}}
	const session = "native-unix-allow"
	token := "authenticated-generation-token"
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := hookexec.Run(t.Context(), hookexec.Options{
		Connector: "claudecode", Event: "PreToolUse", APIAddr: "127.0.0.1:0",
		FailMode: "closed", ManagedEnterprise: true, AuthenticatedManagedToken: &token,
		Home: home, HookDir: filepath.Join(home, "hooks"),
		Stdin:  strings.NewReader(managedHookBody(session, "PreToolUse")),
		Stdout: &stdout, Stderr: &stderr, HTTPClient: client, StartedAt: time.Now(),
	})
	if code != 0 || strings.Contains(stdout.String()+stderr.String(), "deny") {
		t.Fatalf("native Unix answer code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := f.audited(t, session)[session]; got == "allow" {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("native Unix audit = %q, want acknowledged allow", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestManagedEarlyReceiptKeepsFinalPeerRefusal(t *testing.T) {
	for _, verified := range []bool{false, true} {
		name := "unverified peer"
		if verified {
			name = "verified peer refused by handler"
		}
		t.Run(name, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "dc-h-*")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "hook.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{
				ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
					if verified {
						return withManagedHookConnPeer(ctx, func() managedHookPeer { return managedHookPeer{UID: os.Getuid()} })
					}
					return ctx
				},
				Handler: managedHookEarlyReceipt(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "peer refused", http.StatusForbidden)
				})),
			}
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() { _ = server.Close() })
			client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", path)
				}}}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://unix/api/v1/claude-code/hook", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
			var hints int
			request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
				Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
					if code == http.StatusEarlyHints {
						hints++
					}
					return nil
				},
			}))
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusForbidden || hints != map[bool]int{false: 0, true: 1}[verified] {
				t.Fatalf("status=%d early hints=%d for verified=%v", response.StatusCode, hints, verified)
			}
		})
	}
}
