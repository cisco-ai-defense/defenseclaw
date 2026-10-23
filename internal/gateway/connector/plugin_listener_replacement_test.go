// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A valid proof on one TCP connection cannot authorize a later connection.
// The gateway can close its listener after answering the challenge while a
// second account takes the port. That later listener must receive no bearer,
// payload, or chance to return an allow verdict.
func TestManagedPluginProofStaysOnTheProvenConnection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the accepted-socket rebind fixture uses Unix SO_REUSEADDR")
	}
	nodeForTest(t)
	for _, tc := range []struct{ asset, scope string }{
		{"opencode-plugin.js", "opencode"}, {"amp-plugin.ts", "amp"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			const credential = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			root := testenv.PrivateTempDir(t)
			tokenPath := filepath.Join(root, ".hook-"+tc.scope+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			first, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := first.Addr().String()
			peerSeen := &listenerProofRecorder{}
			peer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				peerSeen.record(r)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"action":"allow","hook_output":{"decision":"allow"}}`))
			})}
			gateway := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != UserScopedListenerProofPath {
					t.Errorf("gateway got %s", r.URL.Path)
					return
				}
				proof, proofErr := UserScopedListenerProof(credential, tc.scope, r.Header.Get(UserScopedListenerNonceHeader))
				if proofErr != nil {
					t.Error(proofErr)
					return
				}
				w.Header().Set(UserScopedListenerProofHeader, proof)
				w.Header().Set("Connection", "close")
				w.WriteHeader(http.StatusNoContent)
				if err := first.Close(); err != nil {
					t.Error(err)
				}
				replacement, err := net.Listen("tcp", addr)
				if err != nil {
					t.Errorf("rebind peer port: %v", err)
					return
				}
				go func() { _ = peer.Serve(replacement) }()
			})}
			go func() { _ = gateway.Serve(first) }()
			t.Cleanup(func() { _ = gateway.Close(); _ = peer.Close(); _ = first.Close() })
			verdict := runListenerProofPlugin(t, tc.asset, addr, tokenPath, true)
			if !strings.HasPrefix(verdict, "block:") {
				t.Errorf("replacement listener verdict = %q, want block", verdict)
			}
			if seen := peerSeen.snapshot(); len(seen) != 0 {
				t.Errorf("replacement listener received credential or tool payload: %+v", seen)
			}
		})
	}
}

func TestManagedPluginProofAndHookUseOneConnection(t *testing.T) {
	nodeForTest(t)
	for _, tc := range []struct{ asset, scope string }{
		{"opencode-plugin.js", "opencode"}, {"amp-plugin.ts", "amp"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			const credential = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			root := testenv.PrivateTempDir(t)
			tokenPath := filepath.Join(root, ".hook-"+tc.scope+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var proofRemote, hookRemote string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case UserScopedListenerProofPath:
					proofRemote = r.RemoteAddr
					proof, err := UserScopedListenerProof(credential, tc.scope, r.Header.Get(UserScopedListenerNonceHeader))
					if err != nil {
						t.Error(err)
						return
					}
					w.Header().Set(UserScopedListenerProofHeader, proof)
					w.WriteHeader(http.StatusNoContent)
				case "/api/v1/" + tc.scope + "/hook":
					hookRemote = r.RemoteAddr
					_, _ = w.Write([]byte(`{"action":"allow","hook_output":{"decision":"allow"}}`))
				default:
					t.Errorf("unexpected request path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			verdict := runListenerProofPlugin(t, tc.asset, strings.TrimPrefix(server.URL, "http://"), tokenPath, true)
			if verdict != "allow" || proofRemote == "" || proofRemote != hookRemote {
				t.Fatalf("proven request verdict=%q, proof connection=%q, hook connection=%q", verdict, proofRemote, hookRemote)
			}
		})
	}
}

// An attacker can answer a challenge with a malformed 64-character header.
// The proof comparison must name an unverified peer rather than surfacing a
// buffer-size exception, even when the supplied outage fail mode is open.
func TestManagedOpenModeRejectsMalformedListenerProof(t *testing.T) {
	nodeForTest(t)
	for _, tc := range []struct{ asset, scope, harness, name string }{
		{"opencode-plugin.js", "opencode", openCodeListenerProofHarness, "opencode-plugin.mjs"},
		{"amp-plugin.ts", "amp", ampListenerProofHarness, "amp-plugin.mts"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			const credential = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			root := testenv.PrivateTempDir(t)
			tokenPath := filepath.Join(root, ".hook-"+tc.scope+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			seen := &listenerProofRecorder{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen.record(r)
				if r.URL.Path == UserScopedListenerProofPath {
					// 32 UTF-8 characters occupy 64 header bytes. Node's header
					// string has length 64 but re-encodes to more than 64 bytes.
					w.Header().Set(UserScopedListenerProofHeader, strings.Repeat("é", 32))
					w.WriteHeader(http.StatusNoContent)
					return
				}
				_, _ = w.Write([]byte(`{"action":"allow","hook_output":{"decision":"allow"}}`))
			}))
			defer server.Close()
			plugin := writeRenderedPlugin(t, tc.asset, tc.name, templateData{
				APIAddr:     strings.TrimPrefix(server.URL, "http://"),
				TokenFileJS: javaScriptStringContent(tokenPath), ListenerProofJS: "1",
				FailMode: "open", Managed: true,
			})
			verdict := strings.Join(runNodeHarness(t, tc.harness, plugin), "\n")
			if !strings.HasPrefix(verdict, "block:") || !strings.Contains(verdict, "did not prove its identity") {
				t.Fatalf("malformed proof under outage-open = %q, want identity block", verdict)
			}
			requests := seen.snapshot()
			if len(requests) != 1 || requests[0].path != UserScopedListenerProofPath ||
				requests[0].authorization != "" || requests[0].body != "" {
				t.Fatalf("malformed proof caused a hook request or credential disclosure: %+v", requests)
			}
		})
	}
}
