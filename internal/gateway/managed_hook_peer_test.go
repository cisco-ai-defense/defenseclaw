// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func uidPtr(uid int) *int { return &uid }

func TestManagedHookAuthorizerMatrix(t *testing.T) {
	ledger := managedHookLedger{Targets: []managedHookLedgerTarget{
		{User: "alice", Connector: "claudecode", OK: true},
		{UID: uidPtr(2001), Connector: "cursor", OK: true},
		{User: "carol", Connector: "hermes", OK: false},
		{User: "dave", UID: uidPtr(4001), Connector: "claudecode", OK: true},
	}}
	load := func() (managedHookLedger, error) { return ledger, nil }
	alice := managedHookPeer{UID: 1001, Name: "alice"}
	bob := managedHookPeer{UID: 2001, Name: "bob"}
	carol := managedHookPeer{UID: 3001, Name: "carol"}
	root := managedHookPeer{UID: 0, Name: "root"}

	cases := []struct {
		name       string
		enrollment config.EnterpriseEnrollmentConfig
		loader     func() (managedHookLedger, error)
		peer       managedHookPeer
		connector  string
		allow      bool
		reason     string
		exempt     bool
	}{
		{name: "machine policy inspects unenrolled users", peer: carol, connector: "codex", allow: true},
		{name: "per-user connector requires enrollment", peer: carol, connector: "claudecode", reason: managedHookReasonUIDUnregistered},
		{name: "enrolled by name", peer: alice, connector: "ClaudeCode", allow: true},
		{name: "enrolled by uid", peer: bob, connector: "cursor", allow: true},
		{name: "uid row ignores a name reused by another uid", peer: managedHookPeer{UID: 4002, Name: "dave"}, connector: "claudecode", reason: managedHookReasonUIDUnregistered},
		{name: "enrollment is per connector", peer: alice, connector: "cursor", reason: managedHookReasonUIDUnregistered},
		{name: "failed rows do not enroll", peer: carol, connector: "hermes", reason: managedHookReasonUIDUnregistered},
		{name: "strict machine policy requires any enrollment", enrollment: config.EnterpriseEnrollmentConfig{UnenrolledUsers: "deny"}, peer: carol, connector: "codex", reason: managedHookReasonUIDUnregistered},
		{name: "strict machine policy accepts enrolled user", enrollment: config.EnterpriseEnrollmentConfig{UnenrolledUsers: "deny"}, peer: alice, connector: "codex", allow: true},
		{name: "root inspected by default", peer: root, connector: "cursor", allow: true},
		{name: "root denied", enrollment: config.EnterpriseEnrollmentConfig{Root: "deny"}, peer: root, connector: "codex", reason: managedHookReasonRootDenied},
		{name: "exempt by name", enrollment: config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"carol"}}, peer: carol, connector: "hermes", allow: true, exempt: true},
		{name: "exempt by uid", enrollment: config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"3001"}}, peer: carol, connector: "hermes", allow: true, exempt: true},
		{name: "unknown connector", peer: alice, connector: "", reason: managedHookReasonConnectorUnknown},
		{name: "refuse denies a user whose only codex install is a refused surface", enrollment: config.EnterpriseEnrollmentConfig{UnverifiedVersions: "refuse"}, peer: carol, connector: "codex", reason: managedHookReasonSurfaceUnverified},
		{name: "refuse keeps inspecting other users", enrollment: config.EnterpriseEnrollmentConfig{UnverifiedVersions: "refuse"}, peer: bob, connector: "codex", allow: true},
		{name: "ledger failure fails closed", loader: func() (managedHookLedger, error) { return managedHookLedger{}, errors.New("untrusted") }, peer: alice, connector: "claudecode", reason: managedHookReasonLedgerUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loader := tc.loader
			if loader == nil {
				loader = load
			}
			authorizer := newManagedHookAuthorizer(tc.enrollment, []string{"codex", " "}, loader)
			authorizer.loadRefused = func() (managedHookLedger, error) {
				return managedHookLedger{Refused: []managedHookLedgerTarget{{UID: uidPtr(3001), Connector: "codex"}}}, nil
			}
			decision := authorizer.decide(tc.peer, tc.connector)
			if decision.Allow != tc.allow || decision.Reason != tc.reason || decision.Exempt != tc.exempt {
				t.Fatalf("decision = %+v, want allow=%v reason=%q exempt=%v", decision, tc.allow, tc.reason, tc.exempt)
			}
			if !decision.Allow && decision.Status != http.StatusForbidden && decision.Status != http.StatusServiceUnavailable {
				t.Fatalf("refusal status = %d", decision.Status)
			}
		})
	}
}

func TestManagedHookLedgerLoaderValidatesAndCaches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "protected_targets.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"protected_targets":[{"user":"alice","connector":"codex","ok":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := validateManagedGuardianAuthorization
	t.Cleanup(func() { validateManagedGuardianAuthorization = restore })
	validations := 0
	validateManagedGuardianAuthorization = func(string, string) error { validations++; return nil }

	loader := newManagedHookLedgerLoader(path)
	now := time.Unix(1000, 0)
	loader.now = func() time.Time { return now }
	ledger, err := loader.Load()
	if err != nil || !ledger.enrolled(managedHookPeer{Name: "alice"}, "codex") {
		t.Fatalf("load: %+v %v", ledger, err)
	}
	if _, err := loader.Load(); err != nil || validations != 1 {
		t.Fatalf("second load within the TTL must use the cache (validations=%d, err=%v)", validations, err)
	}
	now = now.Add(3 * time.Second)
	if _, err := loader.Load(); err != nil || validations != 2 {
		t.Fatalf("load after the TTL must revalidate (validations=%d, err=%v)", validations, err)
	}
	validateManagedGuardianAuthorization = func(string, string) error { return errors.New("owner uid 1000 is not trusted") }
	now = now.Add(3 * time.Second)
	if _, err := loader.Load(); err == nil {
		t.Fatal("an untrusted ledger must fail")
	}
}

func TestManagedHookPeerIdentityMiddlewareReplacesClaims(t *testing.T) {
	var seen *http.Request
	handler := managedHookPeerIdentityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
	}))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", nil)
	request.Header.Set(llmEventUserIDHeader, "0")
	request.Header.Set("X-User", "admin")
	request.Header.Set("Authorization", "Bearer stolen")
	request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: 1001, Name: "alice"}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if seen == nil {
		t.Fatal("handler not reached")
	}
	if seen.Header.Get(llmEventUserIDHeader) != "1001" || seen.Header.Get(llmEventUserNameHeader) != "alice" {
		t.Fatalf("identity headers not replaced: %v", seen.Header)
	}
	if seen.Header.Get("X-User") != "" || seen.Header.Get("Authorization") != "" {
		t.Fatalf("caller claims survived: %v", seen.Header)
	}
	host, _, _ := net.SplitHostPort(seen.RemoteAddr)
	if host != "127.0.0.1" {
		t.Fatalf("remote addr = %q", seen.RemoteAddr)
	}

	recorder := httptest.NewRecorder()
	unverified := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", nil)
	seen = nil
	handler.ServeHTTP(recorder, unverified)
	if recorder.Code != http.StatusForbidden || seen != nil {
		t.Fatalf("request without kernel credentials must be refused: %d", recorder.Code)
	}
}

func TestInheritedAddrMatches(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	if err := inheritedAddrMatches(addr, "127.0.0.1:18970"); err != nil {
		t.Fatal(err)
	}
	if err := inheritedAddrMatches(addr, "localhost:18970"); err != nil {
		t.Fatal(err)
	}
	for _, configured := range []string{"127.0.0.1:18971", "0.0.0.0:18970", "10.0.0.1:18970", "bad"} {
		if err := inheritedAddrMatches(addr, configured); err == nil {
			t.Errorf("%q accepted", configured)
		}
	}
	if err := inheritedAddrMatches(&net.UnixAddr{Name: "/run/x.sock", Net: "unix"}, "127.0.0.1:18970"); err == nil {
		t.Fatal("a unix socket must not stand in for the TCP API")
	}
}

func TestAcquireAPIListenerFailsClosedOnInheritedMismatch(t *testing.T) {
	inheritedSocket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inheritedSocket.Close()
	restore := inheritedAPIListener
	t.Cleanup(func() { inheritedAPIListener = restore })
	inheritedAPIListener = func() (net.Listener, bool, error) { return inheritedSocket, true, nil }

	api := NewAPIServer("127.0.0.1:1", NewSidecarHealth(), nil, nil, nil)
	if _, err := api.acquireAPIListener(t.Context()); err == nil {
		t.Fatal("a socket-activated listener on another port must fail closed")
	}
	inheritedSocket, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inheritedSocket.Close()
	api = NewAPIServer(inheritedSocket.Addr().String(), NewSidecarHealth(), nil, nil, nil)
	listener, err := api.acquireAPIListener(t.Context())
	if err != nil || listener.Addr().String() != inheritedSocket.Addr().String() {
		t.Fatalf("matching inherited listener: %v %v", listener, err)
	}
}
