// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Rotation holds the machine key, but its root process is not the account
// named by each derived credential. A foreign TCP listener must not receive
// even a credential fingerprint or nonce while rotation checks that key.
func TestRotationProofRefusesUnverifiedTCPListener(t *testing.T) {
	var requests atomic.Int32
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer listener.Close()

	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	layout.APIAddr = strings.TrimPrefix(listener.URL, "http://")
	env := &Env{GOOS: runtime.GOOS, Layout: layout}
	env.fillDefaults()
	_, err = env.ListenerProof(context.Background(), "opencode", strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err == nil || !strings.Contains(err.Error(), "hook socket") {
		t.Fatalf("rotation did not refuse an unverified listener: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("foreign TCP listener received %d rotation challenge(s)", got)
	}
}
