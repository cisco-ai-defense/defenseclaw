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

func TestLegacyAPIHealthRefusesUnverifiedListenerBeforeReadingItsDecision(t *testing.T) {
	var requests atomic.Int32
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"api":{"state":"running"}}`))
	}))
	defer listener.Close()

	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	layout.APIAddr = strings.TrimPrefix(listener.URL, "http://")
	env := &Env{GOOS: runtime.GOOS, Layout: layout}
	env.fillDefaults()
	_, _, err = env.APIHealthGet(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("unverified listener supplied a gateway health decision: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("unverified listener received %d gateway health request(s)", got)
	}
}
