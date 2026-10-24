// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

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
