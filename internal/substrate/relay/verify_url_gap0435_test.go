// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0435: a relay with session keys and no verify_url checked only the
// token's signature and actor, never that its person owns the agent. It
// now refuses to start; with verify_url it starts and asks the gateway.
func TestRelaySessionKeysNeedVerifyURLGAP0435(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	p := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := kit.DefaultConfig()
	cfg.Relay.SessionKeys = map[string]string{"k1": p}
	cfg.Relay.SessionIssuer = "https://defenseclaw-admin"
	if _, err := NewVerifier(cfg); err == nil || !strings.Contains(err.Error(), "relay.verify_url") {
		t.Fatalf("a relay with session keys and no verify_url started: %v", err)
	}

	cfg.Relay.VerifyURL = kit.RelayVerifyURL(cfg.GatewayURL)
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("a relay with session keys and verify_url did not start: %v", err)
	}
	cv, ok := v.(*CheckedVerifier)
	if !ok || cv.Keys == nil || cv.Gateway == nil || cv.Gateway.URL != cfg.Relay.VerifyURL {
		t.Fatalf("verifier %T, want the keys, then the gateway at %s", v, cfg.Relay.VerifyURL)
	}

	// verify_url alone: the gateway check.
	cfg.Relay.SessionKeys, cfg.Relay.SessionIssuer = nil, ""
	v, err = NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(*GatewayVerifier); !ok {
		t.Fatalf("verifier %T, want the gateway check", v)
	}
}

// With both, a token must pass the keys and the gateway: the gateway's
// refusal of a token for another person (session_not_owner) wins over a
// good signature, and a token the keys refuse never reaches the gateway.
func TestCheckedVerifierAsksTheGatewayGAP0435(t *testing.T) {
	kv, ec, _ := testVerifier(t)
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if code := int(status.Load()); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"person":"alice@example.test","actor":"` + self.Atespace + "/" + self.Name + `","actor_uid":"` + self.UID + `"}`))
	}))
	defer srv.Close()
	v := &CheckedVerifier{Keys: kv, Gateway: &GatewayVerifier{URL: srv.URL, Client: srv.Client()}}
	req := func(tok string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}
	good := ec.token(t, claims(time.Now(), nil), TokenType)

	s, err := v.Verify(context.Background(), req(good))
	if err != nil || s.Person != "alice@example.test" || calls.Load() != 1 {
		t.Fatalf("a good token the gateway accepts: %+v %v (gateway calls %d)", s, err, calls.Load())
	}

	status.Store(http.StatusForbidden)
	if _, err := v.Verify(context.Background(), req(good)); err == nil {
		t.Fatal("a token the gateway refuses (not the owner) was accepted on its signature")
	}

	before := calls.Load()
	other := ec.token(t, claims(time.Now(), func(c map[string]any) { c["iss"] = "https://elsewhere" }), TokenType)
	if _, err := v.Verify(context.Background(), req(other)); err == nil {
		t.Fatal("a token the keys refuse was accepted")
	}
	if calls.Load() != before {
		t.Fatal("a token the keys refuse reached the gateway")
	}
}
