// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// GAP-0819: one live relay certificate per actor. A renewal proves the
// live key and is an INFO row; in flag mode (OSS auto, GAP-0861) a second
// certificate asked for with the actor JWT alone is issued (a restarted
// relay lost its key) with a HIGH row; a renewal with a proof that does
// not hold is refused, HIGH.
func TestGAP0819SecondRelayCertIsFlagged(t *testing.T) {
	const uid = "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"
	var rows []string
	st := &substrateState{cfg: SubstrateConfig{RelayCA: tixRelayCA(t), RelayCerts: tixRelayCerts(t)}, audit: func(_ context.Context, sev, _ string, d map[string]any) {
		rows = append(rows, sev+" "+d["event"].(string))
	}}
	ctx := withSubstrateActor(t.Context(), *f14Actor(t, "tix", uid))
	ask := func(in relay.CertRequest) (*httptest.ResponseRecorder, string) {
		t.Helper()
		rows = nil
		body, _ := json.Marshal(in)
		w := httptest.NewRecorder()
		(&APIServer{}).serveSubstrateRelayCert(st, w, httptest.NewRequest(http.MethodPost, substrateRelayCert, bytes.NewReader(body)).WithContext(ctx))
		if len(rows) != 1 {
			t.Fatalf("rows %v", rows)
		}
		return w, rows[0]
	}
	key1, csr1, _ := relaytls.NewKeyAndCSR()
	w, row := ask(relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr1)})
	if w.Code != http.StatusOK || row != "INFO substrate.relay.cert" {
		t.Fatalf("first: %d %s", w.Code, row)
	}
	var out relay.CertResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	cur, err := relaytls.KeyPair([]byte(out.Cert), key1)
	if err != nil {
		t.Fatal(err)
	}

	// The relay's renewal: a new key, proved with the live one.
	_, csr2, _ := relaytls.NewKeyAndCSR()
	proof, err := relaytls.RenewalProof(cur, csr2)
	if err != nil {
		t.Fatal(err)
	}
	w, row = ask(relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr2), Current: out.Cert, Proof: base64.StdEncoding.EncodeToString(proof)})
	if w.Code != http.StatusOK || row != "INFO substrate.relay.cert" {
		t.Fatalf("renewal: %d %s", w.Code, row)
	}

	// The actor JWT alone, while a certificate is live: issued, HIGH.
	_, csr3, _ := relaytls.NewKeyAndCSR()
	w, row = ask(relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr3)})
	if w.Code != http.StatusOK || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("second without proof: %d %s", w.Code, row)
	}

	// A proof made with another key, or over another CSR: refused, HIGH.
	other, _ := relaytls.RenewalProof(cur, csr1)
	w, row = ask(relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr3), Current: out.Cert, Proof: base64.StdEncoding.EncodeToString(other)})
	if w.Code != http.StatusForbidden || reasonOf(t, w) != "renewal_proof_refused" || row != "HIGH substrate.relay.cert_refused" {
		t.Fatalf("bad proof: %d %s %s", w.Code, w.Body, row)
	}
}
