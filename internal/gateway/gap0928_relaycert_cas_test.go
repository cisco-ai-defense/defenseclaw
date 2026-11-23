//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// gap0928Cert asks for a certificate without proof; it returns the code,
// the audit row, the PEM (or the reason) and the key.
func gap0928Cert(t *testing.T, g *gap0861Replica) (int, string, string, *ecdsa.PrivateKey) {
	t.Helper()
	key, csr, err := relaytls.NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	code, row, out := g.ask(t, relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr)})
	return code, row, out, key
}

// gap0928Renew renews certPEM with proof of key.
func gap0928Renew(t *testing.T, g *gap0861Replica, certPEM string, key *ecdsa.PrivateKey) (int, string, string) {
	t.Helper()
	kp, err := relaytls.KeyPair([]byte(certPEM), key)
	if err != nil {
		t.Fatal(err)
	}
	_, csr, _ := relaytls.NewKeyAndCSR()
	proof, err := relaytls.RenewalProof(kp, csr)
	if err != nil {
		t.Fatal(err)
	}
	return g.ask(t, relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr), Current: certPEM, Proof: base64.StdEncoding.EncodeToString(proof)})
}

func gap0928Leaf(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(certPEM))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func gap0928Store(t *testing.T) *registry.FileStore {
	t.Helper()
	s, err := registry.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// GAP-0928 (RV-S1H probe): a renewal is a compare-and-swap on the live
// serial. Before, proof of any unexpired certificate for the actor renewed
// it, so whoever got the first certificate with a stolen actor JWT kept
// renewing after recover, with INFO rows only.
func TestGAP0928RenewalBoundToLiveManaged(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	g := gap0861New(ca, store, true, "")
	want := func(label string, code int, row string, gotCode int, gotRow string) {
		t.Helper()
		if gotCode != code || gotRow != row {
			t.Errorf("%s: %d %s, want %d %s", label, gotCode, gotRow, code, row)
		}
	}
	code, row, certA, keyA := gap0928Cert(t, g)
	want("attacker first", 200, "INFO substrate.relay.cert", code, row)
	code, row, _, _ = gap0928Cert(t, g)
	want("relay second", 403, "HIGH substrate.relay.cert_refused", code, row)
	if err := store.ClearRelayCert(t.Context(), "eng-web", gap0861UID); err != nil {
		t.Fatal(err)
	}
	// Recover's mark: no certificate issued before it renews.
	code, row, out := gap0928Renew(t, g, certA, keyA)
	want("attacker renews after recover", 403, "HIGH substrate.relay.cert_refused", code, row)
	if out != "renewal_not_live" {
		t.Errorf("reason %q", out)
	}
	_, csrR, _ := relaytls.NewKeyAndCSR()
	code, row, _ = g.ask(t, relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csrR)})
	want("relay first after recover", 200, "INFO substrate.relay.cert", code, row)
	code, row, _ = gap0928Renew(t, g, certA, keyA)
	want("attacker renews", 403, "HIGH substrate.relay.cert_refused", code, row)
	code, row, _, _ = gap0928Cert(t, g)
	want("attacker without proof", 403, "HIGH substrate.relay.cert_refused", code, row)
}

// The relay itself keeps renewing (each renewal is the live one next).
func TestGAP0928RelayKeepsRenewing(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	g := gap0861New(ca, store, true, "")
	code, _, cert, key := gap0928Cert(t, g)
	for i := 0; i < 3 && code == 200; i++ {
		k, csr, _ := relaytls.NewKeyAndCSR()
		kp, _ := relaytls.KeyPair([]byte(cert), key)
		proof, _ := relaytls.RenewalProof(kp, csr)
		var row string
		code, row, cert = g.ask(t, relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr), Current: cert, Proof: base64.StdEncoding.EncodeToString(proof)})
		if code != 200 || row != "INFO substrate.relay.cert" {
			t.Fatalf("renewal %d: %d %s %s", i, code, row, cert)
		}
		key = k
	}
	if code != 200 {
		t.Fatalf("first: %d", code)
	}
}

// Flag (OSS): a renewal of a certificate that is not the live one is
// issued with HIGH every time, and the live one stays the live one.
func TestGAP0928RenewalBoundToLiveFlag(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	g := gap0861New(ca, store, false, config.SubstrateRelayCertReissueFlag)
	_, _, certA, keyA := gap0928Cert(t, g)
	code, row, certR, keyR := gap0928Cert(t, g)
	if code != 200 || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("relay second: %d %s", code, row)
	}
	for i := 0; i < 2; i++ {
		if code, row, _ := gap0928Renew(t, g, certA, keyA); code != 200 || row != "HIGH substrate.relay.cert_second" {
			t.Fatalf("attacker renewal %d: %d %s", i, code, row)
		}
	}
	if code, row, _ := gap0928Renew(t, g, certR, keyR); code != 200 || row != "INFO substrate.relay.cert" {
		t.Fatalf("relay renewal: %d %s", code, row)
	}
	if err := store.ClearRelayCert(t.Context(), "eng-web", gap0861UID); err != nil {
		t.Fatal(err)
	}
	if code, row, _ := gap0928Renew(t, g, certA, keyA); code != 200 || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("attacker renewal after recover: %d %s", code, row)
	}
}

// Attach takes only the live certificate (GAP-0928): refuse takes none
// after recover until the relay asks again; flag takes the CA's word then.
func TestGAP0928AttachTakesOnlyTheLiveCert(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	g := gap0861New(ca, store, true, "")
	_, _, certA, _ := gap0928Cert(t, g)
	_, csr, _ := relaytls.NewKeyAndCSR()
	other, err := ca.Sign(csr, gap0861UID, g.st.clock())
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.Registration{Atespace: "eng-web", Name: "tix", UID: gap0861UID}
	if err := g.st.relayCertLive(t.Context(), reg, gap0928Leaf(t, certA)); err != nil {
		t.Fatalf("live cert: %v", err)
	}
	if err := g.st.relayCertLive(t.Context(), reg, gap0928Leaf(t, string(other))); err == nil {
		t.Fatal("a certificate the CA signed for the UID that is not the live one is taken at attach")
	}
	if err := store.ClearRelayCert(t.Context(), "eng-web", gap0861UID); err != nil {
		t.Fatal(err)
	}
	if err := g.st.relayCertLive(t.Context(), reg, gap0928Leaf(t, certA)); err == nil {
		t.Fatal("refuse takes a certificate issued before recover at attach")
	}
	flag := gap0861New(ca, store, false, config.SubstrateRelayCertReissueFlag)
	if err := flag.st.relayCertLive(t.Context(), reg, gap0928Leaf(t, certA)); err != nil {
		t.Fatalf("flag after recover: %v", err)
	}
}

// GAP-0929: after an emergency CA rotation the renewal is refused with
// renewal_ca_dropped (the relay then asks without proof, under the mode's
// rules: refused in managed until recover, flagged in OSS).
func TestGAP0929DroppedCARenewal(t *testing.T) {
	for _, c := range []struct {
		name    string
		managed bool
		mode    string
		code    int
		row     string
	}{
		{"managed", true, "", http.StatusForbidden, "HIGH substrate.relay.cert_refused"},
		{"oss", false, "", http.StatusOK, "HIGH substrate.relay.cert_second"},
	} {
		t.Run(c.name, func(t *testing.T) {
			oldCA, newCA, store := tixRelayCA(t), tixRelayCA(t), gap0928Store(t)
			before := gap0861New(oldCA, store, c.managed, c.mode)
			_, _, cert, key := gap0928Cert(t, before)
			after := gap0861New(newCA, store, c.managed, c.mode)
			code, row, out := gap0928Renew(t, after, cert, key)
			if code != http.StatusForbidden || out != "renewal_ca_dropped" || row != "HIGH substrate.relay.cert_refused" {
				t.Fatalf("renewal after rotation: %d %s %s", code, row, out)
			}
			var prevCA any
			inner := after.st.audit
			after.st.audit = func(ctx context.Context, sev, sum string, d map[string]any) {
				prevCA = d["previous_ca"]
				inner(ctx, sev, sum, d)
			}
			code, row, _, _ = gap0928Cert(t, after)
			if code != c.code || row != c.row {
				t.Fatalf("without proof after rotation: %d %s", code, row)
			}
			if prevCA != "dropped" {
				t.Errorf("the row does not say the CA was dropped: %v", prevCA)
			}
			if c.managed {
				if err := store.ClearRelayCert(t.Context(), "eng-web", gap0861UID); err != nil {
					t.Fatal(err)
				}
				if code, row, _, _ := gap0928Cert(t, after); code != 200 || row != "INFO substrate.relay.cert" {
					t.Fatalf("after recover: %d %s", code, row)
				}
			}
			// A stranger's certificate (never this CA's) is refused as before.
			stranger := gap0861New(tixRelayCA(t), gap0928Store(t), c.managed, c.mode)
			_, _, sc, sk := gap0928Cert(t, stranger)
			if code, _, out := gap0928Renew(t, after, sc, sk); code != http.StatusForbidden || out != "renewal_proof_refused" {
				t.Fatalf("stranger renewal: %d %s", code, out)
			}
		})
	}
}
