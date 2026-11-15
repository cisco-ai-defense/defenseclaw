// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// issuerServer is an OIDC issuer over TLS whose discovery document names
// issuer (the server's own URL when empty) and serves keys keys.
func issuerServer(t *testing.T, issuer string, keys int, discoveryStatus int) (*httptest.Server, string) {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if discoveryStatus != 0 {
				w.WriteHeader(discoveryStatus)
				return
			}
			iss := issuer
			if iss == "" {
				iss = srv.URL
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": srv.URL + "/keys"})
		case "/keys":
			set := make([]map[string]string, keys)
			for i := range set {
				set[i] = map[string]string{"kty": "EC", "kid": "k"}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": set})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, ca
}

func diagnose(t *testing.T, issuer, ca string) IssuerDiagnosis {
	t.Helper()
	ks, err := NewKeySet(KeySetOptions{Issuer: issuer, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	return ks.DiagnoseIssuer(context.Background())
}

// GAP-0262: each way the sign-in server can fail from where the gateway
// runs is named, and a healthy issuer passes.
func TestDiagnoseIssuerGAP0262(t *testing.T) {
	healthy, ca := issuerServer(t, "", 2, 0)
	if d := diagnose(t, healthy.URL, ca); d.Cause != "" || d.Keys != 2 {
		t.Fatalf("healthy issuer: %+v", d)
	}

	// Unreachable: nothing listens (the old address after a restart).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "https://" + ln.Addr().String()
	ln.Close()
	if d := diagnose(t, dead, ca); d.Cause != IssuerUnreachable {
		t.Errorf("unreachable: %+v", d)
	}

	// TLS name: the certificate names 127.0.0.1 and example.com, not localhost.
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(healthy.URL, "https://"))
	if d := diagnose(t, "https://localhost:"+port, ca); d.Cause != IssuerTLSName {
		t.Errorf("TLS name mismatch: %+v", d)
	}

	// TLS untrusted: the gateway's trust bundle does not hold the issuer's CA.
	if d := diagnose(t, healthy.URL, otherCAFile(t)); d.Cause != IssuerTLSUntrusted {
		t.Errorf("TLS untrusted: %+v", d)
	}

	// No discovery document at the configured address.
	notFound, nfCA := issuerServer(t, "", 1, http.StatusNotFound)
	if d := diagnose(t, notFound.URL, nfCA); d.Cause != IssuerHTTP {
		t.Errorf("no discovery: %+v", d)
	}

	// The discovery document names another issuer (exact match).
	mismatch, mCA := issuerServer(t, "https://idp.example/realms/dc", 1, 0)
	if d := diagnose(t, mismatch.URL, mCA); d.Cause != IssuerMismatch || !strings.Contains(d.Detail, "idp.example") {
		t.Errorf("issuer mismatch: %+v", d)
	}

	// The key set holds no keys.
	empty, eCA := issuerServer(t, "", 0, 0)
	if d := diagnose(t, empty.URL, eCA); d.Cause != IssuerKeys {
		t.Errorf("empty key set: %+v", d)
	}
}

// otherCAFile is a trust bundle with one unrelated CA.
func otherCAFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "other-ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
