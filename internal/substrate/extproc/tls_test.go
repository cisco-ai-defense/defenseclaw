// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCert(t *testing.T, dir, name string, uri string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	kb, _ := x509.MarshalECPrivateKey(key)
	file := filepath.Join(dir, name+".pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})...)
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key, file
}

// TestServerTLSRequiresClientCA is GAP-0065: TLS without a client CA is a
// startup error, and with one the egress gateway's chain is verified, so a
// self-signed certificate naming the egress SPIFFE ID is refused.
func TestServerTLSRequiresClientCA(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, caFile := writeCert(t, dir, "ca", "", true, nil, nil)
	_, _, bundle := writeCert(t, dir, "server", "", false, ca, caKey)
	if _, err := ServerTLS(TLSOptions{Bundle: bundle, Peers: []string{DefaultEgressPeer}}); err == nil {
		t.Fatal("TLS without a client CA accepted")
	}
	cfg, err := ServerTLS(TLSOptions{Bundle: bundle, ClientCA: caFile, Peers: []string{DefaultEgressPeer}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil {
		t.Fatalf("client auth %v", cfg.ClientAuth)
	}
	// A forged self-signed egress identity does not chain to the CA.
	forged, _, _ := writeCert(t, dir, "forged", DefaultEgressPeer, false, nil, nil)
	if _, err := forged.Verify(x509.VerifyOptions{Roots: cfg.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("forged client certificate verifies")
	}
	good, _, _ := writeCert(t, dir, "egress", DefaultEgressPeer, false, ca, caKey)
	if _, err := good.Verify(x509.VerifyOptions{Roots: cfg.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{good}}); err != nil {
		t.Fatalf("egress peer refused: %v", err)
	}
	other, _, _ := writeCert(t, dir, "other", "spiffe://cluster.local/ns/x/sa/y", false, ca, caKey)
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}}); err == nil {
		t.Fatal("other SPIFFE ID accepted")
	}
}
