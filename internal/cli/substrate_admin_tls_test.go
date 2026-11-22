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

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// adminTLSTestCert is a self-signed serving certificate for names.
func adminTLSTestCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return pair, pool, certPEM, keyPEM
}

// adminTLSHandshake dials server on a loopback listener as a client that
// trusts roots and checks serverName; it returns the client's handshake
// error. Deadlines keep a refused handshake from hanging the test.
func adminTLSHandshake(t *testing.T, server *tls.Config, roots *x509.CertPool, serverName string) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))
		_ = tls.Server(s, server).Handshake()
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	err = tls.Client(c, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}).Handshake()
	_ = c.Close()
	<-done
	return err
}

// TestSubstrateAdminTLSKeepsThePodCertificateForInClusterNamesGAP0186: with
// an operator certificate for the external name (admin.tlsSecretName), the
// admin listener still answers an in-cluster Service name with the pod
// serving certificate, so the callout's judge and ask client (which trust
// the cluster CA and dial defenseclaw-admin.<ns>.svc) keep working. Before
// the fix the operator certificate answered every name and the callout
// failed every TLS check.
func TestSubstrateAdminTLSKeepsThePodCertificateForInClusterNamesGAP0186(t *testing.T) {
	podPair, podRoots, _, _ := adminTLSTestCert(t, "defenseclaw-admin.dc.svc", "defenseclaw-actor.dc.svc")
	_, extRoots, extCert, extKey := adminTLSTestCert(t, "admin.example.test")
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, extCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, extKey, 0o600); err != nil {
		t.Fatal(err)
	}
	saved := substrateAdminTLSFlags
	t.Cleanup(func() { substrateAdminTLSFlags = saved })
	substrateAdminTLSFlags.cert, substrateAdminTLSFlags.key = certFile, keyFile

	serving := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &podPair, nil }}
	cfg, err := substrateAdminTLS(serving)
	if err != nil {
		t.Fatal(err)
	}
	if err := adminTLSHandshake(t, cfg, podRoots, "defenseclaw-admin.dc.svc"); err != nil {
		t.Errorf("in-cluster name with the cluster CA: %v", err)
	}
	if err := adminTLSHandshake(t, cfg, extRoots, "admin.example.test"); err != nil {
		t.Errorf("external name with the operator CA: %v", err)
	}
	// A laptop that names nothing in-cluster gets the operator certificate.
	if err := adminTLSHandshake(t, cfg, podRoots, "admin.example.test"); err == nil {
		t.Error("external name answered with the pod certificate")
	}
	for _, sni := range []string{"defenseclaw-admin.dc.svc", "DEFENSECLAW-ADMIN.DC.SVC.", "defenseclaw-admin.dc.svc.cluster.local"} {
		if !substrateInClusterServerName(sni) {
			t.Errorf("%q is an in-cluster name", sni)
		}
	}
	for _, sni := range []string{"", "admin.example.test", "svc", "evil-svc.example.test"} {
		if substrateInClusterServerName(sni) {
			t.Errorf("%q is not an in-cluster name", sni)
		}
	}

	// No operator certificate: the serving config is used as it is.
	substrateAdminTLSFlags.cert, substrateAdminTLSFlags.key = "", ""
	if got, err := substrateAdminTLS(serving); err != nil || got != serving {
		t.Fatalf("no --admin-tls-cert: %v %v", got, err)
	}
}
