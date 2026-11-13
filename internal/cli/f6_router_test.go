// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA issues certificates for the fake router (DNS name) and the gateway
// (SPIFFE URI).
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t *testing.T, dns string, spiffe string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	if dns != "" {
		tpl.DNSNames = []string{dns}
	}
	if spiffe != "" {
		u, _ := url.Parse(spiffe)
		tpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeRouter is atenet-router's CONNECT-TLS listener as Envoy runs it: a
// client certificate from clientCA whose SPIFFE ID is not in allowed is
// refused with a TLS alert; a known actor gets 200, others 503.
func fakeRouter(t *testing.T, serverCA, clientCA *testCA, allowed string) string {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(clientCA.cert)
	cfg := &tls.Config{Certificates: []tls.Certificate{serverCA.issue(t, "atenet-router.ate-system.svc", "")},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
			for _, u := range chains[0][0].URIs {
				if u.String() == allowed {
					return nil
				}
			}
			return &net.AddrError{Err: "SPIFFE ID not allowed"}
		}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if req.Header.Get("ate-target-actor") == "eng-web/alice-1" {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\nrelay-hello"))
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func routerFixture(t *testing.T, gatewayID, allowed string) *routerDialer {
	t.Helper()
	serverCA, clientCA := newTestCA(t), newTestCA(t)
	addr := fakeRouter(t, serverCA, clientCA, allowed)
	caFile := filepath.Join(t.TempDir(), "router-ca.pem")
	if err := os.WriteFile(caFile, serverCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	cert := clientCA.issue(t, "", gatewayID)
	d, err := newRouterDialer(addr, "atenet-router.ate-system.svc", caFile, 8080, func() (*tls.Certificate, error) { return &cert, nil })
	if err != nil {
		t.Fatal(err)
	}
	return d
}

const testGatewayID = "spiffe://cluster.local/ns/dc/sa/defenseclaw-gateway"

// GAP-0157: attach dials the actor relay through the router.
func TestRouterDialRelay(t *testing.T) {
	d := routerFixture(t, testGatewayID, testGatewayID)
	conn, err := d.DialRelay(context.Background(), "eng-web", "alice-1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b := make([]byte, 11)
	if _, err := conn.Read(b); err != nil || string(b) != "relay-hello" {
		t.Fatalf("relay stream %q, %v", b, err)
	}
}

// GAP-0157: the doctor row says what is wrong: no router address, a router
// that refuses the gateway's SPIFFE ID (names the setting and the ID), or a
// router that admits it.
func TestSubstrateRouterCheck(t *testing.T) {
	ctx := context.Background()
	if c := substrateRouterCheck(ctx, nil, nil); c.Status != "fail" || !strings.Contains(c.Detail, "--router-address") ||
		!strings.Contains(c.Fix, "substrate.router.enabled") {
		t.Fatalf("no router: %+v", c)
	}
	refused := routerFixture(t, testGatewayID, "spiffe://cluster.local/ns/ate-system/sa/atenet-client")
	c := substrateRouterCheck(ctx, refused, nil)
	if c.Status != "fail" || !strings.Contains(c.Fix, "ingressAllowedSPIFFEIDs") || !strings.Contains(c.Detail, testGatewayID) {
		t.Fatalf("refused: %+v", c)
	}
	// The attach error names the setting too, not a bare TLS error.
	if _, err := refused.DialRelay(ctx, "eng-web", "alice-1"); err == nil || !strings.Contains(err.Error(), "ingressAllowedSPIFFEIDs") {
		t.Fatalf("attach through a refusing router: %v", err)
	}
	ok := routerFixture(t, testGatewayID, testGatewayID)
	if c := substrateRouterCheck(ctx, ok, nil); c.Status != "pass" || !strings.Contains(c.Detail, "HTTP 503") {
		t.Fatalf("admitted: %+v", c)
	}
}
