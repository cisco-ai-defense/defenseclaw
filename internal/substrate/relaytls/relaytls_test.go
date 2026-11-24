// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package relaytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

const uidA, uidB = "6f1c2d3e-aaaa-4bbb-8ccc-0123456789ab", "7f1c2d3e-aaaa-4bbb-8ccc-0123456789ab"

func newCA(t *testing.T) *CA {
	t.Helper()
	c, k, err := GenerateCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// serve runs a TLS relay stand-in with a certificate for uid and returns
// its address.
func serve(t *testing.T, ca *CA, uid string) string {
	t.Helper()
	key, csr, err := NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.Sign(csr, uid, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kp, err := KeyPair(certPEM, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sp := Split(ln.Addr(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*kp}}, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			_, _ = io.WriteString(w, "tls")
			return
		}
		_, _ = io.WriteString(w, "plain")
	})
	go func() { _ = http.Serve(sp.TLS(), mux) }()
	go func() { _ = http.Serve(ln, sp.Handler(mux)) }()
	return ln.Addr().String()
}

func get(t *testing.T, addr string, conf *tls.Config) (string, error) {
	t.Helper()
	tr := &http.Transport{DisableKeepAlives: true}
	if conf != nil {
		// TLS as the gateway dials it: the upgrade, then TLS (GAP-1067).
		tr.DialContext = func(ctx context.Context, network, a string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, a)
			if err != nil {
				return nil, err
			}
			tc, err := Upgrade(ctx, raw, conf)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		}
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	resp, err := c.Get("http://" + addr + "/readyz")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

// TestRelayCertSANMismatch: a gateway dialing actor B that reaches actor
// A's relay refuses the handshake; the right UID is accepted.
func TestRelayCertSANMismatch(t *testing.T) {
	ca := newCA(t)
	addr := serve(t, ca, uidA)
	confA, _ := ClientConfig(ca.Pool(), uidA)
	if body, err := get(t, addr, confA); err != nil || body != "tls" {
		t.Fatalf("own uid: %q %v", body, err)
	}
	confB, _ := ClientConfig(ca.Pool(), uidB)
	if _, err := get(t, addr, confB); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("another actor's relay was accepted: %v", err)
	}
}

// TestRelayCertOtherCARefused: a certificate from any other CA (for example
// one the agent made) is refused.
func TestRelayCertOtherCARefused(t *testing.T) {
	addr := serve(t, newCA(t), uidA)
	conf, _ := ClientConfig(newCA(t).Pool(), uidA)
	if _, err := get(t, addr, conf); err == nil {
		t.Fatal("a certificate from another CA was accepted")
	}
}

// TestRelaySplitServesPlainProbe: the same port answers a plain probe.
func TestRelaySplitServesPlainProbe(t *testing.T) {
	addr := serve(t, newCA(t), uidA)
	if body, err := get(t, addr, nil); err != nil || body != "plain" {
		t.Fatalf("plain probe: %q %v", body, err)
	}
}

// TestRelayCertSignIgnoresCSRNames: the certificate names the UID the
// gateway authenticated, never a name in the CSR.
func TestRelayCertSignIgnoresCSRNames(t *testing.T) {
	ca := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"uid." + uidB + SANSuffix, "gateway.example.com"}}, key)
	p, err := ca.Sign(csr, uidA, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kp, err := KeyPair(p, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := kp.Leaf
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "uid."+uidA+SANSuffix {
		t.Fatalf("names %v", leaf.DNSNames)
	}
	if d := time.Until(leaf.NotAfter); d > CertTTL || d < CertTTL-time.Minute {
		t.Fatalf("ttl %v", d)
	}
}

// TestRelayCertRefusesBadInput: RSA keys, a broken CSR signature and a UID
// that is not a DNS label are refused.
func TestRelayCertRefusesBadInput(t *testing.T) {
	ca := newCA(t)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, rk)
	if _, err := ca.Sign(rsaCSR, uidA, time.Now()); err == nil {
		t.Fatal("rsa key signed")
	}
	_, good, _ := NewKeyAndCSR()
	bad := append([]byte(nil), good...)
	bad[len(bad)-3] ^= 0xff
	if _, err := ca.Sign(bad, uidA, time.Now()); err == nil {
		t.Fatal("broken csr signed")
	}
	for _, uid := range []string{"", "a.b", "../x", "x y", strings.Repeat("a", 64), "-ab"} {
		if _, err := ca.Sign(good, uid, time.Now()); err == nil {
			t.Fatalf("uid %q signed", uid)
		}
	}
}

// TestRelayCANameConstraint: the CA cannot vouch for a name outside the
// relay suffix even if its key signs one.
func TestRelayCANameConstraint(t *testing.T) {
	ca := newCA(t)
	if len(ca.cert.PermittedDNSDomains) != 1 || !ca.cert.PermittedDNSDomainsCritical {
		t.Fatalf("constraints %v", ca.cert.PermittedDNSDomains)
	}
}

// TestRelayTLSDecide is the mode table: a TLS kit is never dialed plain
// in any mode (its relay refuses plain); required refuses an old kit; auto
// and off fall back.
func TestRelayTLSDecide(t *testing.T) {
	for _, c := range []struct {
		m    Mode
		tls  bool
		want Decision
	}{
		{ModeAuto, true, DialTLS}, {ModeAuto, false, DialPlain},
		{ModeRequired, true, DialTLS}, {ModeRequired, false, Refuse},
		{ModeOff, true, DialTLS}, {ModeOff, false, DialPlain},
	} {
		if got := Decide(c.m, c.tls); got != c.want {
			t.Errorf("Decide(%s,%v)=%v want %v", c.m, c.tls, got, c.want)
		}
	}
	for in, want := range map[string]Mode{"": ModeAuto, "AUTO": ModeAuto, " required ": ModeRequired, "off": ModeOff} {
		if m, err := ParseMode(in); err != nil || m != want {
			t.Errorf("ParseMode(%q)=%v,%v", in, m, err)
		}
	}
	if _, err := ParseMode("on"); err == nil {
		t.Error("ParseMode(on) accepted")
	}
}
