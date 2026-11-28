// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package relaytls is the TLS between the gateway and an actor's relay
// (B3.5). The relay makes a P-256 key at start and asks the gateway, on the
// actor listener, to sign it with the relay CA. The certificate names the
// actor UID only (SANForUID), so a gateway that dials actor A and reaches
// actor B's relay refuses the handshake. The relay CA key is its own
// Secret: the session-token key never signs serving certificates (D3-9).
package relaytls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // the RFC 6455 accept value, not a security hash
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SANSuffix is the DNS name suffix of every relay certificate. The
// .invalid TLD never resolves, so the name is only ever a pin.
const SANSuffix = ".relay.defenseclaw.invalid"

// CertTTL is the life of a relay serving certificate. The relay renews at
// half life and on resume (a resumed or forked actor has a new UID).
const CertTTL = 24 * time.Hour

// Mode is substrate.relay_tls.
type Mode string

const (
	// ModeAuto uses TLS for every actor whose signed kit serves it and
	// plain HTTP, with an audit row, for templates built before 1.0.11.
	ModeAuto Mode = "auto"
	// ModeRequired refuses an actor whose kit does not serve TLS.
	ModeRequired Mode = "required"
	// ModeOff dials templates built before relay TLS in plain HTTP with no
	// audit row or doctor warning. A TLS kit's relay serves attachments
	// over TLS only, so a TLS kit is still dialed with TLS.
	ModeOff Mode = "off"
)

// ParseMode accepts "", auto, required and off ("" is auto).
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case "", ModeAuto:
		return ModeAuto, nil
	case ModeRequired, ModeOff:
		return m, nil
	}
	return "", fmt.Errorf("relay_tls %q: want auto, required or off", s)
}

// Decision is how the gateway dials one actor.
type Decision int

const (
	// DialTLS verifies the relay certificate against the relay CA and the
	// actor UID.
	DialTLS Decision = iota
	// DialPlain is the pre-1.0.11 path; the caller writes an audit row.
	DialPlain
	// Refuse answers relay_tls_required.
	Refuse
)

// Decide picks the dial for an actor. kitServesTLS comes from the
// template's signed attestation, never from the relay, so an attacker on
// the cluster network cannot downgrade a TLS kit to plain in auto mode.
// A TLS kit is dialed with TLS in every mode: its relay refuses plain
// attachments.
func Decide(m Mode, kitServesTLS bool) Decision {
	switch {
	case kitServesTLS:
		return DialTLS
	case m == ModeRequired:
		return Refuse
	}
	return DialPlain
}

// SANForUID is the one DNS name a relay certificate for uid carries.
func SANForUID(uid string) (string, error) {
	if !validUID(uid) {
		return "", fmt.Errorf("actor uid %q is not a DNS label", uid)
	}
	return "uid." + strings.ToLower(uid) + SANSuffix, nil
}

// validUID accepts a Kubernetes UID (hex and dashes) of 1-63 bytes.
func validUID(uid string) bool {
	if uid == "" || len(uid) > 63 || uid[0] == '-' || uid[len(uid)-1] == '-' {
		return false
	}
	for _, c := range uid {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && c != '-' {
			return false
		}
	}
	return true
}

// CA is the relay CA the gateway signs relay serving certificates with.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
	// prev is the CAs after the first in ca.pem: trusted, never used to
	// sign (GAP-0820), so a rotation keeps relays on their old-CA
	// certificate working for one certificate lifetime.
	prev []*x509.Certificate
}

// MaxCABundle bounds the certificates in ca.pem: the signing CA and the
// ones it replaced.
const MaxCABundle = 4

// GenerateCA makes a new relay CA (substrate setup). It is valid for ten
// years. To rotate it, put the new CA first in ca.pem and the old one after
// it, restart the gateway, and drop the old one after CertTTL (GAP-0820).
func GenerateCA(now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "DefenseClaw relay CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		// The CA can only name relays.
		PermittedDNSDomains:         []string{SANSuffix[1:]},
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), nil
}

// LoadCA parses the relay CA Secret's PEM files. ca.pem holds the signing
// CA first (its key is ca-key.pem), then any CA it replaced, still trusted
// for the certificates it signed (GAP-0820).
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, rest := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("relay CA: no CERTIFICATE block")
	}
	var prev []*x509.Certificate
	for len(bytes.TrimSpace(rest)) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" {
			return nil, errors.New("relay CA: ca.pem holds something other than CERTIFICATE blocks")
		}
		p, err := x509.ParseCertificate(b.Bytes)
		if err != nil || !p.IsCA {
			return nil, errors.New("relay CA: a previous certificate in ca.pem is not a CA")
		}
		if prev = append(prev, p); len(prev) >= MaxCABundle {
			return nil, fmt.Errorf("relay CA: ca.pem holds more than %d certificates", MaxCABundle)
		}
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("relay CA: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("relay CA: no key block")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("relay CA key: %w", err)
	}
	if !cert.IsCA || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("relay CA: the key does not match a CA certificate")
	}
	return &CA{cert: cert, key: key, der: cb.Bytes, prev: prev}, nil
}

// Pool is the trust pool a gateway dials relays with: the signing CA and
// the previous ones in ca.pem.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	for _, prev := range c.prev {
		p.AddCert(prev)
	}
	return p
}

// Fingerprint is the signing CA's fingerprint, kept with each relay
// certificate record (GAP-0929).
func (c *CA) Fingerprint() string { return caFingerprint(c.der) }

// Trusts reports whether the CA with this fingerprint is still in the
// pool: false after an emergency rotation dropped it.
func (c *CA) Trusts(fp string) bool {
	if fp == c.Fingerprint() {
		return true
	}
	for _, p := range c.prev {
		if caFingerprint(p.Raw) == fp {
			return true
		}
	}
	return false
}

func caFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ErrRenewalUntrustedCA is a renewal proof that holds but whose
// certificate no CA in the pool signed (an emergency rotation dropped its
// CA, GAP-0929, or it was never this CA's).
var ErrRenewalUntrustedCA = errors.New("renewal proof: the current certificate's CA is not trusted")

// RenewalProof signs a new CSR with the key of the certificate it renews
// (GAP-0819): the gateway then knows the request comes from the holder of
// the actor's live relay key, not only from a holder of the actor JWT.
func RenewalProof(cur *tls.Certificate, csrDER []byte) ([]byte, error) {
	k, ok := cur.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("renewal proof: the current key is not ECDSA")
	}
	sum := sha256.Sum256(csrDER)
	return ecdsa.SignASN1(rand.Reader, k, sum[:])
}

// CheckRenewal verifies a renewal proof: curPEM is an unexpired certificate
// of this CA's pool for uid, and proof is its key's signature of csrDER.
// It returns the certificate renewed. A proof that holds for a certificate
// no CA in the pool signed returns it with ErrRenewalUntrustedCA.
func (c *CA) CheckRenewal(uid string, curPEM, csrDER, proof []byte, now time.Time) (*x509.Certificate, error) {
	san, err := SANForUID(uid)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(curPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("renewal proof: no current certificate")
	}
	cur, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("renewal proof: %w", err)
	}
	pub, ok := cur.PublicKey.(*ecdsa.PublicKey)
	sum := sha256.Sum256(csrDER)
	if !ok || !ecdsa.VerifyASN1(pub, sum[:], proof) {
		return nil, errors.New("renewal proof: the signature is not the current key's")
	}
	if _, err := cur.Verify(x509.VerifyOptions{Roots: c.Pool(), DNSName: san, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		var ua x509.UnknownAuthorityError
		if errors.As(err, &ua) {
			// The caller tells a dropped CA from a stranger with the record.
			return cur, fmt.Errorf("%w: %v", ErrRenewalUntrustedCA, err)
		}
		return nil, fmt.Errorf("renewal proof: %w", err)
	}
	return cur, nil
}

// CertPEM is the CA certificate (no key).
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// Sign signs a relay CSR for uid. The CSR's own names are ignored: the
// gateway names the actor it authenticated, never what the relay asks for.
// Only P-256 keys are signed.
func (c *CA) Sign(csrDER []byte, uid string, now time.Time) ([]byte, error) {
	san, err := SANForUID(uid)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("csr: the key must be ECDSA P-256")
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: san},
		DNSNames:     []string{san},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(CertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, pub, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// ClientConfig is the gateway's TLS config for one actor's relay: the
// relay CA only, the actor's own SAN, TLS 1.3.
func ClientConfig(pool *x509.CertPool, uid string) (*tls.Config, error) {
	san, err := SANForUID(uid)
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: pool, ServerName: san, MinVersion: tls.VersionTLS13}, nil
}

// NewKeyAndCSR makes the relay's serving key and a CSR for it.
func NewKeyAndCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "defenseclaw-actor-relay"}}, key)
	return key, der, err
}

// KeyPair is the serving certificate for key and the PEM chain the
// gateway signed (Sign). Leaf is set, so the caller can read its names and
// lifetime.
func KeyPair(certPEM []byte, key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
	if err != nil {
		return nil, err
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// The gateway reaches a relay through the atenet router: CONNECT, then a
// stream the worker-side Envoy parses as HTTP/1.1. It proxies HTTP and a
// WebSocket upgrade (opaque bytes after the 101) and answers anything else,
// a raw TLS ClientHello included, itself with 400 (GAP-1067). So TLS to the
// relay starts with an upgrade the ingress passes: the gateway asks for
// UpgradePath with Upgrade: websocket and the UpgradeProtocol subprotocol,
// the relay answers 101, and TLS runs end to end on the upgraded stream.
// The upgrade is framing only: the TLS session after it is what the
// gateway trusts (relay CA, actor UID, live certificate).
const (
	// UpgradePath is the request that switches a relay stream to TLS.
	UpgradePath = "/.defenseclaw/relay-tls"
	// UpgradeProtocol is its Sec-WebSocket-Protocol value.
	UpgradeProtocol = "defenseclaw.relay-tls.v1"
	// upgradeHost is the authority of the upgrade request; the relay
	// stream's requests all name it (attach's reverse proxy).
	upgradeHost  = "actor.invalid"
	wsAcceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// ErrNoUpgrade is a relay stream that did not switch to TLS: a relay that
// does not serve TLS, one built before this handshake, or an ingress that
// refused the upgrade. The gateway refuses the attachment; it never falls
// back to plain for a TLS kit.
var ErrNoUpgrade = errors.New("relay TLS: the relay did not switch the stream to TLS")

// Upgrade switches c, a stream to one actor's relay, to TLS with conf: an
// HTTP/1.1 WebSocket upgrade to UpgradePath, then a TLS client handshake on
// the upgraded stream. ctx bounds both. The caller closes c on an error.
func Upgrade(ctx context.Context, c net.Conn, conf *tls.Config) (*tls.Conn, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	req := "GET " + UpgradePath + " HTTP/1.1\r\nHost: " + upgradeHost + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Protocol: " + UpgradeProtocol + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return nil, fmt.Errorf("relay TLS upgrade: %w", err)
	}
	br := bufio.NewReaderSize(c, 4096)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("relay TLS upgrade: %w", err)
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode != http.StatusSwitchingProtocols:
		return nil, fmt.Errorf("%w (HTTP %d)", ErrNoUpgrade, resp.StatusCode)
	case !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket"),
		resp.Header.Get("Sec-WebSocket-Protocol") != UpgradeProtocol,
		resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key):
		return nil, fmt.Errorf("%w (the 101 answer is not the relay's)", ErrNoUpgrade)
	}
	// The relay sends nothing after the 101 before the ClientHello's
	// answer, but keep anything read ahead.
	pre, _ := br.Peek(br.Buffered())
	tc := tls.Client(&prefixConn{Conn: c, prefix: bytes.NewReader(bytes.Clone(pre))}, conf)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return tc, nil
}

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsAcceptGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// isUpgrade reports whether req asks to switch the stream to TLS.
func isUpgrade(req *http.Request) bool {
	if req.Method != http.MethodGet || req.URL.Path != UpgradePath || !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		!headerToken(req.Header, "Connection", "upgrade") || !headerToken(req.Header, "Sec-WebSocket-Protocol", UpgradeProtocol) {
		return false
	}
	k, err := base64.StdEncoding.DecodeString(req.Header.Get("Sec-WebSocket-Key"))
	return err == nil && len(k) == 16
}

func headerToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// Splitter serves TLS and plain HTTP on the relay's one port, so
// Substrate's plain wake-up probe still reaches /readyz (design unknown
// (a)). The port serves plain HTTP; the Upgrade request, on any request of
// any connection (the worker Envoy may send it on a pooled upstream
// connection), is answered 101 and the connection goes to the TLS
// listener once its TLS handshake is done. A raw TLS ClientHello is not
// HTTP: no ingress carries one (GAP-1067), and the plain server refuses
// it. A failed handshake goes to failed when it is not nil (the relay
// renews at once when the gateway refuses its certificate, GAP-0929).
type Splitter struct {
	tls    *chanListener
	conf   *tls.Config
	failed func(error)
}

// Split makes the Splitter for a port at addr.
func Split(addr net.Addr, tlsConf *tls.Config, failed func(error)) *Splitter {
	return &Splitter{tls: newChanListener(addr), conf: tlsConf, failed: failed}
}

// TLS is the listener of upgraded, handshaken TLS connections.
func (s *Splitter) TLS() net.Listener { return s.tls }

// Handler serves plain on the port and switches an Upgrade request to TLS.
func (s *Splitter) Handler(plain http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpgrade(r) {
			plain.ServeHTTP(w, r)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "relay TLS needs HTTP/1.1", http.StatusHTTPVersionNotSupported)
			return
		}
		c, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			wsAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\nSec-WebSocket-Protocol: " + UpgradeProtocol + "\r\n\r\n")
		if err == nil {
			err = rw.Flush()
		}
		if err != nil {
			_ = c.Close()
			return
		}
		// The gateway sends nothing before the 101, but keep what was read.
		pre, _ := rw.Peek(rw.Reader.Buffered())
		tc := tls.Server(&prefixConn{Conn: c, prefix: bytes.NewReader(bytes.Clone(pre))}, s.conf)
		err = tc.Handshake()
		_ = c.SetDeadline(time.Time{})
		if err != nil {
			if s.failed != nil {
				s.failed(err)
			}
			_ = tc.Close()
			return
		}
		s.tls.push(tc)
	})
}

type prefixConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if p.prefix.Len() > 0 {
		return p.prefix.Read(b)
	}
	return p.Conn.Read(b)
}

type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener(a net.Addr) *chanListener {
	return &chanListener{addr: a, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) close() { l.once.Do(func() { close(l.done) }) }

// Close closes this side only; the caller closes the shared listener.
func (l *chanListener) Close() error { l.close(); return nil }

func (l *chanListener) Addr() net.Addr { return l.addr }

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}
