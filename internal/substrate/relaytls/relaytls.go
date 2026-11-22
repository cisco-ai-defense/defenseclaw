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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
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
	// ModeOff dials plain HTTP. It is the escape hatch until 1.0.13.
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
// A TLS kit is dialed with TLS in every mode but off.
func Decide(m Mode, kitServesTLS bool) Decision {
	switch {
	case m == ModeOff:
		return DialPlain
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
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '-') {
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
}

// GenerateCA makes a new relay CA (substrate setup). It is valid for ten
// years; rotating it means a new Secret and a gateway restart, after which
// relays renew at their next half life.
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

// LoadCA parses the relay CA Secret's PEM files.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("relay CA: no CERTIFICATE block")
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
	return &CA{cert: cert, key: key, der: cb.Bytes}, nil
}

// Pool is the trust pool a gateway dials relays with.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
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

// Holder keeps the relay's current certificate; renewals swap it in place
// so open connections keep theirs.
type Holder struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

// Set installs a certificate for key.
func (h *Holder) Set(certPEM []byte, key *ecdsa.PrivateKey) error {
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	c, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.cert = &c
	h.mu.Unlock()
	return nil
}

// ServerConfig serves the held certificate; a relay with none yet fails
// the handshake rather than serving anything else.
func (h *Holder) ServerConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		if h.cert == nil {
			return nil, errors.New("relay certificate not issued yet")
		}
		return h.cert, nil
	}}
}

// Split serves TLS and plain HTTP on one port: a connection whose first
// byte is a TLS handshake record (0x16) goes to the TLS listener, any other
// to the plain one. The relay keeps one port, so Substrate's plain wake-up
// probe still reaches /readyz (design unknown (a)).
func Split(ln net.Listener, tlsConf *tls.Config) (tlsLn, plainLn net.Listener) {
	s := &splitter{ln: ln, tls: newChanListener(ln.Addr()), plain: newChanListener(ln.Addr())}
	go s.run(tlsConf)
	return s.tls, s.plain
}

type splitter struct {
	ln         net.Listener
	tls, plain *chanListener
}

func (s *splitter) run(conf *tls.Config) {
	defer s.tls.close()
	defer s.plain.close()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		go s.route(c, conf)
	}
}

func (s *splitter) route(c net.Conn, conf *tls.Config) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	b := make([]byte, 1)
	n, err := c.Read(b)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil || n != 1 {
		_ = c.Close()
		return
	}
	pc := &prefixConn{Conn: c, prefix: bytes.NewReader(b)}
	if b[0] == 0x16 {
		s.tls.push(tls.Server(pc, conf))
		return
	}
	s.plain.push(pc)
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
