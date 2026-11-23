// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// certBudget bounds one certificate request to the gateway.
const certBudget = 8 * time.Second

// CertRequest and CertResponse are the body of the gateway's
// /api/v1/substrate/relay/cert route (B3.5).
type CertRequest struct {
	// CSR is the base64 DER certificate request of the relay's key.
	CSR string `json:"csr"`
	// Current and Proof prove a renewal (GAP-0819): the PEM certificate
	// being renewed and its key's base64 signature of the CSR.
	Current string `json:"current,omitempty"`
	Proof   string `json:"proof,omitempty"`
}

// CertResponse carries the signed serving certificate.
type CertResponse struct {
	// Cert is the PEM certificate, SAN uid.<actor uid>.relay.defenseclaw.invalid.
	Cert string `json:"cert"`
}

// CertSource keeps the relay's TLS serving certificate for the actor it
// serves now (B3.5). The key is made in the relay and never leaves it; the
// gateway signs a CSR for the actor its JWT names. Every actor of a
// template is restored from one snapshot and a fork or resume has a new
// UID, so the certificate is fetched for the UID of the projected identity
// at handshake time: a changed UID or a certificate past half its life
// asks the gateway again. A relay with no certificate fails the handshake;
// it never serves another actor's certificate.
type CertSource struct {
	URL    string
	Client *http.Client
	Self   func() (Identity, error)
	Now    func() time.Time
	// Budget bounds one request; 0 is certBudget.
	Budget time.Duration

	mu  sync.Mutex // one request at a time
	cur atomic.Pointer[heldCert]
}

type heldCert struct {
	uid      string
	cert     *tls.Certificate
	renewAt  time.Time
	notAfter time.Time
}

func (c *CertSource) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// ServerConfig is the relay's TLS 1.3 server configuration.
func (c *CertSource) ServerConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.Get(hi.Context())
	}}
}

// Get is the certificate for the actor the relay serves now.
func (c *CertSource) Get(ctx context.Context) (*tls.Certificate, error) {
	id, err := c.Self()
	if err != nil {
		return nil, err
	}
	if h := c.cur.Load(); h != nil && h.uid == id.UID && c.now().Before(h.renewAt) {
		return h.cert, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.cur.Load(); h != nil && h.uid == id.UID && c.now().Before(h.renewAt) {
		return h.cert, nil
	}
	h, err := c.fetch(ctx, id.UID)
	if err != nil {
		// A renewal that fails keeps a certificate of this actor that has
		// not expired; a new actor gets none.
		if old := c.cur.Load(); old != nil && old.uid == id.UID && c.now().Before(old.notAfter) {
			return old.cert, nil
		}
		return nil, err
	}
	c.cur.Store(h)
	return h.cert, nil
}

func (c *CertSource) fetch(ctx context.Context, uid string) (*heldCert, error) {
	want, err := relaytls.SANForUID(uid)
	if err != nil {
		return nil, err
	}
	key, csr, err := relaytls.NewKeyAndCSR()
	if err != nil {
		return nil, err
	}
	in := CertRequest{CSR: base64.StdEncoding.EncodeToString(csr)}
	// A renewal proves the live key, so the gateway can tell it from a
	// second certificate asked for with the actor JWT alone (GAP-0819).
	if h := c.cur.Load(); h != nil && h.uid == uid && c.now().Before(h.notAfter) && h.cert.Leaf != nil {
		if proof, err := relaytls.RenewalProof(h.cert, csr); err == nil {
			in.Current = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.cert.Leaf.Raw}))
			in.Proof = base64.StdEncoding.EncodeToString(proof)
		}
	}
	body, _ := json.Marshal(in)
	budget := c.Budget
	if budget <= 0 {
		budget = certBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(kit.PlaceholderHeader, kit.PlaceholderValue)
	req.Header.Set("X-DefenseClaw-Client", "actor-relay/"+kit.Version)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay certificate: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay certificate refused by the gateway (status %d)", resp.StatusCode)
	}
	var out CertResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("relay certificate: %w", err)
	}
	kp, err := relaytls.KeyPair([]byte(out.Cert), key)
	if err != nil {
		return nil, fmt.Errorf("relay certificate: %w", err)
	}
	// The gateway names the actor of the JWT; the relay serves only a
	// certificate for the actor it is.
	if !slices.Equal(kp.Leaf.DNSNames, []string{want}) {
		return nil, errors.New("relay certificate: the gateway signed it for another actor")
	}
	life := kp.Leaf.NotAfter.Sub(kp.Leaf.NotBefore)
	return &heldCert{uid: uid, cert: kp, renewAt: kp.Leaf.NotBefore.Add(life / 2), notAfter: kp.Leaf.NotAfter}, nil
}

// Warm asks for the certificate now, so the first attach after a start or
// resume does not wait for it; a failure is retried at the next handshake.
func (c *CertSource) Warm(ctx context.Context) error {
	_, err := c.Get(ctx)
	return err
}

// plainOnlyHandler is what a TLS relay serves without TLS: the wake-up
// probe and nothing else (design unknown (a): the probe may be plain).
func plainOnlyHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "relay_tls_required: this relay serves attachments over TLS only", http.StatusUpgradeRequired)
	})
	return mux
}

// serveListeners serves h on ln; a TLS kit splits the port so TLS gets h
// and plain HTTP only the probe.
func serveListeners(ln net.Listener, h http.Handler, certs *CertSource) error {
	if certs == nil {
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
		return srv.Serve(ln)
	}
	tl, pl := relaytls.Split(ln, certs.ServerConfig())
	plain := &http.Server{Handler: plainOnlyHandler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- plain.Serve(pl) }()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { errc <- srv.Serve(tl) }()
	err := <-errc
	_ = srv.Close()
	_ = plain.Close()
	return err
}
