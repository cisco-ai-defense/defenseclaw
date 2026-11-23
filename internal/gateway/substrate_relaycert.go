// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// substrateRelayCertMax bounds a certificate request body (a P-256 CSR is
// well under 1 KiB).
const substrateRelayCertMax = 16 << 10

// substrateRelayHandshakeBudget bounds the TLS handshake with a relay; the
// relay may ask this gateway for its certificate first (relay certBudget).
const substrateRelayHandshakeBudget = 15 * time.Second

// serveSubstrateRelayCert signs the relay's serving certificate (B3.5) on
// the actor listener: the actor JWT names the actor, and the certificate
// carries that actor's UID only, whatever the CSR asks for. The agent in
// the actor shares the actor JWT (GAP-0291), so it can get a certificate
// for its own actor too; it cannot get the relay's key, and the gateway
// dials only the actor's own relay port, so serving one needs the relay
// gone first.
func (a *APIServer) serveSubstrateRelayCert(st *substrateState, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeSubstrateRefusal(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor, ok := substrateActorFrom(r.Context())
	if !ok {
		writeSubstrateRefusal(w, http.StatusUnauthorized, "missing_token")
		return
	}
	if st.cfg.RelayCA == nil {
		writeSubstrateRefusal(w, http.StatusServiceUnavailable, "relay_ca_missing")
		return
	}
	var in relay.CertRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, substrateRelayCertMax)).Decode(&in); err != nil {
		writeSubstrateRefusal(w, http.StatusBadRequest, "bad_csr")
		return
	}
	der, err := base64.StdEncoding.DecodeString(in.CSR)
	if err != nil {
		writeSubstrateRefusal(w, http.StatusBadRequest, "bad_csr")
		return
	}
	now := st.clock()
	row := map[string]any{"atespace": actor.Atespace, "actor": actor.Name, "actor_uid": actor.UID}
	// A renewal proves the live key (GAP-0819). A bad proof is refused: it
	// is never a relay's own renewal.
	renewal := false
	if in.Current != "" || in.Proof != "" {
		proof, perr := base64.StdEncoding.DecodeString(in.Proof)
		if perr == nil {
			_, perr = st.cfg.RelayCA.CheckRenewal(actor.UID, []byte(in.Current), der, proof, now)
		}
		if perr != nil {
			a.substrateRelayCertAudit(st, r, "HIGH", "relay certificate renewal refused for "+actor.Atespace+"/"+actor.Name+": the proof of the current key does not hold",
				"substrate.relay.cert_refused", row, map[string]any{"reason": "renewal_proof_refused"})
			writeSubstrateRefusal(w, http.StatusForbidden, "renewal_proof_refused")
			return
		}
		renewal = true
	}
	cert, err := st.cfg.RelayCA.Sign(der, actor.UID, now)
	if err != nil {
		writeSubstrateRefusal(w, http.StatusBadRequest, "bad_csr")
		return
	}
	prev, second := st.relayCerts.issued(actor.UID, cert, now)
	switch {
	case second && !renewal:
		// One live certificate per actor: a second one asked for with the
		// actor JWT alone is what an attacker holding that JWT would do. A
		// relay that restarted (crash, suspend and resume) does the same
		// and cannot prove a key it lost, so it is issued and flagged.
		a.substrateRelayCertAudit(st, r, "HIGH", "second relay serving certificate issued for "+actor.Atespace+"/"+actor.Name+" without proof of the live key",
			"substrate.relay.cert_second", row, map[string]any{"previous_serial": prev, "ttl_s": int(relaytls.CertTTL / time.Second)})
	default:
		a.substrateRelayCertAudit(st, r, "INFO", "relay serving certificate issued for "+actor.Atespace+"/"+actor.Name,
			"substrate.relay.cert", row, map[string]any{"renewal": renewal, "ttl_s": int(relaytls.CertTTL / time.Second)})
	}
	writeSubstrateJSON(w, http.StatusOK, relay.CertResponse{Cert: string(cert)})
}

func (a *APIServer) substrateRelayCertAudit(st *substrateState, r *http.Request, severity, summary, event string, row, extra map[string]any) {
	if st.audit == nil {
		return
	}
	d := map[string]any{"event": event}
	for k, v := range row {
		d[k] = v
	}
	for k, v := range extra {
		d[k] = v
	}
	st.audit(r.Context(), severity, summary, d)
}

// substrateRelayCertsLive is the live relay serving certificate per actor
// UID (serial and expiry) that this replica issued (GAP-0819).
type substrateRelayCertsLive struct {
	mu   sync.Mutex
	live map[string]substrateRelayCertLive
}

type substrateRelayCertLive struct {
	serial   string
	notAfter time.Time
}

// issued records certPEM as uid's live certificate. second is set when uid
// already had an unexpired one, whose serial is prev.
func (c *substrateRelayCertsLive) issued(uid string, certPEM []byte, now time.Time) (prev string, second bool) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return "", false
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live == nil {
		c.live = map[string]substrateRelayCertLive{}
	}
	if old, ok := c.live[uid]; ok && now.Before(old.notAfter) {
		prev, second = old.serial, true
	}
	if len(c.live) >= 4096 {
		for k, v := range c.live {
			if !now.Before(v.notAfter) {
				delete(c.live, k)
			}
		}
	}
	c.live[uid] = substrateRelayCertLive{serial: cert.SerialNumber.Text(16), notAfter: cert.NotAfter}
	return prev, second
}

func (st *substrateState) clock() time.Time {
	if st.now != nil {
		return st.now()
	}
	return time.Now()
}

// substrateRelayDial is how attach reaches one actor's relay under
// substrate.relay_tls (B3.5): TLS verified against the relay CA and the
// actor's UID when its signed kit serves TLS, plain HTTP with an audit row
// for an older template in auto, or a refusal reason.
func (a *APIServer) substrateRelayDial(ctx context.Context, st *substrateState, reg registry.Registration) (func(context.Context) (net.Conn, error), int, string) {
	space, name := reg.Atespace, reg.Name
	plain := func(ctx context.Context) (net.Conn, error) { return st.cfg.Relays.DialRelay(ctx, space, name) }
	switch relaytls.Decide(st.cfg.RelayTLS, reg.RelayServesTLS()) {
	case relaytls.Refuse:
		return nil, http.StatusForbidden, "relay_tls_required"
	case relaytls.DialPlain:
		if st.cfg.RelayTLS != relaytls.ModeOff && st.audit != nil {
			st.audit(ctx, "MEDIUM", "attach to "+space+"/"+name+" uses plain HTTP to the relay (template built before relay TLS)",
				map[string]any{"event": "substrate.relay.plain", "atespace": space, "actor": name, "actor_uid": reg.UID})
		}
		return plain, http.StatusOK, ""
	}
	if st.cfg.RelayCA == nil {
		return nil, http.StatusServiceUnavailable, "relay_ca_missing"
	}
	conf, err := relaytls.ClientConfig(st.cfg.RelayCA.Pool(), reg.UID)
	if err != nil {
		return nil, http.StatusBadGateway, "relay_unreachable"
	}
	return func(ctx context.Context) (net.Conn, error) {
		c, err := plain(ctx)
		if err != nil {
			return nil, err
		}
		hctx, cancel := context.WithTimeout(ctx, substrateRelayHandshakeBudget)
		defer cancel()
		tc := tls.Client(c, conf)
		if err := tc.HandshakeContext(hctx); err != nil {
			_ = c.Close()
			return nil, err
		}
		return tc, nil
	}, http.StatusOK, ""
}
