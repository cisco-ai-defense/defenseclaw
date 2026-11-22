// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
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
	cert, err := st.cfg.RelayCA.Sign(der, actor.UID, st.clock())
	if err != nil {
		writeSubstrateRefusal(w, http.StatusBadRequest, "bad_csr")
		return
	}
	if st.audit != nil {
		st.audit(r.Context(), "INFO", "relay serving certificate issued for "+actor.Atespace+"/"+actor.Name,
			map[string]any{"event": "substrate.relay.cert", "atespace": actor.Atespace, "actor": actor.Name, "actor_uid": actor.UID,
				"ttl_s": int(relaytls.CertTTL / time.Second)})
	}
	writeSubstrateJSON(w, http.StatusOK, relay.CertResponse{Cert: string(cert)})
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
