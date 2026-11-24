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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
	// A renewal proves a key (GAP-0819), and the leader takes it only for
	// the live certificate (GAP-0928). A bad proof is refused: it is never
	// a relay's own renewal.
	proved := ""
	if in.Current != "" || in.Proof != "" {
		var cur *x509.Certificate
		proof, perr := base64.StdEncoding.DecodeString(in.Proof)
		if perr == nil {
			cur, perr = st.cfg.RelayCA.CheckRenewal(actor.UID, []byte(in.Current), der, proof, now)
		}
		if perr != nil {
			reason := "renewal_proof_refused"
			if errors.Is(perr, relaytls.ErrRenewalUntrustedCA) && st.relayCertCADropped(r.Context(), actor.Atespace, actor.UID, cur) {
				// The relay asks again without proof (GAP-0929).
				reason = "renewal_ca_dropped"
			}
			a.substrateRelayCertAudit(st, r, "HIGH", "relay certificate renewal refused for "+actor.Atespace+"/"+actor.Name+": the proof of the current key does not hold",
				"substrate.relay.cert_refused", row, map[string]any{"reason": reason})
			writeSubstrateRefusal(w, http.StatusForbidden, reason)
			return
		}
		proved = cur.SerialNumber.Text(16)
	}
	cert, err := st.cfg.RelayCA.Sign(der, actor.UID, now)
	if err != nil {
		writeSubstrateRefusal(w, http.StatusBadRequest, "bad_csr")
		return
	}
	rec, err := substrateRelayCertRecord(cert)
	if err != nil {
		writeSubstrateRefusal(w, http.StatusInternalServerError, "relay_cert_failed")
		return
	}
	rec.CA = st.cfg.RelayCA.Fingerprint()
	// One live certificate per actor, on the leader (GAP-0861), so every
	// replica and a restarted gateway answer the same. A renewal replaces
	// it only when it proved the live one (GAP-0928); a request without
	// proof is a first certificate only when the actor has no live one.
	refuse := st.cfg.relayCertRefuse()
	ttl := int(relaytls.CertTTL / time.Second)
	claim := func(replace bool) (registry.RelayCertClaimed, error) {
		if st.cfg.RelayCerts == nil {
			return registry.RelayCertClaimed{}, errSubstrateNoRelayCerts
		}
		return st.cfg.RelayCerts.ClaimRelayCert(r.Context(), registry.RelayCertClaim{
			Atespace: actor.Atespace, UID: actor.UID, Cert: rec, Replace: replace, Expect: proved, Now: now})
	}
	got, cerr := claim(false)
	renewal := proved != ""
	liveExtra := func(extra map[string]any) map[string]any {
		if got.Prev.Cleared {
			extra["previous"] = "cleared by recover"
		} else if got.Prev.Serial != "" {
			extra["previous_serial"] = got.Prev.Serial
		}
		if got.Prev.CA != "" && !st.cfg.RelayCA.Trusts(got.Prev.CA) {
			extra["previous_ca"] = "dropped"
		}
		return extra
	}
	switch {
	case cerr != nil && refuse:
		a.substrateRelayCertAudit(st, r, "HIGH", "relay serving certificate not issued for "+actor.Atespace+"/"+actor.Name+": the leader's record of live relay certificates is unavailable",
			"substrate.relay.cert_refused", row, map[string]any{"reason": "relay_cert_record_unavailable", "error": cerr.Error()})
		w.Header().Set("Retry-After", "5")
		writeSubstrateRefusal(w, http.StatusServiceUnavailable, "relay_cert_record_unavailable")
		return
	case renewal && (cerr != nil || got.Set):
		extra := map[string]any{"renewal": true, "ttl_s": ttl}
		if cerr != nil {
			extra["record"] = "unavailable"
		}
		if got.Retry {
			// The relay asked again with the same proof: the reply to its
			// renewal was lost (GAP-0958). One retry is that; a second
			// and later ones inside the same grace are not (GAP-0970):
			// still issued, but HIGH.
			extra["retry"] = true
			if got.Retries > relayCertRetriesInfo {
				extra["retries"] = got.Retries
				a.substrateRelayCertAudit(st, r, "HIGH", "relay serving certificate renewal retried again for "+actor.Atespace+"/"+actor.Name+": the same previous certificate was proved more than once; a lost reply explains one retry (it is issued)",
					"substrate.relay.cert_retry_repeated", row, extra)
				break
			}
		}
		a.substrateRelayCertAudit(st, r, "INFO", "relay serving certificate issued for "+actor.Atespace+"/"+actor.Name,
			"substrate.relay.cert", row, extra)
	case renewal && refuse:
		// Proof of a certificate that is not the live one: whoever got
		// another certificate for this actor (in the start window, or
		// before recover) cannot keep renewing it.
		a.substrateRelayCertAudit(st, r, "HIGH", "relay certificate renewal refused for "+actor.Atespace+"/"+actor.Name+": the certificate it proves is not the actor's live one (substrate.relay_cert_reissue refuse)",
			"substrate.relay.cert_refused", row, liveExtra(map[string]any{"reason": "renewal_not_live", "proved_serial": proved}))
		writeSubstrateRefusal(w, http.StatusForbidden, "renewal_not_live")
		return
	case renewal:
		// flag: issued, and the live one stays the live one.
		a.substrateRelayCertAudit(st, r, "HIGH", "second relay serving certificate issued for "+actor.Atespace+"/"+actor.Name+": the renewal proves a certificate that is not the actor's live one",
			"substrate.relay.cert_second", row, liveExtra(map[string]any{"reason": "renewal_not_live", "proved_serial": proved, "ttl_s": ttl}))
	case cerr != nil:
		// flag: without the record this may be a second certificate.
		a.substrateRelayCertAudit(st, r, "HIGH", "relay serving certificate issued for "+actor.Atespace+"/"+actor.Name+" without proof of the live key; the leader's record of live relay certificates is unavailable, so it may be a second one",
			"substrate.relay.cert_second", row, map[string]any{"record": "unavailable", "error": cerr.Error(), "ttl_s": ttl})
	case got.Set:
		a.substrateRelayCertAudit(st, r, "INFO", "relay serving certificate issued for "+actor.Atespace+"/"+actor.Name,
			"substrate.relay.cert", row, liveExtra(map[string]any{"renewal": false, "ttl_s": ttl}))
	case refuse:
		// A second certificate asked for with the actor JWT alone is what
		// someone holding that JWT would do. A relay that restarted inside
		// its actor asks the same way and cannot prove a key it lost, as
		// does one whose CA an emergency rotation dropped: the owner or an
		// administrator lets it through with substrate recover.
		a.substrateRelayCertAudit(st, r, "HIGH", "second relay serving certificate refused for "+actor.Atespace+"/"+actor.Name+": no proof of the live key (substrate.relay_cert_reissue refuse; defenseclaw substrate recover clears it)",
			"substrate.relay.cert_refused", row, liveExtra(map[string]any{"reason": "reissue_refused"}))
		writeSubstrateRefusal(w, http.StatusForbidden, "reissue_refused")
		return
	default:
		// flag: issued, and it is the live one now.
		extra := liveExtra(map[string]any{"ttl_s": ttl})
		if _, err := claim(true); err != nil {
			extra["record"] = "unavailable"
		}
		a.substrateRelayCertAudit(st, r, "HIGH", "second relay serving certificate issued for "+actor.Atespace+"/"+actor.Name+" without proof of the live key",
			"substrate.relay.cert_second", row, extra)
	}
	writeSubstrateJSON(w, http.StatusOK, relay.CertResponse{Cert: string(cert)})
}

// relayCertRetriesInfo is how many retries of one renewal inside a grace
// write an INFO row (GAP-0970); later ones write HIGH.
const relayCertRetriesInfo = 1

// relayCertCADropped reports whether cur is the actor's live certificate
// and an emergency rotation dropped the CA that signed it (GAP-0929).
func (st *substrateState) relayCertCADropped(ctx context.Context, atespace, uid string, cur *x509.Certificate) bool {
	if cur == nil || st.cfg.RelayCerts == nil {
		return false
	}
	live, ok, err := st.cfg.RelayCerts.LiveRelayCert(ctx, atespace, uid)
	return err == nil && ok && !live.Cleared && live.Serial == cur.SerialNumber.Text(16) &&
		live.CA != "" && !st.cfg.RelayCA.Trusts(live.CA)
}

// relayCertLive checks the certificate a relay serves at attach against
// the leader's record (GAP-0928). The live one passes, and the one its
// last renewal replaced until the relay presents the new one (GAP-0958: a
// lost renewal reply). Under refuse nothing else passes: the refused relay
// asks for a new certificate at its next handshake (relay
// CertSource.Rejected). Under flag the CA's word is enough, as it is when
// flag signs a second certificate (GAP-0959): any certificate the CA
// signed for the actor passes, with a HIGH audit row when it is not the
// live one.
func (st *substrateState) relayCertLive(ctx context.Context, reg registry.Registration, leaf *x509.Certificate) error {
	if st.cfg.RelayCerts == nil {
		return nil
	}
	refuse := st.cfg.relayCertRefuse()
	serial := leaf.SerialNumber.Text(16)
	live, ok, err := st.cfg.RelayCerts.LiveRelayCert(ctx, reg.Atespace, reg.UID)
	why := ""
	switch {
	case err != nil:
		if refuse {
			return fmt.Errorf("relay certificate record: %w", err)
		}
		// flag: the CA's word is enough, and the row says nothing could
		// be checked (GAP-0971).
		if st.audit != nil {
			st.audit(ctx, "WARN", "attach to "+reg.Atespace+"/"+reg.Name+" takes a relay certificate without checking it is the actor's live one: the leader's record of live relay certificates is unavailable (substrate.relay_cert_reissue flag)",
				map[string]any{"event": "substrate.relay.cert_record_unavailable", "atespace": reg.Atespace, "actor": reg.Name, "actor_uid": reg.UID,
					"serial": serial, "error": err.Error(), "mode": "flag"})
		}
		return nil
	case ok && !live.Cleared && live.Serial == serial:
		if live.Prev != "" {
			// The relay presents the new one: the previous one is done. A
			// failure only leaves it taken until it expires.
			_, _ = st.cfg.RelayCerts.ClaimRelayCert(ctx, registry.RelayCertClaim{Atespace: reg.Atespace, UID: reg.UID, Seen: serial})
		}
		return nil
	case ok && !live.Cleared && live.Prev == serial && st.clock().Before(live.PrevUntil):
		return nil
	case refuse:
		return errSubstrateRelayCertNotLive
	case !ok:
		why = "no live record"
	case live.Cleared:
		why = "cleared by recover"
	default:
		why = "not the live serial"
	}
	if st.audit != nil {
		st.audit(ctx, "HIGH", "attach to "+reg.Atespace+"/"+reg.Name+" takes a relay certificate that is not the actor's live one (substrate.relay_cert_reissue flag)",
			map[string]any{"event": "substrate.relay.cert_not_live", "atespace": reg.Atespace, "actor": reg.Name, "actor_uid": reg.UID,
				"serial": serial, "live_serial": live.Serial, "record": why, "mode": "flag"})
	}
	return nil
}

// errSubstrateRelayCertNotLive is a relay serving a certificate that is
// not its actor's live one.
var errSubstrateRelayCertNotLive = errors.New("relay certificate: not the actor's live one")

// errSubstrateNoRelayCerts is a gateway without the leader's record of
// live relay certificates (SubstrateConfig.RelayCerts nil).
var errSubstrateNoRelayCerts = errors.New("no record of live relay certificates")

// relayCertRefuse reports whether a second relay certificate without proof
// of the live key is refused (substrate.relay_cert_reissue, GAP-0861).
func (c SubstrateConfig) relayCertRefuse() bool {
	switch c.RelayCertReissue {
	case config.SubstrateRelayCertReissueRefuse:
		return true
	case config.SubstrateRelayCertReissueFlag:
		return false
	}
	return c.Managed
}

// substrateRelayCertRecord is the leader's record of a signed certificate.
func substrateRelayCertRecord(certPEM []byte) (registry.RelayCert, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return registry.RelayCert{}, errors.New("relay certificate: no PEM block")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return registry.RelayCert{}, err
	}
	return registry.RelayCert{Serial: cert.SerialNumber.Text(16), NotAfter: cert.NotAfter}, nil
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

func (st *substrateState) clock() time.Time {
	if st.now != nil {
		return st.now()
	}
	return time.Now()
}

// substrateRelayDial is how attach reaches one actor's relay under
// substrate.relay_tls (B3.5): TLS verified against the relay CA and the
// actor's UID, and under refuse only its live certificate (GAP-0928; under
// flag any certificate the CA signed for the UID, with a HIGH row when it
// is not the live one, GAP-0959), when its signed kit serves TLS, plain
// HTTP with an audit row for an older template in auto, or a refusal
// reason.
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
		dconf := conf.Clone()
		dconf.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errSubstrateRelayCertNotLive
			}
			err := st.relayCertLive(hctx, reg, cs.PeerCertificates[0])
			if errors.Is(err, errSubstrateRelayCertNotLive) && st.audit != nil {
				st.audit(hctx, "MEDIUM", "attach to "+space+"/"+name+" refused the relay's certificate: it is not the actor's live one (the relay asks for a new one)",
					map[string]any{"event": "substrate.relay.cert_not_live", "atespace": space, "actor": name, "actor_uid": reg.UID, "serial": cs.PeerCertificates[0].SerialNumber.Text(16)})
			}
			return err
		}
		// The worker ingress parses the router tunnel as HTTP, so TLS
		// starts after an upgrade it passes (GAP-1067); a relay that does
		// not switch is refused, never dialed plain.
		tc, err := relaytls.Upgrade(hctx, c, dconf)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		return tc, nil
	}, http.StatusOK, ""
}
