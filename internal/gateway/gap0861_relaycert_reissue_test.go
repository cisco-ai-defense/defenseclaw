//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

const gap0861UID = "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"

// gap0861Replica is one gateway replica: its own substrateState, the
// shared leader record.
type gap0861Replica struct {
	st   *substrateState
	rows []string
}

func gap0861New(ca *relaytls.CA, rc registry.RelayCerts, managed bool, mode string) *gap0861Replica {
	g := &gap0861Replica{}
	g.st = &substrateState{cfg: SubstrateConfig{RelayCA: ca, RelayCerts: rc, Managed: managed, RelayCertReissue: mode},
		audit: func(_ context.Context, sev, _ string, d map[string]any) {
			g.rows = append(g.rows, sev+" "+d["event"].(string))
		}}
	return g
}

// ask posts a certificate request for the actor; it answers the status,
// the refusal reason or the certificate, and the one audit row.
func (g *gap0861Replica) ask(t *testing.T, in relay.CertRequest) (int, string, string) {
	t.Helper()
	g.rows = nil
	body, _ := json.Marshal(in)
	w := httptest.NewRecorder()
	ctx := withSubstrateActor(t.Context(), *f14Actor(t, "tix", gap0861UID))
	(&APIServer{}).serveSubstrateRelayCert(g.st, w, httptest.NewRequest(http.MethodPost, substrateRelayCert, bytes.NewReader(body)).WithContext(ctx))
	if len(g.rows) != 1 {
		t.Fatalf("audit rows %v (status %d %s)", g.rows, w.Code, w.Body)
	}
	if w.Code != http.StatusOK {
		return w.Code, g.rows[0], reasonOf(t, w)
	}
	var out relay.CertResponse
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, g.rows[0], out.Cert
}

func gap0861Proofless(t *testing.T) relay.CertRequest {
	t.Helper()
	_, csr, err := relaytls.NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	return relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr)}
}

// GAP-0861, managed (auto = refuse): after the first certificate, one
// asked for without proof of the live key is refused, 403 reissue_refused
// with a HIGH row, on the replica that issued it, on a second replica, and
// after a gateway and leader restart. The relay's own renewal still works.
func TestGAP0861ManagedRefusesSecondOnEveryReplica(t *testing.T) {
	ca, dir := tixRelayCA(t), t.TempDir()
	store, err := registry.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, b := gap0861New(ca, store, true, ""), gap0861New(ca, store, true, "")
	key1, csr1, _ := relaytls.NewKeyAndCSR()
	code, row, cert1 := a.ask(t, relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr1)})
	if code != http.StatusOK || row != "INFO substrate.relay.cert" {
		t.Fatalf("first on A: %d %s", code, row)
	}
	for _, g := range []struct {
		name string
		r    *gap0861Replica
	}{{"A", a}, {"replica B", b}} {
		if code, row, reason := g.r.ask(t, gap0861Proofless(t)); code != http.StatusForbidden || reason != "reissue_refused" || row != "HIGH substrate.relay.cert_refused" {
			t.Fatalf("proofless second on %s: %d %s %s", g.name, code, row, reason)
		}
	}
	reopened, err := registry.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := gap0861New(ca, reopened, true, "")
	if code, row, reason := restarted.ask(t, gap0861Proofless(t)); code != http.StatusForbidden || reason != "reissue_refused" || row != "HIGH substrate.relay.cert_refused" {
		t.Fatalf("proofless second after a restart: %d %s %s", code, row, reason)
	}
	// The relay renews on another replica, with proof of its live key.
	cur, err := relaytls.KeyPair([]byte(cert1), key1)
	if err != nil {
		t.Fatal(err)
	}
	_, csr2, _ := relaytls.NewKeyAndCSR()
	proof, err := relaytls.RenewalProof(cur, csr2)
	if err != nil {
		t.Fatal(err)
	}
	if code, row, _ := b.ask(t, relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr2), Current: cert1, Proof: base64.StdEncoding.EncodeToString(proof)}); code != http.StatusOK || row != "INFO substrate.relay.cert" {
		t.Fatalf("renewal on B: %d %s", code, row)
	}
	// Cleared (the recover route): the next request is a first certificate.
	if err := store.ClearRelayCert(t.Context(), "eng-web", gap0861UID); err != nil {
		t.Fatal(err)
	}
	if code, row, _ := b.ask(t, gap0861Proofless(t)); code != http.StatusOK || row != "INFO substrate.relay.cert" {
		t.Fatalf("after clear: %d %s", code, row)
	}
	// Managed with an explicit flag is flag.
	if code, row, _ := gap0861New(ca, store, true, config.SubstrateRelayCertReissueFlag).ask(t, gap0861Proofless(t)); code != http.StatusOK || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("managed flag: %d %s", code, row)
	}
}

// GAP-0861, OSS (auto = flag): the second certificate is issued with a
// HIGH row on every replica and after a restart, not an INFO row
// (RV-TIX3 probe: INFO on replica B and on a restarted gateway).
func TestGAP0861OSSFlagsSecondOnEveryReplica(t *testing.T) {
	ca, dir := tixRelayCA(t), t.TempDir()
	store, err := registry.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, b := gap0861New(ca, store, false, ""), gap0861New(ca, store, false, "")
	if code, row, _ := a.ask(t, gap0861Proofless(t)); code != http.StatusOK || row != "INFO substrate.relay.cert" {
		t.Fatalf("first on A: %d %s", code, row)
	}
	if code, row, _ := b.ask(t, gap0861Proofless(t)); code != http.StatusOK || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("proofless second on replica B: %d %s", code, row)
	}
	reopened, err := registry.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if code, row, _ := gap0861New(ca, reopened, false, "").ask(t, gap0861Proofless(t)); code != http.StatusOK || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("proofless second after a restart: %d %s", code, row)
	}
	// OSS with an explicit refuse is refuse.
	if code, row, reason := gap0861New(ca, reopened, false, config.SubstrateRelayCertReissueRefuse).ask(t, gap0861Proofless(t)); code != http.StatusForbidden || reason != "reissue_refused" || row != "HIGH substrate.relay.cert_refused" {
		t.Fatalf("OSS refuse: %d %s %s", code, row, reason)
	}
}

// GAP-0861: without the leader's record, refuse issues nothing (503) and
// flag issues with a HIGH row.
func TestGAP0861RecordUnavailable(t *testing.T) {
	ca := tixRelayCA(t)
	if code, row, reason := gap0861New(ca, nil, true, "").ask(t, gap0861Proofless(t)); code != http.StatusServiceUnavailable || reason != "relay_cert_record_unavailable" || row != "HIGH substrate.relay.cert_refused" {
		t.Fatalf("refuse: %d %s %s", code, row, reason)
	}
	if code, row, _ := gap0861New(ca, nil, false, "").ask(t, gap0861Proofless(t)); code != http.StatusOK || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("flag: %d %s", code, row)
	}
}

// GAP-0861: the owner's recover (signed in, audited HIGH) clears the
// record, so a relay that lost its key gets a certificate again in refuse
// mode; the actor JWT alone never does.
func TestGAP0861RecoverClearsRelayCertRecord(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "alice-1"}, ActorTemplate: ateapi.Ref("eng-web", "cc"),
		Status: &ateapi.ActorStatus{State: ateapi.ActorStateCrashed}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.RelayCA, c.Managed = tixRelayCA(t), true
		c.RelayCerts = c.Registrations.(registry.RelayCerts)
	})
	st := f.api.substrateState()
	st.cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(context.Context, string, string) error { return nil }}
	csr := func() string {
		b, _ := json.Marshal(gap0861Proofless(t))
		return string(b)
	}
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayCert, "tok-alice", csr()); rec.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayCert, "tok-alice", csr()); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "reissue_refused" {
		t.Fatalf("proofless second: %d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: "CRASHED"}
	f.mu.Unlock()
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/recover", "p-alice", "{}"); rec.Code != http.StatusOK {
		t.Fatalf("recover %d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: identity.ActorRunning}
	f.mu.Unlock()
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayCert, "tok-alice", csr()); rec.Code != http.StatusOK {
		t.Fatalf("after recover: %d %s", rec.Code, rec.Body)
	}
}

// The doctor row names the active mode.
func TestGAP0861DoctorRow(t *testing.T) {
	for _, c := range []struct{ cfg, active, want string }{
		{"auto", "refuse", "relay_cert_reissue is refuse (auto: refuse in this install)"},
		{"auto", "flag", "relay_cert_reissue is flag (auto: flag in this install)"},
		{"refuse", "refuse", "relay_cert_reissue is refuse (set to refuse)"},
	} {
		got := SubstrateRelayCertReissueCheck(c.cfg, c.active)
		if got.ID != "substrate.relay_cert_reissue" || got.Status != "pass" || !bytes.HasPrefix([]byte(got.Detail), []byte(c.want)) {
			t.Fatalf("%+v: %+v", c, got)
		}
	}
}
