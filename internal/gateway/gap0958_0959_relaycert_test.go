//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

var gap0958Reg = registry.Registration{Atespace: "eng-web", Name: "tix", UID: gap0861UID}

// gap0958Renew renews certPEM with proof of key and returns the new key.
func gap0958Renew(t *testing.T, g *gap0861Replica, certPEM string, key *ecdsa.PrivateKey) (int, string, string, *ecdsa.PrivateKey) {
	t.Helper()
	kp, err := relaytls.KeyPair([]byte(certPEM), key)
	if err != nil {
		t.Fatal(err)
	}
	k, csr, _ := relaytls.NewKeyAndCSR()
	proof, err := relaytls.RenewalProof(kp, csr)
	if err != nil {
		t.Fatal(err)
	}
	code, row, out := g.ask(t, relay.CertRequest{CSR: base64.StdEncoding.EncodeToString(csr), Current: certPEM, Proof: base64.StdEncoding.EncodeToString(proof)})
	return code, row, out, k
}

func (g *gap0861Replica) attach(t *testing.T, certPEM string) error {
	t.Helper()
	g.rows = nil
	return g.st.relayCertLive(t.Context(), gap0958Reg, gap0928Leaf(t, certPEM))
}

// GAP-0958: a renewal whose reply never reaches the relay (a timeout, a
// dropped connection) leaves the relay with the certificate it renewed.
// Attach takes it, and the same renewal asked again is accepted, until the
// relay serves the new one.
func TestGAP0958LostRenewalReplyManaged(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	g := gap0861New(ca, store, true, "")
	_, _, r1, k1 := gap0928Cert(t, g)
	code, row, lost, _ := gap0958Renew(t, g, r1, k1) // the reply is lost
	if code != 200 || row != "INFO substrate.relay.cert" {
		t.Fatalf("renewal: %d %s", code, row)
	}
	if err := g.attach(t, r1); err != nil {
		t.Fatalf("attach refuses the relay's certificate after a lost renewal reply: %v", err)
	}
	code, row, r3, _ := gap0958Renew(t, g, r1, k1)
	if code != 200 || row != "INFO substrate.relay.cert" {
		t.Fatalf("the same renewal asked again: %d %s %s", code, row, r3)
	}
	if err := g.attach(t, lost); err == nil {
		t.Fatal("attach takes the certificate whose reply was lost")
	}
	if err := g.attach(t, r3); err != nil {
		t.Fatalf("attach refuses the renewed certificate: %v", err)
	}
	// The relay served the new one: the previous one is done.
	if err := g.attach(t, r1); err == nil {
		t.Fatal("attach takes the previous certificate after the relay served the new one")
	}
	if code, _, _, _ := gap0958Renew(t, g, r1, k1); code != 403 {
		t.Fatalf("the previous certificate renews after the relay served the new one: %d", code)
	}
}

// GAP-0958: the grace does not let a chain survive recover.
func TestGAP0958RecoverClearsThePreviousToo(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	g := gap0861New(ca, store, true, "")
	_, _, r1, k1 := gap0928Cert(t, g)
	_, _, r2, k2 := gap0958Renew(t, g, r1, k1)
	if err := store.ClearRelayCert(t.Context(), "eng-web", gap0861UID); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]string{"live": r2, "previous": r1} {
		if err := g.attach(t, c); err == nil {
			t.Errorf("attach takes the %s certificate after recover", name)
		}
	}
	if code, _, _, _ := gap0958Renew(t, g, r1, k1); code != 403 {
		t.Errorf("the previous certificate renews after recover: %d", code)
	}
	if code, _, _, _ := gap0958Renew(t, g, r2, k2); code != 403 {
		t.Errorf("the live certificate renews after recover: %d", code)
	}
}

// gap0958CommitThenFail is a leader that writes the claim and then loses
// the reply (a failover right after the write).
type gap0958CommitThenFail struct {
	*registry.FileStore
	fail bool
}

func (s *gap0958CommitThenFail) ClaimRelayCert(ctx context.Context, c registry.RelayCertClaim) (registry.RelayCertClaimed, error) {
	out, err := s.FileStore.ClaimRelayCert(ctx, c)
	if s.fail && err == nil {
		s.fail = false
		return registry.RelayCertClaimed{}, errors.New("leader: connection reset")
	}
	return out, err
}

func TestGAP0958LeaderFailoverAfterTheWriteManaged(t *testing.T) {
	rc := &gap0958CommitThenFail{FileStore: gap0928Store(t)}
	g := gap0861New(tixRelayCA(t), rc, true, "")
	_, _, r1, k1 := gap0928Cert(t, g)
	rc.fail = true
	if code, _, reason, _ := gap0958Renew(t, g, r1, k1); code != 503 || reason != "relay_cert_record_unavailable" {
		t.Fatalf("renewal across the failover: %d %s", code, reason)
	}
	if err := g.attach(t, r1); err != nil {
		t.Fatalf("attach refuses the relay's certificate after the failover: %v", err)
	}
	code, row, r2, _ := gap0958Renew(t, g, r1, k1)
	if code != 200 || row != "INFO substrate.relay.cert" {
		t.Fatalf("the renewal asked again: %d %s %s", code, row, r2)
	}
	if err := g.attach(t, r2); err != nil {
		t.Fatalf("attach refuses the renewed certificate: %v", err)
	}
}

// GAP-0959: under flag (the OSS default) attach takes any certificate the
// relay CA signed for the actor, with a HIGH row when it is not the live
// one, so one request without proof does not keep the real relay out.
// refuse still takes only the live one.
func TestGAP0959FlagAttachTakesTheCAsWord(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	g := gap0861New(ca, store, false, config.SubstrateRelayCertReissueFlag)
	_, _, r1, k1 := gap0928Cert(t, g)
	if code, row, _, _ := gap0928Cert(t, g); code != 200 || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("second certificate without proof under flag: %d %s", code, row)
	}
	high := []string{"HIGH substrate.relay.cert_not_live"}
	if err := g.attach(t, r1); err != nil || !slices.Equal(g.rows, high) {
		t.Fatalf("flag attach of the relay's certificate: %v, rows %v", err, g.rows)
	}
	code, row, r2, _ := gap0958Renew(t, g, r1, k1)
	if code != 200 || row != "HIGH substrate.relay.cert_second" {
		t.Fatalf("relay renewal under flag: %d %s", code, row)
	}
	if err := g.attach(t, r2); err != nil || !slices.Equal(g.rows, high) {
		t.Fatalf("flag attach of the renewed certificate: %v, rows %v", err, g.rows)
	}
	if err := gap0861New(ca, store, true, "").st.relayCertLive(t.Context(), gap0958Reg, gap0928Leaf(t, r2)); !errors.Is(err, errSubstrateRelayCertNotLive) {
		t.Fatalf("refuse takes a certificate that is not the live one: %v", err)
	}
	// The live one passes without a row.
	h := gap0861New(ca, gap0928Store(t), false, config.SubstrateRelayCertReissueFlag)
	_, _, live, _ := gap0928Cert(t, h)
	if err := h.attach(t, live); err != nil || len(h.rows) != 0 {
		t.Fatalf("flag attach of the live certificate: %v, rows %v", err, h.rows)
	}
}
