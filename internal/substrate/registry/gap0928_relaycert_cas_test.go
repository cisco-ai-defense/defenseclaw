// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"testing"
	"time"
)

// GAP-0928: a renewal claim is a compare-and-swap on the live serial, and
// recover leaves a mark (kept across a restart) that no older certificate
// renews through, while a request without proof is a first certificate.
func TestGAP0928ClaimCompareAndSwap(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, now := t.Context(), time.Now()
	c := func(serial string) RelayCert { return RelayCert{Serial: serial, NotAfter: now.Add(time.Hour), CA: "fp"} }
	claim := func(cl RelayCertClaim) RelayCertClaimed {
		t.Helper()
		cl.Atespace, cl.UID, cl.Now = "eng-web", gap0861UID, now
		got, err := s.ClaimRelayCert(ctx, cl)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if !claim(RelayCertClaim{Cert: c("a1")}).Set {
		t.Fatal("first")
	}
	if got := claim(RelayCertClaim{Cert: c("x1"), Expect: "other"}); got.Set || got.Prev.Serial != "a1" {
		t.Fatalf("renewal of a certificate that is not live: %+v", got)
	}
	if !claim(RelayCertClaim{Cert: c("a2"), Expect: "a1"}).Set {
		t.Fatal("renewal of the live one")
	}
	if claim(RelayCertClaim{Cert: c("x2"), Expect: "a1"}).Set {
		t.Fatal("a renewed certificate renews again")
	}
	if err := s.ClearRelayCert(ctx, "eng-web", gap0861UID); err != nil {
		t.Fatal(err)
	}
	if live, ok, err := s.LiveRelayCert(ctx, "eng-web", gap0861UID); err != nil || !ok || !live.Cleared || live.Serial != "" {
		t.Fatalf("mark: %+v %v %v", live, ok, err)
	}
	s2, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if live, ok, _ := s2.LiveRelayCert(ctx, "eng-web", gap0861UID); !ok || !live.Cleared {
		t.Fatal("the mark is lost across a restart")
	}
	if got := claim(RelayCertClaim{Cert: c("a3"), Expect: "a2"}); got.Set || !got.Prev.Cleared {
		t.Fatalf("renewal through the mark: %+v", got)
	}
	if !claim(RelayCertClaim{Cert: c("r1")}).Set {
		t.Fatal("first after recover")
	}
	if _, err := s.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: gap0861UID, Cert: RelayCert{Serial: "m", NotAfter: now.Add(time.Hour), Cleared: true}, Replace: true}); err == nil {
		t.Fatal("a claim wrote a mark")
	}
	if _, ok, _ := s.LiveRelayCert(ctx, "eng-web", "aaaa-9999"); ok {
		t.Fatal("record for an unknown actor")
	}
}
