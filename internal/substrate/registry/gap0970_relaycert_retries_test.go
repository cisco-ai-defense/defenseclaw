// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"testing"
	"time"
)

// GAP-0970: the leader counts the retries that prove the previous serial
// inside one grace, keeps the count across a restart, and starts it over
// with a renewal of the live one and when the relay presents the live one.
func TestGAP0970RetryCount(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, now := t.Context(), time.Now()
	claim := func(cl RelayCertClaim) RelayCertClaimed {
		t.Helper()
		cl.Atespace, cl.UID, cl.Now = "eng-web", gap0861UID, now
		cl.Cert.NotAfter, cl.Cert.CA = now.Add(time.Hour), "fp"
		got, err := s.ClaimRelayCert(ctx, cl)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	cert := func(serial string) RelayCert { return RelayCert{Serial: serial} }
	claim(RelayCertClaim{Cert: cert("a1")})
	if got := claim(RelayCertClaim{Cert: cert("a2"), Expect: "a1"}); !got.Set || got.Retry || got.Retries != 0 {
		t.Fatalf("renewal: %+v", got)
	}
	for i, serial := range []string{"x1", "x2", "x3"} {
		if got := claim(RelayCertClaim{Cert: cert(serial), Expect: "a1"}); !got.Retry || got.Retries != i+1 {
			t.Fatalf("retry %d: %+v", i+1, got)
		}
	}
	s, err = OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := claim(RelayCertClaim{Cert: cert("x4"), Expect: "a1"}); got.Retries != 4 {
		t.Fatalf("the count is lost across a restart: %+v", got)
	}
	if !claim(RelayCertClaim{Seen: "x4"}).Set {
		t.Fatal("attach saw the live one")
	}
	if live, _, _ := s.LiveRelayCert(ctx, "eng-web", gap0861UID); live.Retries != 0 {
		t.Fatalf("seen leaves the count: %+v", live)
	}
	claim(RelayCertClaim{Cert: cert("b1"), Expect: "x4"})
	if got := claim(RelayCertClaim{Cert: cert("b2"), Expect: "x4"}); got.Retries != 1 {
		t.Fatalf("first retry of the next grace: %+v", got)
	}
	if _, err := s.ClaimRelayCert(ctx, RelayCertClaim{Atespace: "eng-web", UID: gap0861UID, Now: now,
		Cert: RelayCert{Serial: "c1", NotAfter: now.Add(time.Hour), Retries: 5}}); err == nil {
		t.Fatal("a claim sets the count")
	}
}
