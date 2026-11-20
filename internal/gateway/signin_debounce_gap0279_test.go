// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// seqSignInServer answers its diagnoses in order, then the last one.
type seqSignInServer struct {
	mu    sync.Mutex
	seq   []identity.IssuerDiagnosis
	calls int
}

func (s *seqSignInServer) DiagnoseIssuer(context.Context) identity.IssuerDiagnosis {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.seq[min(s.calls, len(s.seq)-1)]
	s.calls++
	return d
}

func blip(cause string) identity.IssuerDiagnosis {
	return identity.IssuerDiagnosis{Issuer: "https://kc.example/realms/dc", Cause: cause, Detail: "d"}
}

var signInOK = identity.IssuerDiagnosis{Issuer: "https://kc.example/realms/dc", Keys: 2}

// GAP-0279: one failed fetch is made once more before it counts. A blip
// (fail, then pass) is not reported; a failure that repeats is reported by
// that same check, so a real outage shows within one check interval plus
// the retry; and the check waited for the retry pause.
func TestSignInCheckReportsOnlyARepeatedFailureGAP0279(t *testing.T) {
	saved := signInRetryAfter
	signInRetryAfter = 50 * time.Millisecond
	t.Cleanup(func() { signInRetryAfter = saved })

	blipSrv := &seqSignInServer{seq: []identity.IssuerDiagnosis{blip(identity.IssuerUnreachable), signInOK}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.SignInServer = blipSrv })
	st := f.api.substrateState()
	start := time.Now()
	if c := st.checkSignIn(context.Background()); c.Status != "pass" {
		t.Fatalf("a blip was reported: %+v", c)
	}
	if took := time.Since(start); took < signInRetryAfter {
		t.Fatalf("the retry did not wait (%v)", took)
	}
	if blipSrv.calls != 2 {
		t.Fatalf("a failed check was tried %d times, want 2", blipSrv.calls)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/info", "", ""); strings.Contains(rec.Body.String(), "sign_in_server") {
		t.Fatalf("/info after a blip: %s", rec.Body)
	}

	outage := &seqSignInServer{seq: []identity.IssuerDiagnosis{blip(identity.IssuerUnreachable)}}
	f = newSubstrateFixture(t, func(c *SubstrateConfig) { c.SignInServer = outage })
	st = f.api.substrateState()
	if c := st.checkSignIn(context.Background()); c.Status != "fail" || outage.calls != 2 {
		t.Fatalf("a repeated failure: %+v after %d tries", c, outage.calls)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/info", "", ""); !strings.Contains(rec.Body.String(), `"reason":"issuer_unreachable"`) {
		t.Fatalf("/info in an outage: %s", rec.Body)
	}
	// A passing check is tried once.
	ok := &seqSignInServer{seq: []identity.IssuerDiagnosis{signInOK}}
	f = newSubstrateFixture(t, func(c *SubstrateConfig) { c.SignInServer = ok })
	f.api.substrateState().checkSignIn(context.Background())
	if ok.calls != 1 {
		t.Fatalf("a passing check was tried %d times", ok.calls)
	}
}

// GAP-0279: a server error has its own class and a fix that does not
// point at the configured address.
func TestSignInServerErrorHasItsOwnFixGAP0279(t *testing.T) {
	c := SignInServerCheck(blip(identity.IssuerUnavailable))
	if c.Status != "fail" || !strings.Contains(c.Fix, "address is right") || strings.Contains(c.Fix, "/.well-known") {
		t.Fatalf("server error row %+v", c)
	}
}
