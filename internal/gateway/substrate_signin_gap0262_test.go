// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

type fakeSignInServer struct {
	mu sync.Mutex
	d  identity.IssuerDiagnosis
}

func (f *fakeSignInServer) DiagnoseIssuer(context.Context) identity.IssuerDiagnosis {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.d
}

func (f *fakeSignInServer) set(d identity.IssuerDiagnosis) { f.mu.Lock(); f.d = d; f.mu.Unlock() }

// downPeople refuses p-down as a verifier that could not reach its key set.
type downPeople struct{ fakePeople }

func (d downPeople) Verify(ctx context.Context, tok string) (identity.Person, error) {
	if tok == "p-down" {
		return identity.Person{}, &identity.Error{Reason: identity.ReasonKeysetFailed, Message: "dial tcp: i/o timeout"}
	}
	return d.fakePeople.Verify(ctx, tok)
}

// GAP-0262: the gateway's sign-in server check is an administrator doctor
// row with the detail and a fix, an /info sign_in_server member with the
// cause class only, and the cause of a sign-in it cannot verify.
func TestSubstrateSignInServerHealthGAP0262(t *testing.T) {
	srv := &fakeSignInServer{d: identity.IssuerDiagnosis{Issuer: "https://kc.example/realms/dc", Cause: identity.IssuerTLSName,
		Detail: "x509: certificate is valid for old.example, not kc.example"}}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.SignInServer = srv
		c.People = downPeople{c.People.(fakePeople)}
	})
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/doctor", "p-admin", "")
	var doc struct {
		Checks []SubstrateCheck `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || rec.Code != 200 {
		t.Fatalf("doctor %d %s", rec.Code, rec.Body)
	}
	var row *SubstrateCheck
	for i := range doc.Checks {
		if doc.Checks[i].ID == "substrate.oidc_issuer" {
			row = &doc.Checks[i]
		}
	}
	if row == nil || row.Status != "fail" || !strings.Contains(row.Detail, "old.example") || !strings.Contains(row.Fix, "certificate") {
		t.Fatalf("doctor row %+v", row)
	}
	// /info: the class, never the detail.
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/info", "", "")
	if !strings.Contains(rec.Body.String(), `"sign_in_server":{"state":"failing","reason":"issuer_tls_name"`) || strings.Contains(rec.Body.String(), "old.example") {
		t.Fatalf("info %s", rec.Body)
	}
	// A sign-in the gateway cannot verify names the cause.
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-down", "")
	if rec.Code != http.StatusServiceUnavailable || reasonOf(t, rec) != identity.IssuerTLSName || strings.Contains(rec.Body.String(), "old.example") {
		t.Fatalf("unverifiable sign-in %d %s", rec.Code, rec.Body)
	}
	// Healthy again: no /info member, the plain reason, a passing row.
	srv.set(identity.IssuerDiagnosis{Issuer: "https://kc.example/realms/dc", Keys: 2})
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/doctor", "p-admin", "")
	if !strings.Contains(rec.Body.String(), `"substrate.oidc_issuer","status":"pass"`) {
		t.Fatalf("healthy doctor %s", rec.Body)
	}
	if rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/info", "", ""); strings.Contains(rec.Body.String(), "sign_in_server") {
		t.Fatalf("healthy info %s", rec.Body)
	}
	if rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-down", ""); reasonOf(t, rec) != string(identity.ReasonKeysetFailed) {
		t.Fatalf("healthy server, unverifiable sign-in %s", rec.Body)
	}
}

// GAP-0262: every cause has a doctor row with a fix.
func TestSignInServerCheckFixesGAP0262(t *testing.T) {
	for _, cause := range []string{identity.IssuerUnreachable, identity.IssuerTLSName, identity.IssuerTLSUntrusted,
		identity.IssuerHTTP, identity.IssuerMismatch, identity.IssuerKeys} {
		c := SignInServerCheck(identity.IssuerDiagnosis{Issuer: "https://kc.example", Cause: cause, Detail: "d"})
		if c.Status != "fail" || c.Fix == "" || c.ID != "substrate.oidc_issuer" {
			t.Errorf("%s: %+v", cause, c)
		}
	}
}
