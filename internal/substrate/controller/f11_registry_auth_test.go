// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// privateRegistry answers 401 with a Basic challenge to any request
// without its login, and 404 (no attestation) with it. It records the
// Authorization header of every request.
type privateRegistry struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

func newPrivateRegistry(t *testing.T, user, pass string) *privateRegistry {
	t.Helper()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	p := &privateRegistry{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.Header.Get("Authorization"))
		p.mu.Unlock()
		if r.Header.Get("Authorization") == want {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Www-Authenticate", `Basic realm="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *privateRegistry) host() string { return strings.TrimPrefix(p.srv.URL, "http://") }

func (p *privateRegistry) auths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

// GAP-0190: the verifier the controller and the gateway's create path share
// (VerifierFromConfig) reads a private registry with the login in
// substrate.templates.registry_auth; without one it is anonymous (and the
// private registry refuses it, as ECR did on E2); a registry the login is
// not for never gets it.
func TestGAP0190VerifierReadsAPrivateRegistryWithItsLogin(t *testing.T) {
	const pw = "MARKER-PASSWORD-f11"
	home := newPrivateRegistry(t, "svc", pw)
	other := newPrivateRegistry(t, "svc", pw)

	dir := t.TempDir()
	signer, err := attest.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	anchors := filepath.Join(dir, "anchors.pem")
	if err := os.WriteFile(anchors, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("ab", 32)
	tc := config.SubstrateTemplatesConfig{TrustAnchors: anchors,
		AllowedImages: []string{home.host() + "/dc/*", other.host() + "/dc/*"}}
	verify := func(t *testing.T, tc config.SubstrateTemplatesConfig, host string) *attest.Rejection {
		t.Helper()
		v, _ := controller.VerifierFromConfig(tc)
		_, err := v.Verify(context.Background(), host+"/dc/claude@"+digest)
		r, ok := attest.AsRejection(err)
		if !ok {
			t.Fatalf("want a rejection (no attestation in the stub), got %v", err)
		}
		return r
	}

	t.Run("anonymous by default: the private registry refuses", func(t *testing.T) {
		r := verify(t, tc, home.host())
		if !r.Retryable || !strings.Contains(r.Detail, "401") {
			t.Fatalf("want a retryable 401 registry rejection, got %s: %s", r.Code, r.Detail)
		}
	})

	cfgPath := filepath.Join(dir, "config.json")
	auth := base64.StdEncoding.EncodeToString([]byte("svc:" + pw))
	if err := os.WriteFile(cfgPath, []byte(`{"auths": {"`+home.host()+`": {"auth": "`+auth+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tc.RegistryAuth.DockerConfig = cfgPath

	t.Run("with the docker config login the attestation is read", func(t *testing.T) {
		r := verify(t, tc, home.host())
		if r.Code != attest.CodeNoAttestation {
			t.Fatalf("want past the login to no_attestation, got %s: %s", r.Code, r.Detail)
		}
		if strings.Contains(r.Detail, pw) {
			t.Fatal("the rejection carries the password")
		}
	})
	t.Run("a registry the login is not for gets none", func(t *testing.T) {
		r := verify(t, tc, other.host())
		if !strings.Contains(r.Detail, "401") {
			t.Fatalf("the other registry should still refuse: %s: %s", r.Code, r.Detail)
		}
		got := other.auths()
		if len(got) == 0 {
			t.Fatal("the other registry was never asked")
		}
		for _, h := range got {
			if h != "" {
				t.Fatalf("a registry the login is not for got %q", h)
			}
		}
	})
}
