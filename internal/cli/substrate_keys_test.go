// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

const f12Issuer = "https://substrate-e2.idp.invalid"

// f12IDP is ate-idp-server behind the idp Service: discovery names served,
// the key set is at /openid/v1/jwks.
func f12IDP(t *testing.T, served string) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.PublicKey.Bytes()
	enc := base64.RawURLEncoding.EncodeToString
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": served, "jwks_uri": served + "/openid/v1/jwks"})
		case "/openid/v1/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "EC", "kid": "k1", "use": "sig", "alg": "ES256", "crv": "P-256", "x": enc(raw[1:33]), "y": enc(raw[33:])}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// f12CAFile writes the test server's certificate as the keys CA.
func f12CAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	s := base64.StdEncoding.EncodeToString(srv.Certificate().Raw)
	for len(s) > 64 {
		b.WriteString(s[:64] + "\n")
		s = s[64:]
	}
	b.WriteString(s + "\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// GAP-0194: the serve command's actor key set reads substrate.identity
// keys_url and keys_ca_file, and the doctor row says when it works.
func TestSubstrateActorKeySetAndDoctorRow(t *testing.T) {
	srv := f12IDP(t, f12Issuer)
	c := &config.Config{}
	c.Substrate.Identity.Issuer = f12Issuer
	c.Substrate.Identity.KeysURL = srv.URL + "/openid/v1/jwks"
	c.Substrate.Identity.KeysCAFile = f12CAFile(t, srv)
	ks, err := substrateActorKeySet(c)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Issuer() != f12Issuer || ks.KeysURL() != c.Substrate.Identity.KeysURL {
		t.Fatalf("key set %q %q", ks.Issuer(), ks.KeysURL())
	}
	if chk := substrateActorKeysCheck(context.Background(), ks); chk.Status != "pass" {
		t.Fatalf("doctor row %+v", chk)
	}

	// Substrate signs with another issuer than the config trusts.
	other := f12IDP(t, "https://idp.ate-system.svc")
	c.Substrate.Identity.KeysURL = other.URL + "/openid/v1/jwks"
	c.Substrate.Identity.KeysCAFile = f12CAFile(t, other)
	ks, _ = substrateActorKeySet(c)
	if chk := substrateActorKeysCheck(context.Background(), ks); chk.Status != "fail" || !strings.Contains(chk.Detail, "every actor token is refused") {
		t.Fatalf("doctor row for a wrong issuer %+v", chk)
	}

	// A keys URL that does not answer.
	c.Substrate.Identity.KeysURL = other.URL + "/missing"
	ks, _ = substrateActorKeySet(c)
	if chk := substrateActorKeysCheck(context.Background(), ks); chk.Status != "fail" || chk.Fix == "" {
		t.Fatalf("doctor row for a dead keys URL %+v", chk)
	}

	// The default is the idp Service, whatever the issuer is.
	c.Substrate.Identity.KeysURL, c.Substrate.Identity.KeysCAFile = "", ""
	if got := c.Substrate.EffectiveKeysURL(); got != "https://idp.ate-system.svc/openid/v1/jwks" {
		t.Fatalf("default keys URL %q", got)
	}
}

func f12InfoClient(t *testing.T, info map[string]any) *substrateSession {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/info") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	t.Cleanup(srv.Close)
	cl, err := api.New(api.Options{Base: srv.URL, HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "b", nil }})
	if err != nil {
		t.Fatal(err)
	}
	return &substrateSession{Client: cl}
}

// GAP-0194: run --task never says "The task finished" when the gateway
// refused every call of the agent.
func TestSubstrateTaskReportsATokenRefusal(t *testing.T) {
	start := time.Now()
	since := start.Add(time.Second).UTC().Format(time.RFC3339)
	s := f12InfoClient(t, map[string]any{"sign_in": "oidc", "attach": true,
		"actor_tokens": map[string]string{"state": "refusing", "reason": string(identity.ReasonKeysetFailed), "since": since}})
	msg, refused := substrateTokenRefusal(context.Background(), s, start)
	if !refused || !strings.Contains(msg, "did not run") || !strings.Contains(msg, "keyset_unavailable") ||
		!strings.Contains(msg, "defenseclaw substrate verify") || strings.Contains(msg, "finished") {
		t.Fatalf("message %q", msg)
	}

	// A refusal from before the task is not this task's.
	old := f12InfoClient(t, map[string]any{"sign_in": "oidc",
		"actor_tokens": map[string]string{"state": "refusing", "reason": "issuer", "since": start.Add(-time.Hour).UTC().Format(time.RFC3339)}})
	if _, refused := substrateTokenRefusal(context.Background(), old, start); refused {
		t.Fatal("an older refusal was blamed on this task")
	}
	// A healthy cluster (or one that does not report it) is quiet.
	ok := f12InfoClient(t, map[string]any{"sign_in": "oidc", "attach": true})
	if _, refused := substrateTokenRefusal(context.Background(), ok, start); refused {
		t.Fatal("a healthy cluster reported a refusal")
	}
}

// GAP-0194 in verify: the keys URL is read through the Service proxy, and
// a dead keys URL or an issuer Substrate does not sign with fails.
func TestSubstrateVerifyChecksTheActorKeys(t *testing.T) {
	install := writeInstall(t, fleetInstallOK)
	run := func(t *testing.T, raw func(path string) ([]byte, error)) map[string]fleet.Check {
		t.Helper()
		fakeKubectl(t, nil)
		inner := substrateKubectl
		substrateKubectl = func(ctx context.Context, f *substrateClusterFlags, args ...string) ([]byte, error) {
			if len(args) == 3 && args[0] == "get" && args[1] == "--raw" {
				return raw(args[2])
			}
			return inner(ctx, f, args...)
		}
		out, _, _ := runSubstrate(t, newSubstrateVerifyCmd(), "--install-file", install, "--json")
		var doc fleet.VerifyDocument
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%v: %q", err, out)
		}
		got := map[string]fleet.Check{}
		for _, c := range doc.Checks {
			got[c.ID] = c
		}
		return got
	}
	t.Run("keys URL down", func(t *testing.T) {
		c := run(t, func(string) ([]byte, error) {
			return nil, errors.New("the server is currently unable to handle the request")
		})
		if k := c[fleet.CheckActorKeys]; k.Status != fleet.Fail || !strings.Contains(k.Message, "does not answer") {
			t.Fatalf("%+v", k)
		}
	})
	t.Run("Substrate signs with another issuer", func(t *testing.T) {
		c := run(t, func(p string) ([]byte, error) {
			if strings.HasSuffix(p, "/openid/v1/jwks") {
				return []byte(`{"keys":[{"kid":"k1"}]}`), nil
			}
			return []byte(`{"issuer":"https://idp.ate-system.svc"}`), nil
		})
		if k := c[fleet.CheckActorKeys]; k.Status != fleet.Fail || !strings.Contains(k.Message, "another issuer") {
			t.Fatalf("%+v", k)
		}
	})
	t.Run("no Service proxy rights", func(t *testing.T) {
		c := run(t, func(string) ([]byte, error) { return nil, errors.New(`services "https:idp:443" is forbidden`) })
		if k := c[fleet.CheckActorKeys]; k.Status != fleet.Warn {
			t.Fatalf("%+v", k)
		}
	})
}

func TestServiceProxyPath(t *testing.T) {
	for in, want := range map[string]string{
		"https://idp.ate-system.svc/openid/v1/jwks":               "/api/v1/namespaces/ate-system/services/https:idp:443/proxy/openid/v1/jwks",
		"https://idp.sub-x.svc.cluster.local:8443/openid/v1/jwks": "/api/v1/namespaces/sub-x/services/https:idp:8443/proxy/openid/v1/jwks",
	} {
		got, ok := serviceProxyPath(in)
		if !ok || got.keys != want {
			t.Errorf("%s: %q %v", in, got.keys, ok)
		}
	}
	if _, ok := serviceProxyPath("https://keys.example.com/jwks"); ok {
		t.Error("a public host mapped to a Service")
	}
}

// GAP-0194: setup --issuer says whether the keys URL answers.
func TestSubstrateSetupIssuerChecksTheKeysURL(t *testing.T) {
	run := func(t *testing.T, raw func() ([]byte, error)) string {
		t.Helper()
		fakeKubectl(t, nil)
		inner := substrateKubectl
		substrateKubectl = func(ctx context.Context, f *substrateClusterFlags, args ...string) ([]byte, error) {
			if len(args) == 3 && args[1] == "--raw" {
				return raw()
			}
			return inner(ctx, f, args...)
		}
		file := filepath.Join(t.TempDir(), "install.yaml")
		out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--dry-run", "--issuer", f12Issuer)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := run(t, func() ([]byte, error) { return nil, errors.New("services \"idp\" not found") })
	if !strings.Contains(out, "WARNING: the keys URL https://idp.ate-system.svc/openid/v1/jwks does not answer") ||
		!strings.Contains(out, "refuse every actor token") {
		t.Fatalf("no warning:\n%s", out)
	}
	out = run(t, func() ([]byte, error) { return []byte(`{"keys":[{"kid":"k1"},{"kid":"k2"}]}`), nil })
	if !strings.Contains(out, "answers (2 keys)") || !strings.Contains(out, "substrate.identity.issuer") || strings.Contains(out, "WARNING") {
		t.Fatalf("output:\n%s", out)
	}
	// Without a cluster the note says it was not checked; setup still works.
	fakeKubectl(t, errors.New("kubectl is not installed or not on PATH"))
	file := filepath.Join(t.TempDir(), "install.yaml")
	out, _, err := runSubAdmin(newSubstrateSetupCmd(), "--install-file", file, "--dry-run", "--issuer", f12Issuer)
	if err != nil || !strings.Contains(out, "was not checked (kubectl is not installed") {
		t.Fatalf("%v\n%s", err, out)
	}
}
