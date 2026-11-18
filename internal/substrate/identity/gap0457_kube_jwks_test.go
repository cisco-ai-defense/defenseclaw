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

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// kubeIssuer answers like the Kubernetes API server's service-account
// issuer: the discovery document is application/json, the key set is
// application/jwk-set+json, and a request whose Accept header does not
// allow that type is 406 Not Acceptable.
func kubeIssuer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var accepts []string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepts = append(accepts, r.URL.Path+" "+r.Header.Get("Accept"))
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if !acceptsType(r, "application/json") {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/openid/v1/jwks"})
		case "/openid/v1/jwks":
			if !acceptsType(r, "application/jwk-set+json") {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			w.Header().Set("Content-Type", "application/jwk-set+json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{jwkOf("sa-1", "ES256", k.Public())}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &accepts
}

// acceptsType is the API server's negotiation: no Accept header, */*, or
// the media type itself.
func acceptsType(r *http.Request, want string) bool {
	h := r.Header.Get("Accept")
	if h == "" {
		return true
	}
	for _, part := range strings.Split(h, ",") {
		mt, _, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err == nil && (mt == want || mt == "*/*") {
			return true
		}
	}
	return false
}

// substrate-1 GAP-0457: workload_oidc with the in-cluster service-account
// issuer never verified, because the key set was asked for with Accept:
// application/json only and the API server answers that with 406.
func TestGAP0457KeySetLoadsFromTheKubernetesServiceAccountIssuer(t *testing.T) {
	srv, accepts := kubeIssuer(t)
	ks, err := NewKeySet(KeySetOptions{Issuer: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	n, err := ks.Probe(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("the service-account issuer's key set did not load: %d keys, %v (requests %q)", n, err, *accepts)
	}
	d := ks.DiagnoseIssuer(context.Background())
	if d.Cause != "" || d.Keys != 1 {
		t.Fatalf("doctor's issuer check of the service-account issuer: %+v (requests %q)", d, *accepts)
	}
}
