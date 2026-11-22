// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func kubeAPI(t *testing.T, reviews *atomic.Int64) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Header.Get("Authorization") != "Bearer gateway-sa" {
			w.WriteHeader(403)
			return
		}
		reviews.Add(1)
		var in struct {
			Spec struct{ Token string } `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		user := map[string]any{}
		ok := true
		switch in.Spec.Token {
		case "kube-alice":
			user = map[string]any{"username": "alice@example.com", "uid": "u-1", "groups": []string{"dc-devs", "system:authenticated"}}
		case "kube-pod":
			user = map[string]any{"username": "system:serviceaccount:ns:default"}
		default:
			ok = false
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": ok, "user": user}})
	}))
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tok, []byte("gateway-sa"), 0o600)
	return srv, tok
}

// An OSS cluster without OIDC: the person is the Kubernetes user.
func TestKubeTokenVerifier(t *testing.T) {
	var reviews atomic.Int64
	srv, tok := kubeAPI(t, &reviews)
	k := &KubeTokenVerifier{Server: srv.URL, TokenFile: tok, HTTP: srv.Client()}
	ctx := context.Background()
	p, err := k.Verify(ctx, "kube-alice")
	if err != nil || p.Kind != PersonKube || p.Subject != "alice@example.com" || p.ID() != "kubernetes#alice@example.com" || len(p.Groups) != 2 {
		t.Fatalf("alice %+v %v", p, err)
	}
	if _, err := k.Verify(ctx, "kube-alice"); err != nil || reviews.Load() != 1 {
		t.Fatalf("cached review: %v, %d reviews", err, reviews.Load())
	}
	_, err = k.Verify(ctx, "kube-pod")
	wantReason(t, err, ReasonSubject)
	_, err = k.Verify(ctx, "forged")
	wantReason(t, err, ReasonSignature)
	_, err = k.Verify(ctx, "")
	wantReason(t, err, ReasonMissing)
	down := &KubeTokenVerifier{Server: "https://127.0.0.1:1", TokenFile: tok, HTTP: srv.Client()}
	_, err = down.Verify(ctx, "kube-alice")
	wantReason(t, err, ReasonUnavailable)
}

// OIDC first; a token that is no configured issuer's goes to the review.
func TestPersonVerifiersFallBackToKubernetes(t *testing.T) {
	var reviews atomic.Int64
	srv, tok := kubeAPI(t, &reviews)
	p := newIDP(t)
	ks, _ := NewKeySet(KeySetOptions{Issuer: p.srv.URL, HTTPClient: p.srv.Client()})
	oidc, _ := NewPersonVerifier([]PersonIssuer{{KeySet: ks, Audience: "dc-launcher"}}, nil)
	v := PersonVerifiers{OIDC: oidc, Kube: &KubeTokenVerifier{Server: srv.URL, TokenFile: tok, HTTP: srv.Client()}}
	got, err := v.Verify(context.Background(), "kube-alice")
	if err != nil || got.Kind != PersonKube {
		t.Fatalf("kube token through the combined verifier: %+v %v", got, err)
	}
	only := PersonVerifiers{OIDC: oidc}
	_, err = only.Verify(context.Background(), "kube-alice")
	if err == nil {
		t.Fatal("OIDC-only verifier accepted a kube token")
	}
}
