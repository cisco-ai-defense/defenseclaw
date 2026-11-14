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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// PersonKube is a person known by their Kubernetes credentials: an open
// source cluster without an OIDC provider (STEER 11-12 22:55Z). The
// launcher sends the bearer token of the user's kubeconfig; the gateway
// asks the API server who it is (TokenReview), and the person is that
// Kubernetes user (id_kind k8s_user). Managed installs require OIDC.
const PersonKube = "k8s_user"

// KubeTokenAudience is the audience of the ServiceAccount token the
// launcher mints with TokenRequest for a person whose kubeconfig signs in
// with a client certificate (GAP-0192). The gateway accepts a
// ServiceAccount only when the API server authenticates its token for this
// audience: a pod's mounted token (the API server's audience) is refused.
const KubeTokenAudience = "defenseclaw-substrate"

// KubeIssuer is the Issuer of a Kubernetes person: the cluster's API
// server, the one authority for the name.
const KubeIssuer = "kubernetes"

const (
	kubeReviewTTL     = 30 * time.Second
	kubeReviewMaxKeys = 4096
)

// KubeTokenVerifier verifies a person's Kubernetes bearer token with a
// TokenReview (the gateway's ServiceAccount needs create on
// tokenreviews, the system:auth-delegator role).
type KubeTokenVerifier struct {
	// Server is https://<API server>; TokenFile the gateway's own token.
	Server    string
	TokenFile string
	HTTP      *http.Client
	Now       func() time.Time

	mu    sync.Mutex
	cache map[string]kubeReview
}

type kubeReview struct {
	p  Person
	at time.Time
}

func (k *KubeTokenVerifier) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

// Verify implements the admin listener's person check.
func (k *KubeTokenVerifier) Verify(ctx context.Context, token string) (Person, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 16<<10 {
		return Person{}, reasonf(ReasonMissing, "no Kubernetes token")
	}
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])
	now := k.now()
	k.mu.Lock()
	if c, ok := k.cache[key]; ok && now.Sub(c.at) < kubeReviewTTL {
		k.mu.Unlock()
		return c.p, nil
	}
	k.mu.Unlock()
	u, ok, err := k.review(ctx, token, nil)
	if err != nil {
		return Person{}, err
	}
	switch {
	case !ok:
		// Not a token of the API server's own audience: it counts only as a
		// ServiceAccount token minted for DefenseClaw (GAP-0192).
		u, ok, err = k.review(ctx, token, []string{KubeTokenAudience})
		if err != nil {
			return Person{}, err
		}
		if !ok {
			return Person{}, reasonf(ReasonSignature, "the Kubernetes API does not know the token")
		}
		if !strings.HasPrefix(u.Username, "system:serviceaccount:") {
			return Person{}, reasonf(ReasonSubject, "only a ServiceAccount token may carry the DefenseClaw audience")
		}
	case strings.HasPrefix(u.Username, "system:serviceaccount:"):
		// A pod's own token: the ServiceAccount of a workload is not a
		// person, and an actor has no Kubernetes identity (D15).
		return Person{}, reasonf(ReasonSubject, "a ServiceAccount token must be minted for DefenseClaw (audience %s); sign in with defenseclaw substrate login --kube", KubeTokenAudience)
	}
	if strings.HasPrefix(u.Username, "system:node:") {
		return Person{}, reasonf(ReasonSubject, "a node token is not a person")
	}
	p := Person{Kind: PersonKube, Issuer: KubeIssuer, Subject: u.Username, Principal: u.Username,
		Expires: now.Add(kubeReviewTTL)}
	for _, g := range u.Groups {
		if g = strings.TrimSpace(g); g != "" && len(p.Groups) < 512 {
			p.Groups = append(p.Groups, g)
		}
	}
	k.mu.Lock()
	if k.cache == nil || len(k.cache) >= kubeReviewMaxKeys {
		k.cache = map[string]kubeReview{}
	}
	k.cache[key] = kubeReview{p: p, at: now}
	k.mu.Unlock()
	return p, nil
}

// kubeUser is the user of an authenticated TokenReview.
type kubeUser struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

// review asks the API server who token is, for audiences (nil: the API
// server's own). ok is false when the token is not authenticated for one of
// them; a ServiceAccount token reviewed for its own audience must also be
// answered with that audience.
func (k *KubeTokenVerifier) review(ctx context.Context, token string, audiences []string) (kubeUser, bool, error) {
	own, err := os.ReadFile(k.TokenFile)
	if err != nil {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "the gateway has no Kubernetes token")
	}
	spec := map[string]any{"token": token}
	if len(audiences) > 0 {
		spec["audiences"] = audiences
	}
	body, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": spec})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.Server+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "token review request")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(own)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "the Kubernetes API did not answer")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "token review: HTTP %d", resp.StatusCode)
	}
	var tr struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			User          kubeUser `json:"user"`
			Audiences     []string `json:"audiences"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &tr) != nil {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "token review answer is unreadable")
	}
	u := tr.Status.User
	if !tr.Status.Authenticated || strings.TrimSpace(u.Username) == "" {
		return kubeUser{}, false, nil
	}
	for _, want := range audiences {
		found := false
		for _, got := range tr.Status.Audiences {
			found = found || got == want
		}
		if !found {
			return kubeUser{}, false, nil
		}
	}
	return u, true, nil
}

// PersonVerifiers tries OIDC first and a Kubernetes token second: a token
// that is not from a configured issuer (a kubeconfig token, which may also
// be a JWT of the cluster's own issuer) goes to the TokenReview.
type PersonVerifiers struct {
	OIDC interface {
		Verify(ctx context.Context, token string) (Person, error)
	}
	Kube *KubeTokenVerifier
}

// Verify implements the admin listener's person check.
func (v PersonVerifiers) Verify(ctx context.Context, token string) (Person, error) {
	if v.OIDC != nil {
		p, err := v.OIDC.Verify(ctx, token)
		if err == nil || v.Kube == nil {
			return p, err
		}
		var ie *Error
		if !errors.As(err, &ie) || (ie.Reason != ReasonIssuer && ie.Reason != ReasonMalformed) {
			return p, err
		}
	}
	if v.Kube == nil {
		return Person{}, reasonf(ReasonIssuer, "no sign-in is configured")
	}
	return v.Kube.Verify(ctx, token)
}
