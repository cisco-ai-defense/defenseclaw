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

package controller_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// gap1076Provider is the Substrate Kubernetes credential provider as the
// egress calls it: the URI is ate-secret://k8s.io/<provider-name>/<ns>/
// <secret>/<key>, the only provider name is default (the local cluster),
// and the namespace policy says which namespaces an atespace may read.
type gap1076Provider struct {
	allowed map[string][]string // atespace -> namespaces
	secrets map[string]string   // ns/secret/key -> value
}

func (p gap1076Provider) fetch(uri, atespace string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "ate-secret" || u.Host != "k8s.io" {
		return "", errors.New("not a k8s.io credential URI")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "default" {
		return "", errors.New("credential fetch failed: credential URI " + uri + ": path must begin with default (only local Secrets are supported)")
	}
	if !slices.Contains(p.allowed[atespace], parts[1]) {
		return "", errors.New("namespace " + parts[1] + " is not allowed for atespace " + atespace)
	}
	v, ok := p.secrets[strings.Join(parts[1:], "/")]
	if !ok {
		return "", errors.New("no such Secret key")
	}
	return v, nil
}

// gap1076Egress is the egress's mitm leg for one request: the HTTPS rule of
// the request's host replaces each credential header with the provider's
// value. A fetch error leaves the header out, as the live egress did
// (GitHub answered "Requires authentication").
func gap1076Egress(t *testing.T, policy *ateapi.EgressPolicy, p gap1076Provider, atespace string, req *http.Request) []error {
	t.Helper()
	var errs []error
	for _, rule := range policy.GetRules() {
		https := rule.GetHttps()
		if https == nil || !slices.Contains(https.GetHostnames(), req.URL.Hostname()) {
			continue
		}
		for _, h := range https.GetEffects().GetReplaceHeaders() {
			if h.GetCredentialUri() == "" {
				continue
			}
			v, err := p.fetch(h.GetCredentialUri(), atespace)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			req.Header.Set(h.GetHeader(), h.GetPrefix()+v)
		}
	}
	return errs
}

// TestBoundPersonSecretIsInjectedOnEgressGAP1076: a person's own secret,
// bound to api.github.com with the github template (the SV-LIVE5 repro),
// reaches GitHub as the template's Authorization header: the source the
// controller renders is one the Kubernetes credential provider resolves,
// from the self-service namespace the chart grants, at the key the gateway
// stored the value under. A host the secret is not bound to gets no
// credential, and another person's actor gets none either.
func TestBoundPersonSecretIsInjectedOnEgressGAP1076(t *testing.T) {
	store := secretbind.New(&cmBindings{})
	now := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	binding := secretbind.Binding{ID: "b-00001076a1", Name: "sv5gh", Owner: render.PersonKey("sub-alice"), Template: "github",
		Hosts: []string{"api.github.com"}, State: secretbind.Active, Created: now}
	if err := store.Update(context.Background(), func(d *secretbind.Doc) error {
		d.Bindings = append(d.Bindings, binding)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var cfg *config.Config
	r := newRig(t, func(c *config.Config, o *controller.Options) {
		c.Substrate.Egress.Allow = append(c.Substrate.Egress.Allow, "api.github.com", "gitlab.com")
		cfg = c
		o.Bindings = controller.BindingsFrom(store, c, func() time.Time { return now })
	})
	alice := ateapi.RefOf(r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice").GetMetadata())
	bob := ateapi.RefOf(r.actor("eng-web", "bob-1", ateapi.ActorStateRunning, "sub-bob").GetMetadata())
	r.pass()

	// The value as the gateway stores it on `secrets add` (made-up token).
	tpl, ok := secretbind.Find(secretbind.Catalog(cfg.Substrate.SecretTemplates), "github")
	if !ok {
		t.Fatal("no github template")
	}
	token := "t6-fixsec-gap1076-token"
	stored, err := tpl.StoredValue(binding, token)
	if err != nil {
		t.Fatal(err)
	}
	ss := cfg.Substrate.SelfServiceSecrets
	provider := gap1076Provider{
		// The chart grants the launcher atespace the admin secrets and the
		// self-service namespace (credentialProvider.userSecrets).
		allowed: map[string][]string{"eng-web": {"defenseclaw-actor-secrets", ss.EffectiveNamespace()}},
		secrets: map[string]string{ss.EffectiveNamespace() + "/" + secretbind.ValueSecretName(render.PersonKey("sub-alice")) + "/" + binding.ID: stored},
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if errs := gap1076Egress(t, r.api.Policy(alice), provider, "eng-web", req); len(errs) > 0 {
		t.Fatalf("the egress could not fetch the bound secret: %v", errs)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("api.github.com request Authorization = %q, want the github template's Basic form", got)
	}

	other, _ := http.NewRequest(http.MethodGet, "https://gitlab.com/api/v4/user", nil)
	if errs := gap1076Egress(t, r.api.Policy(alice), provider, "eng-web", other); len(errs) > 0 || other.Header.Get("Authorization") != "" {
		t.Fatalf("an unbound host got a credential: %q %v", other.Header.Get("Authorization"), errs)
	}
	bobs, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if errs := gap1076Egress(t, r.api.Policy(bob), provider, "eng-web", bobs); len(errs) > 0 || bobs.Header.Get("Authorization") != "" {
		t.Fatalf("another person's actor got alice's credential: %q %v", bobs.Header.Get("Authorization"), errs)
	}
}
