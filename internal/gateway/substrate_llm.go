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

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Model traffic of actors (D2): every model call goes through the
// DefenseClaw guardrail proxy at /llm/<provider>/<provider path> on the
// actor listener. The caller is the verified actor (its JWT) and the
// person bound to it; X-User-Id and every identity header the actor sends
// are dropped. The provider credential never enters the actor: the actor
// holds a placeholder, and the gateway replaces whatever credential header
// arrives with the key it reads from its own Secret, per request (so a
// rotation needs no restart). Provider hosts are never in an actor's egress
// allow list, so this is the only way to a model.
//
// Request bodies are inspected and responses forwarded by the proxy's
// passthrough path, which keeps Bedrock's eventstream framing unchanged.
//
// SubstrateLLMRouter is the seam where stream 1 routing and stream 10
// usage plug in (lane A12): it may choose another upstream for the call.

// SubstrateLLMProvider is one model provider the actor listener serves.
type SubstrateLLMProvider struct {
	// Origin is the upstream scheme://host[:port], no path.
	Origin string
	// CredentialFile holds the provider key (re-read per request).
	CredentialFile string
	// AuthHeader is where the key goes: "authorization" (Bearer, default),
	// "x-api-key" (Anthropic) or "api-key" (Azure).
	AuthHeader string
}

// SubstrateLLMRoute is the upstream a call goes to.
type SubstrateLLMRoute struct {
	Provider string
	Origin   string
	Path     string
}

// SubstrateLLMRouter may change a call's route (routing, budgets). It
// returns an error to refuse the call (for example a batch over budget).
type SubstrateLLMRouter interface {
	RouteModelCall(ctx context.Context, actor SubstrateModelCaller, route SubstrateLLMRoute) (SubstrateLLMRoute, error)
}

// SubstrateModelCaller is what a router sees of the caller.
type SubstrateModelCaller struct {
	Atespace, Name, UID, Owner, Profile, BatchID string
	Unattended                                   bool
}

// SubstrateLLMConfig configures /llm.
type SubstrateLLMConfig struct {
	Providers map[string]SubstrateLLMProvider
	// Proxy serves the call (GuardrailProxy.SubstrateHandler).
	Proxy  http.Handler
	Router SubstrateLLMRouter
}

var substrateProviderRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// DefaultSubstrateLLMProviders returns the upstreams of the providers the
// proxy serves, with their keys under credDir/<provider>.
func DefaultSubstrateLLMProviders(credDir, bedrockRegion string) map[string]SubstrateLLMProvider {
	if bedrockRegion == "" {
		bedrockRegion = "us-east-1"
	}
	key := func(p string) string { return filepath.Join(credDir, p) }
	return map[string]SubstrateLLMProvider{
		"anthropic": {Origin: "https://api.anthropic.com", CredentialFile: key("anthropic"), AuthHeader: "x-api-key"},
		"openai":    {Origin: "https://api.openai.com", CredentialFile: key("openai")},
		"bedrock":   {Origin: "https://bedrock-runtime." + bedrockRegion + ".amazonaws.com", CredentialFile: key("bedrock")},
		"gemini":    {Origin: "https://generativelanguage.googleapis.com", CredentialFile: key("gemini"), AuthHeader: "x-goog-api-key"},
	}
}

// NewSubstrateLLMHandler validates cfg and returns the /llm handler.
func NewSubstrateLLMHandler(cfg SubstrateLLMConfig) (http.Handler, error) {
	if cfg.Proxy == nil {
		return nil, errors.New("substrate llm: no guardrail proxy")
	}
	for name, p := range cfg.Providers {
		u, err := url.Parse(p.Origin)
		if !substrateProviderRE.MatchString(name) || err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return nil, fmt.Errorf("substrate llm: provider %q needs an https origin", name)
		}
		if p.CredentialFile == "" {
			return nil, fmt.Errorf("substrate llm: provider %q has no credential file", name)
		}
	}
	return &substrateLLM{cfg: cfg}, nil
}

type substrateLLM struct{ cfg SubstrateLLMConfig }

// substrateCredentialHeaders are the credential headers an actor may send
// (placeholders); all are removed before the gateway sets its own.
var substrateCredentialHeaders = []string{
	"Authorization", "X-Api-Key", "Api-Key", "X-Goog-Api-Key", "X-AI-Auth", "X-DC-Auth", "X-DC-Target-URL",
	"X-Amz-Security-Token", "X-Amz-Date", "X-Amz-Content-Sha256",
}

func (s *substrateLLM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	actor, ok := substrateActorFrom(r.Context())
	if !ok {
		writeSubstrateRefusal(w, http.StatusUnauthorized, "missing_token")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, substrateLLMPrefix)
	provider, upstreamPath, _ := strings.Cut(rest, "/")
	p, known := s.cfg.Providers[provider]
	if !known {
		writeSubstrateRefusal(w, http.StatusNotFound, "provider_not_served")
		return
	}
	route := SubstrateLLMRoute{Provider: provider, Origin: p.Origin, Path: "/" + upstreamPath}
	if s.cfg.Router != nil {
		reg, _ := substrateRegistrationFrom(r.Context())
		next, err := s.cfg.Router.RouteModelCall(r.Context(), SubstrateModelCaller{
			Atespace: actor.Atespace, Name: actor.Name, UID: actor.UID, Owner: reg.Person.ID(),
			Profile: reg.Profile, BatchID: reg.BatchID, Unattended: reg.Unattended,
		}, route)
		if err != nil {
			writeSubstrateRefusal(w, http.StatusForbidden, "model_call_refused")
			return
		}
		if np, ok := s.cfg.Providers[next.Provider]; ok {
			route, p = next, np
		}
	}
	key, err := os.ReadFile(p.CredentialFile)
	if err != nil || strings.TrimSpace(string(key)) == "" {
		fmt.Fprintf(os.Stderr, "[substrate] llm: provider %s has no readable credential (%s)\n", route.Provider, p.CredentialFile)
		writeSubstrateRefusal(w, http.StatusServiceUnavailable, "provider_credential_unavailable")
		return
	}
	secret := strings.TrimSpace(string(key))
	r2 := r.Clone(r.Context())
	for _, h := range substrateCredentialHeaders {
		r2.Header.Del(h)
	}
	r2.Header.Set("X-DC-Target-URL", route.Origin)
	r2.Header.Set("X-AI-Auth", "Bearer "+secret)
	switch strings.ToLower(p.AuthHeader) {
	case "x-api-key":
		r2.Header.Set("x-api-key", secret)
	case "api-key":
		r2.Header.Set("api-key", secret)
	case "x-goog-api-key":
		r2.Header.Set("x-goog-api-key", secret)
	default:
		r2.Header.Set("Authorization", "Bearer "+secret)
	}
	u := *r.URL
	u.Path, u.RawPath = route.Path, ""
	r2.URL = &u
	r2.RequestURI = ""
	s.cfg.Proxy.ServeHTTP(w, r2)
}
