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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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
// Two seams (lane A12, PLAN D6) take the 1.0.10 layers when they land:
//   - SubstrateLLMRouter: stream 1 routing and the admin rules. It sees
//     the verified caller and the requested route and may keep, narrow or
//     refuse it, never widen it: the upstream origin always comes from
//     the provider table, a provider outside the table is refused, and
//     the caller is the registration's, whatever the request says.
//   - SubstrateModelMeter: stream 10 usage. Its shape is the stream 1 and
//     10 usage interface (internal/modelusage Recorder and Call); until
//     that engine lands the gateway meters tokens itself
//     (NewSubstrateUsageMeter) into the leader's usage store.

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
	// Origin is ignored on a router's answer: it is always the provider
	// table's origin for Provider.
	Origin string
	Path   string
	// Model is the model the call names (from the path for Bedrock and
	// Gemini, from the body otherwise). A router changes the model of a
	// path-model provider by changing Path; a body model cannot be
	// rewritten here, so a router that names another body model refuses
	// the call.
	Model string
}

// SubstrateLLMRouter may change a call's route (routing, budgets). It
// returns an error to refuse the call (for example a batch over budget);
// a *SubstrateModelRefusal error carries the reason and the plain text
// the actor sees (the request-access text).
type SubstrateLLMRouter interface {
	RouteModelCall(ctx context.Context, actor SubstrateModelCaller, route SubstrateLLMRoute) (SubstrateLLMRoute, error)
}

// SubstrateModelRefusal is a router's refusal with words for the actor.
type SubstrateModelRefusal struct {
	// Reason is a closed token (model_not_allowed, budget_exceeded, ...).
	Reason string
	// Message is the plain text the actor sees: why, and who to ask.
	Message string
}

func (e *SubstrateModelRefusal) Error() string { return "model call refused: " + e.Reason }

// SubstrateModelCaller is what a router and a meter see of the caller:
// all of it from the actor's registration, none from the request.
type SubstrateModelCaller struct {
	Atespace, Name, UID, Owner, Profile, BatchID string
	Unattended                                   bool
	// Principal, Kind and Groups are the verified person's (empty for an
	// attributed actor); stream 1 admin rules match on them.
	Principal, Kind string
	Groups          []string
	Connector       string
	Template        string
}

// SubstrateLLMConfig configures /llm.
type SubstrateLLMConfig struct {
	Providers map[string]SubstrateLLMProvider
	// Proxy serves the call (GuardrailProxy.SubstrateHandler).
	Proxy  http.Handler
	Router SubstrateLLMRouter
	// Meter meters every forwarded call (nil: none).
	Meter SubstrateModelMeter
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

// Route decisions on a usage record.
const (
	substrateRouteNone     = "none"     // no router configured
	substrateRouteKept     = "kept"     // the router kept the requested route
	substrateRouteNarrowed = "narrowed" // the router chose another allowed route
)

// substrateLLMMaxBody is the most of a request body /llm reads to find the
// model; it is the guardrail proxy's own passthrough cap.
const substrateLLMMaxBody = 10 << 20

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
	reqPath := "/" + upstreamPath
	if !substrateCleanPath(reqPath) {
		writeSubstrateRefusal(w, http.StatusNotFound, "not_found")
		return
	}
	var body []byte
	if r.Body != nil && substrateBodyModel(provider) {
		b, err := io.ReadAll(io.LimitReader(r.Body, substrateLLMMaxBody+1))
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeSubstrateRefusal(w, http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		if err != nil {
			writeSubstrateRefusal(w, http.StatusBadRequest, "body_unreadable")
			return
		}
		if len(b) > substrateLLMMaxBody {
			writeSubstrateRefusal(w, http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		body = b
		r.Body = io.NopCloser(bytes.NewReader(b))
	}
	requested := SubstrateLLMRoute{Provider: provider, Origin: p.Origin, Path: reqPath}
	requested.Model, _ = substrateCallModel(provider, reqPath, body)
	reg, _ := substrateRegistrationFrom(r.Context())
	caller := SubstrateModelCaller{
		Atespace: actor.Atespace, Name: actor.Name, UID: actor.UID, Owner: reg.Person.ID(),
		Profile: reg.Profile, BatchID: reg.BatchID, Unattended: reg.Unattended,
		Principal: reg.Person.Principal, Kind: reg.Person.Kind, Groups: append([]string(nil), reg.Person.Groups...),
		Connector: reg.Connector, Template: reg.Template,
	}
	route, decision := requested, substrateRouteNone
	if s.cfg.Router != nil {
		next, err := s.cfg.Router.RouteModelCall(r.Context(), caller, requested)
		if err != nil {
			writeSubstrateModelRefusal(w, err)
			return
		}
		var refusal *SubstrateModelRefusal
		route, decision, refusal = substrateNarrowRoute(s.cfg.Providers, requested, next)
		if refusal != nil {
			fmt.Fprintf(os.Stderr, "[substrate] llm: router answer refused for %s/%s: %s\n", actor.Atespace, actor.Name, refusal.Reason)
			writeSubstrateModelRefusal(w, refusal)
			return
		}
		p = s.cfg.Providers[route.Provider]
	}
	key, err := os.ReadFile(p.CredentialFile)
	if err != nil || strings.TrimSpace(string(key)) == "" {
		fmt.Fprintf(os.Stderr, "[substrate] llm: provider %s has no readable credential\n", route.Provider)
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
	if s.cfg.Meter == nil {
		s.cfg.Proxy.ServeHTTP(w, r2)
		return
	}
	_, streaming := substrateCallModel(route.Provider, route.Path, body)
	call := s.cfg.Meter.Begin(r.Context(), SubstrateModelCall{
		RequestID: RequestIDFromContext(r.Context()), Caller: caller,
		Requested: requested, Selected: route, Route: decision,
		API: substrateAPIFamily(route.Provider, route.Path), Streaming: streaming, StartedAt: time.Now(),
	})
	mw := &substrateMeterWriter{ResponseWriter: w, call: call}
	defer func() {
		if v := recover(); v != nil {
			call.End(fmt.Errorf("proxy panic"))
			panic(v)
		}
	}()
	s.cfg.Proxy.ServeHTTP(mw, r2)
	mw.header()
	call.End(nil)
}

// substrateCleanPath refuses dot segments, empty segments and encoded
// separators: the provider path is forwarded as it is cleaned.
func substrateCleanPath(p string) bool {
	if strings.Contains(p, "\\") {
		return false
	}
	return path.Clean(p) == p
}

// substrateNarrowRoute enforces that a router answer only keeps, narrows
// or refuses: the provider must be one the table serves, the origin is the
// table's, the path is clean, and a body model cannot be swapped.
func substrateNarrowRoute(providers map[string]SubstrateLLMProvider, requested, next SubstrateLLMRoute) (SubstrateLLMRoute, string, *SubstrateModelRefusal) {
	if next.Provider == "" {
		next.Provider = requested.Provider
	}
	if next.Path == "" {
		next.Path = requested.Path
	}
	p, ok := providers[next.Provider]
	if !ok {
		return requested, "", &SubstrateModelRefusal{Reason: "route_outside_providers",
			Message: "This model route is not available. Ask your DefenseClaw administrator which models your profile allows."}
	}
	if !substrateCleanPath(next.Path) {
		return requested, "", &SubstrateModelRefusal{Reason: "route_path_invalid",
			Message: "This model route is not available."}
	}
	next.Origin = p.Origin
	model, _ := substrateCallModel(next.Provider, next.Path, nil)
	if substrateBodyModel(next.Provider) {
		if next.Model != "" && next.Model != requested.Model {
			return requested, "", &SubstrateModelRefusal{Reason: "model_not_allowed",
				Message: "The requested model is not allowed for your profile. Choose an allowed model, or ask your DefenseClaw administrator for access."}
		}
		model = requested.Model
	}
	next.Model = model
	if next.Provider == requested.Provider && next.Path == requested.Path {
		return next, substrateRouteKept, nil
	}
	return next, substrateRouteNarrowed, nil
}

// writeSubstrateModelRefusal answers a refused model call: 403 with a
// closed reason and, from a SubstrateModelRefusal, the plain text.
func writeSubstrateModelRefusal(w http.ResponseWriter, err error) {
	var ref *SubstrateModelRefusal
	if !errors.As(err, &ref) || ref.Reason == "" {
		writeSubstrateRefusal(w, http.StatusForbidden, "model_call_refused")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": http.StatusText(http.StatusForbidden), "reason": ref.Reason, "message": ref.Message,
	})
}

// substrateBodyModel reports a provider whose model is in the body.
func substrateBodyModel(provider string) bool {
	switch provider {
	case "bedrock", "gemini":
		return false
	}
	return true
}

var (
	substrateBedrockPathRE = regexp.MustCompile(`^/model/([^/]+)/(invoke|invoke-with-response-stream|converse|converse-stream)$`)
	substrateGeminiPathRE  = regexp.MustCompile(`^/v1(?:beta|alpha)?/models/([^/:]+):([A-Za-z]+)$`)
)

// substrateCallModel finds the model a call names and whether it streams.
func substrateCallModel(provider, p string, body []byte) (model string, streaming bool) {
	switch provider {
	case "bedrock":
		if m := substrateBedrockPathRE.FindStringSubmatch(p); m != nil {
			return m[1], strings.HasSuffix(m[2], "stream")
		}
		return "", false
	case "gemini":
		if m := substrateGeminiPathRE.FindStringSubmatch(p); m != nil {
			return m[1], strings.HasPrefix(m[2], "stream")
		}
		return "", false
	}
	if len(body) == 0 {
		return "", false
	}
	var head struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if json.Unmarshal(body, &head) != nil {
		return "", false
	}
	return head.Model, head.Stream
}

// substrateAPIFamily names a call's provider API.
func substrateAPIFamily(provider, p string) string {
	switch provider {
	case "bedrock":
		if m := substrateBedrockPathRE.FindStringSubmatch(p); m != nil {
			switch m[2] {
			case "invoke-with-response-stream":
				return "invoke-stream"
			default:
				return m[2]
			}
		}
	case "gemini":
		if substrateGeminiPathRE.MatchString(p) {
			return "generate"
		}
	case "anthropic":
		if strings.HasSuffix(p, "/messages") {
			return "messages"
		}
	case "openai":
		switch {
		case strings.HasSuffix(p, "/chat/completions"):
			return "chat"
		case strings.HasSuffix(p, "/responses"):
			return "responses"
		}
	}
	return "other"
}
