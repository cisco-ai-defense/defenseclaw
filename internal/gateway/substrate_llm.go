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
// Routing (1.0.10 stream 1) and usage (stream 10) run inside the proxy
// (handleChatCompletion and handlePassthrough) for this call as for any
// other, on the verified caller the actor listener attached
// (substrate_identity.go); /llm adds neither.

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

// SubstrateLLMConfig configures /llm.
type SubstrateLLMConfig struct {
	Providers map[string]SubstrateLLMProvider
	// Proxy serves the call (GuardrailProxy.SubstrateHandler).
	Proxy http.Handler
	// ExposedValues, when set, returns the actor_secrets values of a
	// profile (SubstrateExposedValues): a request body that carries one is
	// refused before it reaches the proxy (PLAN §7.2, exact-value DLP).
	ExposedValues func(profile string) map[string]string
}

// substrateLLMMaxDLPBody bounds the body /llm reads to look for an exposed
// value; a larger body of an actor with exposed values is refused.
const substrateLLMMaxDLPBody = 32 << 20

var substrateProviderRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// substrateModelPaths are the provider paths /llm serves: the model APIs
// and nothing else. The proxy's own routes (provider registry and reload,
// egress events, health, models) and every other provider path answer 404
// (D15; GAP-0041). A provider with no entry serves nothing.
var substrateModelPaths = map[string][]*regexp.Regexp{
	"bedrock": {regexp.MustCompile(`^/model/[^/]+/(invoke|invoke-with-response-stream|converse|converse-stream)$`)},
	"anthropic": {
		regexp.MustCompile(`^/v1/messages$`),
		regexp.MustCompile(`^/v1/messages/count_tokens$`),
	},
	"openai": {
		regexp.MustCompile(`^/v1/chat/completions$`),
		regexp.MustCompile(`^/v1/responses$`),
	},
	"gemini": {regexp.MustCompile(`^/v1(beta|alpha)?/models/[^/:]+:(generateContent|streamGenerateContent|countTokens)$`)},
}

func substrateModelPath(provider, p string) bool {
	for _, re := range substrateModelPaths[provider] {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

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
	if _, ok := substrateActorFrom(r.Context()); !ok {
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
	upstream := "/" + upstreamPath
	// A Bedrock ARN model ID (application inference profile, provisioned
	// throughput) carries an escaped slash; it is forwarded escaped, and
	// accepted only when that segment is a Bedrock ARN (GAP-0129).
	rawUpstream := ""
	if provider == "bedrock" {
		if esc, ok := strings.CutPrefix(r.URL.EscapedPath(), substrateLLMPrefix+provider); ok {
			if dec, ok := substrateBedrockARNPath(esc); ok && dec == upstream {
				rawUpstream = esc
			}
		}
	}
	if rawUpstream == "" && (path.Clean(upstream) != upstream || strings.Contains(upstream, "\\") || !substrateModelPath(provider, upstream)) {
		writeSubstrateRefusal(w, http.StatusNotFound, "not_found")
		return
	}
	if !s.exposedValueCheck(w, r) {
		return
	}
	key, err := os.ReadFile(p.CredentialFile)
	if err != nil || strings.TrimSpace(string(key)) == "" {
		fmt.Fprintf(os.Stderr, "[substrate] llm: provider %s has no readable credential (%s)\n", provider, p.CredentialFile)
		writeSubstrateRefusal(w, http.StatusServiceUnavailable, "provider_credential_unavailable")
		return
	}
	secret := strings.TrimSpace(string(key))
	r2 := r.Clone(r.Context())
	for _, h := range substrateCredentialHeaders {
		r2.Header.Del(h)
	}
	r2.Header.Set("X-DC-Target-URL", p.Origin)
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
	u.Path, u.RawPath = upstream, rawUpstream
	r2.URL = &u
	r2.RequestURI = ""
	s.cfg.Proxy.ServeHTTP(w, r2)
}

// exposedValueCheck refuses a model call whose body carries one of the
// actor's exposed values (its profile's actor_secrets), and puts the body
// back otherwise. A body it cannot read whole (too large, compressed) is
// refused for an actor that has exposed values: the check fails closed.
// The refusal names the secret, never its value.
func (s *substrateLLM) exposedValueCheck(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.ExposedValues == nil {
		return true
	}
	reg, ok := substrateRegistrationFrom(r.Context())
	if !ok {
		return true
	}
	values := s.cfg.ExposedValues(reg.Profile)
	if len(values) == 0 {
		return true
	}
	if enc := strings.TrimSpace(r.Header.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		writeSubstrateRefusal(w, http.StatusUnsupportedMediaType, "exposed_value_check_needs_plain_body")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, substrateLLMMaxDLPBody+1))
	if err != nil || len(body) > substrateLLMMaxDLPBody {
		writeSubstrateRefusal(w, http.StatusRequestEntityTooLarge, "body_too_large")
		return false
	}
	_ = r.Body.Close()
	if name, hit := substrateExposedValueIn(body, values); hit {
		fmt.Fprintf(os.Stderr, "[substrate] llm: refused a model call of %s/%s carrying the exposed value %s (actor_secrets)\n",
			reg.Atespace, reg.Name, name)
		writeSubstrateRefusal(w, http.StatusForbidden, "exposed_secret_in_request")
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return true
}

// substrateRouterAnswerNarrows reports a semantic-router answer an Agent
// Substrate actor's chat call may take (GAP-0104): the router brings no key
// of its own and keeps the upstream origin /llm set from the provider
// table, so it can pick another model of the same provider but never send
// the call elsewhere (another provider, a loopback backend) or with another
// credential. Which models a profile allows is stream 1 (routing overlay),
// which narrows inside this.
func substrateRouterAnswerNarrows(target string, d *ModelRouterDecision) bool {
	if d == nil {
		return true
	}
	if d.APIKeyOverride {
		return false
	}
	if !d.TargetURLOverride {
		return true
	}
	from, err1 := url.Parse(strings.TrimSpace(target))
	to, err2 := url.Parse(strings.TrimSpace(d.TargetURL))
	if err1 != nil || err2 != nil || from.Host == "" || to.User != nil {
		return false
	}
	return strings.EqualFold(from.Scheme, to.Scheme) && strings.EqualFold(from.Host, to.Host)
}

var (
	substrateBedrockRawPathRE = regexp.MustCompile(`^/model/([^/]+)/(invoke|invoke-with-response-stream|converse|converse-stream)$`)
	substrateBedrockARNRE     = regexp.MustCompile(`^arn:aws(-[a-z]+)*:bedrock:[a-z0-9-]+:[0-9]{12}:` +
		`(application-inference-profile|inference-profile|provisioned-model|custom-model|imported-model|foundation-model)/[A-Za-z0-9._:-]+$`)
)

// substrateBedrockARNPath reads an escaped Bedrock model path whose model
// segment is an ARN: one segment on the wire, a Bedrock ARN with exactly
// one slash once unescaped. It returns the decoded path.
func substrateBedrockARNPath(escaped string) (string, bool) {
	m := substrateBedrockRawPathRE.FindStringSubmatch(escaped)
	if m == nil {
		return "", false
	}
	id, err := url.PathUnescape(m[1])
	if err != nil || strings.Count(id, "/") != 1 || !substrateBedrockARNRE.MatchString(id) {
		return "", false
	}
	return "/model/" + id + "/" + m[2], true
}
