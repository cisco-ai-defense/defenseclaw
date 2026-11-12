// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// Same-API routing on the provider-native passthrough paths (DESIGN 5):
// Anthropic Messages and OpenAI Responses swap the body model; Bedrock
// Converse / InvokeModel swap the model id in the path and are routed only
// with a bearer key (a SigV4-signed request is never rewritten, GAP-1893).

// providerDefaultOrigins is where a routed backend without base_url goes
// when its provider differs from the inbound one.
var providerDefaultOrigins = map[string]string{
	"anthropic": "https://api.anthropic.com",
	"openai":    "https://api.openai.com",
}

// passthroughAPIFamily names the routable API family of a passthrough path
// ("" when the path is not routed).
func passthroughAPIFamily(path string) string {
	p := strings.TrimRight(path, "/")
	switch {
	case strings.HasSuffix(p, "/v1/messages"):
		return config.RoutingAPIMessages
	case strings.HasSuffix(p, "/v1/responses"), strings.HasSuffix(p, "/backend-api/codex/responses"):
		return config.RoutingAPIResponses
	}
	if strings.Contains(p, "/model/") {
		switch bedrockActionFromPath(p) {
		case "converse", "converse-stream":
			return config.RoutingAPIConverse
		case "invoke", "invoke-with-response-stream":
			return config.RoutingAPIInvoke
		}
	}
	return ""
}

// passthroughRoute is a routed passthrough request ready to forward.
type passthroughRoute struct {
	Origin   string // scheme://host[:port] of the selected backend
	Path     string // RequestURI to send (model id swapped for Bedrock)
	Body     []byte
	Provider string
	// Auth replaces the agent credential (Bearer form) unless KeepInbound.
	Auth        string
	KeepInbound bool
}

type passthroughRouteInput struct {
	APIFamily     string
	Body          []byte
	Text          string
	Model         string
	Severity      string
	InboundOrigin string
	Provider      string
	Signed        bool
}

// routePassthrough asks the router about one passthrough request. ok is
// false when the request goes out unchanged; deny is set for a managed
// refusal.
func (p *GuardrailProxy) routePassthrough(r *http.Request, in passthroughRouteInput) (route passthroughRoute, ok bool, outcome SemanticRouteOutcome) {
	if in.APIFamily == "" || in.Signed || !p.routerActive(r.Context()) {
		return passthroughRoute{}, false, p.gateUnrouted(r, in)
	}
	caller, profiles := routeCallerFromContext(r.Context())
	var probe struct {
		Tools              json.RawMessage `json:"tools"`
		PreviousResponseID string          `json:"previous_response_id"`
	}
	_ = json.Unmarshal(in.Body, &probe)
	hasTools := len(bytes.TrimSpace(probe.Tools)) > 2
	model := in.Model
	if in.APIFamily == config.RoutingAPIConverse || in.APIFamily == config.RoutingAPIInvoke {
		model = bedrockModelFromPath(r.URL.Path)
	}
	input := &ModelRouterInput{
		Model: model, RequestModel: model, APIFamily: in.APIFamily, Connector: p.connectorName(),
		Listener: engine.ListenerGuardrail, Severity: in.Severity, RequestedProvider: in.Provider,
		ConversationID: r.Header.Get("X-DC-Session-Id"), Text: in.Text, Caller: caller, Profiles: profiles,
	}
	if hasTools {
		input.Tools = []interface{}{true}
	}
	outcome = p.routeDetailed(r.Context(), input)
	p.applyRouteGate(r.Context(), &outcome, in.Provider, model)
	p.recordSemanticRoutingDecisionV8(r.Context(), outcome)
	d := outcome.Decision
	if outcome.Result != SemanticRouteApplied || d == nil {
		return passthroughRoute{}, false, outcome
	}
	if probe.PreviousResponseID != "" && !strings.EqualFold(d.Provider, in.Provider) {
		// A stored response id belongs to the original provider (DESIGN 5).
		return passthroughRoute{}, false, p.gateOriginal(r.Context(), outcome, in.Provider, model)
	}
	origin := originOf(d.TargetURL)
	sameProvider := strings.EqualFold(d.Provider, in.Provider)
	if origin == "" {
		if sameProvider {
			origin = in.InboundOrigin
		} else {
			origin = providerDefaultOrigins[strings.ToLower(d.Provider)]
		}
	}
	if origin == "" {
		return passthroughRoute{}, false, p.gateOriginal(r.Context(), outcome, in.Provider, model)
	}
	route = passthroughRoute{Origin: origin, Path: r.URL.RequestURI(), Body: in.Body, Provider: d.Provider}
	switch in.APIFamily {
	case config.RoutingAPIConverse, config.RoutingAPIInvoke:
		if !strings.EqualFold(d.Provider, "bedrock") {
			return passthroughRoute{}, false, outcome
		}
		route.Path = swapBedrockPathModel(r.URL, d.Model)
		if route.Path == "" {
			return passthroughRoute{}, false, outcome
		}
	default:
		route.Body = patchModelInBody(in.Body, d.Model)
	}
	// The agent credential stays only when the backend holds no key of its
	// own and is the same provider at the same origin; otherwise the
	// gateway-held key (possibly none, for a local model) replaces it.
	if d.APIKey == "" && sameProvider && strings.EqualFold(origin, in.InboundOrigin) {
		route.KeepInbound = true
	} else if d.APIKey != "" {
		route.Auth = "Bearer " + d.APIKey
	}
	return route, true, outcome
}

// routeDetailed calls the installed router with its detailed outcome.
func (p *GuardrailProxy) routeDetailed(ctx context.Context, in *ModelRouterInput) SemanticRouteOutcome {
	if detailed, ok := p.modelRouter.(detailedModelRouter); ok {
		return detailed.RouteDetailed(ctx, in)
	}
	return outcomeFromDecision(in, p.modelRouter.Route(ctx, in), 0)
}

func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// swapBedrockPathModel replaces the model id segment of a Bedrock runtime
// path, keeping every other segment in its escaped form.
func swapBedrockPathModel(u *url.URL, model string) string {
	escaped := u.EscapedPath()
	const marker = "/model/"
	i := strings.Index(escaped, marker)
	if i < 0 || model == "" {
		return ""
	}
	rest := escaped[i+len(marker):]
	j := strings.Index(rest, "/")
	if j <= 0 {
		return ""
	}
	out := escaped[:i+len(marker)] + url.PathEscape(model) + rest[j:]
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// routeDenyMessage is the text an agent shows for a managed routing deny.
func routeDenyMessage(o SemanticRouteOutcome) string {
	if o.Deny != nil && o.Deny.Message != "" {
		return "[DefenseClaw] " + o.Deny.Message
	}
	return "[DefenseClaw] Your organization does not allow this model request."
}

// routeRequestedProvider is the provider of the upstream the request was
// addressed to (resolved from its URL), else the provider the model name
// suggests. The managed deny judges this, not a client-chosen model name.
func routeRequestedProvider(targetURL, requestURI string, providers *configs.ProvidersConfig, fallback string) string {
	if strings.TrimSpace(targetURL) != "" {
		if inferred := inferProviderFromRegistry(rawForwardUpstreamURL(targetURL, requestURI), providers); inferred != "" {
			return inferred
		}
	}
	return fallback
}
