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

// Package signin decides how an Agent Substrate actor may reach its model
// (PLAN E9, J41).
//
// A connector reaches its model one of three ways:
//
//   - gateway: every model call goes to the DefenseClaw gateway with a
//     placeholder key and the gateway holds the real credential (Claude Code,
//     Codex, OpenCode, Copilot CLI, Hermes);
//   - vendor key: the vendor's own API key, bound as a Substrate secret, so
//     egress adds it to the request and the actor holds only a placeholder
//     (Cursor, Amp, Kiro, Antigravity);
//   - subscription: the agent signs in to a vendor account and keeps the
//     token and its refresh token inside the actor, which puts them in every
//     snapshot (suspend, fork, revert). Devin has no key route at all; the
//     other four fall back to this when no key is bound.
//
// A managed deployment refuses the subscription route. An open-source
// deployment allows it and says what it costs. The gateway, the actor kit
// and the launcher all call Evaluate, so the three agree.
package signin

import (
	"fmt"
	"strings"
)

// Route is how a connector reaches its model from an actor.
type Route string

const (
	RouteGateway      Route = "gateway"
	RouteVendorKey    Route = "vendor_key"
	RouteSubscription Route = "subscription"
)

// RefusedCode is the machine-readable reason of a refusal (HTTP 403 body and
// the hook's block text both carry it).
const RefusedCode = "subscription_signin_refused"

type spec struct {
	// Name is the connector's display name.
	Name string
	// ViaGateway is true when the connector's model calls always go to the
	// DefenseClaw gateway (no vendor credential in the actor).
	ViaGateway bool
	// KeyEnv is the environment variable that carries the vendor API key
	// (or its placeholder) for the connector; "" when the vendor offers no
	// key route.
	KeyEnv string
}

var specs = map[string]spec{
	"claudecode": {Name: "Claude Code", ViaGateway: true},
	"codex":      {Name: "Codex", ViaGateway: true},
	"opencode":   {Name: "OpenCode", ViaGateway: true},
	"copilot":    {Name: "GitHub Copilot CLI", ViaGateway: true},
	"hermes":     {Name: "Hermes", ViaGateway: true},
	// Measured on the pinned releases (lanes/a11/HANDOFF.md): each takes the
	// key from this variable instead of a sign-in.
	"cursor":      {Name: "Cursor Agent CLI", KeyEnv: "CURSOR_API_KEY"},
	"amp":         {Name: "Amp", KeyEnv: "AMP_API_KEY"},
	"kiro":        {Name: "Kiro CLI", KeyEnv: "KIRO_API_KEY"},
	"antigravity": {Name: "Antigravity CLI", KeyEnv: "GEMINI_API_KEY"},
	// Devin CLI 3000.4.25 documents no API key: its only route is
	// "devin auth login".
	"devin": {Name: "Devin CLI"},
}

func normalize(connector string) string {
	return strings.ToLower(strings.TrimSpace(connector))
}

// Known reports whether the connector has a model route on record.
func Known(connector string) bool {
	_, ok := specs[normalize(connector)]
	return ok
}

// DisplayName is the connector's name for messages; unknown connectors keep
// the name they were given.
func DisplayName(connector string) string {
	if s, ok := specs[normalize(connector)]; ok {
		return s.Name
	}
	return connector
}

// KeyEnv is the environment variable the connector's vendor API key (or its
// placeholder) lives in; "" for a gateway connector and for Devin.
func KeyEnv(connector string) string {
	return specs[normalize(connector)].KeyEnv
}

// Classify gives the route of connector when placeholders are the
// environment variable names the actor carries in place of bound secrets.
// A connector this package does not know is a gateway connector: its
// render is refused elsewhere, and a refusal here would hide that reason.
func Classify(connector string, placeholders []string) Route {
	s, ok := specs[normalize(connector)]
	if !ok || s.ViaGateway {
		return RouteGateway
	}
	if s.KeyEnv != "" {
		for _, p := range placeholders {
			if p == s.KeyEnv {
				return RouteVendorKey
			}
		}
	}
	return RouteSubscription
}

// Decision is the outcome of Evaluate.
type Decision struct {
	Route Route
	// Allowed is false when a managed deployment refuses the route.
	Allowed bool
	// Code is RefusedCode on a refusal.
	Code string
	// Message is the refusal, or the warning an allowed subscription route
	// shows; empty otherwise.
	Message string
	// Warn is true when Allowed carries a warning in Message.
	Warn bool
}

// Evaluate applies E9: managed refuses a subscription sign-in, open source
// allows it with a warning, and the other routes are untouched.
func Evaluate(connector string, managed bool, placeholders []string) Decision {
	route := Classify(connector, placeholders)
	if route != RouteSubscription {
		return Decision{Route: route, Allowed: true}
	}
	name := DisplayName(connector)
	keyEnv := KeyEnv(connector)
	if managed {
		hint := "Ask your administrator for an agent that runs through the DefenseClaw model route."
		if keyEnv != "" {
			hint = fmt.Sprintf("Ask your administrator to bind %s as a Substrate secret (egress adds the key, so the actor never holds it), or use an agent that runs through the DefenseClaw model route.", keyEnv)
		}
		return Decision{
			Route: route, Code: RefusedCode,
			Message: fmt.Sprintf("%s signs in with a vendor account, and a managed deployment does not allow that: the sign-in token would sit in the actor and in every snapshot of it. %s", name, hint),
		}
	}
	hint := fmt.Sprintf("%s has no API key route, so the token cannot be kept out of the actor.", name)
	if keyEnv != "" {
		hint = fmt.Sprintf("To keep the token out of the actor, bind %s as a Substrate secret instead.", keyEnv)
	}
	return Decision{
		Route: route, Allowed: true, Warn: true,
		Message: fmt.Sprintf("%s signs in with a vendor account. Its sign-in token is stored in this actor and kept in every snapshot of it (suspend, fork and revert); deleting the actor purges them. %s", name, hint),
	}
}
