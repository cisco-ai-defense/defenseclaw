// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The routing block (rel-1-0-10 GAP-0574) is an optional member of status and
// verify on the standalone profile: whether model routing is on, how many
// models, rules and budgets the administrator config holds, and for each
// route-only connector whether the gateway reports it ready. It carries
// counts, connector ids and closed codes only (the not-ready cause too):
// never an account, a model name, a rule, a budget id, an upstream or a
// free-text problem. It is not in
// the forward schema, so a management agent that projects the result drops
// it (nothing about routing leaves the device by default).

// Reasons a route-only connector is not ready (RoutingRouteOnly.ReasonCode).
const (
	RoutingReasonGatewayDidNotReport = "gateway_did_not_report"
	RoutingReasonNotReady            = "not_ready"
	RoutingReasonNoReadiness         = "no_readiness_row"
)

// Closed causes of a route-only connector the gateway reports not ready
// (RoutingRouteOnly.Cause). The gateway publishes the same codes in /health
// routing.details.route_only[].cause: it names them from these constants.
const (
	RoutingCauseRouteEpoch          = "route_epoch"
	RoutingCauseAliasNoCredential   = "allowed_alias_no_credential"
	RoutingCauseUpstreamNotSet      = "upstream_not_set"
	RoutingCauseSigningNotReady     = "signing_not_ready"
	RoutingCauseCredentialNotStored = "credential_not_stored"
	RoutingCauseNoCredential        = "credential_not_configured"
	RoutingCauseNoEnrolledAccount   = "no_enrolled_account"
)

// routingCauseText is the short text status and verify print after each
// cause: fixed text, never a name from the policy (the gateway /health of an
// administrator, and doctor where it runs, carry the full problem and fix).
var routingCauseText = map[string]string{
	RoutingCauseRouteEpoch:          "the gateway route epoch is not published, so no account's route-only settings can be rendered; gateway.log says why",
	RoutingCauseAliasNoCredential:   "a routing.admin rule for every caller allows only models with no gateway credential on this host",
	RoutingCauseUpstreamNotSet:      "routing.route_only.upstreams is not set for the connector",
	RoutingCauseSigningNotReady:     "gateway Bedrock signing is not ready",
	RoutingCauseCredentialNotStored: "a gateway credential the policy names is not stored on this host (enterprise secret set stores it)",
	RoutingCauseNoCredential:        "no gateway credential covers the route-only upstream",
	RoutingCauseNoEnrolledAccount:   "no enrolled account has the connector protected yet",
}

// RoutingCauseText is the short text of a closed cause; "" for any other code.
func RoutingCauseText(cause string) string { return routingCauseText[cause] }

// routingRouteOnlyMax bounds RoutingState.RouteOnly.
const routingRouteOnlyMax = 16

// RoutingState is the routing block.
type RoutingState struct {
	// Enabled is routing.enabled of the installed config.
	Enabled bool `json:"enabled"`
	// Classifier is rules, systemone or vllm_sr (the effective value).
	Classifier string `json:"classifier"`
	// Models, Rules and Budgets count routing.models and
	// routing.admin.rules and .budgets.
	Models  int `json:"models"`
	Rules   int `json:"rules"`
	Budgets int `json:"budgets"`
	// RouteOnly lists routing.route_only.connectors, sorted by connector.
	RouteOnly []RoutingRouteOnly `json:"route_only,omitempty"`
}

// RoutingRouteOnly is one route-only connector.
type RoutingRouteOnly struct {
	Connector string `json:"connector"`
	// ManagedHook: the connector runs from administrator machine policy.
	// Absent when the connectors block does not know.
	ManagedHook *bool `json:"managed_hook,omitempty"`
	// Ready is the gateway own readiness check of the connector route
	// (credential, upstream, signing); absent when the gateway did not
	// report. ReasonCode says why it is absent or false.
	Ready      *bool  `json:"ready,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
	// Cause is the closed code (RoutingCause*) of why the gateway reports
	// the connector not ready; absent when ready, when the gateway did not
	// report, and for a code this build does not know (never free text).
	Cause string `json:"cause,omitempty"`
}

// RoutingInputs are what BuildRouting reads.
type RoutingInputs struct {
	Config *config.Config
	// Connectors is the connectors block (ManagedHook).
	Connectors map[string]ConnectorState
	// Health is the gateway /health body; nil when it did not report.
	Health []byte
}

// BuildRouting returns the routing block, or nil when there is no config or
// routing is neither enabled nor configured (nothing to report).
func BuildRouting(in RoutingInputs) *RoutingState {
	cfg := in.Config
	if cfg == nil {
		return nil
	}
	r := cfg.Routing
	state := &RoutingState{
		Enabled:    r.Enabled,
		Classifier: r.EffectiveClassifier(),
		Models:     len(r.Models),
	}
	if r.Admin != nil {
		state.Rules, state.Budgets = len(r.Admin.Rules), len(r.Admin.Budgets)
	}
	ready, causes := parseRouteOnlyReadiness(in.Health)
	connectors := append([]string(nil), r.RouteOnly.Connectors...)
	sort.Strings(connectors)
	for _, name := range connectors {
		if !connectorIDPattern.MatchString(name) || len(state.RouteOnly) >= routingRouteOnlyMax {
			continue
		}
		row := RoutingRouteOnly{Connector: name}
		if c, ok := in.Connectors[name]; ok && c.ManagedHook != nil {
			managed := *c.ManagedHook
			row.ManagedHook = &managed
		}
		switch got, known := ready[name]; {
		case in.Health == nil || ready == nil:
			row.ReasonCode = RoutingReasonGatewayDidNotReport
		case !known:
			row.ReasonCode = RoutingReasonNoReadiness
		default:
			ok := got
			row.Ready = &ok
			if !ok {
				row.ReasonCode = RoutingReasonNotReady
				row.Cause = causes[name]
			}
		}
		state.RouteOnly = append(state.RouteOnly, row)
	}
	if !state.Enabled && state.Models == 0 && state.Rules == 0 && state.Budgets == 0 && len(state.RouteOnly) == 0 {
		return nil
	}
	return state
}

// parseRouteOnlyReadiness reads routing.details.route_only of a gateway
// /health body: connector -> ready, and connector -> the closed cause of a
// connector that is not ready (an unknown code is dropped). nil when the
// body does not carry the member (an older gateway, or no route-only
// connector).
func parseRouteOnlyReadiness(body []byte) (map[string]bool, map[string]string) {
	if len(body) == 0 {
		return nil, nil
	}
	var health struct {
		Routing struct {
			Details struct {
				RouteOnly *[]struct {
					Connector string `json:"connector"`
					Ready     bool   `json:"ready"`
					Cause     string `json:"cause"`
				} `json:"route_only"`
			} `json:"details"`
		} `json:"routing"`
	}
	if json.Unmarshal(body, &health) != nil {
		return nil, nil
	}
	if health.Routing.Details.RouteOnly == nil {
		return nil, nil
	}
	out, causes := map[string]bool{}, map[string]string{}
	for _, row := range *health.Routing.Details.RouteOnly {
		if connectorIDPattern.MatchString(row.Connector) {
			out[row.Connector] = row.Ready
			if _, known := routingCauseText[row.Cause]; known && !row.Ready {
				causes[row.Connector] = row.Cause
			}
		}
	}
	return out, causes
}

// RoutingLines are the text status lines of the routing block.
func RoutingLines(state *RoutingState) []string {
	if state == nil {
		return nil
	}
	on := "off"
	if state.Enabled {
		on = "on"
	}
	lines := []string{fmt.Sprintf("routing: %s classifier=%s models=%d rules=%d budgets=%d", on, state.Classifier, state.Models, state.Rules, state.Budgets)}
	if len(state.RouteOnly) > 0 {
		parts := make([]string, 0, len(state.RouteOnly))
		var causes []string
		for _, row := range state.RouteOnly {
			status := "unknown"
			switch {
			case row.Ready != nil && *row.Ready:
				status = "ready"
			case row.Ready != nil:
				status = "not ready"
				if row.Cause != "" {
					status += " (" + row.Cause + ")"
					causes = append(causes, "route-only "+row.Connector+": "+row.Cause+": "+RoutingCauseText(row.Cause))
				}
			}
			parts = append(parts, row.Connector+" "+status)
		}
		lines = append(lines, "route-only: "+strings.Join(parts, ", "))
		// One line per named cause, so an administrator reads why from
		// status and verify (rel-1-0-10 GAP-1319).
		lines = append(lines, causes...)
	}
	return lines
}
