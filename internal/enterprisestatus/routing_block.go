// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The routing block (rel-1-0-10 GAP-0574) is an optional member of status and
// verify on the standalone profile: whether model routing is on, how many
// models, rules and budgets the administrator config holds, and for each
// route-only connector whether the gateway reports it ready. It carries
// counts, connector ids and closed codes only: never an account, a model
// name, a rule, a budget id, an upstream or a free-text problem. It is not in
// the forward schema, so a management agent that projects the result drops
// it (nothing about routing leaves the device by default).

// Reasons a route-only connector is not ready (RoutingRouteOnly.ReasonCode).
const (
	RoutingReasonGatewayDidNotReport = "gateway_did_not_report"
	RoutingReasonNotReady            = "not_ready"
	RoutingReasonNoReadiness         = "no_readiness_row"
)

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
	// Cause is a closed code (RoutingCauses) of why the gateway reports the
	// connector not ready; absent for any other problem. doctor and the
	// gateway /health carry the full text.
	Cause string `json:"cause,omitempty"`
}

// RoutingCauses are the causes of a not-ready route-only connector that
// status names; the gateway publishes the same codes in /health.
var RoutingCauses = []string{"route_epoch", "allowed_alias_no_credential"}

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
	ready := parseRouteOnlyReadiness(in.Health)
	causes := parseRouteOnlyCauses(in.Health)
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
// /health body: connector -> ready. nil when the body does not carry the
// member (an older gateway, or no route-only connector).
func parseRouteOnlyReadiness(body []byte) map[string]bool {
	if len(body) == 0 {
		return nil
	}
	var health struct {
		Routing struct {
			Details struct {
				RouteOnly *[]struct {
					Connector string `json:"connector"`
					Ready     bool   `json:"ready"`
				} `json:"route_only"`
			} `json:"details"`
		} `json:"routing"`
	}
	if json.Unmarshal(body, &health) != nil {
		return nil
	}
	if health.Routing.Details.RouteOnly == nil {
		return nil
	}
	out := map[string]bool{}
	for _, row := range *health.Routing.Details.RouteOnly {
		if connectorIDPattern.MatchString(row.Connector) {
			out[row.Connector] = row.Ready
		}
	}
	return out
}

// parseRouteOnlyCauses reads the closed cause of each not-ready route-only
// connector of a gateway /health body; an unknown code is dropped.
func parseRouteOnlyCauses(body []byte) map[string]string {
	var health struct {
		Routing struct {
			Details struct {
				RouteOnly []struct {
					Connector string `json:"connector"`
					Cause     string `json:"cause"`
				} `json:"route_only"`
			} `json:"details"`
		} `json:"routing"`
	}
	out := map[string]string{}
	if len(body) == 0 || json.Unmarshal(body, &health) != nil {
		return out
	}
	for _, row := range health.Routing.Details.RouteOnly {
		if connectorIDPattern.MatchString(row.Connector) && slices.Contains(RoutingCauses, row.Cause) {
			out[row.Connector] = row.Cause
		}
	}
	return out
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
		for _, row := range state.RouteOnly {
			status := "unknown"
			switch {
			case row.Ready != nil && *row.Ready:
				status = "ready"
			case row.Ready != nil:
				status = "not ready"
				if row.Cause != "" {
					status += " (" + row.Cause + ")"
				}
			}
			parts = append(parts, row.Connector+" "+status)
		}
		lines = append(lines, "route-only: "+strings.Join(parts, ", "))
	}
	return lines
}
