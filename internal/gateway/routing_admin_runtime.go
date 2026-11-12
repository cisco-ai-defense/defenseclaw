// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// routingAdminRuntime holds the process-wide part of routing.admin rules
// and budgets: the spend ledger (only while budgets exist) and the recent
// decisions `routing explain` and `routing status` read. Each config
// generation compiles its own evaluator from it (routingAdminRuntime.For).
var routingAdminRuntime = routingadmin.NewRuntime()

// activeEngineRouter is the sidecar's routing engine, for the dry run of
// POST /api/v1/routing/test (nil until routing starts).
var activeEngineRouter atomic.Pointer[engineRouter]

// recordRoutingDecision keeps one routed call in the recent-decisions ring:
// no prompt text, headers or credentials, and the verified caller key only.
func recordRoutingDecision(ctx context.Context, in *ModelRouterInput, d *engine.Decision, managed bool) {
	if in == nil || d == nil {
		return
	}
	entry := routingadmin.DecisionEntry{
		Time:           time.Now().UTC(),
		RequestID:      RequestIDFromContext(ctx),
		CallerKey:      routingadmin.CallerFromEngine(in.Caller, managed).Key,
		Connector:      in.Connector,
		Listener:       in.Listener,
		APIFamily:      in.APIFamily,
		Category:       d.Category,
		RequestedModel: in.RequestModel,
		Outcome:        d.Outcome,
		Source:         d.Source,
		RuleIDs:        d.RuleIDs,
		Warnings:       d.Warnings,
	}
	if entry.RequestedModel == "" {
		entry.RequestedModel = in.Model
	}
	if d.Backend != nil {
		entry.SelectedAlias, entry.SelectedModel = d.Backend.Alias, d.Backend.Model
	}
	if d.FailureCode != "" && d.FailureCode != engine.FailureNone {
		entry.Reasons = append(entry.Reasons, d.FailureCode)
	}
	if d.FilteredBy != "" {
		entry.Reasons = append(entry.Reasons, "filtered_by:"+d.FilteredBy)
	}
	if d.Deny != nil {
		entry.Reasons = append(entry.Reasons, d.Deny.Code)
	}
	routingAdminRuntime.Decisions().Record(entry)
}

// routingCallerMatcher answers routing.admin identity selectors (groups,
// users, agents) for ctx's verified subject with the proof rules of
// guardrail.profile_assignments (assignmentState): yes, no, or maybe when a
// fact is not proven. nil when the request has no verified subject.
func routingCallerMatcher(ctx context.Context) func(config.ProfileMatch) engine.Tri {
	subject, source := profileRequestSubject(ctx)
	if subject == nil || source == "" {
		return nil
	}
	cfg := routingRequestConfig(ctx)
	set := &guardrailProfileSet{base: cfg, groupSIDs: routingGroupSIDsFor(cfg)}
	res := resolveIdentity(subject, nil)
	connectorName := profileAssignmentConnector(ctx)
	agent := ""
	if id, ok := profileAgentSource(ctx); ok {
		agent = strings.TrimSpace(id)
	}
	return func(m config.ProfileMatch) engine.Tri {
		state, _, _, _ := set.assignmentState(m, subject, res, true, connectorName, agent)
		switch state {
		case matchYes:
			return engine.Yes
		case matchMaybe:
			return engine.Maybe
		default:
			return engine.No
		}
	}
}

// routingRequestConfig is the config of the generation ctx pinned, else the
// current one.
func routingRequestConfig(ctx context.Context) *config.Config {
	if g := pinnedGeneration(ctx); g.published() && g.Config != nil {
		return g.Config
	}
	if g := currentGeneration(); g.published() {
		return g.Config
	}
	return nil
}

// routingGroupSIDs resolves the group names routing.admin rules and budgets
// name, as the profile set does for assignments: on a standalone Windows
// device a group name matches its SID only (GAP-0860). One table per
// config generation.
var routingGroupSIDs struct {
	sync.Mutex
	cfg   *config.Config
	table *profileGroupSIDs
}

func routingGroupSIDsFor(cfg *config.Config) *profileGroupSIDs {
	if cfg == nil || cfg.Routing.Admin == nil || runtime.GOOS != "windows" || !cfg.StandaloneEnterprise() || profileGroupSIDLookup == nil {
		return nil
	}
	routingGroupSIDs.Lock()
	defer routingGroupSIDs.Unlock()
	if routingGroupSIDs.cfg == cfg {
		return routingGroupSIDs.table
	}
	var names []config.ProfileAssignment
	for _, r := range cfg.Routing.Admin.Rules {
		if len(r.Match.Groups) > 0 {
			names = append(names, config.ProfileAssignment{Match: config.ProfileMatch{Groups: r.Match.Groups}})
		}
	}
	for _, b := range cfg.Routing.Admin.Budgets {
		if b.Scope == config.RoutingBudgetScopeGroup {
			names = append(names, config.ProfileAssignment{Match: config.ProfileMatch{Groups: []string{b.Subject}}})
		}
	}
	routingGroupSIDs.cfg = cfg
	routingGroupSIDs.table = nil
	if len(names) > 0 {
		routingGroupSIDs.table = buildProfileGroupSIDs(names, profileGroupSIDLookup, profileGroupLocalSIDLookup, profileGroupSIDWait)
	}
	return routingGroupSIDs.table
}
