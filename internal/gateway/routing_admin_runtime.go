// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync/atomic"
	"time"

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
