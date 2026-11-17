// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
)

// An administrator's read of other people's agents is audited (GAP-0424):
// the plan's privacy rule lets an administrator see every person's agents,
// asks, batches and usage, and every such look is recorded as who looked
// and at what. One substrate audit row per request (INFO: an allowed read,
// not an alert) names the administrator, the route pattern (a closed set,
// never caller text), the atespace and name for a single agent, and how
// many records the answer held. The gateway log gets a line without the
// person. A person's own reads, and an administrator's own agents, write
// nothing.

// substrateAuditAdminRead records an administrator's read of other people's
// records: what is the view ("actors", "actor", "asks", "batches",
// "usage"), count how many records it answered with, ref the one agent
// ("atespace/name") or "".
func (a *APIServer) substrateAuditAdminRead(st *substrateState, r *http.Request, what string, count int, ref string) {
	c, ok := substrateCallerFrom(r.Context())
	if !ok || !c.admin {
		return
	}
	route := r.Pattern
	if route == "" {
		route = r.Method + " " + what
	}
	summary := fmt.Sprintf("administrator read of other people's %s: %d record(s) (%s)", what, count, route)
	if ref != "" {
		summary = fmt.Sprintf("administrator read of another person's agent %s (%s)", ref, route)
	}
	details := map[string]any{
		"event": "admin_read", "view": what, "route": route, "count": count,
		"admin": c.person.Principal, "admin_id": ownerOf(c.person).ID(),
	}
	if ref != "" {
		details["actor"] = ref
	}
	if a.logger != nil {
		_ = a.logger.LogAlertCtx(context.WithoutCancel(r.Context()), "substrate", "INFO", summary, details)
	}
	st.logRefusal("%s", summary)
}

// substrateAllView reports whether the request is an administrator's
// all=1 view over every person.
func substrateAllView(r *http.Request) bool {
	c, ok := substrateCallerFrom(r.Context())
	return ok && c.admin && r.URL.Query().Get("all") == "1"
}
