// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
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
	a.substrateAuditAdmin(st, r, what, count, ref, "INFO")
}

// substrateAuditAdmin is substrateAuditAdminRead with a severity: an
// administrator deleting another person's agent is HIGH (GAP-0435).
func (a *APIServer) substrateAuditAdmin(st *substrateState, r *http.Request, what string, count int, ref, severity string) {
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
		verb := what
		if what == "actor" {
			verb = "read"
		}
		summary = fmt.Sprintf("administrator %s of another person's agent %s (%s)", verb, ref, route)
	}
	details := map[string]any{
		"event": "admin_read", "view": what, "route": route, "count": count,
		"admin": c.person.Principal, "admin_id": ownerOf(c.person).ID(),
	}
	if ref != "" {
		details["actor"] = ref
	}
	if a.logger != nil {
		_ = a.logger.LogAlertCtx(context.WithoutCancel(r.Context()), "substrate", severity, summary, details)
	}
	st.logRefusal("%s", summary)
}

// substrateAllView reports whether the request is an administrator's
// all=1 view over every person.
func substrateAllView(r *http.Request) bool {
	c, ok := substrateCallerFrom(r.Context())
	return ok && c.admin && r.URL.Query().Get("all") == "1"
}

// substrateOwnedBy reports whether reg's actor is the caller's own: only its
// person may hold a session on it (GAP-0435).
func substrateOwnedBy(c substrateCaller, reg registry.Registration) bool {
	return reg.Person.Subject != "" && reg.Person.ID() == ownerOf(c.person).ID()
}

// substrateAuditAdminTarget audits an administrator's management of
// another person's agent (what: "actor", "delete", "policy explain").
func (a *APIServer) substrateAuditAdminTarget(st *substrateState, r *http.Request, reg registry.Registration, what, severity string) {
	if c, ok := substrateCallerFrom(r.Context()); ok && c.admin && !substrateOwnedBy(c, reg) {
		a.substrateAuditAdmin(st, r, what, 1, reg.Atespace+"/"+reg.Name, severity)
	}
}

// substrateFindSession is substrateFind for a session (a session
// certificate, attach, exec): only the agent's own person gets one, an
// administrator included. Admins see every person's inventory, never their
// sessions (owner privacy rule, J34). A person who is not an administrator
// gets substrateFind's 404 as before; an administrator gets 403
// not_your_agent, and the refusal is audited as them.
func (a *APIServer) substrateFindSession(st *substrateState, r *http.Request, atespace, name string) (registry.Registration, int, string) {
	reg, status, reason := a.substrateFind(st, r, atespace, name)
	if status != http.StatusOK {
		return reg, status, reason
	}
	c, _ := substrateCallerFrom(r.Context())
	if !substrateOwnedBy(c, reg) {
		a.substrateAuditDenied(st, r, reg.Atespace+"/"+reg.Name, "not_your_agent")
		return registry.Registration{}, http.StatusForbidden, "not_your_agent"
	}
	return reg, http.StatusOK, ""
}
