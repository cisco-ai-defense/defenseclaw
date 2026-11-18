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
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// Standing approvals (GAP-0492): what `approve --always` opened, listed and
// taken back on the admin listener. A person sees and revokes only their
// own agents' approvals; an administrator sees everyone's with all=1
// (audited) and revokes anyone's (audited as themselves).
//
//	GET    /api/v1/substrate/approvals[?all=1]                  -> {"approvals":[...]}
//	DELETE /api/v1/substrate/approvals/{atespace}/{name}/{host} -> the approvals of host taken back
//
// An approval is a host in the agent's registration (which the controller
// keeps in its network policy) or an always-approved ask (a url_rules
// approval covers its rule only, GAP-0177). Who approved it and when come
// from the ask that was answered.

// substrateApproval is one standing approval as the launcher shows it.
type substrateApproval struct {
	Atespace string `json:"atespace"`
	Actor    string `json:"actor"`
	Host     string `json:"host"`
	// Scope is "host" for the whole host, else the url_rules rule and
	// methods the approval covers.
	Scope string `json:"scope"`
	// ApprovedBy is "you", "owner" or "administrator"; empty, with
	// ApprovedAt, when the ask store no longer has the answer.
	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitzero"`
	AskID      string    `json:"ask_id,omitempty"`
	// Owner is the agent's person, in an administrator's all=1 view.
	Owner string `json:"owner,omitempty"`
}

// substrateApprovalScope is the scope of an approval of an ask raised by
// rule.
func substrateApprovalScope(rule string) string {
	if asks.HostWide(rule) {
		return "host"
	}
	return rule
}

func (a *APIServer) substrateListApprovals(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := substrateCallerFrom(r.Context())
		me := ownerOf(c.person).ID()
		all := c.admin && r.URL.Query().Get("all") == "1"
		if me == "" && !all {
			writeSubstrateJSON(w, http.StatusOK, map[string]any{"approvals": []substrateApproval{}})
			return
		}
		f := registry.Filter{OwnerID: me}
		if all {
			f.OwnerID = ""
		}
		regs, err := st.cfg.Registrations.List(r.Context(), f)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "registrations_unavailable")
			return
		}
		var answered []asks.Ask
		if st.cfg.Asks != nil {
			if answered, err = st.cfg.Asks.List(r.Context(), asks.ListRequest{OwnerID: f.OwnerID, All: all}); err != nil {
				writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
				return
			}
		}
		out := substrateStandingApprovals(regs, answered, me, all)
		if all {
			a.substrateAuditAdminRead(st, r, "approvals", len(out), "")
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"approvals": out})
	}
}

// substrateStandingApprovals joins the live registrations' approved hosts
// with the always-approved asks of the same agents: one row per agent,
// host and scope, with the newest answer's person and time. An always
// approval the person gave on an earlier agent of the same profile is
// listed on each of their live agents of that profile, since the callout
// answers those with it too (GAP-0387), and a revoke there takes it back.
func substrateStandingApprovals(regs []registry.Registration, answered []asks.Ask, me string, all bool) []substrateApproval {
	type key struct{ uid, host, scope string }
	type ownerProfile struct{ owner, profile string }
	live := map[string]registry.Registration{}
	byProfile := map[ownerProfile][]registry.Registration{}
	for _, reg := range regs {
		if !reg.Deleted {
			live[reg.UID] = reg
			if id := reg.Person.ID(); id != "" && !reg.Attributed && reg.Profile != "" {
				k := ownerProfile{id, reg.Profile}
				byProfile[k] = append(byProfile[k], reg)
			}
		}
	}
	newest := map[key]asks.Ask{}
	note := func(uid string, x asks.Ask) {
		k := key{uid, x.Host, substrateApprovalScope(x.Rule)}
		if cur, ok := newest[k]; !ok || x.DecidedAt.After(cur.DecidedAt) {
			newest[k] = x
		}
	}
	for _, x := range answered {
		if x.State != asks.StateApproved || !x.Always || x.Host == "" {
			continue
		}
		if reg, ok := live[x.UID]; ok && reg.Atespace == x.Atespace {
			note(x.UID, x)
		}
		if x.Kind == "tool" || x.Profile == "" {
			continue
		}
		for _, reg := range byProfile[ownerProfile{x.OwnerID, x.Profile}] {
			if reg.UID != x.UID {
				note(reg.UID, x)
			}
		}
	}
	row := func(reg registry.Registration, host, scope string) substrateApproval {
		v := substrateApproval{Atespace: reg.Atespace, Actor: reg.Name, Host: host, Scope: scope}
		if all {
			v.Owner = reg.Person.Principal
		}
		if x, ok := newest[key{reg.UID, host, scope}]; ok {
			v.ApprovedAt, v.AskID = x.DecidedAt, x.ID
			switch x.DecidedBy {
			case me:
				v.ApprovedBy = "you"
			case reg.Person.ID():
				v.ApprovedBy = "owner"
			default:
				v.ApprovedBy = "administrator"
			}
			delete(newest, key{reg.UID, host, scope})
		}
		return v
	}
	out := []substrateApproval{}
	for _, reg := range live {
		for _, h := range reg.Approved {
			out = append(out, row(reg, h, "host"))
		}
	}
	// What is left are url_rules approvals (the registration holds hosts
	// only), which the callout honours all the same.
	for k := range newest {
		out = append(out, row(live[k.uid], k.host, k.scope))
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		switch {
		case x.Atespace != y.Atespace:
			return x.Atespace < y.Atespace
		case x.Actor != y.Actor:
			return x.Actor < y.Actor
		case x.Host != y.Host:
			return x.Host < y.Host
		}
		return x.Scope < y.Scope
	})
	return out
}

// substrateRevokeApproval takes back every standing approval of one host
// for one agent: the host leaves the registration at once (the callout
// answers no request on it from now) and the network policy on the
// controller's next pass. The agent's person or an administrator may; an
// administrator's revoke of another person's agent is audited.
func (a *APIServer) substrateRevokeApproval(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.Asks == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "asks_unavailable")
			return
		}
		host := strings.ToLower(strings.TrimSpace(r.PathValue("host")))
		if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\") {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_host")
			return
		}
		reg, status, reason := a.substrateFind(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		a.substrateAuditAdminTarget(st, r, reg, "revoke", "MEDIUM")
		got, err := st.cfg.Asks.Revoke(r.Context(), asks.RevokeRequest{
			Atespace: reg.Atespace, Actor: reg.Name, UID: reg.UID, OwnerID: reg.Person.ID(), Host: host, Profile: reg.Profile,
			CallerID: ownerOf(c.person).ID(), Admin: c.admin,
		})
		switch {
		case asks.IsNotFound(err):
			writeSubstrateJSONError(w, http.StatusNotFound, "approval_not_found")
			return
		case err != nil:
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
			return
		}
		if inv, ok := st.cfg.Registrations.(interface{ Invalidate(string, string) }); ok {
			inv.Invalidate(reg.Atespace, reg.UID)
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{
			"atespace": reg.Atespace, "actor": reg.Name, "host": host, "state": asks.StateRevoked,
			"asks": len(got.Asks), "registration": got.Registration,
		})
	}
}
