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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// Asks, decisions and policy explain on the admin listener. The stores
// are on the leader (internal/substrate/asks); the gateway passes the
// caller's owner key and the store filters by it, so a person sees and
// answers only their own asks. An administrator answers as themselves
// (decided_by is their key) and sees everyone's with all=1.
//
//	GET  /api/v1/substrate/asks[?all=1]                 -> {"asks":[...]} pending
//	POST /api/v1/substrate/asks/{id} {decision, always?, reason?}
//	GET  /api/v1/substrate/decisions[?actor=a/n][&limit=][&all=1]
//	GET  /api/v1/substrate/policy/explain[?actor=a/n][&host=][&method=][&tool=]
//	POST /api/v1/substrate/callout/ask   (callout token) {actor, host|tool, summary, reason, severity, ask_id?}
//	     ask_id reads that ask again (the callout's hold); a host already
//	     approved for the actor answers approved.

// SubstrateAskStore is the leader's ask and decision store (asks.Client).
type SubstrateAskStore interface {
	OpenAsk(ctx context.Context, a asks.Ask) (asks.Ask, error)
	Resolve(ctx context.Context, in asks.ResolveRequest) (asks.Ask, error)
	List(ctx context.Context, in asks.ListRequest) ([]asks.Ask, error)
	Record(ctx context.Context, d asks.Decision) (struct{}, error)
	Decisions(ctx context.Context, in asks.ListRequest) ([]asks.Decision, error)
}

// SubstratePolicyReader reads an actor's egress policy (ateapi.Client).
type SubstratePolicyReader interface {
	GetActorEgressPolicy(ctx context.Context, actor *ateapi.ObjectRef) (*ateapi.EgressPolicy, error)
}

const substrateCalloutAskPath = "/api/v1/substrate/callout/ask"

func askView(a asks.Ask) map[string]any {
	return map[string]any{
		"id": a.ID, "atespace": a.Atespace, "actor": a.Actor, "kind": a.Kind, "host": a.Host, "tool": a.Tool,
		"summary": a.Summary, "reason": a.Reason, "severity": a.Severity, "created": a.Created, "expires": a.Expires,
		"state": a.State, "unattended": a.Unattended, "note": a.Note, "rule": a.Rule,
	}
}

func (a *APIServer) substrateListAsks(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.Asks == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "asks_unavailable")
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		in := asks.ListRequest{OwnerID: ownerOf(c.person).ID(), PendingOnly: r.URL.Query().Get("state") != "all"}
		if c.admin && r.URL.Query().Get("all") == "1" {
			in.OwnerID, in.All = "", true
		}
		list, err := st.cfg.Asks.List(r.Context(), in)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
			return
		}
		out := make([]map[string]any, 0, len(list))
		for _, x := range list {
			out = append(out, askView(x))
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"asks": out})
	}
}

func (a *APIServer) substrateDecideAsk(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.Asks == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "asks_unavailable")
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		var in struct {
			Decision string `json:"decision"`
			Always   bool   `json:"always,omitempty"`
			Reason   string `json:"reason,omitempty"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || (in.Decision != "approve" && in.Decision != "deny") {
			writeSubstrateJSONError(w, http.StatusBadRequest, "decision_is_approve_or_deny")
			return
		}
		got, err := st.cfg.Asks.Resolve(r.Context(), asks.ResolveRequest{
			ID: r.PathValue("id"), Decision: in.Decision, Always: in.Always, Note: in.Reason,
			CallerID: ownerOf(c.person).ID(), Admin: c.admin,
		})
		switch {
		case asks.IsNotFound(err):
			writeSubstrateJSONError(w, http.StatusNotFound, "ask_not_found")
			return
		case asks.IsDecided(err):
			writeSubstrateJSONError(w, http.StatusConflict, "ask_already_answered")
			return
		case err != nil:
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
			return
		}
		if got.OwnerID != ownerOf(c.person).ID() {
			// An administrator answering someone else's ask is recorded as
			// themselves (decided_by), and logged here.
			fmt.Fprintf(os.Stderr, "[substrate] administrator answered another person's ask %s (%s)\n", got.ID, got.State)
		}
		writeSubstrateJSON(w, http.StatusOK, askView(got))
	}
}

func (a *APIServer) substrateDecisions(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.Asks == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "decisions_unavailable")
			return
		}
		c, _ := substrateCallerFrom(r.Context())
		q := r.URL.Query()
		in := asks.ListRequest{OwnerID: ownerOf(c.person).ID()}
		if c.admin && q.Get("all") == "1" {
			in.OwnerID, in.All = "", true
		}
		if ref := q.Get("actor"); ref != "" {
			space, name, ok := strings.Cut(ref, "/")
			if !ok || space == "" || name == "" {
				writeSubstrateJSONError(w, http.StatusBadRequest, "actor_is_atespace_slash_name")
				return
			}
			in.Atespace, in.Actor = space, name
		}
		if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
			in.Limit = n
		}
		list, err := st.cfg.Asks.Decisions(r.Context(), in)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "decisions_unavailable")
			return
		}
		out := make([]map[string]any, 0, len(list))
		for _, d := range list {
			m := map[string]any{"at": d.At, "atespace": d.Atespace, "actor": d.Actor, "source": d.Source,
				"verdict": d.Verdict, "reason": d.Reason, "severity": d.Severity, "tool": d.Tool, "event": d.Event,
				"connector": d.Connector}
			if d.DecidedBy != "" && d.DecidedBy != ownerOf(c.person).ID() && !c.admin {
				m["decided_by"] = "administrator"
			}
			out = append(out, m)
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"decisions": out})
	}
}

// substratePolicyExplain answers what applies to one of the caller's
// actors (the policy in force, read from the control API, and the
// registration), or with no actor the caller's default profile. host
// and tool ask what the rules would do, without running anything.
func (a *APIServer) substratePolicyExplain(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := substrateCallerFrom(r.Context())
		q := r.URL.Query()
		ref := q.Get("actor")
		if ref == "" {
			profile, space, err := st.cfg.substrateProfiles()(c.person, "", "", false)
			out := map[string]any{"profile": profile, "launcher_atespace": space}
			if err != nil {
				out = map[string]any{"profile": "", "reason": "no profile with launcher atespaces is assigned to you"}
			}
			writeSubstrateJSON(w, http.StatusOK, out)
			return
		}
		space, name, ok := strings.Cut(ref, "/")
		if !ok {
			writeSubstrateJSONError(w, http.StatusBadRequest, "actor_is_atespace_slash_name")
			return
		}
		reg, status, reason := a.substrateFind(st, r, space, name)
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		out := map[string]any{
			"actor": reg.Atespace + "/" + reg.Name, "uid": reg.UID, "profile": reg.Profile, "connector": reg.Connector,
			"template": reg.Template, "mode": substrateMode(reg), "fail_mode": substrateFailMode(st.cfg, reg),
			"approved_hosts": reg.Approved, "secrets": reg.Secrets,
		}
		var hosts []string
		if st.cfg.Policies != nil {
			pol, err := st.cfg.Policies.GetActorEgressPolicy(r.Context(), ateapi.Ref(reg.Atespace, reg.Name))
			switch {
			case ateapi.IsNotFound(err):
				out["egress"] = map[string]any{"policy": "none", "note": "no policy: the actor has no network"}
			case err != nil:
				out["egress"] = map[string]any{"policy": "unknown", "note": "the control API did not answer"}
			default:
				rules, all := substratePolicyRules(pol)
				hosts = all
				out["egress"] = map[string]any{"policy": "in force", "version": pol.GetMetadata().GetVersion(), "rules": rules}
			}
		}
		if host := strings.ToLower(strings.TrimSpace(q.Get("host"))); host != "" {
			allowed := slices.ContainsFunc(hosts, func(p string) bool { return substrateHostMatches(p, host) })
			out["host"] = map[string]any{"host": host, "allowed": allowed}
		}
		if tool := strings.TrimSpace(q.Get("tool")); tool != "" {
			ctx := a.substrateEvaluationContext(r.Context(), reg, "hook")
			tv := a.inspectToolPolicyCtx(ctx, &ToolInspectRequest{Tool: tool, Args: json.RawMessage(`{}`), Connector: reg.Connector})
			res := map[string]any{"tool": tool, "action": "allow"}
			if tv != nil {
				res["action"], res["reason"], res["severity"] = tv.Action, tv.Reason, tv.Severity
			}
			out["tool"] = res
		}
		writeSubstrateJSON(w, http.StatusOK, out)
	}
}

// substratePolicyRules lists a policy's rules as protocol, hosts and
// ports, and every host pattern.
func substratePolicyRules(p *ateapi.EgressPolicy) ([]map[string]any, []string) {
	var rules []map[string]any
	var all []string
	ports := func(pp *ateapi.Ports) any {
		if pp == nil || pp.GetAll() != nil {
			return "all"
		}
		return pp.GetNumbers()
	}
	for _, r := range p.GetRules() {
		switch {
		case r.GetHttps() != nil:
			rules = append(rules, map[string]any{"protocol": "https", "hosts": r.GetHttps().GetHostnames(), "ports": ports(r.GetHttps().GetPorts()),
				"credentials": len(r.GetHttps().GetEffects().GetReplaceHeaders()) > 0})
			all = append(all, r.GetHttps().GetHostnames()...)
		case r.GetHttp() != nil:
			rules = append(rules, map[string]any{"protocol": "http", "hosts": r.GetHttp().GetHostnames(), "ports": ports(r.GetHttp().GetPorts())})
			all = append(all, r.GetHttp().GetHostnames()...)
		case r.GetTlsPassthrough() != nil:
			rules = append(rules, map[string]any{"protocol": "tls_passthrough", "hosts": r.GetTlsPassthrough().GetHostnames(),
				"ports": ports(r.GetTlsPassthrough().GetPorts())})
			all = append(all, r.GetTlsPassthrough().GetHostnames()...)
		}
	}
	return rules, all
}

// substrateHostMatches matches a rule host pattern ("*.example.com"
// matches one label or more below example.com).
func substrateHostMatches(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}

// substrateCalloutAsk lets the callout raise an ask for an actor (the
// leader RPC is the gateway's; the callout calls only the chain check
// there, GAP-0094).
func (a *APIServer) substrateCalloutAsk(st *substrateState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeSubstrateJSONError(w, http.StatusMethodNotAllowed, "method")
			return
		}
		if !substrateCalloutAuthorized(st, r) {
			writeSubstrateJSONError(w, http.StatusUnauthorized, "callout_unauthorized")
			return
		}
		if st.cfg.Asks == nil || st.cfg.Lookup == nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
			return
		}
		raw, ok := readAllLimited(r.Body, 64<<10)
		if !ok {
			writeSubstrateJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		var in struct {
			Actor struct {
				Atespace string `json:"atespace"`
				Name     string `json:"name"`
				UID      string `json:"uid,omitempty"`
			} `json:"actor"`
			Host     string `json:"host,omitempty"`
			Tool     string `json:"tool,omitempty"`
			Summary  string `json:"summary,omitempty"`
			Reason   string `json:"reason,omitempty"`
			Severity string `json:"severity,omitempty"`
			Rule     string `json:"rule,omitempty"`
			AskID    string `json:"ask_id,omitempty"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || in.Actor.Atespace == "" || in.Actor.Name == "" || (in.Host == "" && in.Tool == "") || len(in.Rule) > 256 {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		live, err := st.cfg.Lookup.LookupActor(r.Context(), in.Actor.Atespace, in.Actor.Name)
		if err != nil || (in.Actor.UID != "" && in.Actor.UID != live.UID) {
			writeSubstrateJSONError(w, http.StatusNotFound, "actor_not_found")
			return
		}
		reg, found, err := st.cfg.Registrations.Get(r.Context(), in.Actor.Atespace, live.UID)
		if err != nil || !found || reg.Deleted || reg.Person.Subject == "" {
			writeSubstrateJSONError(w, http.StatusNotFound, "actor_not_found")
			return
		}
		ask := asks.Ask{
			Atespace: reg.Atespace, Actor: reg.Name, UID: reg.UID, OwnerID: reg.Person.ID(),
			Host: strings.ToLower(strings.TrimSpace(in.Host)), Tool: in.Tool, Summary: in.Summary, Reason: in.Reason, Severity: in.Severity,
			Rule: strings.TrimSpace(in.Rule),
		}
		hostWide := asks.HostWide(ask.Rule)
		// The leader's store is the record of this actor's asks; the
		// registration copy here is cached (registry.Remote) and can miss an
		// approval for seconds, so an approved host is looked up in the store.
		list, err := st.cfg.Asks.List(r.Context(), asks.ListRequest{All: true, Atespace: reg.Atespace, Actor: reg.Name})
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
			return
		}
		if in.AskID != "" {
			// The callout holds the request and reads its ask again; only
			// this actor incarnation's ask is answered.
			for _, a := range list {
				if a.ID == in.AskID && a.UID == reg.UID {
					writeSubstrateJSON(w, http.StatusOK, askView(a))
					return
				}
			}
			writeSubstrateJSONError(w, http.StatusNotFound, "ask_not_found")
			return
		}
		if ask.Host != "" && ((hostWide && slices.Contains(reg.Approved, ask.Host)) || slices.ContainsFunc(list, func(a asks.Ask) bool {
			// A host-wide approval answers a host-wide ask; a url_rules
			// ask is answered only by an approval of the same rule that
			// named every method this ask names (GAP-0177).
			return a.UID == reg.UID && a.Host == ask.Host && a.State == asks.StateApproved &&
				(urlRuleApprovalCovers(a.Rule, ask.Rule) || (hostWide && asks.HostWide(a.Rule)))
		})) {
			// Approved earlier for this actor (the controller adds a
			// host-wide one to the policy on its next pass): not asked twice.
			writeSubstrateJSON(w, http.StatusOK, map[string]any{"state": asks.StateApproved, "reason": "approved earlier for this actor"})
			return
		}
		if reg.Unattended {
			// D12: an unattended run's ask is a deny unless the profile's
			// unattended_asks is queue; then it waits for a person for
			// ask_timeout, and the timeout denies it.
			var rule SubstrateUnattendedAsk
			if st.cfg.UnattendedAsk != nil {
				rule = st.cfg.UnattendedAsk(reg.Profile)
			}
			if !rule.Queue {
				writeSubstrateJSON(w, http.StatusOK, map[string]any{"state": asks.StateDenied, "reason": "unattended runs do not ask"})
				return
			}
			ask.Unattended, ask.TimeoutSeconds = true, int64(rule.Timeout/time.Second)
		}
		got, err := st.cfg.Asks.OpenAsk(r.Context(), ask)
		if err != nil {
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "asks_unavailable")
			return
		}
		if got.Unattended {
			a.dispatchQueuedAskWebhook(got)
		}
		writeSubstrateJSON(w, http.StatusOK, askView(got))
	})
}

// dispatchQueuedAskWebhook tells the configured webhooks that an unattended
// actor's ask is waiting for a person (D12 queue): nobody watches the run,
// so the notification is how the owner learns of it. It names the actor,
// the host or tool and the expiry, never a request body.
func (a *APIServer) dispatchQueuedAskWebhook(got asks.Ask) {
	if a == nil || a.webhookSource == nil {
		return
	}
	webhooks := a.webhookSource()
	if webhooks == nil {
		return
	}
	target := got.Host
	if target == "" {
		target = got.Tool
	}
	webhooks.Dispatch(audit.Event{
		Timestamp: time.Now().UTC(), Action: string(audit.ActionApprovalRequest), Target: target, Actor: "defenseclaw-substrate",
		Details: fmt.Sprintf("ask=%s actor=%s/%s unattended=true expires=%s", got.ID, got.Atespace, got.Actor,
			got.Expires.UTC().Format(time.RFC3339)),
		Severity: orDefaultString(got.Severity, "MEDIUM"),
	})
}

func orDefaultString(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// substrateRecordDecision keeps a hook verdict that was not a plain
// allow, without holding the answer (best effort, bounded).
func (st *substrateState) substrateRecordDecision(ctx context.Context, reg registry.Registration, event string, answer []byte) {
	if st.cfg.Asks == nil {
		return
	}
	var v struct {
		Action   string `json:"action"`
		Reason   string `json:"reason"`
		Severity string `json:"severity"`
	}
	if json.Unmarshal(answer, &v) != nil {
		return
	}
	switch strings.ToLower(v.Action) {
	case "", "allow", "continue", "approve":
		return
	}
	d := asks.Decision{At: time.Now(), Atespace: reg.Atespace, Actor: reg.Name, UID: reg.UID, OwnerID: reg.Person.ID(),
		Source: "hook", Connector: reg.Connector, Event: event, Verdict: strings.ToLower(v.Action), Reason: v.Reason, Severity: v.Severity}
	go func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = st.cfg.Asks.Record(cctx, d)
	}()
}

// urlRuleApprovalCovers reports whether an approval of the url_rules key
// approved answers the ask key asked (GAP-0177, STEER 03:40Z: an approval
// binds to what the person saw). The callout's key is
// "url_rules:<rule> <METHODS>", METHODS sorted and comma-separated: every
// method the request can stand for (its own, each override header and
// _method value, and a form body's _method, GAP-0046) that the rule
// covers. An approval answers the same rule asking for some of the
// methods it named, never for one it did not, so a person who approved a
// POST never runs a DELETE. Any other key is matched exactly.
func urlRuleApprovalCovers(approved, asked string) bool {
	if approved == asked {
		return true
	}
	if asks.HostWide(approved) || asks.HostWide(asked) {
		return false
	}
	ar, am, ok1 := cutLast(approved, " ")
	qr, qm, ok2 := cutLast(asked, " ")
	if !ok1 || !ok2 || ar != qr || am == "" || qm == "" {
		return false
	}
	have := strings.Split(am, ",")
	for _, m := range strings.Split(qm, ",") {
		if !slices.Contains(have, m) {
			return false
		}
	}
	return true
}

func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
