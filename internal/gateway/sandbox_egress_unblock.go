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
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A sandbox's egress proxy and DefenseClaw's destination rules are two
// controls over one destination: the proxy's blocklist feed refuses
// webhook.site, and the rule C2-WEBHOOK-SITE flags (or, under a stricter
// policy, blocks) a tool call that names it. Once the user unblocks the host
// (`sandbox unblock HOST --sandbox NAME`, or for every sandbox with
// `--always`) the proxy lets the sandbox reach it, and a hook verdict that
// still tells the agent the destination is flagged or blocked is wrong
// (#954). So a sandbox verdict decided only by destination rules, for a
// call whose every destination of those rules is unblocked for the sandbox,
// becomes a plain allow: the agent gets no notice and the activity feed no
// finding. The audit row's source reason names the rules that were not
// applied, its rule_ids stay, and extra.sandbox_egress_unblocked names the
// unblocks that lifted them.
//
// Only an unblock lifts a rule: a destination the proxy allows for another
// reason (the open web with the feed off, an allow entry) keeps its notice,
// since nobody decided that destination is wanted. An unblock names an
// exact host, so a rule is lifted only for a call whose destinations are
// exactly unblocked hosts: an unblock of webhook.site lifts nothing for
// x.webhook.site, which the proxy still refuses too.

// sandboxDestinationRules maps DefenseClaw's built-in destination rules to
// the domains they name: rules whose whole finding is that a call names
// that service. Rules about what a call does (uploads, secrets, DNS
// tunnels) and the cloud metadata rules (never unblockable) are not here.
var sandboxDestinationRules = map[string][]string{
	"C2-WEBHOOK-SITE": {"webhook.site"},
	"C2-NGROK":        {"ngrok.io", "ngrok-free.app"},
	"C2-PIPEDREAM":    {"pipedream.net"},
	"C2-REQUESTBIN":   {"requestbin.com"},
	"C2-HOOKBIN":      {"hookbin.com"},
	"C2-BURP":         {"burpcollaborator.net"},
	"C2-INTERACTSH":   {"interact.sh"},
	"C2-OAST":         {"oast.fun"},
	"C2-CANARY":       {"canarytokens.com"},
	"C2-PASTEBIN":     {"pastebin.com"},
}

// sandboxEgressUnblockExtra is the audit extra key naming the unblocks
// that lifted a sandbox verdict's destination rules.
const sandboxEgressUnblockExtra = "sandbox_egress_unblocked"

// liftUnblockedDestinations returns resp as an allow when every rule that
// decided it is a destination rule (sandboxDestinationRules) and every
// destination those rules name in the hook request is unblocked for the
// request's sandbox (sandboxEgressUnblockSource). ok is false, and
// resp unchanged, otherwise. A destination the request names in a form the
// scan cannot read as one host (a shell expansion next to it, a longer name
// that only contains the domain) keeps the verdict, and so does a verdict a
// scan lane took part in (Cisco AI Defense, the LLM judge), which may block
// without naming a rule.
func (a *APIServer) liftUnblockedDestinations(ctx context.Context, req agentHookRequest, resp agentHookResponse) (agentHookResponse, bool) {
	action := strings.ToLower(strings.TrimSpace(resp.Action))
	raw := strings.ToLower(strings.TrimSpace(resp.RawAction))
	if (action == "" || action == "allow") && (raw == "" || raw == "allow") &&
		severityRank[strings.ToUpper(strings.TrimSpace(resp.Severity))] < severityRank["LOW"] {
		// A plain allow: nothing to lift.
		return resp, false
	}
	if resp.laneVerdict {
		// A scan lane (Cisco AI Defense, the LLM judge) took part: it may
		// block or raise the severity without naming a rule, so the
		// destination rules alone did not decide the verdict.
		return resp, false
	}
	binding, ok := sandboxauth.FromContext(ctx)
	if !ok {
		return resp, false
	}
	rules, ok := sandboxDestinationRuleIDs(resp.RuleIDs, resp.Findings)
	if !ok {
		return resp, false
	}
	unblocked := a.sandboxEgressUnblockSource(ctx)
	if unblocked == nil {
		return resp, false
	}
	var domains []string
	for _, id := range rules {
		domains = append(domains, sandboxDestinationRules[id]...)
	}
	hosts, ok := sandboxRequestDestinations(req, domains)
	if !ok || len(hosts) == 0 {
		return resp, false
	}
	lifted := make([]string, 0, len(hosts))
	for _, host := range hosts {
		scope, ok := unblocked(binding, host)
		if !ok {
			return resp, false
		}
		lifted = append(lifted, host+":"+scope)
	}
	noteSandboxEgressUnblock(ctx, lifted)
	resp.SourceReason = "allowed: " + strings.Join(rules, ", ") + " not applied to " + strings.Join(hosts, ", ") +
		", which the user unblocked for this sandbox's egress proxy (" + strings.Join(lifted, ", ") + ")"
	resp.Action, resp.RawAction = "allow", "allow"
	resp.Severity, resp.WouldBlock = "NONE", false
	resp.Findings, resp.Reason, resp.AdditionalContext = nil, "", ""
	return resp, true
}

// sandboxEgressUnblockSource is the unblock lookup of a sandbox request:
// for a relayed call (a managed host) the managed gateway's own record of
// the caller's unblocks (sandboxRelayUnblock), else the local sandbox
// manager's (SandboxIngressConfig.EgressUnblock). Nil lifts nothing.
func (a *APIServer) sandboxEgressUnblockSource(ctx context.Context) func(sandboxauth.Binding, string) (string, bool) {
	if state := sandboxRelayStateFrom(ctx); state != nil {
		return a.sandboxRelayUnblock(ctx, state.reg)
	}
	st := a.sandboxIngressState()
	if st == nil || st.egressUnblock == nil {
		return nil
	}
	return st.egressUnblock
}

// sandboxRelayUnblock is the unblock lookup of a call relayed for reg. The
// managed gateway keeps every unblock a managed user makes, for one
// sandbox or for every sandbox (handleSandboxDecide stores each one after
// checking it against the floor), so the lift is decided here, from that
// record alone: an unblock of the host for reg's own registration in the
// session its sandbox runs now (sandboxreg.SessionStart), or for every
// sandbox of the caller, that reg's floor still allows now (allow_unblock,
// the organization's block and allowed lists). The registration outlives
// a stop and start, and its daemon then ends its own session unblocks
// (es:GAP-0676), so a session unblock made before that start lifts
// nothing (GAP-0009). A user block of the host wins, and so does every
// block of the registration's own sandbox policy that an unblock does not
// lift in the egress proxy: its pack's and its repository policy's
// egress.block, the organization's lists, the deny network mode
// (sandboxPolicyUnblockAdmits, GAP-0432). Nothing the daemon
// or the sandbox sends decides it, so no process of the user can make the
// gateway lift a destination rule the user could not lift with
// `defenseclaw sandbox unblock` (#1192).
// Nil when the record or the floor can't be read: nothing is lifted.
func (a *APIServer) sandboxRelayUnblock(ctx context.Context, reg sandboxreg.Registration) func(sandboxauth.Binding, string) (string, bool) {
	auth, err := a.sandboxAuth()
	if err != nil || auth.decisions == nil {
		return nil
	}
	floor, _, err := sandboxRegistrationFloor(a.liveBaseConfig(ctx), reg)
	if err != nil {
		return nil
	}
	saved, err := auth.decisions.List(reg.UID, "")
	if err != nil || len(saved) == 0 {
		return nil
	}
	sessionStart := sandboxreg.SessionStart(reg)
	// The registration's sandbox policy, resolved again from its run record
	// at the first stored unblock that passes the floor; nil, or an error,
	// lifts nothing.
	var eff *packs.Effective
	resolved := false
	policyAdmits := func(host string) bool {
		if !resolved {
			resolved = true
			peer, ok := managedHookPeerFromContext(ctx)
			if !ok || peer.UID != reg.UID {
				peer = managedHookPeer{UID: reg.UID}
			}
			if e, _, err := sandboxRegistrationEffective(a.liveBaseConfig(ctx), auth, peer, reg, floor); err == nil {
				eff = e
			}
		}
		return eff != nil && sandboxPolicyUnblockAdmits(eff, host)
	}
	return func(b sandboxauth.Binding, host string) (string, bool) {
		if b.RegistrationID != reg.ID {
			return "", false
		}
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		scope := ""
		for _, d := range saved {
			if d.Registration != reg.ID && d.Scope != sandboxrelay.DecisionScopeAlways {
				continue
			}
			if !strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(d.Host), "."), host) {
				continue
			}
			switch d.Kind {
			case sandboxrelay.DecisionEgressBlock:
				return "", false
			case sandboxrelay.DecisionUnblock:
				if d.Scope == sandboxrelay.DecisionScopeSession && d.CreatedAt.Before(sessionStart) {
					// An earlier session's: it ended when the sandbox stopped.
					continue
				}
				check := sandboxrelay.DecisionRequest{V: sandboxrelay.WireVersion, Registration: reg.ID, Kind: d.Kind, Host: d.Host, Scope: d.Scope}
				if sandboxCheckDecision(floor, check) != nil || !policyAdmits(host) {
					continue
				}
				if d.Scope == sandboxrelay.DecisionScopeSession {
					scope = string(audit.SandboxApprovalScopeSandbox)
				} else if scope == "" {
					scope = string(audit.SandboxApprovalScopeAlways)
				}
			}
		}
		return scope, scope != ""
	}
}

// sandboxPolicyUnblockAdmits reports whether an unblock of host lets the
// egress proxy of a sandbox under eff reach it, as the daemon's own lookup
// (manager.EgressUnblock) decides it: the proxy's decider for eff with an
// unblock of host allows it by that unblock. A block of the pack or the
// repository policy, the organization's lists and the deny network mode
// come first, so the proxy still refuses the host, and a hook verdict
// lifted for it told the agent a destination was allowed that is not.
func sandboxPolicyUnblockAdmits(eff *packs.Effective, host string) bool {
	d, err := eff.EgressDecider(sandboxHostUnblock(host))
	if err != nil {
		return false
	}
	dec := d.DecideHost(egress.Principal{BindingID: "sandbox-unblock-check"}, host)
	return dec.Allowed && dec.Source == egress.SourceUnblock
}

// sandboxHostUnblock is an unblock of one exact host, for
// sandboxPolicyUnblockAdmits.
type sandboxHostUnblock string

func (h sandboxHostUnblock) Unblocked(_ egress.Principal, host string) (egress.Unblock, bool) {
	if !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(string(h), ".")) {
		return egress.Unblock{}, false
	}
	return egress.Unblock{Pattern: string(h)}, true
}

// sandboxDestinationRuleIDs returns the canonical IDs of a verdict's
// deciding rules, from its rule IDs and finding labels ("RULE-ID:Title"),
// when there is at least one and every one is a destination rule.
func sandboxDestinationRuleIDs(ruleIDs, findings []string) ([]string, bool) {
	candidates := slices.Clone(ruleIDs)
	for _, label := range findings {
		id, _, _ := strings.Cut(strings.TrimSpace(label), ":")
		candidates = append(candidates, id)
	}
	var out []string
	for _, id := range candidates {
		id = strings.ToUpper(strings.TrimSpace(id))
		if _, ok := sandboxDestinationRules[id]; !ok {
			return nil, false
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out, len(out) > 0
}

// sandboxRequestDestinations returns the hosts under domains that a hook
// request names anywhere in its payload, tool input and content, sorted and
// unique. ok is false when an occurrence of a domain is not a whole host
// name the scan can read (sandboxHostAt).
func sandboxRequestDestinations(req agentHookRequest, domains []string) (hosts []string, ok bool) {
	ok = true
	visit := func(s string) {
		if !ok {
			return
		}
		found, fine := sandboxDestinationsIn(s, domains)
		if !fine {
			ok = false
			return
		}
		for _, h := range found {
			if !slices.Contains(hosts, h) {
				hosts = append(hosts, h)
			}
		}
	}
	walkSandboxHookStrings(req.Payload, visit)
	if len(req.ToolArgs) > 0 {
		var args any
		if json.Unmarshal(req.ToolArgs, &args) == nil {
			walkSandboxHookStrings(args, visit)
		} else {
			visit(string(req.ToolArgs))
		}
	}
	visit(req.Content)
	visit(req.ToolName)
	slices.Sort(hosts)
	return hosts, ok
}

// walkSandboxHookStrings calls visit with every string in a decoded JSON
// value, map keys included.
func walkSandboxHookStrings(v any, visit func(string)) {
	switch x := v.(type) {
	case string:
		visit(x)
	case map[string]interface{}:
		for k, item := range x {
			visit(k)
			walkSandboxHookStrings(item, visit)
		}
	case []interface{}:
		for _, item := range x {
			walkSandboxHookStrings(item, visit)
		}
	}
}

// sandboxDestinationsIn returns the host names under domains (the domain
// or a subdomain) that s names. Every occurrence of a domain is read, as
// the destination rules match it anywhere in the text; ok is false when one
// cannot be read as a host name (sandboxHostAt). An occurrence inside
// another name (notwebhook.site, webhook.site.log) names no destination of
// the domain and is skipped, unless the shell joined that name from parts
// (webhook.site'.log'), where a rule may have matched one part alone.
func sandboxDestinationsIn(s string, domains []string) (hosts []string, ok bool) {
	lower := strings.ToLower(s)
	for _, domain := range domains {
		for from := 0; ; {
			i := strings.Index(lower[from:], domain)
			if i < 0 {
				break
			}
			i += from
			from = i + len(domain)
			host, joined, fine := sandboxHostAt(lower, i, i+len(domain))
			if !fine {
				return nil, false
			}
			if host != domain && !strings.HasSuffix(host, "."+domain) {
				if joined {
					return nil, false
				}
				continue
			}
			if !slices.Contains(hosts, host) {
				hosts = append(hosts, host)
			}
		}
	}
	return hosts, true
}

// sandboxHostByte reports a byte of a host name.
func sandboxHostByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_'
}

// sandboxHostJoiner reports a byte the shell drops between two parts of one
// word ("web"hook.site, webhook\.site).
func sandboxHostJoiner(c byte) bool {
	return c == '\'' || c == '"' || c == '\\'
}

// sandboxHostDelimiter reports a byte that may border a host name in a
// command, URL or JSON value without changing it: space, the URL and shell
// separators. Anything else next to a host name ($, `, {, *, %, ...) may
// expand or rewrite it, so the name cannot be read.
func sandboxHostDelimiter(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || strings.IndexByte("/@:=,;<>|&()[]?#!", c) >= 0
}

// sandboxHostAt reads the host name around lower[start:end], an occurrence
// of a domain: the run of host bytes and shell joiners it sits in, joiners
// dropped (joined reports one), without a trailing dot. ok is false when
// the run borders a byte that may rewrite it, or starts with "." or "-" (a
// fragment: something the scan cannot read comes before it).
func sandboxHostAt(lower string, start, end int) (host string, joined, ok bool) {
	i, j := start, end
	for i > 0 && (sandboxHostByte(lower[i-1]) || sandboxHostJoiner(lower[i-1])) {
		i--
	}
	for j < len(lower) && (sandboxHostByte(lower[j]) || sandboxHostJoiner(lower[j])) {
		j++
	}
	if i > 0 && !sandboxHostDelimiter(lower[i-1]) || j < len(lower) && !sandboxHostDelimiter(lower[j]) {
		return "", false, false
	}
	var b strings.Builder
	for k := i; k < j; k++ {
		if sandboxHostJoiner(lower[k]) {
			joined = true
		} else {
			b.WriteByte(lower[k])
		}
	}
	host = strings.TrimSuffix(b.String(), ".")
	if host == "" || host[0] == '.' || host[0] == '-' || strings.Contains(host, "..") {
		return "", joined, false
	}
	return host, joined, true
}

// noteSandboxEgressUnblock records, for the request's audit row, the
// unblocks ("host:scope") that lifted its destination rules.
func noteSandboxEgressUnblock(ctx context.Context, lifted []string) {
	coverage, ok := ctx.Value(sandboxCoverageContextKey{}).(*sandboxCoverage)
	if !ok {
		return
	}
	coverage.mu.Lock()
	coverage.unblocked = append(coverage.unblocked, lifted...)
	coverage.mu.Unlock()
}

// sandboxEgressUnblocks returns what noteSandboxEgressUnblock recorded.
func sandboxEgressUnblocks(ctx context.Context) []string {
	coverage, ok := ctx.Value(sandboxCoverageContextKey{}).(*sandboxCoverage)
	if !ok {
		return nil
	}
	coverage.mu.Lock()
	defer coverage.mu.Unlock()
	return slices.Clone(coverage.unblocked)
}
