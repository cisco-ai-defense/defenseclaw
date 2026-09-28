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

// Package triage decides what happens to OpenShell draft policy proposals.
//
// A sandboxed client that ignores HTTPS_PROXY and connects directly is
// denied by OpenShell, which then drafts a proposal to open that
// destination. Approving one adds a direct OpenShell network rule that
// bypasses the DefenseClaw egress proxy, its blocklist and its SSRF guard, so
// triage holds every proposal to what the proxy would enforce, by asking the
// sandbox's own proxy decider (packs.Effective.EgressDecider) and applying
// the proxy's dial-time address rules to what every destination name
// resolves to (egress.Decider.CheckAddrs):
//
//   - rejected: anything the effective sandbox policy refuses (the
//     administrator's blocklist and allow-only list, link-local, metadata
//     and reserved addresses, DefenseClaw's own listeners and the OpenShell
//     gateway), wildcard or malformed destinations, what the proxy refuses
//     and no unblock lifts (the block lists, the blocklist feed), public IP
//     literals in the open mode until they are unblocked (they sidestep the
//     name-based blocklist), names that resolve to this machine or do not
//     exist, ports the proxy does not carry, and requests the harness
//     binary itself makes around the proxy for something it does without
//     (Policy.HarnessFetches: Codex's startup tip download);
//   - deferred: proposals with a name whose lookup timed out or failed
//     temporarily stay pending and are decided again later;
//   - asked: doors into the user's machine or network (host.openshell.internal
//     and other host-local names, private addresses, intranet names and
//     names that resolve to private addresses), proposals OpenShell's
//     advisor flagged, and everything the pack's approvals mode does not
//     auto-approve;
//   - approved automatically: the rest, when the pack's approvals mode is
//     auto, or triage on an open network, or the proxy allows the host
//     through an unblock or an allow entry.
//
// Approvals are applied by a Batcher at hook-quiescent moments: every
// OpenShell policy reload closes the sandbox's open connections, including
// a hook request waiting on a verdict. The Batcher's Recheck judges each
// approval again, with fresh DNS answers, right before it is applied.
package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)

// Verdict is what triage does with a proposal.
type Verdict string

const (
	// Approve applies the proposal without asking.
	Approve Verdict = "approve"
	// Reject rejects it in OpenShell with the reason.
	Reject Verdict = "reject"
	// Ask queues it for the user.
	Ask Verdict = "ask"
	// Defer leaves it pending for now: a destination could not be checked
	// (its DNS lookup timed out or failed temporarily), so neither an
	// approval nor a rejection would be sound. Decide it again later.
	Defer Verdict = "defer"
)

// ErrDeferred marks an approval that could not be checked right before it
// was applied (see Defer): it is neither approved nor refused, and the
// check is worth repeating.
var ErrDeferred = errors.New("triage: the approval cannot be checked now")

// Reason is the stable machine token behind a verdict.
type Reason string

// Rejections.
const (
	ReasonNoEndpoints      Reason = "no_endpoints"
	ReasonInvalid          Reason = "invalid_destination"
	ReasonWildcard         Reason = "wildcard_destination"
	ReasonPolicy           Reason = "policy_refused"
	ReasonAdmin            Reason = "admin_violation"
	ReasonBlocklisted      Reason = "blocklisted"
	ReasonIPLiteral        Reason = "ip_literal"
	ReasonPortNotAllowed   Reason = "port_not_allowed"
	ReasonAgentProposalOff Reason = "agent_proposals_disabled"
	// ReasonResolvesToHost: the name resolves to this machine or what only
	// it reaches (link-local, metadata, reserved addresses).
	ReasonResolvesToHost Reason = "resolves_to_host"
	// ReasonUnresolved: the name does not exist or has no address, so where
	// a direct rule would lead cannot be checked.
	ReasonUnresolved Reason = "unresolved"
	// ReasonLookupFailed defers: the name's DNS lookup timed out or failed
	// temporarily.
	ReasonLookupFailed Reason = "lookup_failed"
	// ReasonRuleShape: the proposal names a reserved or non-mechanistic
	// rule, or asks for rule features triage never approves (layer-7
	// rules, access presets, credential handling).
	ReasonRuleShape Reason = "unsupported_rule"
	// ReasonMultipleHosts: the proposal's endpoints name more than one
	// destination host. Approving a proposal opens all of it, but an ask
	// shows the user one destination, so each host must be its own rule.
	ReasonMultipleHosts Reason = "multiple_hosts"
	// ReasonHarnessFetch: the sandbox's harness binary itself made the
	// denied connection, for a request it does without (Policy.HarnessFetches).
	ReasonHarnessFetch Reason = "harness_background_fetch"
)

// Flood limits the sandbox manager applies to triage decisions.
const (
	// ReasonRateLimited asks instead of approving automatically: the
	// sandbox proposed many destinations in a short time.
	ReasonRateLimited Reason = "rate_limited"
	// ReasonRuleLimit rejects: the sandbox added its limit of rules this
	// session.
	ReasonRuleLimit Reason = "rule_limit"
	// ReasonTooManyPending rejects: too many asks are waiting.
	ReasonTooManyPending Reason = "too_many_pending"
)

// Asks.
const (
	ReasonHostLocal       Reason = "host_local"
	ReasonPrivateNetwork  Reason = "private_network"
	ReasonSecurityFlagged Reason = "security_flagged"
	ReasonManual          Reason = "manual_approvals"
	ReasonNotAllowlisted  Reason = "not_allowlisted"
	ReasonNetworkDeny     Reason = "network_deny"
)

// Automatic approvals.
const (
	ReasonAllowed     Reason = "allowed"
	ReasonAutoMode    Reason = "approvals_auto"
	ReasonOpenNetwork Reason = "open_network"
)

// Approval kinds (audit.SandboxApprovalKind values).
const (
	KindNetworkRule = "network_rule"
	KindHostPort    = "host_port"
)

// Endpoint is one destination of a proposal.
type Endpoint struct {
	Host     string
	Port     int
	Protocol string
}

// Proposal is one OpenShell draft chunk.
type Proposal struct {
	Sandbox     string
	ChunkID     string
	ReviewToken string
	// RuleName is the network_policies key approving the chunk merges into.
	RuleName  string
	Endpoints []Endpoint
	// AllowedIPs are the addresses the destinations may resolve to. When
	// set they replace OpenShell's own private-address check.
	AllowedIPs []string
	// Binary is the executable whose denied connection drafted the chunk;
	// Binaries are the executables the proposed rule applies to.
	Binary        string
	Binaries      []string
	Rationale     string
	SecurityNotes string
	HitCount      int
	// Unsupported lists the rule features triage never approves (see
	// FromChunk); any entry rejects the proposal.
	Unsupported []string
	// Digest is ContentDigest of the chunk; RuleDigest leaves the advisor's
	// security notes out, so proposals of the same rule share it.
	Digest     string
	RuleDigest string
}

// FromChunk extracts a Proposal from an OpenShell draft chunk. An endpoint
// with a port list becomes one Endpoint per port.
func FromChunk(sandbox string, c openshell.PolicyChunk) Proposal {
	p := Proposal{
		Sandbox: sandbox, ChunkID: c.ID, ReviewToken: c.ReviewToken, RuleName: c.RuleName,
		Binary: c.Binary, Rationale: c.Rationale, SecurityNotes: strings.TrimSpace(c.SecurityNotes),
		HitCount: int(c.HitCount), Digest: ContentDigest(c), RuleDigest: RuleDigest(c),
	}
	if c.ProposedRule == nil {
		return p
	}
	if p.RuleName == "" {
		p.RuleName = c.ProposedRule.Name
	}
	for _, ep := range c.ProposedRule.Endpoints {
		ports := make([]int, 0, 1+len(ep.Ports))
		if ep.Port != 0 {
			ports = append(ports, int(ep.Port))
		}
		for _, port := range ep.Ports {
			if int(port) != int(ep.Port) {
				ports = append(ports, int(port))
			}
		}
		if len(ports) == 0 {
			ports = append(ports, 0)
		}
		for _, port := range ports {
			p.Endpoints = append(p.Endpoints, Endpoint{Host: ep.Host, Port: port, Protocol: ep.Protocol})
		}
		p.AllowedIPs = append(p.AllowedIPs, ep.AllowedIPs...)
		for _, feature := range endpointFeatures(ep) {
			p.Unsupported = appendUnique(p.Unsupported, feature+" on "+ep.Host)
		}
	}
	for _, b := range c.ProposedRule.Binaries {
		p.Binaries = appendUnique(p.Binaries, b.Path)
	}
	if p.Binary == "" && len(p.Binaries) > 0 {
		p.Binary = p.Binaries[0]
	}
	// Approving merges the proposal into an existing rule of the same name,
	// which then applies the rule's other settings to the new endpoints.
	if c.CurrentEffectivePolicy != nil && p.RuleName != "" {
		if existing, ok := c.CurrentEffectivePolicy.NetworkPolicies[p.RuleName]; ok {
			for _, ep := range existing.Endpoints {
				if len(endpointFeatures(ep)) > 0 {
					p.Unsupported = appendUnique(p.Unsupported, "a merge into the existing rule "+p.RuleName+", which carries credentials or layer-7 controls")
					break
				}
			}
			p.Unsupported = appendForeignHosts(p, existing)
		}
	}
	// The candidate policy shows the rule as approving would leave it.
	if c.CandidateEffectivePolicy != nil && p.RuleName != "" {
		if merged, ok := c.CandidateEffectivePolicy.NetworkPolicies[p.RuleName]; ok {
			p.Unsupported = appendForeignHosts(p, merged)
		}
	}
	return p
}

// appendForeignHosts adds to p.Unsupported a merge into rule, the rule of
// p's name, that holds a destination host other than p's own. A rule name
// is only a map key: nothing ties allow_<host>_<port> to its host, so an
// agent can name another destination's rule. The merged rule would open
// p's destination under the rule and the approval (the user's, say) that
// admitted the other host, which the ask for p never showed.
func appendForeignHosts(p Proposal, rule v1.NetworkPolicyRule) []string {
	hosts := destinationHosts(p)
	out := p.Unsupported
	for _, ep := range rule.Endpoints {
		if host := NormalizeHost(ep.Host); !slices.Contains(hosts, host) {
			out = appendUnique(out, "a merge into the existing rule "+p.RuleName+" for "+strconv.Quote(truncate(host, 80)))
		}
	}
	return out
}

// endpointFeatures names the endpoint settings triage never approves. A
// triaged rule is a plain host-and-port allow: anything that inspects,
// rewrites or injects credentials into the traffic belongs to provider
// profiles, which DefenseClaw renders itself.
func endpointFeatures(ep v1.PolicyNetworkEndpoint) []string {
	var out []string
	if !approvableProtocols[strings.ToLower(strings.TrimSpace(ep.Protocol))] {
		out = append(out, "protocol "+strconv.Quote(ep.Protocol))
	}
	if len(ep.Rules) > 0 || len(ep.DenyRules) > 0 || ep.Path != "" || ep.AllowEncodedSlash {
		out = append(out, "layer-7 rules")
	}
	if ep.Access != v1.NetworkAccessPresetUnspecified {
		out = append(out, "an access preset")
	}
	if ep.TLS != v1.NetworkTLSModeUnspecified && ep.TLS != v1.NetworkTLSModeSkip {
		out = append(out, "a TLS mode")
	}
	if ep.CredentialBinding != nil || ep.ProviderCredentialed || ep.AllowUninspectedCredentials ||
		ep.WebsocketCredentialRewrite || ep.RequestBodyCredentialRewrite || ep.CredentialSigning != "" || ep.SigningService != "" {
		out = append(out, "credential handling")
	}
	if ep.Mcp != nil || ep.PersistedQueries != "" || len(ep.GraphqlPersistedQueries) > 0 || ep.GraphqlMaxBodyBytes != 0 || ep.JSONRPCMaxBodyBytes != 0 {
		out = append(out, "protocol inspection settings")
	}
	return out
}

// approvableProtocols are the endpoint protocols a triaged rule may use.
var approvableProtocols = map[string]bool{"": true, "tcp": true}

func appendUnique(list []string, v string) []string {
	for _, have := range list {
		if have == v {
			return list
		}
	}
	return append(list, v)
}

// ContentDigest identifies what approving a chunk adds: its rule name, the
// proposed rule (every endpoint, port, allowed IP, setting and binary),
// the triggering binary and the advisor's security notes. A chunk whose
// digest changed since it was decided must be decided again.
func ContentDigest(c openshell.PolicyChunk) string {
	return digest(c.RuleName, c.ProposedRule, c.Binary, strings.TrimSpace(c.SecurityNotes))
}

// RuleDigest is ContentDigest without the security notes.
func RuleDigest(c openshell.PolicyChunk) string {
	return digest(c.RuleName, c.ProposedRule, c.Binary)
}

func digest(parts ...any) string {
	h := sha256.New()
	for _, part := range parts {
		data, _ := json.Marshal(part)
		var v any
		if json.Unmarshal(data, &v) == nil {
			data, _ = json.Marshal(pruneZero(v))
		}
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// pruneZero drops zero-valued object members, so a field the gateway sends
// as nil one time and empty the next hashes alike.
func pruneZero(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if val = pruneZero(val); isZeroJSON(val) {
				delete(x, k)
			} else {
				x[k] = val
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = pruneZero(x[i])
		}
		return x
	}
	return v
}

func isZeroJSON(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case float64:
		return x == 0
	case string:
		return x == ""
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	}
	return false
}

// Policy is what a proposal is judged against.
type Policy struct {
	// Effective is the sandbox's resolved policy. Required.
	Effective *packs.Effective
	// Decider is the sandbox's egress proxy decider
	// (Effective.EgressDecider with the sandbox's unblocks) and Principal
	// the sandbox's proxy principal: a proposal is held to exactly what the
	// proxy decides for this sandbox, its unblocks included. Nil uses the
	// policy's decider without unblocks.
	Decider   *egress.Decider
	Principal egress.Principal
	// Resolver resolves destination names for the proxy's dial-time address
	// checks; nil uses net.DefaultResolver.
	Resolver egress.Resolver
	// AgentProposals is openshell.approvals.agent_proposals; false rejects
	// every proposal.
	AgentProposals bool
	// HarnessFetches are requests the sandbox's harness binary makes around
	// the proxy that it does without; their proposals are rejected.
	HarnessFetches []HarnessFetch

	// asNamed judges destination names as named, without looking them up
	// (ApprovesAutomatically).
	asNamed bool
}

// HarnessFetch is a destination the sandbox's pinned harness binary (a path
// under BinaryRoot) reaches on its own around the egress proxy for
// something it does without, with no setting that turns the request off
// (harness.DirectFetch). A direct rule for it would bypass the proxy and
// reload the sandbox policy, which closes its open connections, for
// nothing.
type HarnessFetch struct {
	BinaryRoot string
	Host       string
	Port       int
	// What says what the request is for.
	What string
}

// harnessFetch returns the fetch p is: every binary the proposal names
// lives under the fetch's BinaryRoot and every endpoint is its host and
// port.
func harnessFetch(p Proposal, fetches []HarnessFetch) (HarnessFetch, bool) {
	binaries := append([]string{p.Binary}, p.Binaries...)
	for _, f := range fetches {
		root := strings.TrimSuffix(f.BinaryRoot, "/")
		if root == "" || f.Host == "" || len(p.Endpoints) == 0 {
			continue
		}
		match := true
		for _, b := range binaries {
			if !strings.HasPrefix(b, root+"/") || strings.Contains(b, "/../") {
				match = false
			}
		}
		for _, ep := range p.Endpoints {
			if NormalizeHost(ep.Host) != NormalizeHost(f.Host) || ep.Port != f.Port {
				match = false
			}
		}
		if match {
			return f, true
		}
	}
	return HarnessFetch{}, false
}

// resolveTimeout bounds the DNS lookup of one proposed destination.
const resolveTimeout = 5 * time.Second

// decider returns the policy's decider, building the one without unblocks
// when none is set.
func (pol Policy) decider() (*egress.Decider, error) {
	if pol.Decider != nil {
		return pol.Decider, nil
	}
	return pol.Effective.EgressDecider(nil)
}

// Decision is triage's verdict on one proposal.
type Decision struct {
	Verdict Verdict
	Reason  Reason
	// Message is the display sentence (the agent and the feed see it).
	Message string
	// Kind, Host and Port name the endpoint that decided (the first one
	// for approvals).
	Kind string
	Host string
	Port int
	// Risky marks private, IP-literal or host-local reach.
	Risky bool
	// Unblockable reports a rejection an unblock of Host would lift: the
	// proxy's own verdict (a blocklist feed entry, an open-mode IP literal).
	Unblockable bool
	// Violation is the refusing policy decision, when one refused it.
	Violation *packs.Violation
}

// Classify judges a proposal. The rule itself is judged first (its name,
// its features, one destination host), then its allowed_ips and every
// endpoint: any rejection rejects the proposal, then an endpoint that could
// not be checked defers it, then any ask asks, otherwise it is approved. An
// ask for more than one port names them all. Destination names are
// resolved (bounded by ctx and a per-name timeout) and held to the proxy's
// dial-time address rules.
func Classify(ctx context.Context, p Proposal, pol Policy) Decision {
	if pol.Effective == nil {
		return Decision{Verdict: Reject, Reason: ReasonPolicy, Message: "the sandbox policy is not resolved", Kind: KindNetworkRule}
	}
	decider, err := pol.decider()
	if err != nil {
		host, port := firstEndpoint(p)
		return Decision{Verdict: Reject, Reason: ReasonPolicy, Kind: KindNetworkRule, Host: host, Port: port,
			Message: "the sandbox's egress policy cannot be evaluated: " + err.Error()}
	}
	if !pol.AgentProposals {
		host, port := firstEndpoint(p)
		return Decision{Verdict: Reject, Reason: ReasonAgentProposalOff, Kind: KindNetworkRule, Host: host, Port: port,
			Message: "agent policy proposals are turned off (openshell.approvals.agent_proposals)"}
	}
	if len(p.Endpoints) == 0 {
		return Decision{Verdict: Reject, Reason: ReasonNoEndpoints, Kind: KindNetworkRule,
			Message: "the proposal names no destination"}
	}
	if d, bad := judgeRule(p); bad {
		d.Host, d.Port = firstEndpoint(p)
		return d
	}
	if f, ok := harnessFetch(p, pol.HarnessFetches); ok {
		host, port := firstEndpoint(p)
		return Decision{Verdict: Reject, Reason: ReasonHarnessFetch, Kind: KindNetworkRule, Host: host, Port: port,
			Message: f.What + "; DefenseClaw opens no direct rule for it"}
	}
	if hosts := destinationHosts(p); len(hosts) > 1 {
		host, port := firstEndpoint(p)
		shown := hosts
		if len(shown) > 3 {
			shown = append(slices.Clip(shown[:3]), fmt.Sprintf("%d more", len(hosts)-3))
		}
		return Decision{Verdict: Reject, Reason: ReasonMultipleHosts, Kind: KindNetworkRule, Host: host, Port: port,
			Message: fmt.Sprintf("the proposal names %d destination hosts (%s); propose each host as its own rule", len(hosts),
				truncate(strings.Join(shown, ", "), 200))}
	}
	return withPorts(classifyEndpoints(ctx, p, pol, decider), p)
}

// classifyEndpoints judges a proposal's allowed_ips and endpoints.
func classifyEndpoints(ctx context.Context, p Proposal, pol Policy, decider *egress.Decider) Decision {
	var ipAsk *Decision
	for _, entry := range p.AllowedIPs {
		d := judgeAllowedIP(pol.Effective, entry)
		switch d.Verdict {
		case Reject:
			d.Host, d.Port = firstEndpoint(p)
			return d
		case Ask:
			if ipAsk == nil {
				ipAsk = &d
			}
		}
	}
	var ask, deferred, approve *Decision
	for _, ep := range p.Endpoints {
		d := judgeEndpoint(ctx, ep, p.AllowedIPs, pol, decider)
		switch d.Verdict {
		case Reject:
			return d
		case Defer:
			if deferred == nil {
				deferred = &d
			}
		case Ask:
			if ask == nil {
				ask = &d
			}
		default:
			if approve == nil {
				approve = &d
			}
		}
	}
	if deferred != nil {
		// Its lookup may still reject the whole proposal.
		return *deferred
	}
	if ask != nil {
		return *ask
	}
	if ipAsk != nil {
		d := *ipAsk
		d.Host, d.Port = approve.Host, approve.Port
		d.Message = "the sandbox asks to reach " + d.Host + " at " + d.Message + " on your private network"
		return d
	}
	if p.SecurityNotes != "" {
		d := *approve
		d.Verdict, d.Reason = Ask, ReasonSecurityFlagged
		d.Message = "OpenShell's policy advisor flagged this proposal: " + truncate(p.SecurityNotes, 300)
		return d
	}
	return *approve
}

// mechanisticRuleName is the network_policies key OpenShell drafts for a
// denied connection (allow_<host>_<port>). DefenseClaw's own rules
// (defenseclaw_*) and the provider rules (_provider_*) never match it, so a
// triaged approval can only add to rules of the same kind.
var mechanisticRuleName = regexp.MustCompile(`^allow_[a-z0-9][a-z0-9_.-]{0,200}$`)

// judgeRule refuses proposals whose rule is not a plain host-and-port
// allow: approving merges the proposal into network_policies[RuleName], so
// a reserved or foreign name would add endpoints to DefenseClaw's egress
// relay, a provider rule that injects credentials, or the rule of another
// destination (FromChunk lists those merges in Unsupported).
func judgeRule(p Proposal) (Decision, bool) {
	d := Decision{Kind: KindNetworkRule}
	name := p.RuleName
	switch {
	case strings.HasPrefix(name, "defenseclaw_") || strings.HasPrefix(name, "defenseclaw-") || strings.HasPrefix(name, "_"):
		return reject(d, ReasonRuleShape, "the proposal would add to DefenseClaw's or a provider's own rule "+strconv.Quote(name)), true
	case !mechanisticRuleName.MatchString(name):
		return reject(d, ReasonRuleShape, "the proposal's rule name "+strconv.Quote(truncate(name, 80))+
			" is not an OpenShell allow_<host>_<port> rule; propose the destination without a custom rule name"), true
	case len(p.Unsupported) > 0:
		return reject(d, ReasonRuleShape, "the proposal asks for "+strings.Join(p.Unsupported, ", ")+
			", which DefenseClaw never approves; propose a plain host and port"), true
	}
	return Decision{}, false
}

// destinationHosts are the distinct destination hosts of a proposal's
// endpoints, in order.
func destinationHosts(p Proposal) []string {
	var out []string
	for _, ep := range p.Endpoints {
		if host := NormalizeHost(ep.Host); !slices.Contains(out, host) {
			out = append(out, host)
		}
	}
	return out
}

// withPorts names every port of an ask for more than one: the ask shows
// one destination and port, and approving opens all of them.
func withPorts(d Decision, p Proposal) Decision {
	if d.Verdict != Ask || len(p.Endpoints) < 2 {
		return d
	}
	var ports []int
	for _, ep := range p.Endpoints {
		if !containsInt(ports, ep.Port) {
			ports = append(ports, ep.Port)
		}
	}
	if len(ports) > 1 {
		d.Message += "; approving opens ports " + joinInts(ports)
	}
	return d
}

func firstEndpoint(p Proposal) (string, int) {
	if len(p.Endpoints) == 0 {
		return "", 0
	}
	return p.Endpoints[0].Host, p.Endpoints[0].Port
}

// judgeEndpoint classifies one destination against the sandbox's proxy
// decider. allowedIPs are the proposal's allowed_ips, which the
// administrator checks see.
func judgeEndpoint(ctx context.Context, ep Endpoint, allowedIPs []string, pol Policy, decider *egress.Decider) Decision {
	eff := pol.Effective
	host := NormalizeHost(ep.Host)
	d := Decision{Kind: KindNetworkRule, Host: host, Port: ep.Port}
	switch {
	case host == "":
		return reject(d, ReasonInvalid, "the proposal names no destination host")
	case strings.Contains(host, "*"):
		return reject(d, ReasonWildcard, "wildcard destinations are never approved automatically; allow the exact host instead")
	case ep.Port < 0 || ep.Port > 65535:
		return reject(d, ReasonInvalid, "the proposal names an invalid port")
	}
	local := IsHostLocal(host)
	if local {
		d.Kind, d.Risky = KindHostPort, true
	}
	if err := checkApproval(eff, host, ep.Port, false, allowedIPs); err != nil {
		var v *packs.Violation
		if errors.As(err, &v) {
			d.Violation = v
			reason := ReasonPolicy
			if v.Admin() {
				reason = ReasonAdmin
			}
			return reject(d, reason, v.Error())
		}
		return reject(d, ReasonInvalid, err.Error())
	}
	if local {
		return ask(d, ReasonHostLocal, fmt.Sprintf("the sandbox asks to reach port %s on your machine", portText(ep.Port)))
	}
	_, isIP := parseIP(host)
	if isIP {
		d.Risky = true
	}
	// The proxy's verdict for this sandbox, before the port: approvals
	// carry their own ports (checked below).
	dec := decider.DecideHost(pol.Principal, host)
	d.Unblockable = !dec.Allowed && dec.Unblockable
	if !dec.Allowed {
		switch {
		case dec.Category == egress.CategoryPrivateNetwork:
			d.Risky = true
			return ask(d, ReasonPrivateNetwork, "the sandbox asks to reach "+host+" on your private network")
		case dec.Category == egress.CategoryIPLiteral:
			return reject(d, ReasonIPLiteral, "IP-literal destinations bypass the egress blocklist; use a host name through the proxy, "+
				"or unblock "+host+" first")
		case dec.Source == egress.SourceGuard:
			return reject(d, ReasonInvalid, "the egress proxy refuses "+host+": "+dec.Reason)
		case dec.Source == egress.SourceAdmin, dec.Source == egress.SourceOperator, dec.Source == egress.SourceFeed:
			return reject(d, ReasonBlocklisted, blocklistedMessage(host, dec))
		}
		// Not allowlisted: the approvals mode decides below.
	}
	if ep.Port != 0 && !containsInt(eff.Egress.Ports, ep.Port) {
		return reject(d, ReasonPortNotAllowed, fmt.Sprintf(
			"port %d is not an egress port (%s); use HTTPS, or open it with an explicit allow rule", ep.Port, joinInts(eff.Egress.Ports)))
	}
	verdict := approvalsMode(d, eff, host)
	switch {
	case dec.Allowed && dec.Source == egress.SourceUnblock:
		verdict = approve(d, ReasonAllowed, host+" was unblocked")
	case dec.Allowed && dec.Source != egress.SourceDefault:
		verdict = approve(d, ReasonAllowed, host+" is on the allow list")
	}
	if isIP || pol.asNamed {
		return verdict
	}
	return checkResolved(ctx, verdict, pol, decider, dec)
}

// approvalsMode is the verdict for a destination the proxy neither refuses
// outright nor allows through an unblock or an allow entry.
func approvalsMode(d Decision, eff *packs.Effective, host string) Decision {
	switch eff.Approvals {
	case packs.ApprovalsAuto:
		return approve(d, ReasonAutoMode, "approved automatically (approvals: auto)")
	case packs.ApprovalsTriage:
		switch eff.NetworkMode {
		case packs.NetworkOpen:
			return approve(d, ReasonOpenNetwork, "approved automatically: open network, not on the blocklist")
		case packs.NetworkDeny:
			return ask(d, ReasonNetworkDeny, "the "+eff.Profile+" profile has no web egress; approve to open "+host)
		default:
			return ask(d, ReasonNotAllowlisted, host+" is not on the allowlist")
		}
	default:
		return ask(d, ReasonManual, "approvals are manual for the "+eff.Profile+" profile")
	}
}

func blocklistedMessage(host string, dec egress.Decision) string {
	msg := host + " is on the egress blocklist"
	switch {
	case dec.Entry != "":
		msg += " (" + dec.Entry + ")"
	case dec.Rule != "":
		msg += " (" + dec.Rule + ")"
	case dec.Category == egress.CategoryAdminAllowOnly:
		msg = host + " is not on your organization's list of allowed destinations"
	}
	return msg
}

// checkResolved holds an approval or ask for a destination name to the
// proxy's dial-time address rules, applied to what the name resolves to
// now: a direct OpenShell rule reaches whatever the name resolves to
// without the proxy's guard, so a name that leads to this machine is
// rejected and one that leads to a private network asks (or is rejected
// when unblocking is off). A name that does not exist or has no address is
// rejected: where its rule would lead cannot be checked. A lookup that
// timed out or failed temporarily defers the proposal instead, so a flaky
// resolver never turns into a rejection the agent has to work around.
func checkResolved(ctx context.Context, verdict Decision, pol Policy, decider *egress.Decider, dec egress.Decision) Decision {
	if verdict.Verdict == Reject {
		return verdict
	}
	lctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	addrs, err := egress.LookupHost(lctx, pol.Resolver, verdict.Host)
	cancel()
	if err != nil {
		verdict.Risky = true
		if lookupTransient(err) {
			verdict.Verdict, verdict.Reason = Defer, ReasonLookupFailed
			verdict.Message = verdict.Host + " could not be looked up just now (" + truncate(err.Error(), 120) +
				"); DefenseClaw decides it again on its next pass"
			return verdict
		}
		return reject(verdict, ReasonUnresolved, verdict.Host+" does not resolve from this machine, so DefenseClaw cannot check "+
			"where a direct rule would lead; reach it through the egress proxy (HTTPS_PROXY) instead")
	}
	// Judge the addresses as the proxy would once the destination is
	// admitted; a not-allowlisted destination asks, and its addresses count.
	probe := dec
	probe.Allowed = true
	chk := decider.CheckAddrs(pol.Principal, probe, addrs)
	if chk.Allowed {
		return verdict
	}
	verdict.Risky, verdict.Unblockable = true, chk.Unblockable
	switch {
	case chk.Category == egress.CategoryHostInternal:
		return reject(verdict, ReasonResolvesToHost, verdict.Host+" resolves to "+resolvedWhat(chk)+
			"; sandboxes reach services on this machine only through a host port")
	case chk.Category == egress.CategoryPrivateNetwork:
		if !decider.UnblocksAllowed() {
			verdict.Violation = &packs.Violation{
				Key: "approvals.approve", Source: packs.SourceUser, Attempted: verdict.Host,
				Constraint: "openshell.admin.allow_unblock", Message: "blocked by your organization's DefenseClaw policy: approvals.approve",
				Detail: verdict.Host + " resolves to a private network address, which the egress proxy refuses",
			}
			return reject(verdict, ReasonAdmin, verdict.Violation.Error())
		}
		return ask(verdict, ReasonPrivateNetwork, "the sandbox asks to reach "+verdict.Host+", which resolves to a private network address")
	case chk.Category == egress.CategoryAdminBlock:
		return reject(verdict, ReasonAdmin, verdict.Host+" resolves to an address your organization's DefenseClaw policy blocks")
	default:
		return reject(verdict, ReasonBlocklisted, verdict.Host+" resolves to an address on the egress blocklist ("+chk.Rule+")")
	}
}

// lookupTransient reports a lookup failure worth retrying: a timeout, a
// canceled lookup, or a DNS error other than "no such host" (SERVFAIL, an
// unreachable server). A name that does not exist or resolves to no
// address is final.
func lookupTransient(err error) bool {
	if errors.Is(err, egress.ErrNoAddresses) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && !dnsErr.IsNotFound
}

// ResolvesToHost reports a proposal (typically a rule approved earlier)
// with a destination name that now resolves to this machine or what only it
// reaches, which a direct rule must never lead to whoever approved it.
// Host-local names and IP literals are judged as named by CheckProposal; a
// name that does not resolve does not count.
func ResolvesToHost(ctx context.Context, p Proposal, pol Policy) bool {
	if pol.Effective == nil {
		return false
	}
	decider, err := pol.decider()
	if err != nil {
		return false
	}
	for _, ep := range p.Endpoints {
		host := NormalizeHost(ep.Host)
		if host == "" || IsHostLocal(host) {
			continue
		}
		if _, isIP := parseIP(host); isIP {
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		addrs, err := egress.LookupHost(lctx, pol.Resolver, host)
		cancel()
		if err != nil {
			continue
		}
		probe := decider.DecideHost(pol.Principal, host)
		probe.Allowed = true
		if chk := decider.CheckAddrs(pol.Principal, probe, addrs); chk.Category == egress.CategoryHostInternal {
			return true
		}
	}
	return false
}

// ApprovesAutomatically reports whether pol approves the destinations of p
// on its own (Classify's Approve for its endpoints and allowed_ips), judged
// as named: no name is looked up, what names resolve to is ResolvesToHost's
// to re-check. A rule DefenseClaw approved on its own keeps no authority
// once this no longer holds: the approvals mode or the network mode became
// stricter (an administrator's required pack or minimum profile), the
// destination left an allow list, an unblock was taken back, or its port
// is no longer an egress port. The rule's shape (Classify's rule and
// harness checks) is not judged again.
func ApprovesAutomatically(ctx context.Context, p Proposal, pol Policy) bool {
	if pol.Effective == nil || len(p.Endpoints) == 0 {
		return false
	}
	decider, err := pol.decider()
	if err != nil {
		return false
	}
	pol.asNamed = true
	return classifyEndpoints(ctx, p, pol, decider).Verdict == Approve
}

// resolvedWhat names the refused address kind from a dial-time refusal.
func resolvedWhat(chk egress.Decision) string {
	reason := strings.TrimSuffix(strings.TrimPrefix(chk.Reason, "The destination resolves to "), ".")
	if reason == chk.Reason || reason == "" {
		return "an address of this machine"
	}
	return reason
}

// judgeAllowedIP classifies one allowed_ips entry as the proxy's guard
// would (packs.Effective.AllowedIPReach). A non-empty allowed_ips replaces
// OpenShell's own private-address check for the rule, and its name may
// resolve to any address in the range later, so a range that overlaps the
// user's network (a private range, or a public subnet this machine is on)
// asks (Message is the entry), and one that holds what DefenseClaw never
// opens (this machine's own addresses among them) rejects.
func judgeAllowedIP(eff *packs.Effective, entry string) Decision {
	d := Decision{Kind: KindNetworkRule, Risky: true}
	_, class, err := eff.AllowedIPReach(entry)
	switch {
	case err != nil:
		return reject(d, ReasonInvalid, "the proposal lists an invalid allowed IP "+strconv.Quote(truncate(strings.TrimSpace(entry), 64)))
	case class == packs.AllowedIPNever:
		return reject(d, ReasonPolicy, "the proposal would open "+strings.TrimSpace(entry)+", which DefenseClaw never opens to a sandbox")
	case class == packs.AllowedIPHost:
		return reject(d, ReasonResolvesToHost, "the proposal would open "+strings.TrimSpace(entry)+
			", which holds an address of this machine; sandboxes reach services on this machine only through a host port")
	case class == packs.AllowedIPPrivate:
		return ask(d, ReasonPrivateNetwork, strings.TrimSpace(entry))
	}
	return Decision{Verdict: Approve}
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// CheckApproval runs the effective policy's checks for approving a
// destination once (always false) or for future sandboxes (always true).
// Every approval, triage or operator, goes through it.
func CheckApproval(eff *packs.Effective, host string, port int, always bool) error {
	return checkApproval(eff, host, port, always, nil)
}

// CheckProposal runs CheckApproval for every endpoint of a proposal, with
// its allowed_ips.
func CheckProposal(eff *packs.Effective, p Proposal, always bool) error {
	if len(p.Endpoints) == 0 {
		return errors.New("sandbox policy: the proposal names no destination")
	}
	for _, ep := range p.Endpoints {
		if err := checkApproval(eff, NormalizeHost(ep.Host), ep.Port, always, p.AllowedIPs); err != nil {
			return err
		}
	}
	return nil
}

func checkApproval(eff *packs.Effective, host string, port int, always bool, allowedIPs []string) error {
	kind := packs.ActionApprove
	if always {
		kind = packs.ActionApproveAlways
	}
	return eff.Allow(packs.Action{Kind: kind, Host: host, Port: port, AllowedIPs: allowedIPs})
}

// CheckUnblock runs the effective policy's checks for an egress unblock.
func CheckUnblock(eff *packs.Effective, host string) error {
	return eff.Allow(packs.Action{Kind: packs.ActionUnblock, Host: host})
}

// NormalizeHost lowercases a destination and strips brackets and a
// trailing dot.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return strings.TrimSuffix(host, ".")
}

// IsHostLocal reports destinations that reach the user's own machine.
func IsHostLocal(host string) bool {
	host = NormalizeHost(host)
	switch {
	case host == packs.OpenShellHostAlias, host == "localhost", strings.HasSuffix(host, ".localhost"),
		host == "host.docker.internal", host == "gateway.docker.internal":
		return true
	}
	if addr, ok := parseIP(host); ok {
		return addr.IsLoopback() || addr.IsUnspecified()
	}
	return false
}

// IsPrivate reports RFC 1918, CGNAT and ULA addresses.
func IsPrivate(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsPrivate() || cgnatPrefix.Contains(addr)
}

func parseIP(host string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func reject(d Decision, r Reason, msg string) Decision {
	d.Verdict, d.Reason, d.Message = Reject, r, msg
	return d
}

func ask(d Decision, r Reason, msg string) Decision {
	d.Verdict, d.Reason, d.Message = Ask, r, msg
	return d
}

func approve(d Decision, r Reason, msg string) Decision {
	d.Verdict, d.Reason, d.Message = Approve, r, msg
	return d
}

func portText(port int) string {
	if port == 0 {
		return "(any)"
	}
	return strconv.Itoa(port)
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

// truncate cuts s to at most n bytes, plus an ellipsis, without splitting a
// UTF-8 sequence: the policy advisor's notes and the rule names it quotes
// can hold any text.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for i := n; i > 0 && i > n-utf8.UTFMax; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i] + "…"
		}
	}
	return s[:n] + "…"
}

// Persister keeps "always" decisions for future sandboxes in the
// DefenseClaw configuration, through the gateway's ConfigManager so the
// running daemon reloads them.
type Persister interface {
	// AllowAlways adds host to openshell.egress.unblocked. It must not
	// write openshell.egress.allow: an allow entry is operator
	// configuration that also opens the private addresses the name
	// resolves to, which one click on an agent-chosen name must never do.
	AllowAlways(ctx context.Context, host string) error
	// BlockAlways adds host to openshell.egress.block.
	BlockAlways(ctx context.Context, host string) error
}
