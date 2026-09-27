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
// triage holds every proposal to what the proxy would enforce:
//
//   - rejected: anything the effective sandbox policy refuses (the
//     administrator's blocklist and allow-only list, link-local, metadata
//     and reserved addresses, DefenseClaw's own listeners and the OpenShell
//     gateway), wildcard or malformed destinations, blocklisted hosts,
//     public IP literals (they sidestep the name-based blocklist) and ports
//     the proxy does not carry;
//   - asked: doors into the user's machine or network (host.openshell.internal
//     and other host-local names, private addresses), proposals OpenShell's
//     advisor flagged, and everything the pack's approvals mode does not
//     auto-approve;
//   - approved automatically: the rest, when the pack's approvals mode is
//     auto, or triage on an open network, or the host is already allowed
//     (an "always" decision or the curated allowlist).
//
// Approvals are applied by a Batcher at hook-quiescent moments: every
// OpenShell policy reload closes the sandbox's open connections, including
// a hook request waiting on a verdict.
package triage

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
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
)

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
	Sandbox       string
	ChunkID       string
	ReviewToken   string
	RuleName      string
	Endpoints     []Endpoint
	AllowedIPs    []string
	Binary        string
	Rationale     string
	SecurityNotes string
	HitCount      int
}

// FromChunk extracts a Proposal from an OpenShell draft chunk. An endpoint
// with a port list becomes one Endpoint per port.
func FromChunk(sandbox string, c openshell.PolicyChunk) Proposal {
	p := Proposal{
		Sandbox: sandbox, ChunkID: c.ID, ReviewToken: c.ReviewToken, RuleName: c.RuleName,
		Binary: c.Binary, Rationale: c.Rationale, SecurityNotes: strings.TrimSpace(c.SecurityNotes),
		HitCount: int(c.HitCount),
	}
	if c.ProposedRule == nil {
		return p
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
	}
	if p.Binary == "" && len(c.ProposedRule.Binaries) > 0 {
		p.Binary = c.ProposedRule.Binaries[0].Path
	}
	return p
}

// Policy is what a proposal is judged against.
type Policy struct {
	// Effective is the sandbox's resolved policy. Required.
	Effective *packs.Effective
	// Feed matches the egress proxy's blocklist feeds. Required whenever the
	// effective policy has feeds.
	Feed packs.FeedMatcher
	// AgentProposals is openshell.approvals.agent_proposals; false rejects
	// every proposal.
	AgentProposals bool
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
	// Violation is the refusing policy decision, when one refused it.
	Violation *packs.Violation
}

// Classify judges a proposal. Endpoints are judged one by one: any
// rejection rejects the proposal, then any ask asks, otherwise it is
// approved.
func Classify(p Proposal, pol Policy) Decision {
	if pol.Effective == nil {
		return Decision{Verdict: Reject, Reason: ReasonPolicy, Message: "the sandbox policy is not resolved", Kind: KindNetworkRule}
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
	for _, entry := range p.AllowedIPs {
		if d, bad := judgeAllowedIP(entry); bad {
			d.Host, d.Port = firstEndpoint(p)
			return d
		}
	}
	var ask *Decision
	var approve *Decision
	for _, ep := range p.Endpoints {
		d := judgeEndpoint(ep, pol)
		switch d.Verdict {
		case Reject:
			return d
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
	if ask != nil {
		return *ask
	}
	if p.SecurityNotes != "" {
		d := *approve
		d.Verdict, d.Reason = Ask, ReasonSecurityFlagged
		d.Message = "OpenShell's policy advisor flagged this proposal: " + truncate(p.SecurityNotes, 300)
		return d
	}
	return *approve
}

func firstEndpoint(p Proposal) (string, int) {
	if len(p.Endpoints) == 0 {
		return "", 0
	}
	return p.Endpoints[0].Host, p.Endpoints[0].Port
}

// judgeEndpoint classifies one destination.
func judgeEndpoint(ep Endpoint, pol Policy) Decision {
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
	if err := CheckApproval(eff, host, ep.Port, false, pol.Feed); err != nil {
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
	addr, isIP := parseIP(host)
	if isIP && IsPrivate(addr) {
		d.Risky = true
		return ask(d, ReasonPrivateNetwork, "the sandbox asks to reach "+host+" on your private network")
	}
	if isIP {
		d.Risky = true
		return reject(d, ReasonIPLiteral, "IP-literal destinations bypass the egress blocklist; use a host name through the proxy")
	}
	if dec := eff.DecideEgress(host, 0, pol.Feed); !dec.Allowed {
		switch dec.Rule {
		case packs.RuleAdminBlock, packs.RuleAdminAllowOnly, packs.RuleBlock, packs.RuleFeed, packs.RuleInvalid:
			msg := host + " is on the egress blocklist"
			if dec.Match != "" {
				msg += " (" + dec.Match + ")"
			}
			return reject(d, ReasonBlocklisted, msg)
		}
	}
	if ep.Port != 0 && !containsInt(eff.Egress.Ports, ep.Port) {
		return reject(d, ReasonPortNotAllowed, fmt.Sprintf(
			"port %d is not an egress port (%s); use HTTPS, or open it with an explicit allow rule", ep.Port, joinInts(eff.Egress.Ports)))
	}
	if packs.MatchAnyHost(eff.Egress.Allow, host) || packs.MatchAnyHost(eff.Egress.AllowOnly, host) {
		return approve(d, ReasonAllowed, host+" is on the allow list")
	}
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

// judgeAllowedIP refuses allowed_ips entries that would open host-internal
// or metadata ranges. Other entries are left to the endpoint checks.
func judgeAllowedIP(entry string) (Decision, bool) {
	entry = strings.TrimSpace(entry)
	d := Decision{Kind: KindNetworkRule, Risky: true}
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		addr, aerr := netip.ParseAddr(entry)
		if aerr != nil {
			return reject(d, ReasonInvalid, "the proposal lists an invalid allowed IP "+strconv.Quote(entry)), true
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	addr := prefix.Masked().Addr()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() ||
		prefix.Bits() == 0 || metadataPrefix.Overlaps(prefix) || syntheticPrefix.Overlaps(prefix) {
		return reject(d, ReasonPolicy, "the proposal would open "+entry+", which DefenseClaw never opens to a sandbox"), true
	}
	return Decision{}, false
}

var (
	metadataPrefix  = netip.MustParsePrefix("169.254.0.0/16")
	syntheticPrefix = netip.MustParsePrefix("198.18.0.0/15")
	cgnatPrefix     = netip.MustParsePrefix("100.64.0.0/10")
)

// CheckApproval runs the effective policy's checks for approving a
// destination once (always false) or for future sandboxes (always true).
// Every approval, triage or operator, goes through it; feed is the egress
// proxy's blocklist matcher.
func CheckApproval(eff *packs.Effective, host string, port int, always bool, feed packs.FeedMatcher) error {
	kind := packs.ActionApprove
	if always {
		kind = packs.ActionApproveAlways
	}
	return eff.Allow(packs.Action{Kind: kind, Host: host, Port: port, Feed: feed})
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Persister keeps "always" decisions for future sandboxes in the
// DefenseClaw configuration (openshell.egress.allow and
// openshell.egress.block), through the gateway's ConfigManager so the
// running daemon reloads them.
type Persister interface {
	AllowAlways(ctx context.Context, host string) error
	BlockAlways(ctx context.Context, host string) error
}
