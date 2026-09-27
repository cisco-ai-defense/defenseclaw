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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

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
	// ReasonRuleShape: the proposal names a reserved or non-mechanistic
	// rule, or asks for rule features triage never approves (layer-7
	// rules, access presets, credential handling).
	ReasonRuleShape Reason = "unsupported_rule"
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
		}
	}
	return p
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
	// Feed matches the egress proxy's blocklist feeds. Required whenever the
	// effective policy has feeds.
	Feed packs.FeedMatcher
	// AgentProposals is openshell.approvals.agent_proposals; false rejects
	// every proposal.
	AgentProposals bool
	// Unblocked are the destinations the user unblocked or approved for
	// every sandbox (openshell.egress.unblocked). They lift blocklist feed
	// and allowlist refusals as they do in the egress proxy, never the
	// private-address, host or administrator checks.
	Unblocked []string
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

// Classify judges a proposal. The rule itself is judged first (its name
// and features), then its allowed_ips and every endpoint: any rejection
// rejects the proposal, then any ask asks, otherwise it is approved.
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
	if d, bad := judgeRule(p); bad {
		d.Host, d.Port = firstEndpoint(p)
		return d
	}
	var ipAsk *Decision
	for _, entry := range p.AllowedIPs {
		d := judgeAllowedIP(entry)
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
	var ask *Decision
	var approve *Decision
	for _, ep := range p.Endpoints {
		d := judgeEndpoint(ep, p.AllowedIPs, pol)
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
// relay or a provider rule that injects credentials.
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

func firstEndpoint(p Proposal) (string, int) {
	if len(p.Endpoints) == 0 {
		return "", 0
	}
	return p.Endpoints[0].Host, p.Endpoints[0].Port
}

// judgeEndpoint classifies one destination. allowedIPs are the proposal's
// allowed_ips, which the administrator checks see.
func judgeEndpoint(ep Endpoint, allowedIPs []string, pol Policy) Decision {
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
	if err := checkApproval(eff, host, ep.Port, false, pol.Feed, allowedIPs); err != nil {
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
	// An always decision counts only while unblocking is allowed at all.
	unblocked := packs.MatchAnyHost(pol.Unblocked, host) && CheckUnblock(eff, host) == nil
	if dec := eff.DecideEgress(host, 0, pol.Feed); !dec.Allowed {
		switch {
		case dec.Rule == packs.RuleFeed && unblocked:
			// Lifted by an earlier "always" decision, as in the proxy.
		case dec.Rule == packs.RuleAdminBlock, dec.Rule == packs.RuleAdminAllowOnly, dec.Rule == packs.RuleBlock,
			dec.Rule == packs.RuleFeed, dec.Rule == packs.RuleInvalid:
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
	if unblocked {
		return approve(d, ReasonAllowed, host+" was approved for every sandbox earlier")
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

// judgeAllowedIP classifies one allowed_ips entry. A non-empty allowed_ips
// replaces OpenShell's own private-address check for the rule, so a range
// that overlaps the user's network asks (Message is the entry) and one
// that overlaps what DefenseClaw never opens rejects.
func judgeAllowedIP(entry string) Decision {
	d := Decision{Kind: KindNetworkRule, Risky: true}
	_, class, err := packs.ClassifyAllowedIP(entry)
	switch {
	case err != nil:
		return reject(d, ReasonInvalid, "the proposal lists an invalid allowed IP "+strconv.Quote(truncate(strings.TrimSpace(entry), 64)))
	case class == packs.AllowedIPNever:
		return reject(d, ReasonPolicy, "the proposal would open "+strings.TrimSpace(entry)+", which DefenseClaw never opens to a sandbox")
	case class == packs.AllowedIPPrivate:
		return ask(d, ReasonPrivateNetwork, strings.TrimSpace(entry))
	}
	return Decision{Verdict: Approve}
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// CheckApproval runs the effective policy's checks for approving a
// destination once (always false) or for future sandboxes (always true).
// Every approval, triage or operator, goes through it; feed is the egress
// proxy's blocklist matcher.
func CheckApproval(eff *packs.Effective, host string, port int, always bool, feed packs.FeedMatcher) error {
	return checkApproval(eff, host, port, always, feed, nil)
}

// CheckProposal runs CheckApproval for every endpoint of a proposal, with
// its allowed_ips.
func CheckProposal(eff *packs.Effective, p Proposal, always bool, feed packs.FeedMatcher) error {
	if len(p.Endpoints) == 0 {
		return errors.New("sandbox policy: the proposal names no destination")
	}
	for _, ep := range p.Endpoints {
		if err := checkApproval(eff, NormalizeHost(ep.Host), ep.Port, always, feed, p.AllowedIPs); err != nil {
			return err
		}
	}
	return nil
}

func checkApproval(eff *packs.Effective, host string, port int, always bool, feed packs.FeedMatcher, allowedIPs []string) error {
	kind := packs.ActionApprove
	if always {
		kind = packs.ActionApproveAlways
	}
	return eff.Allow(packs.Action{Kind: kind, Host: host, Port: port, Feed: feed, AllowedIPs: allowedIPs})
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
