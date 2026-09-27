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

package packs

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// The effective egress posture reaches the egress proxy through exactly one
// translation, EgressOptions: every sandbox's proxy decider is built from its
// own Effective, and DecideEgress, the unblock and approval checks, and
// triage ask that same decider. Its decision order (egress.Decider.Decide)
// is the one semantics:
//
//	guard       invalid destinations and this machine (loopback, its own
//	            addresses, host-internal names, link-local, metadata) are
//	            never reachable; private networks only where an allow entry
//	            (Allow or AllowOnly) opens them
//	ports       Ports
//	AdminBlock  refused; never unblockable (the organization's policy)
//	AllowOnly   when set, everything outside it refused; never unblockable
//	Block       the pack's and openshell.egress.block: refused, not
//	            unblockable; reaching the host takes removing the entry
//	unblocks    per-sandbox and "always" unblocks allow (none when
//	            openshell.admin.allow_unblock is false)
//	Allow       allowed, exempt from the feed (after the feed when
//	            allow_unblock is false)
//	Feeds       refused; unblockable unless allow_unblock is false
//	AllowOnly   an entry allows
//	mode        open allows names and refuses IP literals (ip_literal,
//	            unblockable unless allow_unblock is false); allowlist refuses
//	            the rest (not_allowlisted, likewise unblockable); deny runs
//	            without the proxy
//
// The deny network mode (the strict profile) runs without the proxy: the
// sandbox gets no proxy credential, and its decider only judges approvals,
// with unblocks ignored.

// policyProbe is the principal policy-level checks decide for; the policy
// decider has no unblocks, so its identity never matters.
var policyProbe = egress.Principal{BindingID: "sandbox-policy"}

// EgressOptions returns the egress proxy decider options for this policy.
// unblocks supplies the sandbox's unblock decisions (nil: none); the deny
// network mode ignores them, as the proxy is off.
func (e *Effective) EgressOptions(unblocks egress.Unblocks) (egress.DeciderOptions, error) {
	if e == nil {
		return egress.DeciderOptions{}, errors.New("sandbox policy: not resolved")
	}
	eg := e.Egress
	opts := egress.DeciderOptions{
		Mode:       egress.ModeOpen,
		Ports:      slices.Clone(eg.Ports),
		Blocklists: []*egress.Feed{},
		// The allow list already holds the curated allowlist when the
		// profile needs it (resolveAllow); the proxy's own allowlist feed
		// would add hosts the policy does not list.
		Allowlists: []*egress.Feed{},
		AdminBlock: deciderPatterns(eg.AdminBlock),
		AllowOnly:  deciderPatterns(eg.AllowOnly),
		Block:      deciderPatterns(eg.Block),
		Allow:      deciderPatterns(eg.Allow),
		NoUnblock:  isFalse(e.admin.AllowUnblock),
		Unblocks:   unblocks,
	}
	if e.NetworkMode != NetworkOpen || len(eg.AllowOnly) > 0 {
		opts.Mode = egress.ModeAllowlist
	}
	if e.NetworkMode == NetworkDeny {
		opts.Unblocks = nil
	}
	for _, name := range eg.Feeds {
		if name != FeedBuiltin {
			return egress.DeciderOptions{}, fmt.Errorf("sandbox policy: unknown egress feed %q", name)
		}
		feed, err := egress.BuiltinBlocklist()
		if err != nil {
			return egress.DeciderOptions{}, fmt.Errorf("sandbox policy: %w", err)
		}
		opts.Blocklists = append(opts.Blocklists, feed)
	}
	return opts, nil
}

// EgressDecider builds the egress proxy decider for this policy
// (EgressOptions). The sandbox manager gives each sandbox's proxy
// credential its own, with that sandbox's unblocks.
func (e *Effective) EgressDecider(unblocks egress.Unblocks) (*egress.Decider, error) {
	opts, err := e.EgressOptions(unblocks)
	if err != nil {
		return nil, err
	}
	d, err := egress.NewDecider(opts)
	if err != nil {
		return nil, fmt.Errorf("sandbox policy: egress decider: %w", err)
	}
	return d, nil
}

// policyDecider is the decider without unblocks that policy-level checks
// ask. Resolve builds it once; an Effective assembled otherwise builds it
// on demand.
func (e *Effective) policyDecider() (*egress.Decider, error) {
	if e.decider != nil {
		return e.decider, nil
	}
	return e.EgressDecider(nil)
}

// deciderPatterns drops "*", which has no decider form: validated lists
// never hold it, and IsBroadAllowGlob keeps it out of allow lists.
func deciderPatterns(globs []string) []string {
	out := make([]string, 0, len(globs))
	for _, g := range globs {
		if g = strings.TrimSpace(g); g != "" && g != "*" {
			out = append(out, g)
		}
	}
	return out
}

// EgressRule names the step of the egress decision order that decided.
type EgressRule string

const (
	// RuleInvalid: the destination is not a host name or IP address.
	RuleInvalid EgressRule = "invalid"
	// RuleHostInternal: this machine or what only it reaches; never.
	RuleHostInternal EgressRule = "host_internal"
	// RulePrivateNetwork: a private network no allow entry opens.
	RulePrivateNetwork EgressRule = "private_network"
	RulePort           EgressRule = "port"
	RuleAdminBlock     EgressRule = "admin_block"
	// RuleAdminAllowOnly refuses a host outside
	// openshell.admin.egress_allow_only, or allows one on it.
	RuleAdminAllowOnly EgressRule = "admin_allow_only"
	RuleBlock          EgressRule = "block"
	// RuleUnblock: allowed by an unblock decision.
	RuleUnblock EgressRule = "unblock"
	RuleAllow   EgressRule = "allow"
	RuleFeed    EgressRule = "feed"
	// RuleNetworkOpen allows a name in the open network mode.
	RuleNetworkOpen EgressRule = "network_open"
	// RuleIPLiteral refuses an IP address in the open network mode: it would
	// sidestep the name-based feed.
	RuleIPLiteral        EgressRule = "ip_literal"
	RuleNetworkAllowlist EgressRule = "network_allowlist"
	RuleNetworkDeny      EgressRule = "network_deny"
)

// EgressDecision is the effective policy's verdict for one destination.
type EgressDecision struct {
	Allowed bool       `json:"allowed"`
	Rule    EgressRule `json:"rule"`
	// Match is the host pattern or feed entry that decided, or the refused
	// port, if any.
	Match string `json:"match,omitempty"`
	// Unblockable says whether Allow(ActionUnblock) could lift a refusal.
	Unblockable bool `json:"unblockable"`
	// Reason explains the verdict (the proxy's text).
	Reason string `json:"reason,omitempty"`
}

// DecideEgress is the egress proxy's verdict for a destination host and
// port (0 skips the port check) before any unblock: it asks the decider
// EgressOptions builds, so it can never disagree with the proxy. The deny
// network mode reports RuleNetworkDeny for everything the guard, the port
// list and the administrator's lists do not refuse first.
func (e *Effective) DecideEgress(host string, port int) EgressDecision {
	if e == nil {
		return EgressDecision{Rule: RuleInvalid}
	}
	d, err := e.policyDecider()
	if err != nil {
		return EgressDecision{Rule: RuleInvalid, Reason: err.Error()}
	}
	var dec egress.Decision
	if port == 0 {
		dec = d.DecideHost(policyProbe, host)
	} else {
		dec = d.Decide(policyProbe, host, port)
	}
	out := EgressDecision{Allowed: dec.Allowed, Rule: egressRuleOf(dec), Match: dec.Rule,
		Unblockable: dec.Unblockable, Reason: dec.Reason}
	switch out.Rule {
	case RuleFeed:
		out.Match = dec.Entry
	case RulePort:
		out.Match = strconv.Itoa(port)
	}
	if e.NetworkMode == NetworkDeny {
		switch out.Rule {
		case RuleInvalid, RuleHostInternal, RulePrivateNetwork, RulePort, RuleAdminBlock:
		case RuleAdminAllowOnly:
			if out.Allowed {
				out = EgressDecision{Rule: RuleNetworkDeny}
			}
		default:
			out = EgressDecision{Rule: RuleNetworkDeny}
		}
		out.Unblockable = false
		if out.Rule == RuleNetworkDeny {
			out.Reason = "the " + e.Profile + " profile runs without the egress proxy"
		}
	}
	return out
}

// egressRuleOf names the decision order step behind a decider verdict.
func egressRuleOf(dec egress.Decision) EgressRule {
	if dec.Allowed {
		switch dec.Source {
		case egress.SourceUnblock:
			return RuleUnblock
		case egress.SourceOperator, egress.SourceFeed:
			return RuleAllow
		case egress.SourceAdmin:
			return RuleAdminAllowOnly
		}
		return RuleNetworkOpen
	}
	switch dec.Category {
	case egress.CategoryInvalidDestination:
		return RuleInvalid
	case egress.CategoryHostInternal:
		return RuleHostInternal
	case egress.CategoryPrivateNetwork:
		return RulePrivateNetwork
	case egress.CategoryPortNotAllowed:
		return RulePort
	case egress.CategoryAdminBlock:
		return RuleAdminBlock
	case egress.CategoryAdminAllowOnly:
		return RuleAdminAllowOnly
	case egress.CategoryOperatorBlock:
		return RuleBlock
	case egress.CategoryIPLiteral:
		return RuleIPLiteral
	case egress.CategoryNotAllowlisted:
		return RuleNetworkAllowlist
	}
	if dec.Source == egress.SourceFeed {
		return RuleFeed
	}
	return RuleInvalid
}
