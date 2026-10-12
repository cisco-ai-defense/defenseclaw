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

package sandboxreg

import (
	"net/netip"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Rules a DecisionRefusedError names: the floor key that refuses the
// decision, or RuleInvalid for a request that is not a decision at all.
const (
	RuleUserApprovals   = "user_approvals"
	RuleAllowUnblock    = "allow_unblock"
	RuleEgressBlock     = "egress_block"
	RuleEgressAllowOnly = "egress_allow_only"
	RuleAllowHostPorts  = "allow_host_ports"
	RuleInvalid         = "invalid_request"
)

// maxCheckedHostBytes bounds a decision's host (a DNS name's limit).
const maxCheckedHostBytes = 253

// openShellHostAlias is how a sandbox names this computer
// (packs.OpenShellHostAlias): a decision for it opens a host port.
const openShellHostAlias = "host.openshell.internal"

// CheckDecision refuses a decision f does not allow, as a
// *DecisionRefusedError. It is the plan's §6.2 truth table:
//
//	user_approvals  allow_unblock  session  always        unblock
//	unset           true/unset     yes      yes, stored   yes
//	unset           false          yes      -             -
//	session         true/unset     yes      -             session only
//	session         false          yes      -             -
//	none            any            -        -             -
//
// "Session" and "always" are an ask's answer (kind egress_allow), unblock
// is kind unblock in either scope. A user block (egress_block) only
// tightens and always passes. An allow or unblock never opens what the
// floor's own egress lists refuse (egress_block, egress_allow_only), so a
// direct call to the decisions route can't reach past them either. A
// decision for this computer (the OpenShell host alias) is a host-port
// ask's answer: allow_host_ports decides it, for the session only, and the
// egress lists, which never name this computer, do not.
func CheckDecision(f config.OpenShellAdminConfig, d sandboxrelay.DecisionRequest) error {
	kind := strings.TrimSpace(d.Kind)
	scope := strings.TrimSpace(d.Scope)
	switch kind {
	case sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionUnblock:
	default:
		return refused(RuleInvalid, "a decision is egress_allow, egress_block or unblock")
	}
	switch scope {
	case sandboxrelay.DecisionScopeSession, sandboxrelay.DecisionScopeAlways:
	default:
		return refused(RuleInvalid, "a decision's scope is session or always")
	}
	host, addr, ok := decisionHost(d.Host)
	if !ok {
		return refused(RuleInvalid, "a decision names one destination host or IP address")
	}
	if kind == sandboxrelay.DecisionEgressBlock {
		return nil
	}
	if err := CheckApprovals(f, kind, scope); err != nil {
		return err
	}
	if host == openShellHostAlias {
		switch {
		case kind != sandboxrelay.DecisionEgressAllow || scope != sandboxrelay.DecisionScopeSession:
			return refused(RuleInvalid, "a port on this computer is opened for one sandbox's session only")
		case f.AllowHostPorts != nil && !*f.AllowHostPorts:
			return refused(RuleAllowHostPorts, "your profile doesn't let sandboxes reach ports on this computer")
		}
		return nil
	}
	if pattern, hit := matchAny(config.OpenShellAdminBlockPatterns(f.EgressBlock), host, addr); hit {
		return refused(RuleEgressBlock, host+" matches "+pattern+" on your organization's blocklist")
	}
	if len(f.EgressAllowOnly) > 0 {
		if _, hit := matchAny(f.EgressAllowOnly, host, addr); !hit {
			return refused(RuleEgressAllowOnly, host+" is not on your profile's allowed hosts")
		}
	}
	return nil
}

// CheckApprovals is the approvals part of CheckDecision: whether f's
// user_approvals and allow_unblock let the user make a decision of kind
// and scope at all, whatever its host. The sandbox daemon asks it before
// it raises or answers an ask, so a refused one never reaches the user as
// something to approve.
func CheckApprovals(f config.OpenShellAdminConfig, kind, scope string) error {
	if kind == sandboxrelay.DecisionEgressBlock {
		return nil
	}
	approvals := strings.ToLower(strings.TrimSpace(f.UserApprovals))
	noUnblock := f.AllowUnblock != nil && !*f.AllowUnblock
	session := scope == sandboxrelay.DecisionScopeSession
	switch {
	case approvals == config.OpenShellUserApprovalsNone:
		return refused(RuleUserApprovals, "your profile doesn't let you approve sandbox access; you can't approve this")
	case kind == sandboxrelay.DecisionEgressAllow && session:
		return nil
	case kind == sandboxrelay.DecisionEgressAllow && approvals == config.OpenShellUserApprovalsSession:
		return refused(RuleUserApprovals, "your profile lets you approve access for this session only, not for future sandboxes")
	case noUnblock && kind == sandboxrelay.DecisionEgressAllow:
		return refused(RuleAllowUnblock, "approvals can't be kept for future sandboxes; approve it for this session instead")
	case noUnblock:
		return refused(RuleAllowUnblock, "blocked destinations can't be unblocked under your profile")
	case !session && approvals == config.OpenShellUserApprovalsSession:
		return refused(RuleUserApprovals, "your profile lets you unblock a destination for this session only, not for future sandboxes")
	}
	return nil
}

// CapDecisions keeps the saved decisions f still allows: saved decisions
// are capped by the floor at every resolve, so a tightened profile takes
// back what it no longer allows without rewriting the store.
func CapDecisions(f config.OpenShellAdminConfig, saved []Decision) []Decision {
	out := make([]Decision, 0, len(saved))
	for _, d := range saved {
		req := sandboxrelay.DecisionRequest{V: sandboxrelay.WireVersion, Registration: d.Registration, Kind: d.Kind, Host: d.Host, Scope: d.Scope}
		if CheckDecision(f, req) == nil {
			out = append(out, d)
		}
	}
	return out
}

func refused(rule, why string) *DecisionRefusedError {
	return &DecisionRefusedError{Rule: rule, Message: sandboxapi.AdminMessage + ": " + why}
}

// decisionHost canonicalizes a decision's host: one host name or IP
// address, never a wildcard or a CIDR prefix.
func decisionHost(raw string) (string, config.OpenShellEgressPattern, bool) {
	if len(raw) > maxCheckedHostBytes || strings.Contains(raw, "/") {
		return "", config.OpenShellEgressPattern{}, false
	}
	p, err := config.ParseOpenShellEgressPattern(raw)
	if err != nil || p.Wildcard || (p.Prefix.IsValid() && !p.Prefix.IsSingleIP()) {
		return "", config.OpenShellEgressPattern{}, false
	}
	return p.String(), p, true
}

// matchAny returns the first of patterns that matches the host (an
// unparseable entry matches nothing: config validation refuses those).
func matchAny(patterns []string, host string, self config.OpenShellEgressPattern) (string, bool) {
	var addr netip.Addr // the zero Addr: a name
	if self.Prefix.IsValid() {
		addr = self.Prefix.Addr()
	}
	for _, raw := range patterns {
		p, err := config.ParseOpenShellEgressPattern(raw)
		if err != nil {
			continue
		}
		if p.Matches(host, addr) {
			return p.String(), true
		}
	}
	return "", false
}
