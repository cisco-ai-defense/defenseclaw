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

package sandboxapi

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// reasonTexts explain the reason tokens of blocked egress: OpenShell's own
// for the connections it denies, the egress proxy's categories and
// triage's verdicts. The activity feed and the audit record of an
// OpenShell denial use the same words (GAP-0134).
var reasonTexts = map[string]string{
	"transparent_tcp_policy_denied":  "no OpenShell rule allows it",
	"transparent_tcp_mapping_denied": "no OpenShell rule allows this port",
	"policy_dns_ineligible":          "no OpenShell rule allows the name",
	"paste_site":                     "paste site",
	"file_drop":                      "file-sharing site",
	"webhook_catcher":                "webhook catcher",
	"tunnel":                         "tunnel service",
	"anonymizer":                     "anonymizer",
	"host_internal":                  "this machine",
	"private_network":                "private network",
	"port_not_allowed":               "port not allowed",
	"invalid_destination":            "invalid destination",
	"admin_block":                    "blocked by your organization",
	"admin_allow_only":               "not on your organization's allowed list",
	"operator_block":                 "on your block list",
	"pack_block":                     "on the pack's block list",
	"repo_policy_block":              "on the repository policy's block list, .defenseclaw/sandbox.yaml",
	"firewall_block":                 "a deny rule of the host egress firewall",
	"not_allowlisted":                "not on the allowlist",
	"rate_limited":                   "rate limited",
	"ip_literal":                     "IP address instead of a name",
	// Triage's verdicts on the rule OpenShell drafts for a denied
	// connection (triage.Reason).
	"unsupported_rule":         "no OpenShell rule allows it, and DefenseClaw does not approve the rule drafted for it",
	"no_endpoints":             "the rule drafted for it names no destination",
	"wildcard_destination":     "wildcard destination",
	"policy_refused":           "the sandbox policy refuses it",
	"admin_violation":          "blocked by your organization",
	"blocklisted":              "on the block list",
	"agent_proposals_disabled": "no OpenShell rule allows it, and this sandbox takes no new rules",
	"resolves_to_host":         "the name leads to this machine",
	"unresolved":               "the name does not resolve",
	"multiple_hosts":           "the rule drafted for it names several hosts",
	"harness_background_fetch": "a background fetch of the harness, which it does without",
	"rule_limit":               "the sandbox added its limit of rules this session",
	"too_many_pending":         "too many approvals are waiting",
	// An OpenShell refusal on the sandbox's model host (ReasonModelHostSide).
	"model_host_side": "a connection outside the model channel, which stays open; no OpenShell rule allows it",
}

// ReasonModelHostSide is the Reason of an OpenShell refusal on the
// sandbox's model host: a connection besides the model calls, which the
// sandbox's provider rule carries (GAP-0361).
const ReasonModelHostSide = "model_host_side"

// LookupReasonText is the short explanation of a reason token, and whether
// the token has one.
func LookupReasonText(token string) (string, bool) {
	text, ok := reasonTexts[token]
	return text, ok
}

// ReasonText is the short explanation of a reason token; an unknown token
// reads with spaces for its underscores.
func ReasonText(token string) string {
	if text, ok := reasonTexts[token]; ok {
		return text
	}
	return strings.ReplaceAll(token, "_", " ")
}

// metadataText names a cloud metadata or link-local destination.
const metadataText = "cloud metadata or link-local address, never reachable from a sandbox"

// LookupBlockedText is why a block of host reads as it does, and whether
// it has words: LookupReasonText, except that a cloud metadata or
// link-local address is named as such whatever refused it (the proxy's
// host_internal, or OpenShell's missing rule), not as this machine
// (GAP-0147). The feed, a session's notices and the audit reason of an
// OpenShell denial use it, so an alert reads like the feed (GAP-0134).
func LookupBlockedText(token, host string) (string, bool) {
	if metadataOrLinkLocal(host) {
		return metadataText, true
	}
	if PlaceholderRefusal(token) {
		return placeholderText, true
	}
	return LookupReasonText(token)
}

// PlaceholderRefusal reports OpenShell's refusal of a request whose body
// carries a credential placeholder, whose reason reads "POST request body
// credential traffic denied for HOST:PORT". A harness sends its
// conversation with every model request, and its hooks send parts of it:
// once the conversation shows a placeholder (an `env` output), OpenShell
// refuses its requests while the key, the sandbox token and DefenseClaw are
// fine (GAP-0354, GAP-0355).
func PlaceholderRefusal(reason string) bool {
	return strings.Contains(strings.ToLower(reason), "request body credential traffic denied")
}

// placeholderText is LookupBlockedText's words for a PlaceholderRefusal.
const placeholderText = "OpenShell forwards no request whose body carries a sandbox credential placeholder"

// BlockedText is LookupBlockedText's words; an unknown token reads with
// spaces for its underscores.
func BlockedText(token, host string) string {
	if text, ok := LookupBlockedText(token, host); ok {
		return text
	}
	return ReasonText(token)
}

// metadataOrLinkLocal reports a link-local address, the cloud metadata
// addresses and names outside that range the egress guard refuses
// (egress.NeverReachPrefixes), and metadata.google.internal.
func metadataOrLinkLocal(host string) bool {
	h := strings.TrimSuffix(strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]"), ".")
	if h == "metadata.google.internal" {
		return true
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsLinkLocalUnicast() || slices.ContainsFunc(egress.NeverReachPrefixes(), func(p netip.Prefix) bool { return p.Contains(addr) })
}

// SSHBlockedText says what to do instead of SSH to host. OpenShell opens no
// SSH out of a sandbox, which no unblock changes.
func SSHBlockedText(host string) string {
	return "SSH does not leave a sandbox: use an HTTPS remote (https://" + host + "/…)"
}
