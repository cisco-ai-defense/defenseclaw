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
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// OpenShellHostAlias is the name a sandbox uses to reach the host.
const OpenShellHostAlias = "host.openshell.internal"

// ActionKind names a runtime action the effective policy gates.
type ActionKind string

const (
	// ActionUnblock lifts a blocklist or allowlist refusal for a
	// destination host (Action.Host), for one sandbox or always.
	ActionUnblock ActionKind = "unblock"
	// ActionApprove approves one OpenShell draft proposal for
	// Action.Host (and Action.Port) once. Pass Action.Feed: when
	// openshell.admin.allow_unblock is false, an approval is checked
	// against the blocklist feeds and refused without a matcher.
	ActionApprove ActionKind = "approve"
	// ActionApproveAlways approves a proposal and keeps the rule for
	// future sandboxes.
	ActionApproveAlways ActionKind = "approve_always"
	// ActionHostPort opens a host localhost port (Action.Port) to the
	// sandbox, for example for a host-side MCP server.
	ActionHostPort ActionKind = "host_port"
	// ActionMount bind-mounts a host folder (Action.Path: the project or a
	// --context folder) into the sandbox.
	ActionMount ActionKind = "mount"
	// ActionYolo runs the harness in skip-permissions mode.
	ActionYolo ActionKind = "yolo"
	// ActionLearnMode runs observe-and-suggest policy discovery.
	ActionLearnMode ActionKind = "learn_mode"
	// ActionHarness runs a harness (Action.Harness).
	ActionHarness ActionKind = "harness"
)

// Action is a runtime request checked by Effective.Allow. Only the fields
// its Kind names are read.
type Action struct {
	Kind ActionKind
	// Host is the destination host of an unblock or approval.
	Host string
	// Port is the host port to open, or an approval's destination port.
	Port int
	// Path is the absolute host path of a mount.
	Path string
	// Harness is the harness to run.
	Harness string
	// Feed is the egress proxy's blocklist feed matcher, read by approvals
	// (see ActionApprove).
	Feed FeedMatcher
}

// Allow checks a runtime action against the effective policy. It returns nil
// when the action is permitted and a *Violation (use errors.As) naming the
// refusing constraint when it is not. Malformed actions and a nil Effective
// are refused with a plain error, so callers fail closed.
func (e *Effective) Allow(action Action) error {
	if e == nil {
		return errors.New("sandbox policy: not resolved")
	}
	switch action.Kind {
	case ActionUnblock:
		return e.allowUnblock(action.Host)
	case ActionApprove:
		return e.allowApproval("approvals.approve", action, false)
	case ActionApproveAlways:
		return e.allowApproval("approvals.always", action, true)
	case ActionHostPort:
		if err := validPort(action.Port); err != nil {
			return err
		}
		return e.hostPortAllowed(action.Port)
	case ActionMount:
		return e.allowMount(action.Path)
	case ActionYolo:
		if isFalse(e.admin.AllowYolo) {
			return e.adminViolation("yolo", "true", "openshell.admin.allow_yolo",
				"skip-permissions mode is disabled; the harness keeps its permission prompts")
		}
		return nil
	case ActionLearnMode:
		if isFalse(e.admin.AllowLearnMode) {
			return e.adminViolation("learn", "true", "openshell.admin.allow_learn_mode",
				"learn mode is disabled")
		}
		return nil
	case ActionHarness:
		harness := config.NormalizeConnectorName(action.Harness)
		if !harnessNamePattern.MatchString(harness) {
			return fmt.Errorf("sandbox policy: invalid harness name %q", action.Harness)
		}
		return e.harnessAllowed(harness)
	default:
		return fmt.Errorf("sandbox policy: unknown action %q", action.Kind)
	}
}

func (e *Effective) adminViolation(key, attempted, constraint, detail string) *Violation {
	return &Violation{
		Key: key, Source: SourceUser, Attempted: attempted, Constraint: constraint,
		Message: adminMessage(key), Detail: detail,
	}
}

func (e *Effective) allowUnblock(host string) error {
	host, err := validHost(host)
	if err != nil {
		return err
	}
	const key = "egress.unblock"
	if isFalse(e.admin.AllowUnblock) {
		return e.adminViolation(key, host, "openshell.admin.allow_unblock",
			"blocked destinations cannot be unblocked; ask your administrator")
	}
	if v := e.Egress.adminVerdict(key, host); v != nil {
		return v
	}
	if e.NetworkMode == NetworkDeny {
		return e.profileViolation(key, host, "the proxy is off, so destinations cannot be unblocked")
	}
	return nil
}

// allowApproval gates an OpenShell draft proposal. An approval opens a
// direct OpenShell rule that bypasses the DefenseClaw egress proxy and its
// SSRF guard, so it is checked against what the proxy would enforce:
//   - the administrator's blocklist and allow-only list always apply;
//   - the host itself (host.openshell.internal, loopback addresses and
//     names, this machine's name) is a host-port request;
//   - link-local, cloud metadata, multicast and reserved addresses are
//     never approved;
//   - when openshell.admin.allow_unblock is false, a destination on the
//     block list or a blocklist feed, or a private network address, is
//     refused too: approving it would lift the proxy's refusal.
func (e *Effective) allowApproval(key string, action Action, always bool) error {
	host, err := validHost(action.Host)
	if err != nil {
		return err
	}
	port := action.Port
	if port != 0 {
		if err := validPort(port); err != nil {
			return err
		}
	}
	unblockForbidden := isFalse(e.admin.AllowUnblock)
	if always && unblockForbidden {
		return e.adminViolation(key, host, "openshell.admin.allow_unblock",
			"approvals cannot be kept for future sandboxes; approve once instead")
	}
	if v := e.Egress.adminVerdict(key, host); v != nil {
		return v
	}
	if e.isHostLocal(host) {
		if port == 0 {
			return fmt.Errorf("sandbox policy: approving %s needs a port", host)
		}
		return e.hostPortAllowed(port)
	}
	if neverApproved(host) {
		return &Violation{
			Key: key, Source: SourceUser, Attempted: host, Constraint: "defenseclaw",
			Message: "DefenseClaw never opens link-local, cloud metadata, multicast or reserved addresses to a sandbox",
			Detail:  host + " is one of them",
		}
	}
	if !unblockForbidden {
		return nil
	}
	if glob, ok := firstMatch(e.Egress.Block, host); ok {
		return e.adminViolation(key, host, "openshell.admin.allow_unblock",
			host+" matches "+glob+" on the blocklist, and blocked destinations cannot be approved")
	}
	if len(e.Egress.Feeds) > 0 {
		if action.Feed == nil {
			return fmt.Errorf("sandbox policy: approving %s needs the blocklist feed to check it against", host)
		}
		if entry, blocked := action.Feed(e.Egress.Feeds, host); blocked {
			return e.adminViolation(key, host, "openshell.admin.allow_unblock",
				host+" is on the blocklist feed ("+entry+"), and blocked destinations cannot be approved")
		}
	}
	if isPrivateAddress(host) {
		return e.adminViolation(key, host, "openshell.admin.allow_unblock",
			host+" is a private network address, which the egress proxy refuses")
	}
	return nil
}

func (e *Effective) profileViolation(key, attempted, detail string) *Violation {
	constraint := "profile " + e.Profile
	message := fmt.Sprintf("not allowed by the %s sandbox profile: %s", e.Profile, key)
	if setting, ok := e.settings["profile"]; ok && setting.Source == SourceAdmin {
		constraint, message = setting.Origin, adminMessage(key)
	}
	return &Violation{Key: key, Source: SourceUser, Attempted: attempted, Constraint: constraint,
		Message: message, Detail: detail}
}

func (e *Effective) allowMount(path string) error {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("sandbox policy: mount path %q must be absolute", path)
	}
	const key = "workdir.mode"
	if isFalse(e.admin.AllowMount) {
		return e.adminViolation(key, "mount "+path, "openshell.admin.allow_mount",
			"live host mounts are disabled; use copy mode")
	}
	if pattern := e.requiresCopy(path); pattern != "" {
		return e.adminViolation(key, "mount "+path, "openshell.admin.require_copy_for",
			"your organization requires copy mode for projects matching "+pattern)
	}
	return nil
}

// harnessAllowed checks a normalized harness name against the admin and pack
// allowlists. A refusal is Fatal: the sandbox cannot start.
func (e *Effective) harnessAllowed(harness string) error {
	const key = "harness"
	if allowed := e.admin.AllowedHarnesses; len(allowed) > 0 && !containsNormalized(allowed, harness) {
		v := e.adminViolation(key, harness, "openshell.admin.allowed_harnesses",
			"your organization allows only "+strings.Join(allowed, ", "))
		v.Fatal = true
		return v
	}
	if e.Pack != nil && len(e.Pack.Harness.Allowed) > 0 && !containsString(e.Pack.Harness.Allowed, harness) {
		return &Violation{
			Key: key, Source: SourceUser, Attempted: harness, Constraint: "pack " + e.Pack.Name, Fatal: true,
			Message: packMessage(e.Pack.Name, key),
			Detail:  "the pack allows only " + strings.Join(e.Pack.Harness.Allowed, ", "),
		}
	}
	return nil
}

// hostPortAllowed checks one host port: DefenseClaw's own listeners and the
// OpenClaw and OpenShell gateways (reservedPorts) are never opened; then the
// admin switch and the pack's host-port access apply.
func (e *Effective) hostPortAllowed(port int) error {
	const key = "mcp.host_ports"
	attempted := strconv.Itoa(port)
	if what, reserved := e.reservedPorts[port]; reserved {
		return &Violation{
			Key: key, Source: SourceUser, Attempted: attempted, Constraint: "defenseclaw",
			Message: fmt.Sprintf("DefenseClaw never opens %s (port %d) to a sandbox", what, port),
			Detail:  "choose another port",
		}
	}
	if isFalse(e.admin.AllowHostPorts) {
		return e.adminViolation(key, attempted, "openshell.admin.allow_host_ports",
			"host ports cannot be opened to sandboxes")
	}
	if e.Pack != nil && !e.Pack.MCP.HostPorts {
		return &Violation{
			Key: key, Source: SourceUser, Attempted: attempted, Constraint: "pack " + e.Pack.Name,
			Message: packMessage(e.Pack.Name, key), Detail: "the pack does not open host ports",
		}
	}
	return nil
}

// requiresCopy returns the openshell.admin.require_copy_for pattern that
// covers a mount of path (path, an ancestor, or a folder below it; see
// matchProjectPath), or "". An empty path matches nothing: Resolve treats a
// missing project as covered. The path is matched lexically and after
// resolving symbolic links, and each pattern's literal prefix is matched both
// as written and resolved, so a symlinked spelling of a covered project still
// matches.
func (e *Effective) requiresCopy(path string) string {
	if path == "" || len(e.admin.RequireCopyFor) == 0 {
		return ""
	}
	candidates := []string{filepath.Clean(path)}
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != candidates[0] {
		candidates = append(candidates, resolved)
	}
	for _, pattern := range e.admin.RequireCopyFor {
		for _, spelled := range patternSpellings(pattern, e.home) {
			for _, candidate := range candidates {
				if matchProjectPath(spelled, candidate, e.home) {
					return strings.TrimSpace(pattern)
				}
			}
		}
	}
	return ""
}

// EgressRule names the step of the egress decision order that decided.
type EgressRule string

const (
	// RuleInvalid: the destination is not a host name or IP address.
	RuleInvalid          EgressRule = "invalid"
	RuleAdminBlock       EgressRule = "admin_block"
	RuleAdminAllowOnly   EgressRule = "admin_allow_only"
	RulePort             EgressRule = "port"
	RuleBlock            EgressRule = "block"
	RuleFeed             EgressRule = "feed"
	RuleAllow            EgressRule = "allow"
	RuleNetworkOpen      EgressRule = "network_open"
	RuleNetworkAllowlist EgressRule = "network_allowlist"
	RuleNetworkDeny      EgressRule = "network_deny"
)

// EgressDecision is the effective policy's verdict for one destination.
type EgressDecision struct {
	Allowed bool       `json:"allowed"`
	Rule    EgressRule `json:"rule"`
	// Match is the host glob or feed entry that decided, if any.
	Match string `json:"match,omitempty"`
	// Unblockable says whether Allow(ActionUnblock) could lift a refusal.
	Unblockable bool `json:"unblockable"`
}

// FeedMatcher reports whether host is on one of the named blocklist feeds
// and which entry matched. The egress proxy supplies it from its feed data.
type FeedMatcher func(feeds []string, host string) (entry string, blocked bool)

// DecideEgress applies the effective egress posture to a destination host
// and port (0 skips the port check) in the documented order: admin block,
// admin allow-only, ports, the deny network mode, block, feeds (unless the
// host is on the allow list and openshell.admin.allow_unblock is not false),
// then the open or allowlist network mode. SSRF protection (loopback, private
// ranges, metadata, rebinding) is the proxy's job and runs before this.
func (e *Effective) DecideEgress(host string, port int, feed FeedMatcher) EgressDecision {
	h := strings.Trim(config.NormalizeOpenShellHostGlob(host), "[]")
	if e == nil || h == "" || strings.Contains(h, "*") {
		return EgressDecision{Rule: RuleInvalid}
	}
	eg := e.Egress
	if glob, ok := firstMatch(eg.AdminBlock, h); ok {
		return EgressDecision{Rule: RuleAdminBlock, Match: glob}
	}
	allowOnlyGlob, inAllowOnly := firstMatch(eg.AllowOnly, h)
	if len(eg.AllowOnly) > 0 && !inAllowOnly {
		return EgressDecision{Rule: RuleAdminAllowOnly}
	}
	if port != 0 && !containsInt(eg.Ports, port) {
		return EgressDecision{Rule: RulePort, Match: strconv.Itoa(port)}
	}
	if e.NetworkMode == NetworkDeny {
		return EgressDecision{Rule: RuleNetworkDeny}
	}
	unblockable := !isFalse(e.admin.AllowUnblock)
	if glob, ok := firstMatch(eg.Block, h); ok {
		return EgressDecision{Rule: RuleBlock, Match: glob, Unblockable: unblockable}
	}
	allowGlob, allowed := firstMatch(eg.Allow, h)
	// With unblocking forbidden, nothing lifts a feed entry.
	if (!allowed || !unblockable) && feed != nil && len(eg.Feeds) > 0 {
		if entry, blocked := feed(eg.Feeds, h); blocked {
			return EgressDecision{Rule: RuleFeed, Match: entry, Unblockable: unblockable}
		}
	}
	switch {
	case allowed:
		return EgressDecision{Allowed: true, Rule: RuleAllow, Match: allowGlob}
	case inAllowOnly:
		return EgressDecision{Allowed: true, Rule: RuleAdminAllowOnly, Match: allowOnlyGlob}
	case e.NetworkMode == NetworkOpen:
		return EgressDecision{Allowed: true, Rule: RuleNetworkOpen}
	default:
		return EgressDecision{Rule: RuleNetworkAllowlist, Unblockable: unblockable}
	}
}

// adminVerdict refuses a host the administrator blocked or left outside a
// non-empty allow-only list. No unblock or approval lifts these.
func (eg Egress) adminVerdict(key, host string) *Violation {
	if glob, ok := firstMatch(eg.AdminBlock, host); ok {
		return &Violation{
			Key: key, Source: SourceUser, Attempted: host, Constraint: "openshell.admin.egress_block",
			Message: adminMessage(key), Detail: host + " matches " + glob + " on your organization's blocklist",
		}
	}
	if len(eg.AllowOnly) > 0 {
		if _, ok := firstMatch(eg.AllowOnly, host); !ok {
			return &Violation{
				Key: key, Source: SourceUser, Attempted: host, Constraint: "openshell.admin.egress_allow_only",
				Message: adminMessage(key), Detail: host + " is not on your organization's list of allowed destinations",
			}
		}
	}
	return nil
}

func firstMatch(globs []string, host string) (string, bool) {
	for _, glob := range globs {
		if MatchHost(glob, host) {
			return glob, true
		}
	}
	return "", false
}

// validHost normalizes a destination host (lowercase, no trailing dot or
// brackets). It refuses globs, and names that end in a number but are not a
// canonical IP address ("127.1", "2130706433", "0x7f000001"): resolvers read
// those as IPv4 addresses, which would slip past every textual check.
func validHost(host string) (string, error) {
	h := config.NormalizeOpenShellHostGlob(host)
	if h == "" || h == "*" || strings.HasPrefix(h, "*.") {
		return "", fmt.Errorf("sandbox policy: %q is not a destination host", host)
	}
	if err := config.ValidateOpenShellHostGlob(h); err != nil {
		return "", fmt.Errorf("sandbox policy: %w", err)
	}
	h = strings.Trim(h, "[]")
	if net.ParseIP(h) == nil && endsInNumber(h) {
		return "", fmt.Errorf("sandbox policy: %q is neither a host name nor a canonical IP address", host)
	}
	return h, nil
}

// endsInNumber reports a host whose last label is decimal or 0x-hex, which
// URL parsers and inet_aton treat as an IPv4 address.
func endsInNumber(host string) bool {
	label := host[strings.LastIndex(host, ".")+1:]
	if hex, ok := strings.CutPrefix(label, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return label != "" && strings.Trim(label, "0123456789") == ""
}

func validPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("sandbox policy: port %d must be between 1 and 65535", port)
	}
	return nil
}

// hostLocalNames reach the host itself: the OpenShell and Docker host
// aliases and the loopback names distributions put in /etc/hosts.
var hostLocalNames = map[string]bool{
	OpenShellHostAlias:        true,
	"host.docker.internal":    true,
	"gateway.docker.internal": true,
	"localhost":               true,
	"localhost.localdomain":   true,
	"localhost4":              true,
	"localhost4.localdomain4": true,
	"localhost6":              true,
	"localhost6.localdomain6": true,
	"ip6-localhost":           true,
	"ip6-loopback":            true,
}

// metadataNames are cloud instance-metadata host names.
var metadataNames = map[string]bool{
	"metadata":                   true,
	"metadata.google.internal":   true,
	"metadata.goog":              true,
	"instance-data":              true,
	"instance-data.ec2.internal": true,
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isHostLocal reports a destination that is the host itself. host is
// normalized (validHost).
func (e *Effective) isHostLocal(host string) bool {
	if hostLocalNames[host] || strings.HasSuffix(host, ".localhost") || containsString(e.hostNames, host) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// neverApproved reports metadata host names and addresses no sandbox may
// reach directly even when private networks are allowed: link-local, cloud
// metadata and task-credential endpoints, multicast and reserved ranges.
func neverApproved(host string) bool {
	if metadataNames[host] {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return netguard.V8NetworkSafetyPolicy{AllowPrivateNetworks: true, AllowCGNAT: true}.ValidateIP(ip) != nil
}

// isPrivateAddress reports an RFC 1918, IPv6 ULA or RFC 6598 (CGNAT)
// address literal.
func isPrivateAddress(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsPrivate() || cgnatPrefix.Contains(addr)
}

func containsNormalized(names []string, harness string) bool {
	for _, name := range names {
		if config.NormalizeConnectorName(name) == harness {
			return true
		}
	}
	return false
}
