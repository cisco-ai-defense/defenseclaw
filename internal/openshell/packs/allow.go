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
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
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
	// Action.Host (and Action.Port) once.
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
	// AllowedIPs are an approval's allowed_ips entries: the addresses the
	// destination may resolve to. Set, they replace OpenShell's own
	// private-address check, so ranges DefenseClaw never opens are refused
	// and private ranges need openshell.admin.allow_unblock.
	AllowedIPs []string
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
		if e.requiredPack && e.Pack != nil && !e.Pack.Harness.Yolo {
			return e.adminViolation("yolo", "true", requiredPackConstraint,
				"the required "+e.Pack.Name+" sandbox pack keeps the harness permission prompts")
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

// allowUnblock checks an unblock against the egress decider the proxy
// uses (EgressOptions): the refusals it reports unblockable (the blocklist
// feed and the mode defaults) can be lifted, and so can a host it allows
// today (the unblock then only matters once the policy refuses it). The
// guard, the administrator's lists and the block list are never lifted.
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
	// The organization's and the user's own lists explain a refusal best,
	// whatever else would refuse the host too.
	if v := e.Egress.adminVerdict(key, host); v != nil {
		return v
	}
	if v := e.blockVerdict(key, host); v != nil {
		return v
	}
	d, err := e.policyDecider()
	if err != nil {
		return err
	}
	dec := d.DecideHost(policyProbe, host)
	if !dec.Allowed {
		switch dec.Source {
		case egress.SourceGuard:
			return guardViolation(key, host, dec)
		case egress.SourceAdmin:
			return e.adminRefusal(key, host, dec)
		case egress.SourceOperator:
			return e.blockRefusal(key, host, dec)
		}
	}
	if e.NetworkMode == NetworkDeny {
		return e.profileViolation(key, host, "the proxy is off, so destinations cannot be unblocked")
	}
	return nil
}

// guardViolation refuses what the egress proxy's guard never lets an
// unblock or approval open: this machine and what only it reaches, and
// private networks (only an allow entry opens those).
func guardViolation(key, host string, dec egress.Decision) error {
	switch dec.Category {
	case egress.CategoryHostInternal:
		return &Violation{
			Key: key, Source: SourceUser, Attempted: host, Constraint: "defenseclaw",
			Message: "DefenseClaw never opens this machine, link-local, cloud metadata or reserved addresses to a sandbox",
			Detail:  dec.Reason,
		}
	case egress.CategoryPrivateNetwork:
		return &Violation{
			Key: key, Source: SourceUser, Attempted: host, Constraint: "defenseclaw",
			Message: "unblocks never open private networks: " + key,
			Detail:  "add the exact host name or address to openshell.egress.allow to reach " + host,
		}
	}
	return fmt.Errorf("sandbox policy: %s is not a destination the egress proxy reaches: %s", host, dec.Reason)
}

// adminRefusal explains a refusal by the administrator's lists
// (egress.SourceAdmin).
func (e *Effective) adminRefusal(key, host string, dec egress.Decision) *Violation {
	if v := e.Egress.adminVerdict(key, host); v != nil {
		return v
	}
	constraint, detail := "openshell.admin.egress_allow_only", host+" is not on your organization's list of allowed destinations"
	if dec.Category == egress.CategoryAdminBlock {
		constraint, detail = "openshell.admin.egress_block", host+" matches "+dec.Rule+" on your organization's blocklist"
	}
	return &Violation{Key: key, Source: SourceUser, Attempted: host, Constraint: constraint, Message: adminMessage(key), Detail: detail}
}

// blockRefusal explains a refusal by the block list (egress.SourceOperator).
func (e *Effective) blockRefusal(key, host string, dec egress.Decision) *Violation {
	if v := e.blockVerdict(key, host); v != nil {
		return v
	}
	return &Violation{
		Key: key, Source: SourceUser, Attempted: host, Constraint: "openshell.egress.block",
		Message: "blocked by the sandbox's block list: " + key,
		Detail:  host + " matches " + dec.Rule + "; remove the entry to reach it",
	}
}

// blockVerdict refuses a host on the block list (the pack's egress.block and
// openshell.egress.block). The egress proxy applies those entries before any
// unblock decision, after only the guard and the administrator's lists, so
// neither an unblock nor an approval, which bypasses the proxy, may lift
// them: reaching the host takes removing the entry.
func (e *Effective) blockVerdict(key, host string) *Violation {
	glob, ok := firstMatch(e.Egress.Block, host)
	if !ok {
		return nil
	}
	if e.Pack != nil && MatchAnyHost(e.Pack.Egress.Block, host) {
		return &Violation{
			Key: key, Source: SourceUser, Attempted: host, Constraint: "pack " + e.Pack.Name,
			Message: packMessage(e.Pack.Name, key), Detail: host + " matches " + glob + " on the pack's block list",
		}
	}
	return &Violation{
		Key: key, Source: SourceUser, Attempted: host, Constraint: "openshell.egress.block",
		Message: "blocked by your own openshell.egress.block list: " + key,
		Detail:  host + " matches " + glob + "; remove the entry to reach it",
	}
}

// allowApproval gates an OpenShell draft proposal. An approval opens a
// direct OpenShell rule that bypasses the DefenseClaw egress proxy and its
// SSRF guard, so it is checked against what the proxy would enforce:
//   - the administrator's blocklist and allow-only list always apply;
//   - the host itself (host.openshell.internal, loopback addresses and
//     names, this machine's names and interface addresses) is a host-port
//     request;
//   - link-local, cloud metadata, multicast and reserved addresses are
//     never approved;
//   - other names the proxy treats as this machine (the guard's
//     host-internal names) are never approved;
//   - a destination on the block list (the pack's and the user's) is
//     never approved: no unblock lifts those entries either;
//   - when openshell.admin.allow_unblock is false, a destination on a
//     blocklist feed, or on a private network (an address, or an intranet
//     name the proxy refuses), is refused too: approving it would lift the
//     proxy's refusal.
//
// These checks see the host as named. What a name resolves to is checked by
// triage, when it decides and again when the approval is applied, with the
// proxy's own dial-time rules (egress.Decider.CheckAddrs).
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
	privateIPs := ""
	for _, entry := range action.AllowedIPs {
		_, class, err := e.AllowedIPReach(entry)
		if err != nil {
			return err
		}
		switch class {
		case AllowedIPNever:
			return &Violation{
				Key: key, Source: SourceUser, Attempted: entry, Constraint: "defenseclaw",
				Message: "DefenseClaw never opens loopback, link-local, cloud metadata, multicast or reserved addresses to a sandbox",
				Detail:  "allowed_ips entry " + entry + " includes some",
			}
		case AllowedIPHost:
			return &Violation{
				Key: key, Source: SourceUser, Attempted: entry, Constraint: "defenseclaw",
				Message: "DefenseClaw never opens this machine's own addresses to a sandbox",
				Detail:  "allowed_ips entry " + entry + " includes an address of this machine; list the exact addresses the sandbox needs",
			}
		case AllowedIPPrivate:
			if privateIPs == "" {
				privateIPs = entry
			}
		}
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
	d, err := e.policyDecider()
	if err != nil {
		return err
	}
	dec := d.DecideHost(policyProbe, host)
	switch dec.Category {
	case egress.CategoryHostInternal:
		return &Violation{
			Key: key, Source: SourceUser, Attempted: host, Constraint: "defenseclaw",
			Message: "DefenseClaw never opens this machine, link-local, cloud metadata or reserved addresses to a sandbox",
			Detail:  dec.Reason,
		}
	case egress.CategoryInvalidDestination:
		// A single-label name, which resolvers complete with the host's
		// search domains.
		return fmt.Errorf("sandbox policy: approving %s: %s", host, dec.Reason)
	}
	if v := e.blockVerdict(key, host); v != nil {
		return v
	}
	if !dec.Allowed {
		switch dec.Source {
		case egress.SourceAdmin:
			return e.adminRefusal(key, host, dec)
		case egress.SourceOperator:
			return e.blockRefusal(key, host, dec)
		}
	}
	if !unblockForbidden {
		return nil
	}
	if !dec.Allowed && dec.Source == egress.SourceFeed {
		return e.adminViolation(key, host, "openshell.admin.allow_unblock",
			host+" is on the blocklist feed ("+dec.Entry+"), and blocked destinations cannot be approved")
	}
	if dec.Category == egress.CategoryPrivateNetwork {
		return e.adminViolation(key, host, "openshell.admin.allow_unblock",
			host+" is on a private network, which the egress proxy refuses")
	}
	if isPrivateAddress(host) {
		return e.adminViolation(key, host, "openshell.admin.allow_unblock",
			host+" is a private network address, which the egress proxy refuses")
	}
	if privateIPs != "" {
		return e.adminViolation(key, host, "openshell.admin.allow_unblock",
			"allowed_ips entry "+privateIPs+" includes private network addresses, which the egress proxy refuses")
	}
	return nil
}

// AllowedIPClass is how an allowed_ips range relates to the networks
// DefenseClaw guards.
type AllowedIPClass int

const (
	// AllowedIPPublic ranges hold only public addresses.
	AllowedIPPublic AllowedIPClass = iota
	// AllowedIPPrivate ranges overlap RFC 1918, CGNAT or IPv6 ULA space:
	// the user's own network.
	AllowedIPPrivate
	// AllowedIPNever ranges overlap addresses no sandbox may reach
	// directly: loopback, link-local, cloud metadata, multicast, reserved
	// and IPv4-translation ranges.
	AllowedIPNever
	// AllowedIPHost ranges hold one of this machine's own interface
	// addresses (Effective.AllowedIPReach): a sandbox never reaches the
	// host's services through them.
	AllowedIPHost
)

// AllowedIPReach classifies an allowed_ips entry as the egress proxy's
// guard would: the fixed ranges first (ClassifyAllowedIP), then this
// machine's own interface addresses, which a range must not hold
// (AllowedIPHost), and the public subnets they sit on, whose other hosts are
// this machine's local network (AllowedIPPrivate). A non-empty allowed_ips
// replaces OpenShell's own connect-time private-address check for its rule,
// and a name the rule allows may resolve to any address in it later, so the
// range as a whole is judged, not the addresses the name resolves to now.
func (e *Effective) AllowedIPReach(entry string) (netip.Prefix, AllowedIPClass, error) {
	prefix, class, err := ClassifyAllowedIP(entry)
	if err != nil || class == AllowedIPNever {
		return prefix, class, err
	}
	d, err := e.policyDecider()
	if err != nil {
		return prefix, AllowedIPNever, err
	}
	own, subnet := d.LocalReach(prefix)
	switch {
	case own:
		return prefix, AllowedIPHost, nil
	case subnet.IsValid():
		return prefix, AllowedIPPrivate, nil
	}
	return prefix, class, nil
}

// ClassifyAllowedIP parses an allowed_ips entry (an address or a CIDR
// range) and classifies it by the widest reach it grants: a range that
// only partly overlaps a guarded network (8.0.0.0/5 holds 10.0.0.0/8)
// counts as that network.
func ClassifyAllowedIP(entry string) (netip.Prefix, AllowedIPClass, error) {
	entry = strings.TrimSpace(entry)
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		addr, aerr := netip.ParseAddr(entry)
		if aerr != nil || addr.Zone() != "" {
			return netip.Prefix{}, AllowedIPNever, fmt.Errorf("sandbox policy: allowed_ips entry %q is not an address or CIDR range", entry)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is6() && mappedPrefix.Overlaps(prefix) {
		if prefix.Bits() < mappedPrefix.Bits() {
			// Wider than the IPv4-mapped block: it holds every IPv4 address.
			return prefix, AllowedIPNever, nil
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-mappedPrefix.Bits())
	}
	for _, never := range neverOpenPrefixes {
		if never.Overlaps(prefix) {
			return prefix, AllowedIPNever, nil
		}
	}
	for _, private := range privatePrefixes {
		if private.Overlaps(prefix) {
			return prefix, AllowedIPPrivate, nil
		}
	}
	return prefix, AllowedIPPublic, nil
}

var (
	mappedPrefix = netip.MustParsePrefix("::ffff:0:0/96")
	// neverOpenPrefixes mirror netguard's v8 address policy with private
	// networks allowed, plus what the sandbox guard alone refuses
	// (egress.NeverReachPrefixes): what stays prohibited is never approved.
	neverOpenPrefixes = append([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("100.100.100.200/32"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/96"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}, egress.NeverReachPrefixes()...)
	privatePrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		cgnatPrefix,
		netip.MustParsePrefix("fc00::/7"),
	}
)

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
	if e.requiredPack && e.Pack != nil && e.Pack.Workspace.Mode == config.OpenShellWorkdirCopy {
		return e.adminViolation(key, "mount "+path, requiredPackConstraint,
			"the required "+e.Pack.Name+" sandbox pack works on a copy of the project; host folders are not mounted")
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

// validHost canonicalizes a destination host: a name lowercased without a
// trailing dot, an IP address in canonical form without brackets and with an
// IPv4-mapped IPv6 address unmapped, so every spelling of an address meets
// the same checks. It refuses globs and CIDR prefixes, and names whose last
// label does not start with a letter ("127.1", "2130706433", "0x7f000001"):
// resolvers read those as IPv4 addresses, which would slip past every
// textual check (config.ParseOpenShellEgressPattern).
func validHost(host string) (string, error) {
	pattern, err := config.ParseOpenShellEgressPattern(host)
	switch {
	case err == nil && (pattern.Wildcard || strings.Contains(host, "/")):
		return "", fmt.Errorf("sandbox policy: %q is not a destination host", host)
	case err != nil:
		return "", fmt.Errorf("sandbox policy: %q is neither a host name nor a canonical IP address", host)
	}
	return pattern.String(), nil
}

func validPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("sandbox policy: port %d must be between 1 and 65535", port)
	}
	return nil
}

// hostLocalNames reach the host itself: the OpenShell, Docker and Podman host
// aliases and the loopback names distributions put in /etc/hosts.
var hostLocalNames = map[string]bool{
	OpenShellHostAlias:         true,
	"host.docker.internal":     true,
	"gateway.docker.internal":  true,
	"host.containers.internal": true,
	"localhost":                true,
	"localhost.localdomain":    true,
	"localhost4":               true,
	"localhost4.localdomain4":  true,
	"localhost6":               true,
	"localhost6.localdomain6":  true,
	"ip6-localhost":            true,
	"ip6-loopback":             true,
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

// interfaceAddrs lists this machine's interface addresses; swapped in tests.
var interfaceAddrs = net.InterfaceAddrs

// isHostLocal reports a destination that is the host itself: a host alias,
// a loopback name or address, the unspecified address, one of this machine's
// names, or an address on one of its interfaces (a Docker bridge gateway such
// as 172.17.0.1, a LAN, VPC or VPN address), which reaches every host service
// listening on all interfaces. host is canonical (validHost). The interface
// list is read on every call, so an address that came up after Resolve (a
// VPN) counts too; when it cannot be read, only the other checks apply.
func (e *Effective) isHostLocal(host string) bool {
	if hostLocalNames[host] || strings.HasSuffix(host, ".localhost") || containsString(e.hostNames, host) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if addr = addr.Unmap(); addr.IsLoopback() || addr.IsUnspecified() {
		return true
	}
	if neverApproved(host) {
		// A link-local interface address stays never approved.
		return false
	}
	list, err := interfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range list {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if own, ok := netip.AddrFromSlice(ip); ok && own.Unmap() == addr {
			return true
		}
	}
	return false
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
