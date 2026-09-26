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

// Package policy renders the OpenShell sandbox policy DefenseClaw submits for
// a sandboxed harness: Landlock filesystem access, the non-root process
// identity and the network rules for the open, balanced and strict profiles.
//
// Credentialed endpoints (the DefenseClaw hook ingress and the harness LLM
// providers) are deliberately absent: OpenShell adds a `_provider_<id>` rule
// for every attached provider profile, and only those rules carry credential
// placeholder substitution. The renderer owns the rest, and output is
// deterministic so it can be golden-tested and compared across restarts
// (every OpenShell policy reload closes in-flight connections).
package policy

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

// Profile selects how much egress a sandbox gets.
type Profile string

const (
	// ProfileOpen is the default: web egress through the DefenseClaw proxy in
	// allow-by-default mode (blocklist, SSRF guard, logging).
	ProfileOpen Profile = "open"
	// ProfileBalanced keeps the proxy rule but the proxy runs in allowlist
	// mode; unknown hosts are triaged.
	ProfileBalanced Profile = "balanced"
	// ProfileStrict removes the proxy rule: provider endpoints only, every
	// other destination needs a manual approval.
	ProfileStrict Profile = "strict"
)

// ParseProfile accepts open, balanced or strict (case-insensitive); empty
// selects ProfileOpen.
func ParseProfile(s string) (Profile, error) {
	switch p := Profile(strings.ToLower(strings.TrimSpace(s))); p {
	case "":
		return ProfileOpen, nil
	case ProfileOpen, ProfileBalanced, ProfileStrict:
		return p, nil
	default:
		return "", fmt.Errorf("openshell policy: unknown profile %q (want open, balanced or strict)", s)
	}
}

// EgressMode is how the DefenseClaw egress proxy treats a profile's sandbox.
type EgressMode string

const (
	EgressAllowByDefault EgressMode = "allow-by-default"
	EgressAllowlist      EgressMode = "allowlist"
	EgressOff            EgressMode = "off"
)

// EgressModeFor returns the proxy mode that matches the rendered policy.
func EgressModeFor(p Profile) EgressMode {
	switch p {
	case ProfileBalanced:
		return EgressAllowlist
	case ProfileStrict:
		return EgressOff
	default:
		return EgressAllowByDefault
	}
}

// WorkdirMode is how the project reaches the sandbox.
type WorkdirMode string

const (
	// WorkdirMount bind-mounts the project live; the process runs as the
	// host uid so files keep the user's ownership.
	WorkdirMount WorkdirMode = "mount"
	// WorkdirCopy uploads a sanitized copy; the process runs as the image's
	// sandbox user.
	WorkdirCopy WorkdirMode = "copy"
)

// Mount is one bind-mount target inside the workload container. Targets
// under the workdir need no entry: Landlock cannot narrow a subtree of a
// read-write grant, so read-only over-mounts (git internals, secret masks)
// are enforced by the mount itself.
type Mount struct {
	Target   string
	ReadOnly bool
}

// Rule names the renderer reserves.
const (
	// EgressRuleName is the network_policies key of the proxy relay rule.
	EgressRuleName = "defenseclaw_egress"
	// EgressHost is how the workload reaches host loopback.
	EgressHost = "host.openshell.internal"
	// SandboxHome is the workload HOME in the community base image.
	SandboxHome = "/sandbox"
	// AnyBinary matches every executable in the workload.
	AnyBinary = "/**"
	// LandlockHardRequirement refuses to start on kernels without the
	// required Landlock ABI instead of silently running unconfined.
	LandlockHardRequirement = "hard_requirement"
)

// systemReadOnly is the read-only base every harness needs (measured with
// Claude Code 2.1.156 and Codex 0.146.0 on the community base image).
var systemReadOnly = []string{"/usr", "/lib", "/etc", "/proc", "/dev/urandom", "/var/log", "/opt"}

// baseReadWrite adds the scratch space, the null device and HOME; the PTY
// devices let interactive harnesses and PTY-backed tools open terminals
// (Landlock hides /dev entries that are not listed).
var baseReadWrite = []string{"/tmp", "/dev/null", "/dev/ptmx", "/dev/pts", "/dev/tty", SandboxHome}

// protectedTargets can never be a workdir or mount target.
var protectedTargets = []string{"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/run", "/sbin", "/sys", "/tmp", "/usr", "/var", SandboxHome}

// Input is everything a sandbox policy depends on.
type Input struct {
	Profile Profile
	// Harness is the connector the sandbox runs (claudecode, codex, ...).
	Harness string
	// Workdir is /work/<repo> in mount mode or the copy workdir.
	Workdir     string
	WorkdirMode WorkdirMode
	// Mounts are additional mount targets outside the workdir (context
	// directories are read-only).
	Mounts []Mount
	// RunAsUser/RunAsGroup are the numeric host uid/gid in mount mode and
	// the image's sandbox user in copy mode. Root is refused.
	RunAsUser  string
	RunAsGroup string
	// IngressPort is the host-loopback hook ingress. It is reached through
	// the defenseclaw-ingress provider rule, never a policy rule; the renderer
	// only checks it cannot collide with the egress port.
	IngressPort int
	// EgressPort is the DefenseClaw egress proxy (required unless strict).
	EgressPort int
	// HarnessReadOnly lists harness install roots outside the system base.
	HarnessReadOnly []string
	// ExtraRules are additional allow rules (for example consented host
	// ports). Keys must not use the reserved defenseclaw_ or _provider_
	// prefixes.
	ExtraRules map[string]v1.NetworkPolicyRule
}

var (
	ruleNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,62}$`)
	harnessRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	principalRE = regexp.MustCompile(`^(?:[0-9]{1,10}|[a-z_][a-z0-9_-]{0,31})$`)
	hostRE      = regexp.MustCompile(`^(?:\*\*\.|\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// Render builds the typed policy for in. The result is validated and
// deterministic: lists are sorted and de-duplicated.
func Render(in Input) (*v1.SandboxPolicy, error) {
	profile, err := ParseProfile(string(in.Profile))
	if err != nil {
		return nil, err
	}
	if !harnessRE.MatchString(in.Harness) {
		return nil, fmt.Errorf("openshell policy: invalid harness %q", in.Harness)
	}
	if in.WorkdirMode != WorkdirMount && in.WorkdirMode != WorkdirCopy {
		return nil, fmt.Errorf("openshell policy: unknown workdir mode %q", in.WorkdirMode)
	}
	if err := validateTarget("workdir", in.Workdir); err != nil {
		return nil, err
	}
	if in.WorkdirMode == WorkdirMount && !strings.HasPrefix(in.Workdir, "/work/") {
		return nil, fmt.Errorf("openshell policy: mount-mode workdir %q must live under /work/", in.Workdir)
	}
	if err := validatePrincipal("run_as_user", in.RunAsUser); err != nil {
		return nil, err
	}
	if err := validatePrincipal("run_as_group", in.RunAsGroup); err != nil {
		return nil, err
	}
	if in.WorkdirMode == WorkdirMount && (!isNumeric(in.RunAsUser) || !isNumeric(in.RunAsGroup)) {
		return nil, fmt.Errorf("openshell policy: mount mode runs as the numeric host uid/gid, got %q:%q", in.RunAsUser, in.RunAsGroup)
	}
	if err := validatePort("ingress", in.IngressPort); err != nil {
		return nil, err
	}
	if profile != ProfileStrict {
		if err := validatePort("egress", in.EgressPort); err != nil {
			return nil, err
		}
		if in.EgressPort == in.IngressPort {
			return nil, fmt.Errorf("openshell policy: egress and ingress share port %d", in.EgressPort)
		}
	}

	readOnly := append([]string(nil), systemReadOnly...)
	for _, p := range in.HarnessReadOnly {
		if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
			return nil, fmt.Errorf("openshell policy: harness path %q must be absolute and clean", p)
		}
		readOnly = append(readOnly, p)
	}
	readWrite := append(append([]string(nil), baseReadWrite...), in.Workdir)
	for _, m := range in.Mounts {
		if err := validateTarget("mount target", m.Target); err != nil {
			return nil, err
		}
		if within(m.Target, in.Workdir) {
			continue
		}
		if m.ReadOnly {
			readOnly = append(readOnly, m.Target)
		} else {
			readWrite = append(readWrite, m.Target)
		}
	}
	readWrite = collapsePaths(readWrite)
	readOnly = collapsePaths(readOnly, readWrite)

	rules := map[string]v1.NetworkPolicyRule{}
	if profile != ProfileStrict {
		rules[EgressRuleName] = v1.NetworkPolicyRule{
			Name: EgressRuleName,
			// A raw relay: OpenShell's HTTP parser rejects CONNECT addressed to
			// another host, so the proxy port is plain TCP with TLS inspection
			// skipped. Every binary may use it; the proxy authenticates the
			// sandbox and decides per destination.
			Endpoints: []v1.PolicyNetworkEndpoint{{
				Host:     EgressHost,
				Port:     uint32(in.EgressPort),
				Protocol: "tcp",
				TLS:      v1.NetworkTLSModeSkip,
			}},
			Binaries: []v1.PolicyNetworkBinary{{Path: AnyBinary}},
		}
	}
	names := make([]string, 0, len(in.ExtraRules))
	for name := range in.ExtraRules {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasPrefix(name, "defenseclaw_") || strings.HasPrefix(name, "_provider_") || !ruleNameRE.MatchString(name) {
			return nil, fmt.Errorf("openshell policy: rule name %q is reserved or invalid", name)
		}
		rule := cloneRule(in.ExtraRules[name])
		rule.Name = name
		for _, ep := range rule.Endpoints {
			if ep.Host == EgressHost && (int(ep.Port) == in.IngressPort || int(ep.Port) == in.EgressPort) {
				return nil, fmt.Errorf("openshell policy: rule %q may not target the DefenseClaw ingress or egress port", name)
			}
		}
		rules[name] = rule
	}

	policy := &v1.SandboxPolicy{
		Version: 1,
		Filesystem: &v1.FilesystemPolicy{
			IncludeWorkdir: true,
			ReadOnly:       readOnly,
			ReadWrite:      readWrite,
		},
		Landlock:        &v1.LandlockPolicy{Compatibility: LandlockHardRequirement},
		Process:         &v1.ProcessPolicy{RunAsUser: in.RunAsUser, RunAsGroup: in.RunAsGroup},
		NetworkPolicies: rules,
	}
	if err := Validate(policy); err != nil {
		return nil, err
	}
	return policy, nil
}

// Validate checks a typed policy against the constraints DefenseClaw relies
// on and OpenShell enforces at load time.
func Validate(p *v1.SandboxPolicy) error {
	if p == nil {
		return fmt.Errorf("openshell policy: nil policy")
	}
	if p.Version != 1 {
		return fmt.Errorf("openshell policy: version %d is not 1", p.Version)
	}
	if p.Landlock == nil || p.Landlock.Compatibility != LandlockHardRequirement {
		return fmt.Errorf("openshell policy: landlock must be %s", LandlockHardRequirement)
	}
	if p.Process == nil {
		return fmt.Errorf("openshell policy: process identity is required")
	}
	for label, v := range map[string]string{"run_as_user": p.Process.RunAsUser, "run_as_group": p.Process.RunAsGroup} {
		if err := validatePrincipal(label, v); err != nil {
			return err
		}
	}
	if p.Filesystem == nil {
		return fmt.Errorf("openshell policy: filesystem policy is required")
	}
	seen := map[string]string{}
	for label, list := range map[string][]string{"read_only": p.Filesystem.ReadOnly, "read_write": p.Filesystem.ReadWrite} {
		for _, entry := range list {
			if !path.IsAbs(entry) || path.Clean(entry) != entry || entry == "/" {
				return fmt.Errorf("openshell policy: %s path %q must be absolute, clean and not /", label, entry)
			}
			if other, dup := seen[entry]; dup {
				return fmt.Errorf("openshell policy: %q is listed in both %s and %s", entry, other, label)
			}
			seen[entry] = label
		}
	}
	if p.NetworkPolicies == nil {
		return fmt.Errorf("openshell policy: network_policies must be present (use an empty map)")
	}
	for name, rule := range p.NetworkPolicies {
		if !ruleNameRE.MatchString(name) {
			return fmt.Errorf("openshell policy: invalid rule name %q", name)
		}
		if rule.Name != "" && rule.Name != name {
			return fmt.Errorf("openshell policy: rule %q carries mismatched name %q", name, rule.Name)
		}
		if len(rule.Endpoints) == 0 || len(rule.Binaries) == 0 {
			return fmt.Errorf("openshell policy: rule %q needs endpoints and binaries", name)
		}
		for _, ep := range rule.Endpoints {
			if err := validateEndpoint(name, ep); err != nil {
				return err
			}
		}
		for _, b := range rule.Binaries {
			if !strings.HasPrefix(b.Path, "/") || strings.ContainsAny(b.Path, "\x00\n") {
				return fmt.Errorf("openshell policy: rule %q binary %q must be an absolute path or glob", name, b.Path)
			}
		}
	}
	if len(p.NetworkMiddlewares) != 0 {
		return fmt.Errorf("openshell policy: network middlewares are not rendered by DefenseClaw")
	}
	return nil
}

func validateEndpoint(rule string, ep v1.PolicyNetworkEndpoint) error {
	if !hostRE.MatchString(ep.Host) {
		return fmt.Errorf("openshell policy: rule %q host %q is invalid", rule, ep.Host)
	}
	ports := append([]uint32(nil), ep.Ports...)
	if ep.Port != 0 {
		ports = append(ports, ep.Port)
	}
	if len(ports) == 0 {
		return fmt.Errorf("openshell policy: rule %q endpoint %s has no port", rule, ep.Host)
	}
	for _, port := range ports {
		if port == 0 || port > 65535 {
			return fmt.Errorf("openshell policy: rule %q endpoint %s port %d is out of range", rule, ep.Host, port)
		}
	}
	switch ep.Protocol {
	case "tcp", "rest", "":
	default:
		return fmt.Errorf("openshell policy: rule %q protocol %q is not rendered by DefenseClaw", rule, ep.Protocol)
	}
	switch ep.TLS {
	case v1.NetworkTLSModeUnspecified, v1.NetworkTLSModeSkip:
	default:
		return fmt.Errorf("openshell policy: rule %q uses a TLS mode OpenShell rejects", rule)
	}
	if ep.Protocol == "tcp" && (ep.Access != v1.NetworkAccessPresetUnspecified || len(ep.Rules) != 0 || len(ep.DenyRules) != 0) {
		return fmt.Errorf("openshell policy: rule %q has L7 controls on a raw tcp endpoint", rule)
	}
	if ep.CredentialBinding != nil || ep.ProviderCredentialed || ep.AdvisorProposed {
		return fmt.Errorf("openshell policy: rule %q carries gateway-derived credential or advisor fields", rule)
	}
	return nil
}

func validateTarget(label, p string) error {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return fmt.Errorf("openshell policy: %s %q must be absolute and clean", label, p)
	}
	for _, protected := range protectedTargets {
		if p == protected || within(protected, p) || (protected != "/" && within(p, protected) && protected != SandboxHome) {
			return fmt.Errorf("openshell policy: %s %q overlaps system path %s", label, p, protected)
		}
	}
	return nil
}

func validatePrincipal(label, v string) error {
	if !principalRE.MatchString(v) {
		return fmt.Errorf("openshell policy: %s %q is not a uid/gid or account name", label, v)
	}
	if v == "0" || v == "root" {
		return fmt.Errorf("openshell policy: %s may not be root", label)
	}
	return nil
}

func validatePort(label string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("openshell policy: %s port %d is out of range", label, port)
	}
	return nil
}

func isNumeric(v string) bool {
	_, err := strconv.ParseUint(v, 10, 32)
	return err == nil
}

// within reports whether p is inside (or equal to) root.
func within(p, root string) bool {
	if root == "/" {
		return true
	}
	return p == root || strings.HasPrefix(p, root+"/")
}

// collapsePaths sorts and de-duplicates list and drops every entry already
// covered by another entry of list or of any cover list: Landlock grants are
// hierarchical unions, so a nested or already-writable entry adds nothing.
func collapsePaths(list []string, cover ...[]string) []string {
	sorted := append([]string(nil), list...)
	sort.Strings(sorted)
	out := make([]string, 0, len(sorted))
	for i, p := range sorted {
		if i > 0 && p == sorted[i-1] {
			continue
		}
		covered := false
		for _, other := range sorted {
			if other != p && within(p, other) {
				covered = true
				break
			}
		}
		for _, list := range cover {
			for _, other := range list {
				if within(p, other) {
					covered = true
				}
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

func cloneRule(r v1.NetworkPolicyRule) v1.NetworkPolicyRule {
	r.Endpoints = append([]v1.PolicyNetworkEndpoint(nil), r.Endpoints...)
	r.Binaries = append([]v1.PolicyNetworkBinary(nil), r.Binaries...)
	return r
}
