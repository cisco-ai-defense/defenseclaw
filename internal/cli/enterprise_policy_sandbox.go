// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/posixacl"
)

// The sandbox rows of `enterprise <os> policy verify --user U`: whether the
// profile U gets requires a sandbox for an agent, whether the machine-policy
// route can refuse a host run of it, and whether the account can start a
// sandbox at all (docker or kvm group). They read; a failing row marks the
// report incomplete only where a required agent could not run anywhere.

// Row states.
const (
	sandboxRowOK   = "ok"
	sandboxRowWarn = "warn"
	sandboxRowFail = "fail"
)

type enterprisePolicySandbox struct {
	Profile string `json:"profile"`
	Match   string `json:"match,omitempty"`
	Group   string `json:"matched_group,omitempty"`
	// Note says why the profile is not known (the gateway did not answer).
	Note string `json:"note,omitempty"`
	// EnrollmentExempt says enterprise.enrollment.exempt_users exempts the
	// account as the hook socket matches it (the gateway's answer or its
	// uid or account-database name): required_for refuses none of its host runs (GAP-0555).
	EnrollmentExempt bool `json:"enrollment_exempt,omitempty"`
	// FloorDigest is the digest of the resolved sandbox floor F, Pack and
	// PackDigest the required pack it names and that pack's content digest,
	// and Sources the layer each sandbox key comes from (organization or
	// profile), as profile-explain's effective.sandbox gives them.
	FloorDigest string                       `json:"floor_digest,omitempty"`
	Pack        string                       `json:"required_pack,omitempty"`
	PackDigest  string                       `json:"required_pack_digest,omitempty"`
	Sources     map[string]string            `json:"sources,omitempty"`
	Rows        []enterprisePolicySandboxRow `json:"rows"`
}

type enterprisePolicySandboxRow struct {
	Check     string `json:"check"`
	Connector string `json:"connector,omitempty"`
	State     string `json:"state"`
	Detail    string `json:"detail"`
}

// enterprisePolicySandboxProfile asks the gateway which profile an account
// gets and whether exempt_users exempts it, as its hooks are matched (the
// same answer as profile-explain); replaceable in tests.
var enterprisePolicySandboxProfile = func(account string) (name, match, group string, exempt bool, err error) {
	var answer struct {
		Profile      string `json:"profile"`
		Match        string `json:"match"`
		MatchedGroup string `json:"matched_group"`
		LookupError  string `json:"lookup_error"`
		Enrollment   struct {
			Exempt bool `json:"exempt"`
		} `json:"enrollment"`
	}
	if _, err := enterpriseIdentityViewGet("/api/v1/guardrail/profiles/resolve?user="+url.QueryEscape(account), &answer); err != nil {
		return "", "", "", false, err
	}
	if answer.LookupError != "" {
		return answer.Profile, answer.Match, answer.MatchedGroup, answer.Enrollment.Exempt, fmt.Errorf("%s", answer.LookupError)
	}
	return answer.Profile, answer.Match, answer.MatchedGroup, answer.Enrollment.Exempt, nil
}

// enterpriseAccountGroups names the groups of an account (accountGroupNames
// of this OS); replaceable in tests.
var enterpriseAccountGroups = accountGroupNames

// enterpriseKVMDevice is the device a MicroVM opens; replaceable in tests.
var enterpriseKVMDevice = "/dev/kvm"

// enterpriseKVMAccess says how the account uid can read and write
// enterpriseKVMDevice other than through the kvm group: its mode opens it to
// every account, or a user ACL entry grants it. "" when neither does, and
// the kvm group decides; an ACL entry that names the account and denies it
// is no access either (GAP-0714, as the lifecycle's groups row judges it).
func enterpriseKVMAccess(uid int) string {
	info, err := os.Stat(enterpriseKVMDevice)
	if err != nil {
		return ""
	}
	if info.Mode().Perm()&0o006 == 0o006 {
		return "it is open to every account"
	}
	if acl, err := posixacl.ReadAccessXattr(enterpriseKVMDevice); err == nil {
		if found, allowed := acl.NamedUserAllows(uid, 0o6); found && allowed {
			return "a user ACL entry grants it"
		}
	}
	return ""
}

// sandboxPolicyConfigured reports whether c carries any sandbox policy: an
// organization key, a profile overlay, or sandboxes turned on.
func sandboxPolicyConfigured(c *config.Config) bool {
	if c == nil {
		return false
	}
	if c.OpenShell.Enabled || !c.OpenShell.Admin.IsZero() {
		return true
	}
	for _, p := range c.Guardrail.Profiles {
		if p.Sandbox != nil && !p.Sandbox.IsZero() {
			return true
		}
	}
	return false
}

// buildEnterprisePolicySandbox builds the sandbox rows for one account; nil
// when the configuration has no sandbox policy at all (no noise on installs
// that do not use sandboxes).
func buildEnterprisePolicySandbox(c *config.Config, goos, account string, uid int, states []enterprisepolicy.State) *enterprisePolicySandbox {
	if !sandboxPolicyConfigured(c) || goos == "windows" {
		return nil
	}
	out := &enterprisePolicySandbox{Rows: []enterprisePolicySandboxRow{}}
	name, match, group, exempt, err := enterprisePolicySandboxProfile(account)
	if err != nil {
		out.Note = "the profile of " + account + " could not be resolved (" + err.Error() + "); the organization's keys apply as the default profile would"
	}
	// The local uid/account-name rule is a subset of the hook's rule and
	// covers older gateways that omit enrollment on a no-profile answer.
	// Discard any partial gateway bit on an error; root follows enrollment.root.
	exempt = uid != 0 && ((err == nil && exempt) || gateway.EnrollmentExemptFromSandbox(c.Enterprise.Enrollment, uid, account))
	out.Profile, out.Match, out.Group, out.EnrollmentExempt = name, match, group, exempt
	view := sandboxPolicyOf(c, name)
	floor := view.floor
	if !view.hasFloor {
		// Without the resolved floor the rows use what both layers say.
		floor = view.base
		if view.overlay != nil {
			floor.RequiredFor = unionSorted(floor.RequiredFor, view.overlay.RequiredFor)
			if view.overlay.Allowed != nil && !*view.overlay.Allowed {
				floor.Allowed = view.overlay.Allowed
			}
		}
	}
	add := func(check, connector, state, detail string) {
		out.Rows = append(out.Rows, enterprisePolicySandboxRow{Check: check, Connector: connector, State: state, Detail: detail})
	}
	if floor.Allowed != nil && !*floor.Allowed {
		detail := "sandboxes are not allowed for this account; a required agent is refused outright"
		if len(floor.RequiredFor) > 0 && gateway.RequireSandboxHostGate(floor.RequiredFor, floor.RequiredFor[0], exempt) == gateway.RequireSandboxHostRunExempt {
			detail = "sandboxes are not allowed for this account; its exempt host runs remain allowed"
		}
		add("allowed", "", sandboxRowWarn, detail)
	}
	byConnector := map[string]enterprisepolicy.State{}
	for _, s := range states {
		byConnector[s.Connector] = s
	}
	// required: some agent's host run is refused, so where no sandbox can
	// start for the account that agent runs nowhere.
	required := false
	for _, conn := range floor.RequiredFor {
		// The hook's own rule decides the host run (GAP-0555).
		if gateway.RequireSandboxHostGate(floor.RequiredFor, conn, exempt) == gateway.RequireSandboxHostRunExempt {
			add("required", conn, sandboxRowWarn, "required_for lists it, but the account is exempt from enrollment (enterprise.enrollment.exempt_users), "+
				"so required_for doesn't apply: a host run is allowed, and its calls are inspected and logged")
			continue
		}
		required = true
		state, known := byConnector[conn]
		switch {
		case known && state.Route == enterprisepolicy.RouteMachinePolicy && state.Covered:
			add("required", conn, sandboxRowOK, "runs only in a sandbox; a host run is refused (the machine policy hook covers it)")
		case known && state.Route == enterprisepolicy.RouteMachinePolicy:
			add("required", conn, sandboxRowFail, "runs only in a sandbox, but its machine policy is not in place, so a host run is not refused")
		default:
			add("required", conn, sandboxRowWarn, "runs only in a sandbox, but this computer has no machine-owned hook for it: a host run is refused only where the account's own hook is installed")
		}
	}
	// A pack or floor that does not resolve stops every sandbox of the
	// profile: a failure where a required agent then runs nowhere, a
	// warning otherwise.
	broken := sandboxRowWarn
	if required {
		broken = sandboxRowFail
	}
	out.Sources = view.Sources
	addRequiredPackRow(out, c, uid, floor, view.Sources["required_pack"], broken)
	switch {
	case view.FloorError != "":
		add("floor", "", broken, "the sandbox floor of "+profileLabel(name)+" does not resolve, so none of its sandboxes start: "+view.FloorError)
	case view.hasFloor:
		out.FloorDigest = view.Digest
		add("floor", "", sandboxRowOK, "the sandbox floor of "+profileLabel(name)+" resolves to "+view.Digest+"; "+sandboxSourcesSummary(view.Sources))
	}
	if goos == "linux" && uid >= 0 {
		driver := c.Enterprise.OpenShell.SandboxDriver(goos)
		fallback := c.Enterprise.OpenShell.SandboxDriverFallback(goos, floor)
		// The MicroVM driver needs read-write access to /dev/kvm, which the
		// kvm group, a user ACL or an open mode gives; its agent images are
		// built in Docker for each account, so it needs docker too, as do
		// the docker driver and the docker fallback (GAP-0511, GAP-0714).
		// essential: without it no sandbox of the account starts at all.
		type groupNeed struct {
			group, what string
			essential   bool
		}
		var needs []groupNeed
		switch driver {
		case config.EnterpriseOpenShellDriverDocker:
			needs = []groupNeed{{"docker", "docker driver", true}}
		case config.EnterpriseOpenShellDriverVM, config.EnterpriseOpenShellDriverAuto:
			docker := "MicroVM agent images, which are built in Docker for each account"
			if fallback == config.EnterpriseOpenShellFallbackDocker {
				docker += ", and the docker fallback where KVM is not available"
			}
			needs = []groupNeed{
				{"kvm", driver + " driver", driver == config.EnterpriseOpenShellDriverVM || fallback != config.EnterpriseOpenShellFallbackDocker},
				{"docker", docker, true},
			}
		}
		var groups []string
		var gerr error
		if len(needs) > 0 {
			groups, gerr = enterpriseAccountGroups(uid)
		}
		for _, need := range needs {
			if need.group == "kvm" {
				// Access decides, not the group alone (GAP-0714).
				if how := enterpriseKVMAccess(uid); how != "" {
					add("kvm group", "", sandboxRowOK, "the account can read and write /dev/kvm ("+how+"), so its MicroVM sandboxes can start ("+need.what+")")
					continue
				}
			}
			switch {
			case gerr != nil:
				add(need.group+" group", "", sandboxRowWarn, "the groups of the account could not be read: "+gerr.Error())
			case slices.Contains(groups, need.group):
				add(need.group+" group", "", sandboxRowOK, "the account is in the "+need.group+" group, so its sandboxes can start ("+need.what+")")
			default:
				state := sandboxRowWarn
				if required && need.essential {
					state = sandboxRowFail
				}
				detail := "the account is not in the " + need.group + " group, so no sandbox can start for it on the " + need.what
				if need.group == "kvm" {
					detail = "the account cannot read and write /dev/kvm (it is not in the kvm group and no user ACL grants it), so no MicroVM can start for it on the " + need.what
					if !need.essential {
						detail += "; it gets the docker fallback"
					}
				}
				add(need.group+" group", "", state, detail+"; `usermod -aG "+need.group+" "+account+"`, then it signs in again")
			}
		}
	}
	return out
}

// addRequiredPackRow checks the required pack the floor names: it loads (as
// the gateway loads it, with the administrator-owned file rule on a managed
// deployment), and its content matches required_pack_digest. A pack nobody
// pinned is a warning that names the digest to pin. source is the layer that
// set required_pack.
func addRequiredPackRow(out *enterprisePolicySandbox, c *config.Config, uid int, floor config.OpenShellAdminConfig, source, broken string) {
	ref := strings.TrimSpace(floor.RequiredPack)
	if ref == "" {
		return
	}
	out.Pack = ref
	add := func(state, detail string) {
		out.Rows = append(out.Rows, enterprisePolicySandboxRow{Check: "required pack", State: state, Detail: detail})
	}
	from := ""
	if source != "" {
		from = ", set by the " + source
	}
	// The account's own subject, as the gateway resolves for it; it has no
	// home here, so a "~/" pack refuses (a managed pack is the policy dir's).
	pack, err := packs.LoadRequired(packs.Subject{UID: uid}, ref, c.OpenShell.PackDir, managed.IsManagedEnterprise(c.DeploymentMode))
	if err != nil {
		add(broken, "the required pack "+ref+from+" does not load, so no sandbox under it starts: "+err.Error())
		return
	}
	out.PackDigest = pack.Digest
	switch pin := strings.TrimSpace(floor.RequiredPackDigest); {
	case pin == "":
		add(sandboxRowWarn, fmt.Sprintf("the required pack %s (%s%s) is present with digest %s, but nothing pins it; set required_pack_digest: %q",
			pack.Name, pack.Source, from, pack.Digest, pack.Digest))
	case pin != pack.Digest:
		add(broken, fmt.Sprintf("the required pack %s (%s%s) has digest %s, not the pinned required_pack_digest %s, so no sandbox under it starts",
			pack.Name, pack.Source, from, pack.Digest, pin))
	default:
		add(sandboxRowOK, fmt.Sprintf("the required pack %s (%s%s) is present and matches the pinned digest %s", pack.Name, pack.Source, from, pin))
	}
}

// profileLabel names a profile in a row; "" is the organization's floor.
func profileLabel(name string) string {
	if name == "" {
		return "the organization (no profile)"
	}
	return "profile " + name
}

// sandboxSourcesSummary lists the sandbox keys by the layer they come from,
// in name order so a rerun prints the same row.
func sandboxSourcesSummary(sources map[string]string) string {
	byLayer := map[string][]string{}
	for key, layer := range sources {
		byLayer[layer] = append(byLayer[layer], key)
	}
	if len(byLayer) == 0 {
		return "no sandbox keys are set"
	}
	layers := make([]string, 0, len(byLayer))
	for layer := range byLayer {
		layers = append(layers, layer)
	}
	slices.Sort(layers)
	parts := make([]string, 0, len(layers))
	for _, layer := range layers {
		keys := byLayer[layer]
		slices.Sort(keys)
		parts = append(parts, "from the "+layer+": "+strings.Join(keys, ", "))
	}
	return strings.Join(parts, "; ")
}

func unionSorted(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// failed reports a failing row.
func (s *enterprisePolicySandbox) failed() bool {
	if s == nil {
		return false
	}
	for _, r := range s.Rows {
		if r.State == sandboxRowFail {
			return true
		}
	}
	return false
}

// sandboxMatchSuffix is " (matched by group X)" for a verify line.
func sandboxMatchSuffix(sb *enterprisePolicySandbox) string {
	if sb.Match == "" {
		return ""
	}
	text := " (matched by " + sb.Match
	if sb.Group != "" {
		text += " " + sb.Group
	}
	return text + ")"
}
