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

package manager

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// resolve resolves the effective sandbox policy for flags against the
// current configuration.
func (m *Manager) resolve(cfg *config.Config, flags packs.Flags) (*packs.Effective, []packs.Violation, error) {
	eff, violations, err := packs.Resolve(cfg, flags)
	if err != nil {
		m.logf("%s: %v", gatewaylog.ErrCodeOpenShellPackInvalid, err)
		return nil, nil, &sandboxapi.Error{Code: sandboxapi.CodePackInvalid, Message: "the sandbox policy pack is invalid", Detail: err.Error()}
	}
	return eff, violations, nil
}

// resolveBox re-resolves a sandbox's policy against the current config, so
// an administrator change applies to running sandboxes.
func (m *Manager) resolveBox(b *box) (*packs.Effective, error) {
	eff, _, err := m.resolveBoxViolations(b)
	return eff, err
}

// resolveBoxViolations is resolveBox with the clamps and refusals the
// current configuration applies to the sandbox's run flags. A sandbox whose
// policy no longer resolves fails closed (policyUnresolved) until it does
// again (policyRestored).
func (m *Manager) resolveBoxViolations(b *box) (*packs.Effective, []packs.Violation, error) {
	m.mu.Lock()
	rec, unrecorded := b.rec, b.unrecorded
	m.mu.Unlock()
	if unrecorded {
		err := errUnrecorded(rec.Name)
		m.policyUnresolved(b, err)
		return nil, nil, err
	}
	cfg := m.config()
	eff, violations, err := m.resolve(cfg, rec.Flags.packs(rec.Harness, rec.Project, m.gatewayPort()))
	if err == nil {
		err = m.checkPolicySources(rec.WorkdirMode, rec.Project, eff)
	}
	var d *egress.Decider
	if err == nil {
		d, err = m.egressDecider(cfg, eff)
	}
	if err != nil {
		m.policyUnresolved(b, err)
		return nil, nil, err
	}
	m.mu.Lock()
	b.eff, b.decider = eff, d
	failed := b.policyErr != ""
	b.policyErr = ""
	m.mu.Unlock()
	if failed {
		m.policyRestored(b, eff)
	}
	return eff, violations, nil
}

// errUnrecorded is why a sandbox adopted without a record has no policy:
// resolving it under the default pack would silently drop the pack,
// profile and flags it was created with (a stricter posture among them).
func errUnrecorded(name string) error {
	return &sandboxapi.Error{Code: sandboxapi.CodeConflict,
		Message: "DefenseClaw has no readable record of sandbox " + name + ", so the policy it was created with is unknown",
		Detail:  "the pack, profile and run flags it was created with are lost; delete it and run a new sandbox"}
}

// checkPolicySources refuses a policy the sandbox could rewrite. In mount
// mode the agent writes the project as the host user, and a custom pack is
// trusted because that user owns it (packs.LoadFile), so a pack file or
// pack directory inside the project (or holding it) would let the agent
// change its own policy on the next resolution: add allow entries that
// lift the blocklist feed or open private networks, drop block entries,
// relax the network mode. Create refuses such a mount (PlanMount with the
// policy sources protected); every later resolution checks again, because
// the configuration (openshell.pack_dir, openshell.pack) can move the
// policy under a running sandbox, which then fails closed.
func (m *Manager) checkPolicySources(mode, project string, eff *packs.Effective) error {
	if mode != config.OpenShellWorkdirMount || project == "" {
		return nil
	}
	for _, src := range eff.PolicySources() {
		if workspace.Overlaps(project, src) {
			m.logf("%s: the sandbox policy source %s overlaps the mounted project %s", gatewaylog.ErrCodeOpenShellPackInvalid, src, project)
			return &sandboxapi.Error{Code: sandboxapi.CodePackInvalid,
				Message: "the sandbox policy pack is inside the project folder the sandbox writes, so the agent could change its own policy",
				Detail:  src + " overlaps " + project + "; keep custom packs outside the project (for example in openshell.pack_dir), or run with --copy"}
		}
	}
	return nil
}

// policyUnresolved fails a sandbox closed while its policy cannot be
// resolved: its custom pack was deleted or edited into one that no longer
// loads, or the configuration no longer accepts one of its run flags. The
// administrator's egress lists live only in each sandbox's own decider, so
// serving the sandbox with the decider of its last good policy would keep
// it out of every later tightening. Instead its cached policy is dropped
// (triage and approvals resolve it again and refuse while that fails) and
// its egress proxy credential is revoked, so the proxy refuses the sandbox
// altogether, as in the deny network mode. enforceAll judges its approved
// OpenShell rules by the organization's policy alone (orgPolicy). The first
// failure (and every different one) is logged with
// OPENSHELL_PACK_INVALID, recorded as degraded health and published to the
// feed.
func (m *Manager) policyUnresolved(b *box, err error) {
	detail := err.Error()
	var apiErr *sandboxapi.Error
	if errors.As(err, &apiErr) && apiErr.Detail != "" {
		detail = apiErr.Detail
	}
	m.mu.Lock()
	b.eff, b.decider = nil, nil
	changed := b.policyErr != detail
	b.policyErr = detail
	name, bindingID, skip := b.rec.Name, b.rec.BindingID, b.creating || b.deleted
	id := b.identity()
	m.mu.Unlock()
	if skip {
		return
	}
	if bindingID != "" {
		m.creds.Revoke(bindingID)
	}
	if !changed {
		return
	}
	m.logf("%s: sandbox %s: its policy cannot be resolved; its egress is blocked until it can: %s",
		gatewaylog.ErrCodeOpenShellPackInvalid, name, detail)
	if err := m.tel.RecordSandboxHealth(context.Background(), audit.SandboxHealthEvent{
		Sandbox: id, State: audit.SandboxHealthDegraded, ErrorCode: errorToken(gatewaylog.ErrCodeOpenShellPackInvalid),
		ErrorSummary: truncate("the sandbox policy cannot be resolved: "+detail, 512), Timestamp: m.now(),
	}); err != nil {
		m.logf("health telemetry for %s: %v", name, err)
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Source: sandboxapi.SourceProxy,
		Reason: policyUnresolvedReason, Message: truncate("✗ all web egress: the sandbox policy cannot be resolved ("+detail+
			"); fix the pack or the configuration, or delete the sandbox", 512)})
}

// policyUnresolvedReason is the feed reason of a sandbox that fails closed
// because its policy cannot be resolved.
const policyUnresolvedReason = "policy_unresolved"

// policyRestored re-registers the egress proxy credential of a sandbox
// whose policy resolves again, with its rebuilt decider.
func (m *Manager) policyRestored(b *box, eff *packs.Effective) {
	m.mu.Lock()
	name, skip := b.rec.Name, b.creating || b.deleted
	id := b.identity()
	m.mu.Unlock()
	if skip {
		return
	}
	m.syncCredential(b, eff)
	m.logf("sandbox %s: its policy resolves again; its egress follows it", name)
	if err := m.tel.RecordSandboxHealth(context.Background(), audit.SandboxHealthEvent{
		Sandbox: id, State: audit.SandboxHealthRestored, Timestamp: m.now(),
	}); err != nil {
		m.logf("health telemetry for %s: %v", name, err)
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Reason: "policy_restored",
		Message: "the sandbox policy resolves again; its egress follows it"})
}

// orgPolicy resolves what binds a sandbox whose own policy cannot be
// resolved: the administrator's constraints (openshell.admin, including a
// required pack) and DefenseClaw's own, which do not depend on the pack the
// user chose, under the built-in default pack with the sandbox's harness,
// project and gateway port.
func (m *Manager) orgPolicy(b *box) (*packs.Effective, error) {
	m.mu.Lock()
	rec := b.rec
	m.mu.Unlock()
	eff, _, err := packs.Resolve(m.config(), packs.Flags{
		Pack: packs.DefaultPack, Harness: rec.Harness, Project: rec.Project, OpenShellGatewayPort: m.gatewayPort(),
	})
	return eff, err
}

// checkStart refuses to start a sandbox the current policy would not let
// the user create: a harness, a live mount or learn mode the organization
// disallowed since. Skip-permissions mode is not refused; the launch
// settings follow the re-resolved policy (see launchYolo).
func (m *Manager) checkStart(ctx context.Context, rec record, eff *packs.Effective, violations []packs.Violation) error {
	if v := packs.FirstFatal(violations); v != nil {
		return m.violationError(ctx, v, rec.Name)
	}
	actions := []packs.Action{packActionHarness(rec.Harness)}
	if rec.WorkdirMode == config.OpenShellWorkdirMount && rec.Project != "" {
		actions = append(actions, packs.Action{Kind: packs.ActionMount, Path: rec.Project})
		for _, c := range rec.Flags.Context {
			actions = append(actions, packs.Action{Kind: packs.ActionMount, Path: c})
		}
	}
	if rec.Flags.Learn {
		actions = append(actions, packs.Action{Kind: packs.ActionLearnMode})
	}
	for _, a := range actions {
		if err := eff.Allow(a); err != nil {
			return m.violationError(ctx, err, rec.Name)
		}
	}
	if rec.WorkdirMode == config.OpenShellWorkdirMount && eff.Workspace.Mode != config.OpenShellWorkdirMount {
		// The mount is part of the sandbox; it cannot become a copy.
		for i := range violations {
			if violations[i].Key == "workdir.mode" {
				return m.violationError(ctx, &violations[i], rec.Name)
			}
		}
		return &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation,
			Message: "the sandbox policy now runs this project in copy mode; delete the sandbox and run it again"}
	}
	return nil
}

// enforceApprovedRules removes the approved OpenShell rules the current
// policy would refuse to approve now: destinations the administrator
// blocked or left off an allow-only list, host ports and private networks
// the administrator closed, what DefenseClaw never opens, destinations the
// sandbox's egress decider now refuses by a block list or the blocklist
// feed with no unblock lifting it (the user's or the pack's block list, a
// new feed entry, an "always" unblock taken back), and names that now
// resolve to this machine (the proxy's dial-time guard, re-applied on
// every reconcile). Approved rules bypass the egress proxy, so an
// administrator change or a changed DNS answer must reach them too. Only
// triaged rules (allow_*) are judged; DefenseClaw renders its own and the
// provider rules. A nil eff means no policy binds the sandbox at all (not
// even the organization's, see enforceAll): every triaged rule is removed.
func (m *Manager) enforceApprovedRules(ctx context.Context, gw *Gateway, b *box, eff *packs.Effective) {
	m.mu.Lock()
	name, ready := b.rec.Name, b.phase == audit.SandboxPhaseReady && !b.deleted && !b.creating
	m.mu.Unlock()
	if !ready {
		return
	}
	cfg, err := gw.Client.SandboxConfig(ctx, name)
	if err != nil || cfg == nil || cfg.Policy == nil {
		return
	}
	var ops []openshell.PolicyMergeOperation
	var removed, blocked, rebound, unbound []string
	var pol triage.Policy
	var decider *egress.Decider
	if eff != nil {
		pol = m.triagePolicy(b, eff)
		if decider = pol.Decider; decider == nil {
			decider, _ = eff.EgressDecider(nil)
		}
	}
	// The DNS re-check runs on the reconcile path: a slow resolver skips
	// the rest of it (keeping the rules) rather than stalling the loop.
	dnsCtx, cancel := context.WithTimeout(ctx, enforceDNSBudget)
	defer cancel()
	for ruleName, rule := range cfg.Policy.NetworkPolicies {
		if !strings.HasPrefix(ruleName, "allow_") {
			continue
		}
		p := triage.FromChunk(name, openshell.PolicyChunk{RuleName: ruleName, ProposedRule: &rule})
		switch {
		case eff == nil:
			unbound = append(unbound, ruleName)
		case orgRefusal(triage.CheckProposal(eff, p, false)):
			removed = append(removed, ruleName)
		case blocklisted(decider, pol.Principal, p):
			blocked = append(blocked, ruleName)
		case triage.ResolvesToHost(dnsCtx, p, pol):
			rebound = append(rebound, ruleName)
		default:
			continue
		}
		ops = append(ops, openshell.PolicyMergeOperation{RemoveRule: &v1.RemoveNetworkRule{RuleName: ruleName}})
	}
	if len(ops) == 0 {
		return
	}
	sort.Strings(removed)
	sort.Strings(blocked)
	sort.Strings(rebound)
	sort.Strings(unbound)
	all := append(append(append(append([]string{}, removed...), blocked...), rebound...), unbound...)
	reason, code := "admin-policy", string(gatewaylog.ErrCodeOpenShellAdminViolation)
	switch {
	case len(removed) > 0:
	case len(blocked) > 0:
		reason, code = "blocklist", "SANDBOX_RULE_BLOCKLISTED"
	case len(rebound) > 0:
		reason, code = "resolves-to-host", "SANDBOX_RULE_RESOLVES_TO_HOST"
	default:
		reason, code = "policy-unresolved", string(gatewaylog.ErrCodeOpenShellPackInvalid)
	}
	res, err := gw.Client.MergePolicy(ctx, name, ops, openshell.PolicyUpdateOptions{
		Annotations: map[string]string{"source": "defenseclaw", "reason": reason},
	})
	if err != nil {
		m.logf("%s: sandbox %s: remove rules the policy now refuses (%s): %v", code, name, strings.Join(all, ", "), err)
		return
	}
	m.logf("%s: sandbox %s: removed approved rules the policy now refuses: %s", code, name, strings.Join(all, ", "))
	m.mu.Lock()
	id := b.identity()
	if b.sb != nil && res != nil && res.Version != 0 {
		b.sb.Status.CurrentPolicyVersion = res.Version
		id.PolicyVersion = res.Version
	}
	m.mu.Unlock()
	// One mandatory record per removed rule: the record's target names one
	// rule (a bounded identifier), and the revision is the same for all.
	for _, list := range []struct {
		rules  []string
		reason string
	}{{removed, policyReasonAdmin}, {blocked, policyReasonBlocklist}, {rebound, policyReasonResolvesToHost}, {unbound, policyReasonUnresolved}} {
		for _, rule := range list.rules {
			ev := audit.SandboxPolicyEvent{Sandbox: id, Operation: audit.SandboxPolicyRuleRemove, Actor: "policy", Origin: "internal",
				Target: rule, Reason: list.reason, ChangeCount: 1, Timestamp: m.now()}
			if res != nil {
				ev.PolicyHash = res.PolicyHash
			}
			if err := m.tel.RecordSandboxPolicy(ctx, ev); err != nil {
				m.logf("policy telemetry for %s of %s: %v", rule, name, err)
			}
		}
	}
	if len(removed) > 0 {
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Source: sandboxapi.SourceOpenShell,
			Reason: "admin_policy", Message: fmt.Sprintf("removed %d approved rule(s) %s", len(removed), sandboxapi.AdminMessage)})
	}
	if len(blocked) > 0 {
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Source: sandboxapi.SourceOpenShell,
			Reason: string(triage.ReasonBlocklisted), Message: fmt.Sprintf(
				"removed %d approved rule(s) to destinations now on the egress block list: %s", len(blocked), strings.Join(blocked, ", "))})
	}
	if len(rebound) > 0 {
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Source: sandboxapi.SourceOpenShell,
			Reason: string(triage.ReasonResolvesToHost), Message: fmt.Sprintf(
				"removed %d approved rule(s) whose destination now resolves to this machine: %s", len(rebound), strings.Join(rebound, ", "))})
	}
	if len(unbound) > 0 {
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Source: sandboxapi.SourceOpenShell,
			Reason: policyUnresolvedReason, Message: fmt.Sprintf(
				"removed %d approved rule(s): neither the sandbox's nor your organization's policy can be resolved", len(unbound))})
	}
}

// blocklisted reports a proposal with a destination the sandbox's decider
// refuses by a block list (the administrator's, the user's, the pack's)
// or the blocklist feed, with no unblock lifting it: triage rejects such a
// proposal, so a rule approved before the block must go too. Refusals of
// the proxy's guard (this machine, private networks) are not judged here:
// the user may have approved those doors on purpose.
func blocklisted(d *egress.Decider, pr egress.Principal, p triage.Proposal) bool {
	if d == nil {
		return false
	}
	for _, ep := range p.Endpoints {
		host := triage.NormalizeHost(ep.Host)
		if host == "" || triage.IsHostLocal(host) {
			continue
		}
		dec := d.DecideHost(pr, host)
		if !dec.Allowed && (dec.Source == egress.SourceAdmin || dec.Source == egress.SourceOperator || dec.Source == egress.SourceFeed) {
			return true
		}
	}
	return false
}

// enforceDNSBudget bounds the DNS re-check of one sandbox's approved rules.
const enforceDNSBudget = 20 * time.Second

// orgRefusal reports a refusal by the administrator or a DefenseClaw
// invariant, as opposed to the user's own pack or profile.
func orgRefusal(err error) bool {
	var v *packs.Violation
	return errors.As(err, &v) && (v.Admin() || v.Constraint == "defenseclaw")
}

// launchYolo reports whether the harness may start in skip-permissions
// mode: the sandbox was created with it and the current policy still
// allows it. Callers hold Manager.mu.
func launchYolo(b *box) bool {
	return b.rec.Yolo && b.eff != nil && b.eff.Yolo
}

func (m *Manager) gatewayPort() int {
	return int(m.gwPort.Load())
}

// policyGatewayPort is the OpenShell gateway port a sandbox policy
// reserves: the registration's, else the local gateway's default, the
// same fallback packs.Resolve applies to Flags.OpenShellGatewayPort
// (policy.Render refuses an unresolved zero).
func policyGatewayPort(port int) int {
	if port > 0 {
		return port
	}
	return packs.OpenShellGatewayPort
}

// violationError turns a policy refusal into the API error, logging admin
// refusals with their gateway error code.
func (m *Manager) violationError(ctx context.Context, err error, sandbox string) error {
	var v *packs.Violation
	if !errors.As(err, &v) {
		return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: err.Error()}
	}
	wire := wireViolation(*v)
	if v.Admin() {
		m.logf("%s: sandbox %s: %s", gatewaylog.ErrCodeOpenShellAdminViolation, sandbox, v.Error())
		_ = m.tel.RecordSandboxHealth(ctx, audit.SandboxHealthEvent{
			State: audit.SandboxHealthDegraded, ErrorCode: errorToken(gatewaylog.ErrCodeOpenShellAdminViolation),
			ErrorSummary: truncate(v.Key+": "+v.Constraint, 512), Timestamp: m.now(),
		})
		msg := v.Message
		if msg == "" {
			msg = sandboxapi.AdminMessage
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: msg, Detail: v.Detail, Violation: &wire}
	}
	return &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation, Message: v.Message, Detail: v.Detail, Violation: &wire}
}

func wireViolation(v packs.Violation) sandboxapi.Violation {
	return sandboxapi.Violation{
		Key: v.Key, Source: string(v.Source), Attempted: v.Attempted, Enforced: v.Enforced,
		Constraint: v.Constraint, Fatal: v.Fatal, Admin: v.Admin(), Message: v.Message, Detail: v.Detail,
	}
}

func wireViolations(list []packs.Violation) []sandboxapi.Violation {
	out := make([]sandboxapi.Violation, 0, len(list))
	for _, v := range list {
		out = append(out, wireViolation(v))
	}
	return out
}

func wireAdmin(a packs.AdminStatus) sandboxapi.AdminStatus {
	return sandboxapi.AdminStatus{Configured: a.Configured, Authority: string(a.Authority), Detail: a.Detail}
}

// Explain resolves a sandbox posture with provenance.
func (m *Manager) Explain(_ context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error) {
	cfg := m.config()
	var flags packs.Flags
	if req.Sandbox != "" {
		b, err := m.box(req.Sandbox)
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		rec := b.rec
		m.mu.Unlock()
		flags = rec.Flags.packs(rec.Harness, rec.Project, m.gatewayPort())
	} else {
		project := req.Project
		if project != "" {
			if !filepath.IsAbs(project) {
				return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "project must be an absolute path")
			}
			if real, err := filepath.EvalSymlinks(project); err == nil {
				project = real
			}
		}
		flags = packs.Flags{
			Harness: config.NormalizeConnectorName(req.Harness), Pack: req.Pack, Profile: req.Profile, Project: project,
			Copy: req.Copy, Safe: req.Safe, Yolo: req.Yolo, Unmask: req.Unmask, OpenShellGatewayPort: m.gatewayPort(),
		}
	}
	eff, violations, err := m.resolve(cfg, flags)
	if err != nil {
		return nil, err
	}
	out := &sandboxapi.Explain{
		Profile: eff.Profile, NetworkMode: eff.NetworkMode, Approvals: eff.Approvals,
		Admin: wireAdmin(eff.Admin), Violations: wireViolations(violations),
	}
	if eff.Pack != nil {
		out.Pack, out.PackSource, out.PackDigest = eff.Pack.Name, eff.Pack.Source, eff.Pack.Digest
	}
	for _, s := range eff.Explain() {
		out.Settings = append(out.Settings, sandboxapi.Setting{
			Key: s.Key, Value: s.Value, Source: string(s.Source), Origin: s.Origin, Requested: s.Requested,
		})
	}
	return out, nil
}

// baseEffective is the configured posture without run flags; the egress
// proxy's global rules and the status come from it.
func (m *Manager) baseEffective(cfg *config.Config) (*packs.Effective, error) {
	eff, _, err := m.resolve(cfg, packs.Flags{OpenShellGatewayPort: m.gatewayPort()})
	return eff, err
}
