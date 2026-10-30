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
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
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
	cfg := m.configForSandbox(rec.Name)
	if cfg == nil {
		err := sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the managed policy for sandbox %s is not confirmed", rec.Name)
		m.policyUnresolved(b, err)
		return nil, nil, err
	}
	eff, violations, err := m.resolve(cfg, rec.Flags.packs(rec.Harness, rec.Project, m.recordFacts(rec)))
	if err == nil {
		err = m.checkPolicySources(rec.WorkdirMode, rec.Project, eff)
	}
	var d *egress.Decider
	if err == nil {
		d, err = m.egressDeciderFor(cfg, eff, m.registrationOf(b))
	}
	if err != nil {
		m.policyUnresolved(b, err)
		return nil, nil, err
	}
	m.mu.Lock()
	b.eff, b.decider, b.violations = eff, d, violations
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
// trusted because that user owns it (packs.Validate), so a pack file or
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
// its egress proxy credential is suspended, so the proxy refuses the sandbox
// altogether (with a 403 that names the reason), as in the deny network
// mode. enforceAll judges its approved
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
	b.eff, b.decider, b.violations = nil, nil, nil
	changed := b.policyErr != detail
	b.policyErr = detail
	name, bindingID, skip := b.rec.Name, b.rec.BindingID, b.creating || b.deleted
	cred, sandboxID := b.cred, scopeID(b.rec.ID, b.rec.Name)
	id := b.identity()
	// A sandbox that is not running sends nothing under the policy, and its
	// start refuses with the reason: its record is no alert (GAP-0160).
	severity := ""
	if cmp.Or(b.phase, audit.SandboxPhase(b.rec.Phase)) != audit.SandboxPhaseReady {
		severity = "MEDIUM"
	}
	m.mu.Unlock()
	if skip {
		return
	}
	if bindingID != "" {
		// The proxy answers the sandbox's requests with the reason (a 403)
		// rather than the 407 of a credential it does not know.
		why := egress.Decision{Category: egress.CategoryEgressOff, Source: egress.SourceDefault,
			Reason: truncate("the sandbox policy cannot be resolved ("+detail+"); fix the pack or the configuration, or delete the sandbox", 512)}
		if cred.Username == "" || m.creds.Suspend(cred, m.principal(bindingID, sandboxID, name, nil, nil), why) != nil {
			m.creds.Revoke(bindingID)
		}
		m.recheckEgress(bindingID)
	}
	if !changed {
		return
	}
	m.logf("%s: sandbox %s: its policy cannot be resolved; its egress is blocked until it can: %s",
		gatewaylog.ErrCodeOpenShellPackInvalid, name, detail)
	m.tel.RecordSandboxHealth(context.Background(), audit.SandboxHealthEvent{
		Sandbox: id, State: audit.SandboxHealthDegraded, ErrorCode: errorToken(gatewaylog.ErrCodeOpenShellPackInvalid), Severity: severity,
		ErrorSummary: truncate("the sandbox policy cannot be resolved: "+truncate(detail, 320)+". Restore the pack or the configuration, "+
			"or delete the sandbox: defenseclaw sandbox delete "+name, 512), Timestamp: m.now(),
	})
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
	m.tel.RecordSandboxHealth(context.Background(), audit.SandboxHealthEvent{
		Sandbox: id, State: audit.SandboxHealthRestored, Timestamp: m.now(),
	})
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
	cfg := m.configForSandbox(rec.Name)
	if cfg == nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the managed policy for sandbox %s is not confirmed", rec.Name)
	}
	eff, _, err := packs.Resolve(cfg, packs.Flags{
		Pack: packs.DefaultPackFor(cfg), Harness: rec.Harness, Project: rec.Project, OpenShellGatewayPort: m.gatewayPort(),
	})
	return eff, err
}

// checkStart refuses to start a sandbox the current policy would not let
// the user create: a harness, a live mount or learn mode the organization
// disallowed since. Skip-permissions mode is not refused; the launch
// settings follow the re-resolved policy (see launchYolo). A sandbox created
// on another compute driver than gw runs is refused before it
// (driverStartRefusal).
func (m *Manager) checkStart(ctx context.Context, gw *Gateway, rec record, eff *packs.Effective, violations []packs.Violation) error {
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
	if gw.Driver.SandboxLimits {
		if v := resourceViolation(rec.Resources, eff.MaxResources()); v != nil {
			return m.violationError(ctx, v, rec.Name)
		}
	} else if _, v := m.driverResources(gw.Driver, eff); v != nil {
		// What every sandbox of the driver gets now, not what it got at
		// create: the gateway-wide values may have changed since.
		return m.violationError(ctx, v, rec.Name)
	}
	// The providers the sandbox was created with must still be ones the
	// floor allows (allowed_credentials), and what the --llm and
	// --credential providers open around the egress proxy is judged by the
	// policy as it is now, as at create.
	if v := credentialsRefusal(m.floor(eff), rec.CredentialProfile, len(rec.Credentials) > 0); v != nil {
		return m.violationError(ctx, v, rec.Name)
	}
	for _, ep := range rec.ProviderEndpoints {
		if err := endpointRefusal(eff, ep); err != nil {
			var v *packs.Violation
			if errors.As(err, &v) {
				return m.violationError(ctx, v, rec.Name)
			}
			return err
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

// driverStartRefusal refuses to start a sandbox on a gateway that runs
// another compute driver than the one it was created on: one gateway runs
// one driver, and the sandbox (a container, or a MicroVM and its disk)
// belongs to the other one. A pull starts the sandbox, so its work is
// reachable only on a gateway that runs that driver again. A live mount is
// refused on a driver that mounts no host folders, too.
func driverStartRefusal(gw *Gateway, rec record) error {
	if created := recordDriver(rec); created != gw.Driver.Name {
		return sandboxapi.Errorf(sandboxapi.CodeConflict,
			"sandbox %[1]s was created on the %[2]s driver; this gateway now runs %[3]s, and one gateway runs one driver. "+
				"Its work can be pulled only on a %[2]s gateway (switch back with `defenseclaw sandbox setup`), "+
				"or drop it with `defenseclaw sandbox delete %[1]s`", rec.Name, created, gw.Driver.Name)
	}
	if rec.WorkdirMode == config.OpenShellWorkdirMount && !gw.Driver.HostMounts {
		return &sandboxapi.Error{Code: sandboxapi.CodeConflict,
			Message: "sandbox " + rec.Name + " mounts its project live, which this gateway's compute driver cannot; delete it and run it again",
			Detail:  gw.Driver.MountRefusal}
	}
	return nil
}

// resourceViolation reports a sandbox whose resource limits (fixed in its
// template when it was created, record.Resources) exceed the organization's
// current openshell.admin.max_resources: the template cannot change, so the
// sandbox must not start again under the larger (or no) limit. Records from
// before the limits were recorded (nil) are not judged.
func resourceViolation(applied *packs.Resources, max config.OpenShellResourcesConfig) *packs.Violation {
	if applied == nil {
		return nil
	}
	for _, q := range []struct {
		key, have, limit string
		parse            func(string) (int64, error)
	}{
		{"resources.cpu", applied.CPU, max.CPU, config.ParseOpenShellCPU},
		{"resources.memory", applied.Memory, max.Memory, config.ParseOpenShellMemory},
	} {
		limit := strings.TrimSpace(q.limit)
		if limit == "" {
			continue
		}
		ceiling, err := q.parse(limit)
		if err != nil {
			continue // the resolver refuses a malformed maximum on its own
		}
		have := strings.TrimSpace(q.have)
		over := have == ""
		if over {
			have = "no limit"
		} else if n, err := q.parse(have); err != nil || n > ceiling {
			over = true
		}
		if !over {
			continue
		}
		what := strings.TrimPrefix(q.key, "resources.")
		return &packs.Violation{Key: q.key, Source: packs.SourceUser, Attempted: have, Enforced: limit,
			Constraint: "openshell.admin.max_resources", Fatal: true,
			Message: "your organization now caps sandbox " + what + " at " + limit + ", and this sandbox was created with " + have +
				"; delete it and run it again",
			Detail: "a sandbox's resource limits are fixed when it is created"}
	}
	return nil
}

// enforceApprovedRules removes the OpenShell rules the current policy would
// refuse to approve now, judging every rule DefenseClaw did not put there
// itself (its own defenseclaw_* rules and the provider rules _provider_*,
// see ownRule), whatever its name or how it got there: destinations the
// administrator blocked or left off an allow-only list, host ports and private networks
// the administrator closed, what DefenseClaw never opens, destinations the
// sandbox's egress decider now refuses by a block list or the blocklist
// feed with no unblock lifting it (the user's or the pack's block list, a
// new feed entry, an "always" unblock taken back), rules DefenseClaw
// approved on its own that the policy now leaves to the user (a stricter
// approvals or network mode, such as an administrator's required strict
// pack, a destination off the allow list, an unblock taken back; see
// triage.ApprovesAutomatically), and names that now resolve where the
// proxy's dial-time rules refuse (triage.RecheckResolved, on every
// reconcile): to this machine, to an address a block list or the
// administrator refuses, or, for a rule DefenseClaw approved on its own,
// to a private network, which only the user approves. Approved rules
// bypass the egress proxy, so an administrator change or a changed DNS
// answer must reach them too. The user's own approvals keep what the
// policy still lets the user approve, unless the floor's user_approvals is
// none: then every rule the user approved goes. In managed mode a rule
// DefenseClaw neither rendered nor approved, and no saved decision of the
// person covers, is foreign (added through OpenShell's own API, say): it
// is removed and reported (foreignRules), and a repeat stops the sandbox.
// So is a rule there in DefenseClaw's or a provider's name that DefenseClaw
// did not render or attach, or one of its own whose destinations changed.
// A nil eff means no policy binds the sandbox at all (not even the
// organization's, see enforceAll): every such rule is removed.
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
	// Who approved each rule is read after the policy: an approval applied
	// in between is then known, not taken for a foreign rule.
	m.mu.Lock()
	rec := b.rec
	applying := m.applyingRules(name)
	m.mu.Unlock()
	origins := rec.ApprovedRules
	managedDaemon := m.authority() != nil
	f := m.floor(eff)
	noUserRules := strings.EqualFold(strings.TrimSpace(f.UserApprovals), config.OpenShellUserApprovalsNone)
	var decided map[string]bool
	var own map[string]v1.NetworkPolicyRule
	if managedDaemon {
		decided = decidedHosts(m.savedDecisions(m.registrationOf(b), f))
		own = m.renderedOwnRules(rec)
	}
	// A rule no longer in the policy (removed outside DefenseClaw) loses
	// its recorded approver: a rule of that name added later is not the
	// one that was approved.
	var gone []string
	for rule := range origins {
		if _, ok := cfg.Policy.NetworkPolicies[rule]; !ok {
			gone = append(gone, rule)
		}
	}
	var ops []openshell.PolicyMergeOperation
	var removed, blocked, unapproved, rebound, unbound, foreign, revoked []string
	// revokedTo is the destination of each revoked rule: the feed names it.
	revokedTo := map[string]triage.Endpoint{}
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
		if ownRule(managedDaemon, own, rec.Providers, ruleName, rule) {
			continue
		}
		p := triage.FromChunk(name, openshell.PolicyChunk{RuleName: ruleName, ProposedRule: &rule})
		origin, approved := origins[ruleName]
		automatic := origin == actorAutomatic
		switch {
		case managedDaemon && reservedRuleName(ruleName):
			// In DefenseClaw's or a provider's name, yet not what DefenseClaw
			// rendered or attached: no decision of the person covers it.
			foreign = append(foreign, ruleName)
		case managedDaemon && !approved && !applying[ruleName] && !coveredByDecisions(p, decided):
			foreign = append(foreign, ruleName)
		case noUserRules && origin == actorOperator:
			revoked = append(revoked, ruleName)
			if len(p.Endpoints) > 0 {
				revokedTo[ruleName] = p.Endpoints[0]
			}
		case eff == nil:
			unbound = append(unbound, ruleName)
		case orgRefusal(triage.CheckProposal(eff, p, false)):
			removed = append(removed, ruleName)
		case blocklisted(decider, pol.Principal, p):
			blocked = append(blocked, ruleName)
		case automatic && !triage.ApprovesAutomatically(ctx, p, pol):
			unapproved = append(unapproved, ruleName)
		default:
			// What the names resolve to now, as the proxy would check it
			// at dial time: a direct rule has no such check.
			switch triage.RecheckResolved(dnsCtx, p, pol) {
			case triage.ReasonResolvesToHost:
				rebound = append(rebound, ruleName)
			case triage.ReasonAdmin:
				removed = append(removed, ruleName)
			case triage.ReasonBlocklisted:
				blocked = append(blocked, ruleName)
			case triage.ReasonPrivateNetwork:
				// Only the user approves a private network: a rule
				// DefenseClaw approved on its own for a name that now
				// resolves to one asks again.
				if !automatic {
					continue
				}
				unapproved = append(unapproved, ruleName)
			default:
				continue
			}
		}
		ops = append(ops, openshell.PolicyMergeOperation{RemoveRule: &v1.RemoveNetworkRule{RuleName: ruleName}})
	}
	if len(ops) == 0 {
		m.forgetApprovedRules(b, gone)
		return
	}
	sort.Strings(removed)
	sort.Strings(blocked)
	sort.Strings(unapproved)
	sort.Strings(rebound)
	sort.Strings(unbound)
	sort.Strings(foreign)
	sort.Strings(revoked)
	all := slices.Concat(removed, blocked, unapproved, rebound, unbound, foreign, revoked)
	reason, code := "admin-policy", string(gatewaylog.ErrCodeOpenShellAdminViolation)
	switch {
	case len(foreign) > 0:
		reason = "foreign-rule"
	case len(revoked) > 0 && len(removed) == 0:
		reason = "user-approvals-none"
	case len(removed) > 0:
	case len(blocked) > 0:
		reason, code = "blocklist", "SANDBOX_RULE_BLOCKLISTED"
	case len(unapproved) > 0:
		reason, code = "approval-required", "SANDBOX_RULE_NEEDS_APPROVAL"
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
		m.forgetApprovedRules(b, gone)
		return
	}
	m.logf("%s: sandbox %s: removed approved rules the policy now refuses: %s", code, name, strings.Join(all, ", "))
	m.forgetApprovedRules(b, append(gone, all...))
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
	}{{removed, policyReasonAdmin}, {blocked, policyReasonBlocklist}, {unapproved, policyReasonApprovalRequired},
		{rebound, policyReasonResolvesToHost}, {unbound, policyReasonUnresolved}, {foreign, policyReasonForeignRule},
		{revoked, policyReasonAdmin}} {
		for _, rule := range list.rules {
			ev := audit.SandboxPolicyEvent{Sandbox: id, Operation: audit.SandboxPolicyRuleRemove, Actor: "policy", Origin: "internal",
				Target: rule, Reason: list.reason, ChangeCount: 1, Timestamp: m.now()}
			if res != nil {
				ev.PolicyHash = res.PolicyHash
			}
			m.tel.RecordSandboxPolicy(ctx, ev)
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
	if len(unapproved) > 0 {
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Source: sandboxapi.SourceOpenShell,
			Reason: policyReasonApprovalRequired, Message: fmt.Sprintf(
				"removed %d rule(s) DefenseClaw approved on its own that the sandbox policy now leaves to you: %s; "+
					"the agent asks again if it needs them", len(unapproved), strings.Join(unapproved, ", "))})
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
	for _, rule := range revoked {
		// One line per destination the user had approved, with the managed
		// refusal under it: a line without a host read "✗  (admin policy)"
		// (GAP-0468).
		ep := revokedTo[rule]
		host := triage.NormalizeHost(ep.Host)
		msg := "removed the rule you approved for " + firstNonEmpty(sandboxapi.HostPort(host, ep.Port), rule) +
			": your profile doesn't let you approve sandbox access"
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Source: sandboxapi.SourceOpenShell,
			Host: host, Port: ep.Port, Reason: "admin_policy", Message: "✗ " + msg,
			Refusal: m.accessRefusal(b, f, "", sandboxreg.RuleUserApprovals, host)})
		m.managedAccessRefused(ctx, b, host, ep.Port, sandboxreg.RuleUserApprovals, accessRefusedRuleRemoved)
	}
	if len(foreign) > 0 {
		m.foreignRules(ctx, b, foreign)
	}
}

// policyReasonForeignRule: a network rule DefenseClaw neither rendered nor
// approved, and no saved decision covers, was removed (managed mode).
const policyReasonForeignRule = "foreign_rule"

// ownRulePrefix starts the names of the rules policy.Render gives a sandbox
// of its own (policy.EgressRuleName, policy.IngressRuleName).
const ownRulePrefix = "defenseclaw_"

// reservedRuleName reports a rule name DefenseClaw and OpenShell reserve:
// DefenseClaw's own rules and the provider rules.
func reservedRuleName(name string) bool {
	return strings.HasPrefix(name, ownRulePrefix) || strings.HasPrefix(name, providerRulePrefix)
}

// ownRule reports a rule DefenseClaw put in the sandbox's policy itself,
// which enforcement leaves alone. Outside managed mode that is every rule
// with a reserved name. On a managed daemon a name proves nothing (a rule
// added through OpenShell's own API can take any), so it is a
// defenseclaw_* rule whose destinations and binaries are those
// policy.Render gives the sandbox (own, renderedOwnRules), or the provider
// rule of a provider DefenseClaw attached to it (providers).
func ownRule(managed bool, own map[string]v1.NetworkPolicyRule, providers []string, name string, rule v1.NetworkPolicyRule) bool {
	switch {
	case !reservedRuleName(name):
		return false
	case !managed:
		return true
	case strings.HasPrefix(name, providerRulePrefix):
		return providerRuleOf(name, providers)
	}
	want, ok := own[name]
	return ok && slices.Equal(ruleReach(want), ruleReach(rule))
}

// providerRuleOf reports the provider rule OpenShell adds for one of
// providers: _provider_ and the provider's name with '-' spelled '_'
// (_provider_<sandbox>_llm for <sandbox>-llm).
func providerRuleOf(name string, providers []string) bool {
	key := strings.TrimPrefix(name, providerRulePrefix)
	for _, p := range providers {
		if p != "" && key == strings.ReplaceAll(p, "-", "_") {
			return true
		}
	}
	return false
}

// renderedOwnRules are the rules of its own (defenseclaw_*) policy.Render
// gives the sandbox of rec on this daemon's listeners. A record that no
// longer renders gives none: every rule in DefenseClaw's name is then
// foreign.
func (m *Manager) renderedOwnRules(rec record) map[string]v1.NetworkPolicyRule {
	uid, gid := m.runAs()
	pol, err := policy.Render(policy.Input{
		Profile: policy.Profile(rec.Profile), Harness: rec.Harness, Workdir: rec.Workdir, WorkdirMode: policy.WorkdirMode(rec.WorkdirMode),
		RunAsUser: strconv.Itoa(uid), RunAsGroup: strconv.Itoa(gid), IngressPort: m.opts.IngressPort, EgressPort: m.opts.EgressPort,
		APIPort: m.opts.APIPort, GatewayPort: packs.OpenShellGatewayPort,
		IngressRule: rec.TokenDelivery == config.OpenShellTokenDeliveryEnv,
	})
	if err != nil {
		m.logf("%s: sandbox %s: render its own network rules: %v", gatewaylog.ErrCodeOpenShellAdminViolation, rec.Name, err)
		return nil
	}
	own := map[string]v1.NetworkPolicyRule{}
	for name, rule := range pol.NetworkPolicies {
		if strings.HasPrefix(name, ownRulePrefix) {
			own[name] = rule
		}
	}
	return own
}

// ruleReach is what a rule opens, in a canonical order: each endpoint's
// host, ports and allowed addresses, and the binaries it opens them to.
// How OpenShell spells a port (Port or Ports) does not count.
func ruleReach(r v1.NetworkPolicyRule) []string {
	out := make([]string, 0, len(r.Endpoints)+len(r.Binaries))
	for _, ep := range r.Endpoints {
		ports := slices.Clone(ep.Ports)
		if ep.Port != 0 {
			ports = append(ports, ep.Port)
		}
		slices.Sort(ports)
		ips := slices.Clone(ep.AllowedIPs)
		slices.Sort(ips)
		out = append(out, fmt.Sprintf("endpoint %s %v %s", triage.NormalizeHost(ep.Host), slices.Compact(ports), strings.Join(slices.Compact(ips), ",")))
	}
	for _, bin := range r.Binaries {
		out = append(out, "binary "+bin.Path)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// applyingRules are the rules an approval of the sandbox is applying or
// just applied (queued, being decided, approved), which its record may not
// list yet. Callers hold Manager.mu.
func (m *Manager) applyingRules(sandbox string) map[string]bool {
	out := map[string]bool{}
	for _, a := range m.approvals {
		if a.sandbox != sandbox || a.proposal.RuleName == "" {
			continue
		}
		switch a.status {
		case sandboxapi.ApprovalQueued, approvalDeciding, sandboxapi.ApprovalApproved:
			out[a.proposal.RuleName] = true
		}
	}
	return out
}

// decidedHosts are the hosts saved decisions open for every sandbox of
// the person: their "always" approvals and unblocks.
func decidedHosts(saved []sandboxrelay.Decision) map[string]bool {
	out := map[string]bool{}
	for _, d := range saved {
		if d.Scope == sandboxrelay.DecisionScopeAlways && d.Kind != sandboxrelay.DecisionEgressBlock {
			out[triage.NormalizeHost(d.Host)] = true
		}
	}
	return out
}

// coveredByDecisions reports a rule whose every endpoint a saved decision
// opens (decidedHosts): the person decided it, so it is not foreign. A
// rule with an endpoint on this machine is never covered.
func coveredByDecisions(p triage.Proposal, decided map[string]bool) bool {
	if len(decided) == 0 || len(p.Endpoints) == 0 {
		return false
	}
	for _, ep := range p.Endpoints {
		host := triage.NormalizeHost(ep.Host)
		if host == "" || triage.IsHostLocal(host) || !decided[host] {
			return false
		}
	}
	return true
}

// foreignRuleStops is how many removals of foreign rules a sandbox gets:
// the next one stops it.
const foreignRuleStops = 2

// foreignRules reports the foreign rules enforceApprovedRules removed from
// a sandbox (managed mode), and stops the sandbox when it is not the first
// time: its agent, or someone with the user's OpenShell credentials, keeps
// opening destinations around DefenseClaw.
func (m *Manager) foreignRules(ctx context.Context, b *box, rules []string) {
	m.mu.Lock()
	name, bindingID := b.rec.Name, b.rec.BindingID
	key := scopeID(b.rec.ID, b.rec.Name)
	m.mu.Unlock()
	registration := m.registrationOf(b)
	st := m.managedSide()
	st.mu.Lock()
	st.foreignRules[key]++
	stop := st.foreignRules[key] >= foreignRuleStops
	st.mu.Unlock()
	action := "removed"
	if stop {
		action = "stopped"
	}
	m.logf("%s: sandbox %s: removed %d network rule(s) DefenseClaw did not render or approve: %s",
		gatewaylog.ErrCodeOpenShellAdminViolation, name, len(rules), strings.Join(rules, ", "))
	m.managedEvent(ctx, registration, sandboxrelay.EventForeignRule, map[string]any{
		"sandbox": name, "rules": rules, "action": action,
	})
	msg := fmt.Sprintf("removed %d network rule(s) added outside DefenseClaw, which your organization requires for sandbox access: %s",
		len(rules), strings.Join(rules, ", "))
	if stop {
		msg += "; this happened before, so DefenseClaw stops the sandbox"
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Source: sandboxapi.SourceOpenShell,
		Severity: "HIGH", Reason: policyReasonForeignRule, Message: truncate(msg, 512)})
	if stop {
		m.scheduleForeignStop(name, bindingID)
	}
}

// scheduleForeignStop stops sandbox name in the background (its caller may
// hold the sandbox's lifecycle lock), unless the session is over by then.
func (m *Manager) scheduleForeignStop(name, bindingID string) {
	m.tamperStops.Add(1)
	go func() {
		defer m.tamperStops.Done()
		ctx, cancel := context.WithTimeout(WithEmergencyStop(context.Background(), "repeated network rules added outside DefenseClaw"), defaultOpTimeout)
		defer cancel()
		b, unlock, err := m.lockBox(name)
		if err != nil {
			m.logf("foreign rules: stop %s: %v", name, err)
			return
		}
		defer unlock()
		m.mu.Lock()
		current := b.rec.BindingID == bindingID && b.phase == audit.SandboxPhaseReady
		m.mu.Unlock()
		if !current {
			return
		}
		if err := m.stop(ctx, b); err != nil {
			m.logf("foreign rules: stop %s: %v", name, err)
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: name, Severity: "HIGH",
				Reason: policyReasonForeignRule, Message: "⚠ DefenseClaw could not stop the sandbox for repeated foreign network rules (" + sandboxapi.AsError(err).Error() + "): stop it yourself"})
		}
	}()
}

// enforceProviderEndpoints detaches from a ready sandbox the --llm and
// --credential providers whose direct endpoints the current policy refuses
// (endpointRefusal): an administrator's egress_block or egress_allow_only,
// a block list or the blocklist feed. Their provider rules open the
// endpoint around the egress proxy, so a tightening must reach them as it
// reaches approved rules. Each detach is logged (OPENSHELL_ADMIN_VIOLATION
// for the administrator's lists), recorded as a policy record and published
// to the feed; one that fails is retried on the next pass, and checkStart
// refuses the next start either way.
func (m *Manager) enforceProviderEndpoints(ctx context.Context, gw *Gateway, b *box, eff *packs.Effective) {
	m.mu.Lock()
	rec, ready := b.rec, b.phase == audit.SandboxPhaseReady && !b.deleted && !b.creating
	m.mu.Unlock()
	if !ready || eff == nil {
		return
	}
	refused := map[string]error{}
	refusedAt := map[string]providerEndpoint{}
	var order []string
	for _, ep := range rec.ProviderEndpoints {
		if _, seen := refused[ep.Provider]; seen || slices.Contains(rec.DetachedProviders, ep.Provider) {
			continue
		}
		if err := endpointRefusal(eff, ep); err != nil {
			refused[ep.Provider], refusedAt[ep.Provider] = err, ep
			order = append(order, ep.Provider)
		}
	}
	for _, provider := range order {
		err := refused[provider]
		var v *packs.Violation
		admin := errors.As(err, &v) && v.Admin()
		code, reason := "SANDBOX_RULE_BLOCKLISTED", policyReasonBlocklist
		if admin {
			code, reason = string(gatewaylog.ErrCodeOpenShellAdminViolation), policyReasonAdmin
		}
		if _, derr := gw.Client.DetachProvider(ctx, rec.Name, provider); derr != nil && !openshell.IsNotFound(derr) {
			m.logf("%s: sandbox %s: detach provider %s, whose endpoint the policy now refuses (%v): %v", code, rec.Name, provider, err, derr)
			m.dropGateway(gw, derr)
			continue
		}
		m.logf("%s: sandbox %s: detached provider %s: %v", code, rec.Name, provider, err)
		m.mu.Lock()
		b.rec.DetachedProviders = append(slices.Clip(b.rec.DetachedProviders), provider)
		id := b.identity()
		m.mu.Unlock()
		if serr := m.saveRecord(b); serr != nil {
			m.logf("record the detached provider of %s: %v", rec.Name, serr)
		}
		m.tel.RecordSandboxPolicy(ctx, audit.SandboxPolicyEvent{Sandbox: id, Operation: audit.SandboxPolicyRuleRemove,
			Actor: "policy", Origin: "internal", Target: provider, Reason: reason, ChangeCount: 1, Timestamp: m.now()})
		ep := refusedAt[provider]
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: rec.Name, Source: sandboxapi.SourceOpenShell,
			Host: ep.Host, Port: ep.Port, Reason: reason, Message: providerClosedText(ep, err)})
	}
}

// forgetApprovedRules drops rules from the sandbox's recorded approvers
// (record.ApprovedRules): they were removed.
func (m *Manager) forgetApprovedRules(b *box, rules []string) {
	m.mu.Lock()
	var next map[string]string
	for _, rule := range rules {
		if _, ok := b.rec.ApprovedRules[rule]; !ok {
			continue
		}
		if next == nil {
			next = maps.Clone(b.rec.ApprovedRules)
		}
		delete(next, rule)
	}
	if next != nil {
		b.rec.ApprovedRules = next
	}
	name := b.rec.Name
	m.mu.Unlock()
	if next == nil {
		return
	}
	if err := m.saveRecord(b); err != nil {
		m.logf("record the removed rules of %s: %v", name, err)
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

// gatewayDriver is the compute driver of the gateway last connected. Until
// one answered it is docker's: an Explain before any create then describes
// the docker posture, and the create, which holds a connection, decides
// with the driver the gateway reports.
func (m *Manager) gatewayDriver() openshell.Driver {
	if d := m.gwDriver.Load(); d != nil {
		return *d
	}
	d, _ := openshell.LookupDriver(string(openshell.DriverDocker))
	return d
}

// recordFacts are the gateway facts a sandbox's policy is re-resolved with:
// the connected gateway's port, and the driver the sandbox was created on,
// not the connected gateway's: a sandbox made on docker keeps its mount
// mode after the gateway switched drivers, instead of being re-resolved to
// a copy it never had.
func (m *Manager) recordFacts(rec record) gatewayFacts {
	d, _ := openshell.LookupDriver(rec.Driver)
	return gatewayFacts{Port: m.gatewayPort(), Driver: d}
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

// violationError turns a policy refusal of a create or start into the API
// error (violationErrorFor).
func (m *Manager) violationError(ctx context.Context, err error, sandbox string) error {
	return m.violationErrorFor(ctx, err, sandbox, audit.SandboxPolicyApply, "")
}

// violationErrorFor turns a policy refusal of op into the API error. An
// admin refusal is logged with its gateway error code and recorded as a
// no-change policy record of op on the sandbox, target naming what was
// refused (the violated key when empty). A refused request degrades
// nothing, so it is not recorded as subsystem health.
func (m *Manager) violationErrorFor(ctx context.Context, err error, sandbox string, op audit.SandboxPolicyOperation, target string) error {
	var v *packs.Violation
	if !errors.As(err, &v) {
		return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: err.Error()}
	}
	wire := wireViolation(*v)
	if v.Admin() {
		m.logf("%s: sandbox %s: %s", gatewaylog.ErrCodeOpenShellAdminViolation, sandbox, v.Error())
		if target == "" {
			target = v.Key
		}
		m.recordAdminRefusal(ctx, sandbox, op, target)
		msg := v.Message
		if msg == "" {
			msg = sandboxapi.AdminMessage
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: msg, Detail: v.Detail, Violation: &wire}
	}
	return &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation, Message: v.Message, Detail: v.Detail, Violation: &wire}
}

// policyTarget is the shape of a policy record's target reference (the
// audit recorder refuses anything else).
var policyTarget = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

// recordAdminRefusal records a request the organization's policy refused as
// a no-change policy record: of the sandbox when it exists (or is being
// created), of every sandbox ("all") for an "always" unblock, and not at
// all for a create that has no name yet (the log line stays).
func (m *Manager) recordAdminRefusal(ctx context.Context, sandbox string, op audit.SandboxPolicyOperation, target string) {
	var id audit.SandboxIdentity
	m.mu.Lock()
	if b := m.boxes[sandbox]; b != nil && !b.deleted {
		id = b.identity()
	}
	m.mu.Unlock()
	switch {
	case id.Name != "":
	case sandbox == "" && op == audit.SandboxEgressUnblock:
		id = audit.SandboxIdentity{Name: "all", Runtime: audit.SandboxRuntimeOpenShell}
	case openshell.ValidSandboxName(sandbox):
		id = audit.SandboxIdentity{Name: sandbox, Runtime: audit.SandboxRuntimeOpenShell}
	default:
		return
	}
	if len(target) > 1024 || !policyTarget.MatchString(target) {
		target = ""
	}
	m.tel.RecordSandboxPolicy(ctx, audit.SandboxPolicyEvent{
		Sandbox: id, Operation: op, Actor: m.person(), Origin: "api", Target: target, Reason: policyReasonAdminRefused,
		NoChange: true, Timestamp: m.now(),
	})
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
func (m *Manager) Explain(ctx context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error) {
	return m.ExplainUnder(ctx, m.config(), req)
}

// ExplainUnder is Explain against cfg instead of the manager's own
// configuration. A managed computer's sandbox daemon explains against the
// floor the managed gateway names for the caller, which its own
// configuration holds only after a create registered a run.
func (m *Manager) ExplainUnder(ctx context.Context, cfg *config.Config, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error) {
	var flags packs.Flags
	tier := ""
	if req.Sandbox != "" {
		b, err := m.box(req.Sandbox)
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		rec := b.rec
		m.mu.Unlock()
		flags = rec.Flags.packs(rec.Harness, rec.Project, m.recordFacts(rec))
		tier = rec.TamperTier
	} else {
		var err error
		if flags, err = m.newRunFlags(req); err != nil {
			return nil, err
		}
		if spec, ok := harness.Get(flags.Harness); ok && req.Harness != "" {
			tier = spec.TamperTier
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
	out.Workspace = WorkspacePolicyOf(eff)
	if eff.Pack != nil {
		out.Pack, out.PackSource, out.PackDigest = eff.Pack.Name, eff.Pack.Source, eff.Pack.Digest
		for _, link := range eff.Pack.Chain {
			out.PackChain = append(out.PackChain, sandboxapi.PackLink{Name: link.Name, Builtin: link.Builtin, Source: link.Source, Digest: link.Digest})
		}
	}
	if rp := eff.RepoPolicy; rp != nil {
		out.RepoPolicy = &sandboxapi.RepoPolicy{Path: rp.Source, Digest: rp.Digest, Tightened: eff.RepoTightened, Content: rp.Content}
	}
	out.Settings = ExplainSettings(eff, tier)
	if req.Sandbox == "" {
		// Only the daemon knows the image a new sandbox would boot.
		out.VMFirstBoot = m.vmFirstBoot(ctx, cfg, m.gatewayDriver(), flags, eff, req.Run)
	}
	return out, nil
}

// WorkspacePolicyOf is the copy policy of eff (sandboxapi.WorkspacePolicy).
func WorkspacePolicyOf(eff *packs.Effective) *sandboxapi.WorkspacePolicy {
	ws := eff.Workspace
	return &sandboxapi.WorkspacePolicy{Masks: slices.Clone(ws.Masks), Unmask: slices.Clone(ws.Unmask), GitDepth: ws.GitDepth,
		MaxUploadMB: ws.MaxUploadMB}
}

// silenceOrigin is the origin of an explained hooks.on_silence that the
// agent's tamper tier decides (ExplainSettings).
const silenceOrigin = "the agent's hooks are managed: alert only"

// ExplainSettings are eff's settings in the API's form. For an agent of
// tamper tier tier ("" when no agent was named) hooks.on_silence is what its
// sandbox does when the hooks fall silent (silenceResponse): an agent whose
// hooks neither it nor a repository can switch off (the managed tier) only
// raises an alert, whatever the policy asks, so the explain does not show
// the user tier's stop for it (GAP-0477).
func ExplainSettings(eff *packs.Effective, tier string) []sandboxapi.Setting {
	var out []sandboxapi.Setting
	for _, s := range eff.Explain() {
		w := sandboxapi.Setting{Key: s.Key, Value: s.Value, Source: string(s.Source), Origin: s.Origin, Requested: s.Requested}
		if s.Key == "hooks.on_silence" && tier != "" {
			if response, _ := silenceResponse(tier, eff); response != s.Value {
				w.Value, w.Source, w.Origin, w.Requested = response, string(packs.SourceDefault), silenceOrigin, s.Value
			}
		}
		out = append(out, w)
	}
	return out
}

// ManagedPostureOf is the posture a managed explain carries (the managed
// gateway's resolution of the caller's own run, sandboxapi.ManagedPosture):
// eff's pack, profile, modes and settings, and the run's violations. The
// pack sources name no host path: an administrator's pack is
// "organization", a built-in one "builtin:<name>".
func ManagedPostureOf(eff *packs.Effective, violations []packs.Violation, tier string) *sandboxapi.ManagedPosture {
	if eff == nil {
		return nil
	}
	source := func(builtin bool, name string) string {
		if builtin {
			return "builtin:" + name
		}
		return sandboxapi.ExplainSourceOrganization
	}
	out := &sandboxapi.ManagedPosture{
		Profile: eff.Profile, NetworkMode: eff.NetworkMode, Approvals: eff.Approvals,
		Settings: ExplainSettings(eff, tier), RepoTightened: slices.Clone(eff.RepoTightened),
	}
	if len(violations) > 0 {
		out.Violations = wireViolations(violations)
	}
	if p := eff.Pack; p != nil {
		out.Pack, out.PackSource, out.PackDigest = p.Name, source(p.Builtin, p.Name), p.Digest
		for _, link := range p.Chain {
			out.PackChain = append(out.PackChain, sandboxapi.PackLink{Name: link.Name, Builtin: link.Builtin,
				Source: source(link.Builtin, link.Name), Digest: link.Digest})
		}
	}
	return out
}

// newRunFlags are the policy flags of a new run an explain describes: its
// harness and flags in its project, with that folder's repository policy.
func (m *Manager) newRunFlags(req sandboxapi.ExplainRequest) (packs.Flags, error) {
	project := req.Project
	if project != "" {
		if !filepath.IsAbs(project) {
			return packs.Flags{}, sandboxapi.Errorf(sandboxapi.CodeInvalid, "project must be an absolute path")
		}
		if real, err := filepath.EvalSymlinks(project); err == nil {
			project = real
		}
	}
	repo, err := m.repoPolicy(project, "")
	if err != nil {
		return packs.Flags{}, err
	}
	return packs.Flags{
		Harness: config.NormalizeConnectorName(req.Harness), Pack: req.Pack, Profile: req.Profile, Project: project,
		Copy: req.Copy, Safe: req.Safe, Yolo: req.Yolo, Unmask: req.Unmask, OpenShellGatewayPort: m.gatewayPort(),
		MountUnsupported: m.gatewayDriver().MountRefusal, RepoPolicy: repo,
	}, nil
}

// validPolicyChecks bounds the destinations of a policy test.
func validPolicyChecks(checks []sandboxapi.PolicyCheck) error {
	switch {
	case len(checks) == 0:
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "name at least one destination to test")
	case len(checks) > sandboxapi.MaxPolicyChecks:
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "a policy test takes at most %d destinations", sandboxapi.MaxPolicyChecks)
	}
	for _, c := range checks {
		if c.Port < 0 || c.Port > 65535 {
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "port %d must be between 1 and 65535 (0: any port)", c.Port)
		}
	}
	return nil
}

// PolicyTest judges destinations with a sandbox's egress policy as its
// proxy does: the policy resolved against the current configuration, with
// the sandbox's own decider and principal, so its unblocks count. The
// decision walks the proxy's order (packs.Effective.CheckEgress, which asks
// the egress decider). A destination one of the sandbox's providers opens
// directly, around the proxy, is named as well.
func (m *Manager) PolicyTest(_ context.Context, req sandboxapi.PolicyTestRequest) (*sandboxapi.PolicyTestResult, error) {
	if err := validPolicyChecks(req.Checks); err != nil {
		return nil, err
	}
	b, err := m.box(req.Sandbox)
	if err != nil {
		return nil, err
	}
	eff, err := m.resolveBox(b)
	if err != nil {
		return nil, err
	}
	pol := m.triagePolicy(b, eff)
	m.mu.Lock()
	rec := b.rec
	m.mu.Unlock()
	out := &sandboxapi.PolicyTestResult{Sandbox: rec.Name, Profile: eff.Profile, NetworkMode: eff.NetworkMode}
	if eff.Pack != nil {
		out.Pack = eff.Pack.Name
	}
	for _, c := range req.Checks {
		if d, ok := hostPortTest(rec, eff, c); ok {
			out.Decisions = append(out.Decisions, d)
			continue
		}
		chk := eff.CheckEgress(pol.Decider, pol.Principal, c.Host, c.Port)
		if m.managedMode() {
			chk = m.savedDecisionProvenance(b, eff, pol.Principal, c.Host, c.Port, chk)
		}
		out.Decisions = append(out.Decisions, sandboxapi.PolicyDecision{
			PolicyCheck: c, Allowed: chk.Allowed, Rule: string(chk.Rule), Match: chk.Match, Source: chk.Source,
			Reason: chk.Reason, Unblockable: chk.Unblockable, Direct: directProvider(rec.ProviderEndpoints, c.Host, c.Port),
		})
	}
	return out, nil
}

// savedDecisionProvenance changes only the explanation of a verdict. The
// actual sandbox decider above remains authoritative, including the guard,
// organization lists, repository constraints and the current approval floor.
func (m *Manager) savedDecisionProvenance(b *box, eff *packs.Effective, principal egress.Principal, host string, port int, chk packs.EgressCheck) packs.EgressCheck {
	if chk.Rule != packs.RuleBlock && chk.Rule != packs.RuleUnblock {
		return chk
	}
	if chk.Rule == packs.RuleBlock {
		// A configured or repository block precedes appended user blocks.
		if base := eff.CheckEgress(nil, principal, host, port); base.Rule == packs.RuleBlock {
			return chk
		}
	} else if _, live := m.unblocks.Unblocked(principal, host); live {
		return chk
	}
	for _, d := range m.savedDecisions(m.registrationOf(b), m.floor(eff)) {
		if triage.NormalizeHost(d.Host) != triage.NormalizeHost(host) || d.Scope != sandboxrelay.DecisionScopeAlways {
			continue
		}
		kind, action := "", ""
		switch {
		case chk.Rule == packs.RuleBlock && d.Kind == sandboxrelay.DecisionEgressBlock:
			kind, action = "block", "blocked"
		case chk.Rule == packs.RuleUnblock && d.Kind == sandboxrelay.DecisionEgressAllow:
			kind, action = "allow", "allowed"
		case chk.Rule == packs.RuleUnblock && d.Kind == sandboxrelay.DecisionUnblock:
			kind, action = "unblock", "unblocked"
		}
		if kind != "" {
			chk.Source = "your saved " + kind + " decision (managed gateway)"
			chk.Reason = "You " + action + " this destination through your organization's DefenseClaw gateway."
			return chk
		}
	}
	return chk
}

// hostPortTest is what a policy test says of a --host-port the sandbox was
// started with: approved, the user opened it; otherwise its first
// connection raises an ask (hostPortDenied), not the plain host_internal
// block the egress check reads (GAP-0265). ok is false for any other
// destination.
func hostPortTest(rec record, eff *packs.Effective, c sandboxapi.PolicyCheck) (d sandboxapi.PolicyDecision, ok bool) {
	if triage.NormalizeHost(c.Host) != openshellHostAlias || c.Port <= 0 || !slices.Contains(rec.Flags.HostPorts, c.Port) ||
		eff == nil || eff.Allow(packs.Action{Kind: packs.ActionHostPort, Port: c.Port}) != nil {
		return d, false
	}
	port := strconv.Itoa(c.Port)
	d = sandboxapi.PolicyDecision{PolicyCheck: c, Rule: "host_port", Source: "--host-port " + port}
	if _, approved := rec.ApprovedRules[hostPortRule(c.Port)]; approved {
		d.Allowed, d.Reason = true, "you approved the sandbox's --host-port "+port
		return d, true
	}
	d.Ask = true
	d.Reason = "port " + port + " is a --host-port of this sandbox: its first connection raises an ask you answer with `defenseclaw sandbox approvals`, and is allowed once approved"
	return d, true
}

// directProvider names the provider of the sandbox whose OpenShell rule
// opens host (on port, 0 any) around the egress proxy, or "".
func directProvider(endpoints []providerEndpoint, host string, port int) string {
	host = triage.NormalizeHost(host)
	for _, ep := range endpoints {
		if ep.Host != host || (port != 0 && ep.Port != 0 && ep.Port != port) {
			continue
		}
		if ep.Role == roleCredential {
			return "the --credential " + ep.Name + " provider (" + ep.Provider + ") opens it directly for the programs it binds"
		}
		return "the model provider (" + ep.Provider + ") opens it directly for the harness's own programs"
	}
	return ""
}

// baseEffective is the configured posture without run flags; the egress
// proxy's global rules and the status come from it.
func (m *Manager) baseEffective(cfg *config.Config) (*packs.Effective, error) {
	eff, _, err := m.resolve(cfg, packs.Flags{OpenShellGatewayPort: m.gatewayPort()})
	return eff, err
}
