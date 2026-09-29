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
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// box is the manager's live state of one sandbox. rec is persisted; the
// rest is rebuilt from OpenShell and the ingress after a restart.
type box struct {
	// op serializes lifecycle operations (create, start, stop, delete,
	// undo) on this sandbox. It is taken before Manager.mu, never under it.
	op sync.Mutex

	// The fields below are guarded by Manager.mu.
	rec record
	sb  *openshell.Sandbox
	eff *packs.Effective
	// decider is the sandbox's own egress proxy decider, built from eff
	// (Manager.egressDecider) whenever eff is.
	decider *egress.Decider
	// policyErr is why the sandbox's policy last failed to resolve, while
	// it fails (Manager.policyUnresolved); eff and decider are nil then.
	policyErr string
	cred      egress.Credential
	phase     audit.SandboxPhase
	creating  bool
	deleted   bool
	orphaned  bool
	missing   bool
	// violations are the clamps and refusals the current configuration
	// applies to the sandbox's run flags, resolved with eff.
	violations []packs.Violation
	// posture is what the feed last heard of the policy the sandbox runs
	// under (announcePosture).
	posture *posture
	// egressOff says why the policy turns the sandbox's web egress off
	// ("" while it is on); egressSynced is set once it was first judged
	// (noteEgressOff).
	egressOff    string
	egressSynced bool
	// unrecorded marks a live sandbox adopted from its labels because the
	// daemon has no readable record of it: the pack, profile and run flags
	// it was created with are unknown, so it fails closed (see
	// errUnrecorded) and its record is never written.
	unrecorded bool
	// retained marks a gone sandbox kept only for its pre-session snapshot
	// (record.Retained, see retire): it has no binding, providers or
	// credential, and only Get, Review, Undo and Delete apply to it.
	retained bool
	// elsewhere says where a sandbox missing from the connected gateway
	// was created, while that is another gateway or workspace
	// (gatewayElsewhere): it is not released then.
	elsewhere string
	started   time.Time

	watchCancel context.CancelFunc
	watchDone   chan struct{}
	// guard is the running nested-repository guard (see guard.go);
	// guardEnding closes once the last one ended, its final pass
	// included.
	guard       *guardRun
	guardEnding chan struct{}

	hooks       hookStats
	activeAt    time.Time
	silentSince time.Time
	// reach is whether the current session's hooks reach the ingress
	// (reach.go); it starts over whenever the sandbox becomes ready.
	reach hookReach
	// tamperStop is set once a hook tamper scheduled this session's stop.
	tamperStop  bool
	silenceSent bool
	// seenChunks are the pending draft chunks triage decided; it is pruned
	// to the inbox's pending chunks on every poll.
	seenChunks map[string]struct{}
	// synthetic maps the synthetic addresses OpenShell's policy DNS handed
	// the sandbox to their names (noteSyntheticAddress).
	synthetic map[string]string
	// closedPorts are the undeclared host ports whose denial the feed
	// explained this session (hostPortDenied).
	closedPorts map[int]bool
	blocked     int
	// triageTimer is a pending draft poll after a denied connection.
	triageTimer *time.Timer
	// triageBusy is set while a triageNow poll runs; triageAgain asks it
	// for one more pass.
	triageBusy, triageAgain bool
	// Proposal flood limits (see approvals.go): recent automatic
	// approvals and recorded rejections, rejections not recorded in the
	// current window, and rules approvals added since the last start.
	autoApproved []time.Time
	rejected     []time.Time
	quietRejects int
	rulesAdded   int

	// triageMu serializes draft polls of this sandbox. It is taken before
	// Manager.mu, never under it.
	triageMu sync.Mutex

	// saveMu serializes writes of rec to disk (saveRecord, removeRecord),
	// so a slower writer never replaces a newer record with an older copy.
	// It is taken before Manager.mu, never under it. dropped, guarded by
	// saveMu, is set once the record file is removed: nothing writes it
	// again.
	saveMu  sync.Mutex
	dropped bool
}

// saveRecord writes the box's record as it is now. Writers change b.rec
// under Manager.mu and then call it; the copy is taken under the box's save
// lock, so concurrent writers leave the newest record on disk. Callers must
// not hold Manager.mu.
func (m *Manager) saveRecord(b *box) error {
	b.saveMu.Lock()
	defer b.saveMu.Unlock()
	if b.dropped {
		return nil
	}
	m.mu.Lock()
	rec, unrecorded := b.rec, b.unrecorded
	m.mu.Unlock()
	if unrecorded {
		// Its labels are all there is: writing them as its record would
		// make the next restart run it under the default policy.
		return nil
	}
	return m.records.save(&rec)
}

// removeRecord deletes the box's record file for good: later saves of the
// box are dropped, so a writer that raced the removal cannot bring the
// record of a deleted sandbox back. Callers must not hold Manager.mu.
func (m *Manager) removeRecord(b *box) error {
	b.saveMu.Lock()
	defer b.saveMu.Unlock()
	b.dropped = true
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	return m.records.remove(name)
}

type hookStats struct {
	lastHook    time.Time
	lastOTLP    time.Time
	lastNotify  time.Time
	requests    int64
	toolCalls   int64
	toolBlocked int64
	lastBlocked string
	// tampered counts tool calls that ran without a DefenseClaw verdict.
	tampered   int64
	lastTamper time.Time
	// ingressRefused counts the ingress connections and requests OpenShell
	// refused.
	ingressRefused     int64
	lastIngressRefused time.Time
	// failed counts the hook posts the ingress answered with an error;
	// lastFailure says how the last one was answered. failureNoticeAt is
	// when the feed last reported failures, unnoticed how many came since.
	failed          int64
	lastFailure     string
	lastFailureAt   time.Time
	failureNoticeAt time.Time
	unnoticed       int64
}

var imageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// identity is the correlation.sandbox group for the box. Callers hold
// Manager.mu.
func (b *box) identity() audit.SandboxIdentity {
	id := audit.SandboxIdentity{
		ID: b.rec.ID, Name: b.rec.Name, Connector: b.rec.Harness, Runtime: audit.SandboxRuntimeOpenShell,
		Profile: b.rec.Profile, Pack: b.rec.Pack, Phase: b.phase, WorkdirMode: b.rec.WorkdirMode,
	}
	// Telemetry names the driver as OpenShell does (audit.SandboxDriverVM is
	// "vm"); one this build does not know is left out, not guessed.
	if d, ok := openshell.LookupDriver(b.rec.Driver); ok {
		id.Driver = string(d.Name)
	}
	// The image that runs: the run image when the driver runs one.
	digest := b.rec.ImageID
	if b.rec.RunImageID != "" {
		digest = b.rec.RunImageID
	}
	if imageDigestPattern.MatchString(digest) {
		id.ImageDigest = digest
	}
	if b.sb != nil {
		id.PolicyVersion = b.sb.Status.CurrentPolicyVersion
	}
	return id
}

// auditPhase maps an OpenShell phase onto the telemetry vocabulary.
func auditPhase(p openshell.SandboxPhase) audit.SandboxPhase {
	switch p {
	case openshell.PhaseProvisioning:
		return audit.SandboxPhaseProvisioning
	case openshell.PhaseStarting:
		return audit.SandboxPhaseStarting
	case openshell.PhaseReady:
		return audit.SandboxPhaseReady
	case openshell.PhaseStopping:
		return audit.SandboxPhaseStopping
	case openshell.PhaseStopped:
		return audit.SandboxPhaseStopped
	case openshell.PhaseCompleted:
		return audit.SandboxPhaseCompleted
	case openshell.PhaseError:
		return audit.SandboxPhaseError
	case openshell.PhaseDeleting:
		return audit.SandboxPhaseDeleting
	default:
		return audit.SandboxPhaseUnknown
	}
}

// lifecycle records a phase transition (and the matching feed event) unless
// the box is already in phase and force is unset. Callers must not hold
// Manager.mu.
func (m *Manager) lifecycle(ctx context.Context, b *box, phase audit.SandboxPhase, trigger audit.SandboxLifecycleTrigger,
	force bool, cond *audit.SandboxCondition, exit *int32) {
	m.mu.Lock()
	if b.phase == phase && !force {
		m.mu.Unlock()
		return
	}
	previous := b.phase
	if previous == "" && b.rec.Phase != "" {
		previous = audit.SandboxPhase(b.rec.Phase)
	}
	b.phase = phase
	if phase == audit.SandboxPhaseReady && (previous != audit.SandboxPhaseReady || b.started.IsZero()) {
		b.started = m.now()
		b.reach = hookReach{}
		b.closedPorts = nil
		// A restarted daemon that finds the sandbox still ready keeps the
		// time it became ready (uptime); a real transition takes now.
		if previous != audit.SandboxPhaseReady || b.rec.ReadyAt.IsZero() {
			b.rec.ReadyAt = b.started.UTC()
			// The session's harness launches with the skip-permissions
			// mode the policy allows now; a later change applies from the
			// next start (launchYolo).
			yolo := launchYolo(b)
			b.rec.SessionYolo = &yolo
		}
	}
	if phase != audit.SandboxPhaseReady {
		b.rec.ReadyAt = time.Time{}
		b.rec.SessionYolo = nil
	}
	b.rec.Phase = string(phase)
	id := b.identity()
	rec := b.rec
	m.mu.Unlock()
	if previous == phase {
		previous = ""
	}
	ev := audit.SandboxLifecycleEvent{
		Sandbox: id, PreviousPhase: previous, Trigger: trigger, ExitCode: exit, Condition: cond, Timestamp: m.now(),
	}
	if err := m.tel.RecordSandboxLifecycle(ctx, ev); err != nil {
		m.logf("lifecycle telemetry for %s: %v", rec.Name, err)
	}
	if phase != audit.SandboxPhaseDeleted {
		if err := m.saveRecord(b); err != nil {
			m.logf("save the record of %s: %v", rec.Name, err)
		}
	}
	m.feed.Publish(sandboxapi.ActivityEvent{
		Kind: sandboxapi.ActivityLifecycle, Sandbox: rec.Name, Phase: string(phase), Reason: string(trigger),
		Message: lifecycleMessage(rec.Name, phase),
	})
	m.syncGuard(b, phase)
}

func lifecycleMessage(name string, phase audit.SandboxPhase) string {
	switch phase {
	case audit.SandboxPhaseCreating:
		return "creating sandbox " + name
	case audit.SandboxPhaseReady:
		return "sandbox " + name + " is ready"
	case audit.SandboxPhaseStopped:
		return "sandbox " + name + " stopped"
	case audit.SandboxPhaseDeleted:
		return "sandbox " + name + " deleted"
	case audit.SandboxPhaseError:
		return "sandbox " + name + " failed"
	default:
		return "sandbox " + name + " is " + string(phase)
	}
}

// displaySafe makes the text of a view that a sandbox or its project can
// shape (warnings naming project files, OpenShell's endpoint reports, the
// last blocked tool, the workspace summary) safe to print on the user's
// terminal. The nested-repository paths are cleaned by nestedView.
func displaySafe(v *sandboxapi.Sandbox) {
	v.Warnings = sandboxapi.DisplayTexts(v.Warnings)
	v.Hooks.LastBlocked = sandboxapi.DisplayText(v.Hooks.LastBlocked)
	for i := range v.Endpoints {
		ep := &v.Endpoints[i]
		ep.Host, ep.Path, ep.Result = sandboxapi.DisplayText(ep.Host), sandboxapi.DisplayText(ep.Path), sandboxapi.DisplayText(ep.Result)
	}
	if w := v.Workspace; w != nil {
		clean := *w
		clean.Project = sandboxapi.DisplayText(w.Project)
		clean.Hidden, clean.Protected = sandboxapi.DisplayTexts(w.Hidden), sandboxapi.DisplayTexts(w.Protected)
		clean.Context, clean.Warnings = sandboxapi.DisplayTexts(w.Context), sandboxapi.DisplayTexts(w.Warnings)
		v.Workspace = &clean
	}
}

// postureDrift explains how the policy a sandbox runs under now (eff)
// differs from the one it was created with (rec): the configuration
// changed since, an administrator's required pack or minimum profile, say.
// A live mount the policy now wants as a copy cannot become one; it keeps
// running until the sandbox stops, and checkStart refuses the next start.
func postureDrift(rec record, eff *packs.Effective) []string {
	var out []string
	pack := ""
	if eff.Pack != nil {
		pack = eff.Pack.Name
	}
	if (rec.Pack != "" && pack != rec.Pack) || (rec.Profile != "" && eff.Profile != rec.Profile) ||
		(rec.NetworkMode != "" && eff.NetworkMode != rec.NetworkMode) || (rec.Approvals != "" && eff.Approvals != rec.Approvals) {
		out = append(out, fmt.Sprintf("the sandbox policy changed since this sandbox was created (pack %s, profile %s, network %s, approvals %s); "+
			"it now runs under pack %s, profile %s, network %s, approvals %s",
			firstNonEmpty(rec.Pack, "-"), firstNonEmpty(rec.Profile, "-"), firstNonEmpty(rec.NetworkMode, "-"), firstNonEmpty(rec.Approvals, "-"),
			firstNonEmpty(pack, "-"), eff.Profile, eff.NetworkMode, eff.Approvals))
	}
	// The harness run files follow the policy from the next start on
	// (refreshRunConfig); the running session keeps what it started with.
	if rec.RunConfig != nil && !rec.RunConfig.Safe && !(rec.Yolo && eff.Yolo) {
		out = append(out, "the sandbox policy no longer lets the harness skip its permission prompts; "+
			"this session keeps skip-permissions mode until the sandbox stops, and its next start keeps the prompts")
	}
	if rec.MCP != nil && rec.MCP.ProjectServers == packs.MCPProjectServersAllow && eff.MCP.ProjectServers != packs.MCPProjectServersAllow {
		out = append(out, "the sandbox policy now blocks the project's own MCP servers; this session may still start them until the sandbox stops")
	}
	if rec.MCP != nil && len(rec.MCP.Imported) > 0 && !eff.MCP.Import {
		out = append(out, "the sandbox policy no longer brings your MCP servers into sandboxes; this session keeps them until the sandbox stops")
	}
	if rec.WorkdirMode == config.OpenShellWorkdirMount && eff.Workspace.Mode != config.OpenShellWorkdirMount {
		out = append(out, "the sandbox policy now works on a copy of this project, but this sandbox mounts it live; "+
			"the mount stays until the sandbox stops, and it cannot start again: delete it and run it again")
	}
	return out
}

// sessionDrift explains how the session running now breaks the policy the
// sandbox would start under today (eff): it keeps what it was launched
// with until it ends, so an administrator checking compliance sees which
// sessions still run out of policy. sessionYolo is the session's
// skip-permissions mode, nextYolo the next launch's.
func sessionDrift(rec record, eff *packs.Effective, sessionYolo, nextYolo bool) []string {
	var out []string
	if sessionYolo && !nextYolo {
		why := "the sandbox policy now keeps the harness's permission prompts"
		var v *packs.Violation
		if err := eff.Allow(packs.Action{Kind: packs.ActionYolo}); errors.As(err, &v) && v.Admin() {
			why = "your organization disabled it (" + v.Constraint + ")"
		}
		out = append(out, "skip-permissions stays on in the session running now, which began before "+why+
			"; the harness keeps its permission prompts from the next start")
	}
	if err := eff.Allow(packActionHarness(rec.Harness)); err != nil {
		out = append(out, "the session running now uses a harness the sandbox policy no longer allows ("+err.Error()+
			"); it keeps running until it ends, and the sandbox cannot start again")
	}
	return out
}

// viewOf renders the API form of a box.
func (m *Manager) viewOf(b *box) sandboxapi.Sandbox {
	m.mu.Lock()
	v := m.view(b)
	proxy := m.proxy
	bindingID := b.rec.BindingID
	m.mu.Unlock()
	m.decorate(&v, proxy, bindingID)
	return v
}

// decorate adds what view leaves out because it needs I/O or other locks:
// the proxy's byte counts and the snapshot. Callers must not hold
// Manager.mu.
func (m *Manager) decorate(v *sandboxapi.Sandbox, proxy ProxyControl, bindingID string) {
	if proxy != nil && proxy.Counter() != nil && bindingID != "" {
		for _, d := range proxy.Counter().DestinationsFor(bindingID) {
			v.Egress.Destinations++
			v.Egress.BytesUp += d.BytesUp
			v.Egress.BytesDown += d.BytesDown
			v.Egress.Blocked += int(d.Blocked)
		}
	}
	if snap, err := m.ws.LoadSnapshot(m.opts.DataDir, v.Name); err == nil && snap != nil {
		info := &sandboxapi.SnapshotInfo{Kind: string(snap.Kind), CreatedAt: snap.CreatedAt}
		if snap.Git != nil {
			info.Ref = snap.Git.Ref
		}
		if snap.UndoneAt != nil {
			info.UndoneAt = *snap.UndoneAt
		}
		v.Snapshot = info
	}
}

// view renders the locked part of a box's API form. Callers hold
// Manager.mu and call decorate after releasing it.
func (m *Manager) view(b *box) sandboxapi.Sandbox {
	r := b.rec
	v := sandboxapi.Sandbox{
		Name: r.Name, ID: r.ID, Harness: r.Harness, Pack: r.Pack, PackDigest: r.PackDigest,
		Profile: r.Profile, NetworkMode: r.NetworkMode, Approvals: r.Approvals, Yolo: launchYolo(b),
		WorkdirMode: r.WorkdirMode, Project: r.Project, Workdir: r.Workdir, Image: r.Image, ImageID: r.ImageID,
		RunImage: r.RunImage, RunImageID: r.RunImageID,
		HarnessVersion: r.HarnessVersion, HookContract: r.HookContract, TamperTier: r.TamperTier,
		CreatedAt: r.CreatedAt, Workspace: r.Workspace, MCP: r.MCP, Violations: r.Violations, Warnings: r.Warnings,
		Orphaned: b.orphaned, NestedRepos: nestedView(r.Guard),
		Launch:      sandboxapi.Launch{Yolo: launchYolo(b), CredentialProfile: r.CredentialProfile, BedrockRegion: r.BedrockRegion},
		Credentials: slices.Clone(r.Credentials), HostPorts: slices.Clone(r.HostPorts),
	}
	if spec, ok := harness.Get(r.Harness); ok {
		v.HarnessName = spec.DisplayName
	}
	switch {
	case b.retained:
		v.Phase = string(audit.SandboxPhaseDeleted)
	case b.missing:
		v.Phase = "missing"
	case b.sb != nil:
		v.Phase = strings.ToLower(string(b.sb.Status.Phase))
		v.ExitCode = b.sb.Status.ExitCode
		if v.ID == "" {
			v.ID = b.sb.ID
		}
		for _, ep := range b.sb.Status.EndpointStatuses {
			v.Endpoints = append(v.Endpoints, sandboxapi.Endpoint{
				Host: ep.Host, Ports: ep.Ports, Path: ep.Path, Result: string(ep.LastResult), ReportedAt: ep.LastReportedAt,
			})
		}
	case b.creating:
		v.Phase = string(audit.SandboxPhaseCreating)
	default:
		v.Phase = string(audit.SandboxPhaseUnknown)
	}
	if b.phase == audit.SandboxPhaseReady && !b.started.IsZero() {
		started := b.started
		// Became ready before this daemon adopted it (record.ReadyAt), and
		// not before OpenShell created it (a sandbox made again since).
		if ready := r.ReadyAt; !ready.IsZero() && ready.Before(started) && (b.sb == nil || !ready.Before(b.sb.CreatedAt)) {
			started = ready
		}
		v.StartedAt = started
		v.UptimeSeconds = int64(m.now().Sub(started) / time.Second)
	}
	v.Hooks = sandboxapi.HookCoverage{
		LastHookAt: b.hooks.lastHook, LastOTLPAt: b.hooks.lastOTLP, HookRequests: b.hooks.requests,
		ToolCalls: b.hooks.toolCalls, ToolBlocked: b.hooks.toolBlocked, LastBlocked: b.hooks.lastBlocked,
		Tampered: b.hooks.tampered, LastTamperAt: b.hooks.lastTamper,
		HookFailed: b.hooks.failed, LastHookFailure: b.hooks.lastFailure, LastHookFailureAt: b.hooks.lastFailureAt,
		Silent: !b.silentSince.IsZero(), SilentSince: b.silentSince,
		IngressRefused: b.hooks.ingressRefused, LastIngressRefusedAt: b.hooks.lastIngressRefused,
		Unreachable: !b.reach.since.IsZero(), UnreachableSince: b.reach.since, UnreachableReason: b.reach.reason,
		NoHookYet: !b.reach.since.IsZero() && b.reach.noHookYet,
	}
	for _, a := range m.approvals {
		if a.sandbox == r.Name && a.status == sandboxapi.ApprovalPending {
			v.PendingApprovals++
		}
	}
	v.Egress.Blocked = b.blocked
	running := b.phase == audit.SandboxPhaseReady && !b.started.IsZero()
	if running {
		v.SessionYolo = launchYolo(b)
		if r.SessionYolo != nil {
			v.SessionYolo = *r.SessionYolo
		}
	}
	if e := b.eff; e != nil {
		// The policy the sandbox runs under now: every configuration change
		// re-resolves it (refreshEgress), so an administrator's change
		// applies to it; the record keeps what it was created with, and so
		// do the create-time clamps, which the current ones replace.
		v.Profile, v.NetworkMode, v.Approvals = e.Profile, e.NetworkMode, e.Approvals
		v.HostPorts = slices.Clone(e.MCP.HostPorts)
		if e.Pack != nil {
			v.Pack, v.PackDigest = e.Pack.Name, e.Pack.Digest
		}
		v.Violations = wireViolations(b.violations)
		v.Warnings = append(slices.Clip(v.Warnings), postureDrift(r, e)...)
		if running {
			v.Warnings = append(v.Warnings, sessionDrift(r, e, v.SessionYolo, v.Yolo)...)
		}
	}
	if res := resourceViolation(r.Resources, m.config().OpenShell.Admin.MaxResources); res != nil && !b.retained {
		v.Warnings = append(slices.Clip(v.Warnings), res.Message+
			" (it keeps its current limits until it stops, and cannot start again)")
	}
	if b.elsewhere != "" {
		v.Warnings = append(slices.Clip(v.Warnings), "this sandbox was created on "+b.elsewhere+
			", not the gateway DefenseClaw is connected to; DefenseClaw keeps it until it connects there again (openshell.gateway), "+
			"or until you delete it, which releases DefenseClaw's side only")
	}
	displaySafe(&v)
	if b.unrecorded {
		v.Warnings = append(slices.Clip(v.Warnings),
			"DefenseClaw has no readable record of this sandbox; it has no web egress and cannot start again until you delete it")
	}
	return v
}
