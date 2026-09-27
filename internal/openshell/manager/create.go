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
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// copyWorkRoot is where copy mode uploads the project: the upload runs as
// the sandbox user, which cannot create /work.
const copyWorkRoot = "/sandbox/work"

// rollback undoes the completed steps of a failed create, newest first.
type rollback struct {
	steps []rollbackStep
	done  bool
}

type rollbackStep struct {
	name string
	fn   func(context.Context) error
}

func (r *rollback) add(name string, fn func(context.Context) error) {
	r.steps = append(r.steps, rollbackStep{name: name, fn: fn})
}

func (r *rollback) commit() { r.done = true }

func (r *rollback) run(m *Manager, sandbox string) {
	if r.done {
		return
	}
	r.done = true
	ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	for i := len(r.steps) - 1; i >= 0; i-- {
		if err := r.steps[i].fn(ctx); err != nil {
			m.logf("create %s: rollback %s: %v", sandbox, r.steps[i].name, err)
		}
	}
}

// Create creates a sandbox, waits until it is ready and returns it. Every
// step it completed is rolled back when a later one fails.
func (m *Manager) Create(ctx context.Context, req sandboxapi.CreateRequest) (*sandboxapi.Sandbox, error) {
	cfg := m.config()
	if !cfg.OpenShell.Enabled {
		return nil, sandboxapi.Errorf(sandboxapi.CodeDisabled, "OpenShell sandboxes are disabled (openshell.enabled is false)")
	}
	if err := m.listenersReady(); err != nil {
		return nil, err
	}
	harnessName := config.NormalizeConnectorName(req.Harness)
	spec, ok := harness.Get(harnessName)
	if !ok {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "unknown harness %q (supported: %s)", req.Harness, strings.Join(harness.Names(), ", "))
	}
	project, err := realProject(req.Project)
	if err != nil {
		return nil, err
	}
	gw, err := m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	flags := runFlags{
		Pack: req.Pack, Profile: req.Profile, Copy: req.Copy, Safe: req.Safe, Yolo: req.Yolo,
		Unmask: req.Unmask, HostPorts: req.HostPorts, NoMCP: req.NoMCP, Learn: req.Learn,
		CPU: req.CPU, Memory: req.Memory, Context: req.Context,
	}
	eff, violations, err := m.resolve(cfg, flags.packs(harnessName, project, gw.Port))
	if err != nil {
		return nil, err
	}
	if v := packs.FirstFatal(violations); v != nil {
		return nil, m.violationError(ctx, v, req.Name)
	}
	mode := eff.Workspace.Mode
	actions := []packs.Action{{Kind: packs.ActionHarness, Harness: harnessName}}
	if mode == config.OpenShellWorkdirMount {
		actions = append(actions, packs.Action{Kind: packs.ActionMount, Path: project})
		for _, c := range req.Context {
			actions = append(actions, packs.Action{Kind: packs.ActionMount, Path: c})
		}
	}
	if eff.Yolo {
		actions = append(actions, packs.Action{Kind: packs.ActionYolo})
	}
	if eff.Learn {
		actions = append(actions, packs.Action{Kind: packs.ActionLearnMode})
	}
	for _, a := range actions {
		if err := eff.Allow(a); err != nil {
			return nil, m.violationError(ctx, err, req.Name)
		}
	}
	if err := m.checkPolicySources(mode, project, eff); err != nil {
		return nil, err
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		if name, err = GenerateName(harnessName, project); err != nil {
			return nil, err
		}
	}
	if !openshell.ValidSandboxName(name) || workspace.ValidateName(name) != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid,
			"sandbox name %q must be lowercase letters, digits and '-', at most 63 characters", name)
	}
	b, err := m.reserve(name, project, mode)
	if err != nil {
		return nil, err
	}
	b.op.Lock()
	defer b.op.Unlock()
	created := false
	defer func() {
		if !created {
			m.release(name, b)
		}
	}()
	// Two live mounts of one folder would each undo the other's running
	// work, and each review would mix in the other's changes. The check
	// runs after the reservation, which records the project, so two
	// concurrent creates on one folder see each other.
	if mode == config.OpenShellWorkdirMount {
		if other := m.sharingMount(b, project, false); other != "" {
			return nil, sandboxapi.Errorf(sandboxapi.CodeConflict,
				"sandbox %s already mounts %s (or a folder inside or around it) live; run this one with --copy, or delete %s first",
				other, project, other)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, defaultCreateTimeout)
	defer cancel()
	if _, err := gw.Client.GetSandbox(ctx, name); err == nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "an OpenShell sandbox named %s already exists", name)
	} else if !openshell.IsNotFound(err) {
		m.dropGateway(gw, err)
		return nil, upstream("look up sandbox "+name, err)
	}

	rb := &rollback{}
	defer rb.run(m, name)
	view, err := m.create(ctx, gw, b, createInput{
		name: name, project: project, harness: spec, flags: flags, eff: eff, violations: violations, mode: mode, req: req,
	}, rb)
	if err != nil {
		rb.run(m, name)
		m.createFailed(ctx, b, name, err)
		return nil, err
	}
	rb.commit()
	created = true
	return view, nil
}

type createInput struct {
	name       string
	project    string
	harness    *harness.Spec
	flags      runFlags
	eff        *packs.Effective
	violations []packs.Violation
	mode       string
	req        sandboxapi.CreateRequest
}

func (m *Manager) create(ctx context.Context, gw *Gateway, b *box, in createInput, rb *rollback) (*sandboxapi.Sandbox, error) {
	cfg := m.config()
	eff, spec, name := in.eff, in.harness, in.name
	egressDec, err := m.egressDecider(cfg, eff)
	if err != nil {
		return nil, err
	}

	img, err := m.image(ctx, cfg, spec, !in.req.NoBuild)
	if err != nil {
		return nil, err
	}
	uid, gid := m.runAs()
	if img.UID != uid || img.GID != gid {
		return nil, sandboxapi.Errorf(sandboxapi.CodeImageUnavailable,
			"the %s sandbox image %s was built for uid %d:%d, not the sandbox run-as identity %d:%d; rebuild it",
			spec.DisplayName, img.Tag, img.UID, img.GID, uid, gid)
	}
	target := connector.SandboxRenderTarget{
		IngressPort: m.opts.IngressPort, AgentVersion: img.HarnessVersion, HookContractID: img.HookContract,
	}
	arts, err := spec.Provider.SandboxArtifacts(target)
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeImageUnavailable, "render %s sandbox artifacts: %v", spec.Name, err)
	}
	llm, err := planLLM(spec, in.req.LLM, img.NetworkRealpaths())
	if err != nil {
		return nil, err
	}
	pinned := map[string]string{}
	for k, v := range arts.Env {
		pinned[k] = v
	}
	reservedNames := map[string]bool{}
	for k := range arts.Env {
		reservedNames[k] = true
	}
	if llm != nil {
		for k, v := range llm.cp.Env {
			pinned[k] = v
		}
		for k := range llm.credentials {
			reservedNames[k] = true
		}
	}
	creds, err := planCredentials(eff, in.req.Credentials, reservedNames)
	if err != nil {
		var v *packs.Violation
		if errors.As(err, &v) {
			return nil, m.violationError(ctx, err, name)
		}
		return nil, err
	}
	if err := validateExtraEnv(in.req.Env, pinned); err != nil {
		return nil, err
	}

	// Workspace: the live mount (and its snapshot), or the copy workdir.
	rec := record{
		Name: name, Harness: spec.Name, Owner: m.opts.Owner, Project: in.project, Flags: in.flags,
		WorkdirMode: in.mode, CreatedAt: m.now().UTC(), Profile: eff.Profile, NetworkMode: eff.NetworkMode,
		Approvals: eff.Approvals, Yolo: eff.Yolo, Image: img.Tag, ImageID: img.ImageID,
		HarnessVersion: img.HarnessVersion, HookContract: img.HookContract, TamperTier: arts.TamperTier,
		Violations: wireViolations(in.violations), TokenDelivery: config.OpenShellTokenDeliveryProvider,
	}
	if strings.EqualFold(cfg.OpenShell.TokenDelivery, config.OpenShellTokenDeliveryEnv) {
		rec.TokenDelivery = config.OpenShellTokenDeliveryEnv
	}
	if eff.Pack != nil {
		rec.Pack, rec.PackDigest = eff.Pack.Name, eff.Pack.Digest
	}
	if llm != nil {
		// The harness's name for the credential (a template ID); the
		// provider's gateway profile may be a regional one.
		rec.CredentialProfile, rec.BedrockRegion = llm.profile.Template, in.req.LLM.BedrockRegion
	}
	workdir := sandboxauth.Workdir{Mode: sandboxauth.WorkdirMode(in.mode)}
	var plan *workspace.MountPlan
	if in.mode == config.OpenShellWorkdirMount {
		plan, err = m.ws.PlanMount(ctx, workspace.MountOptions{
			Project: in.project, Name: name, DataDir: m.opts.DataDir,
			Masks: eff.Workspace.Masks, Unmask: eff.Workspace.Unmask, Context: in.req.Context,
			// The agent writes the mount as the host user, who also owns
			// the custom packs: a folder holding one is never shared.
			Protected: eff.PolicySources(),
		})
		if err != nil {
			return nil, workspaceError(err)
		}
		rb.add("release mount", func(context.Context) error { return m.ws.ReleaseMount(m.opts.DataDir, name) })
		rec.Workdir = plan.Target
		sum := plan.Summary()
		rec.Workspace = &sandboxapi.WorkspaceSummary{Project: sum.Project, Hidden: sum.Hidden, Protected: sum.Protected, Context: sum.Context, Warnings: sum.Warnings}
		rec.Warnings = append(rec.Warnings, plan.Warnings...)
		for _, mt := range plan.Mounts {
			if mt.Kind == workspace.MountProject || mt.Kind == workspace.MountContext {
				workdir.Mounts = append(workdir.Mounts, sandboxauth.Mount{SandboxPath: mt.Target, HostPath: mt.Source, ReadOnly: mt.ReadOnly})
			}
		}
		for _, mk := range plan.Masked {
			workdir.Masks = append(workdir.Masks, path.Join(plan.Target, mk.Rel))
		}
		for _, c := range plan.Contexts {
			for _, mk := range c.Masked {
				workdir.Masks = append(workdir.Masks, path.Join(c.Target, mk.Rel))
			}
		}
		if !in.req.NoSnapshot {
			snap, err := m.ws.Snapshot(ctx, workspace.SnapshotOptions{
				Project: in.project, Name: name, DataDir: m.opts.DataDir, Skip: plan.MaskedRels(), Replace: true,
				Protected: eff.PolicySources(),
			})
			if err != nil {
				return nil, workspaceError(err)
			}
			rb.add("delete snapshot", func(ctx context.Context) error { return m.ws.DeleteSnapshot(ctx, m.opts.DataDir, name) })
			rec.Warnings = append(rec.Warnings, snap.Warnings...)
		}
	} else {
		rec.Workdir = path.Join(copyWorkRoot, workspace.RepoName(in.project))
		if len(in.req.Context) > 0 {
			rec.Warnings = append(rec.Warnings, "--context folders are not mounted in copy mode")
		}
	}

	// Ingress binding.
	bspec := sandboxauth.Spec{
		SandboxName: name, Connector: spec.Name, AgentVersion: img.HarnessVersion, HookContractID: img.HookContract,
		PolicyProfile: eff.Profile, Workdir: workdir,
		HostUser: sandboxauth.HostUser{UID: strconv.Itoa(m.host.UID), Name: m.host.Name},
	}
	binding, token, err := m.mintBinding(bspec)
	if err != nil {
		return nil, err
	}
	rb.add("revoke binding", func(context.Context) error { return m.revokeBinding(binding.ID) })
	rec.BindingID = binding.ID

	// Egress proxy credential.
	proxyURL := ""
	var cred egress.Credential
	if eff.Profile != config.OpenShellProfileStrict {
		if cred, err = egress.NewCredential(); err != nil {
			return nil, err
		}
		if err := m.creds.Register(cred, m.principal(binding.ID, "", name, egressDec, eff)); err != nil {
			return nil, err
		}
		rb.add("revoke proxy credential", func(context.Context) error {
			m.creds.Revoke(binding.ID)
			m.recheckEgress(binding.ID)
			return nil
		})
		proxyURL = cred.ProxyURL(connector.SandboxIngressHost, m.opts.EgressPort)
		rec.EgressUser = cred.Username
	}

	// Provider profiles and providers.
	providerNames, env, err := m.providers(ctx, gw, cfg, &rec, token, llm, creds, rb)
	if err != nil {
		return nil, err
	}
	envOut, err := spec.Env(harness.EnvOptions{
		Artifacts: arts, SandboxID: binding.ID, SandboxName: name, EgressProxyURL: proxyURL,
		CredentialProfile: rec.CredentialProfile, BedrockRegion: rec.BedrockRegion,
	})
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "sandbox environment: %v", err)
	}
	for k, v := range env {
		envOut[k] = v
	}
	var noProxy []string
	for _, c := range creds {
		noProxy = append(noProxy, c.binding.Host)
	}
	if len(noProxy) > 0 {
		harness.SetNoProxy(envOut, joinNoProxy(envOut["NO_PROXY"], noProxy))
	}
	for k, v := range in.req.Env {
		envOut[k] = v
	}

	// Per-run managed harness configuration: the model provider pins, safe
	// mode and the MCP servers the run brings along, mounted read-only.
	var modelProvider *connector.SandboxModelProvider
	if llm != nil {
		modelProvider = llm.cp.ModelProvider
	}
	rc, err := m.planRunConfig(ctx, runConfigInput{
		spec: spec, target: target, eff: eff, env: envOut, credentials: credentialNames(llm, creds),
		provider: modelProvider, workdir: rec.Workdir, project: in.project,
	})
	if err != nil {
		return nil, err
	}
	rb.add("remove run configuration", func(context.Context) error { return m.removeRunConfig(name) })
	runMounts, err := m.writeRunConfig(name, rc)
	if err != nil {
		return nil, err
	}
	if rc != nil {
		rec.MCP = rc.mcp
		rec.Warnings = append(rec.Warnings, rc.notices...)
	}

	// Policy: the workload runs as the identity the image was built for.
	pin := policy.Input{
		Profile: policy.Profile(eff.Profile), Harness: spec.Name, Workdir: rec.Workdir,
		WorkdirMode: policy.WorkdirMode(in.mode), RunAsUser: strconv.Itoa(img.UID), RunAsGroup: strconv.Itoa(img.GID),
		IngressPort: m.opts.IngressPort, EgressPort: m.opts.EgressPort, HarnessReadOnly: []string{spec.InstallRoot()},
		HostPorts: eff.MCP.HostPorts, APIPort: m.opts.APIPort, GatewayPort: policyGatewayPort(gw.Port),
		// Without an ingress provider nothing else opens the ingress.
		IngressRule: rec.TokenDelivery == config.OpenShellTokenDeliveryEnv,
	}
	if plan != nil {
		for _, p := range plan.ReadWrite {
			pin.Mounts = append(pin.Mounts, policy.Mount{Target: p})
		}
		for _, p := range plan.ReadOnly {
			pin.Mounts = append(pin.Mounts, policy.Mount{Target: p, ReadOnly: true})
		}
	}
	pol, err := policy.Render(pin)
	if err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "render the sandbox policy: %v", err)
	}

	// The sandbox.
	labels := m.managedSelector()
	labels[LabelHarness] = spec.Name
	labels[LabelProfile] = eff.Profile
	if v := labelValue(rec.Pack); v != "" {
		labels[LabelPack] = v
	}
	labels[LabelWorkdirMode] = in.mode
	if key, value := workspace.ProjectLabel(in.project); value != "" {
		labels[key] = value
	}
	tmpl := &openshell.SandboxTemplate{Image: img.Tag}
	if plan != nil {
		tmpl.DriverConfig = plan.DriverConfig()
	}
	tmpl.DriverConfig = withRunConfigMounts(tmpl.DriverConfig, runMounts)
	if res := templateResources(eff.Resources); res != nil {
		tmpl.Resources = res
	}
	// The guard's baseline is what the project holds before the sandbox
	// first runs.
	m.takeGuardBaseline(ctx, &rec)
	m.mu.Lock()
	b.rec = rec
	b.eff, b.decider = eff, egressDec
	b.cred = cred
	m.mu.Unlock()
	// Once the box holds its binding: the harness has not run yet, so the
	// session's tool-call ledger is complete.
	m.toolCalls.Begin(rec.BindingID)
	m.lifecycle(ctx, b, audit.SandboxPhaseCreating, audit.SandboxTriggerCreate, false, nil, nil)
	sbSpec := &openshell.SandboxSpec{Environment: envOut, Template: tmpl, Providers: providerNames, Policy: pol}
	if _, err := gw.Client.CreateSandbox(ctx, name, sbSpec, openshell.CreateSandboxOptions{Labels: labels}); err != nil {
		m.dropGateway(gw, err)
		return nil, upstream("create sandbox "+name, err)
	}
	rb.add("delete sandbox", func(ctx context.Context) error {
		if _, err := gw.Client.DeleteSandbox(ctx, name); err != nil {
			return err
		}
		return gw.Client.WaitDeleted(ctx, name)
	})
	sb, err := gw.Client.WaitReady(ctx, name)
	if err != nil {
		var rejected *openshell.ConfigurationRejectedError
		if errors.As(err, &rejected) {
			m.logf("%s: sandbox %s: %s", gatewaylog.ErrCodeOpenShellPolicyRejected, name, rejected.Message)
			return nil, &sandboxapi.Error{Code: sandboxapi.CodePolicyRejected, Message: "OpenShell rejected the sandbox configuration", Detail: rejected.Message}
		}
		return nil, upstream("wait for sandbox "+name, err)
	}
	if _, err := m.opts.Bindings.Update(binding.ID, func(s *sandboxauth.Spec) error { s.SandboxID = sb.ID; return nil }); err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "record the sandbox id on its binding: %v", err)
	}
	if cred.Username != "" {
		_ = m.creds.Register(cred, m.principal(binding.ID, scopeID(sb.ID, name), name, egressDec, eff))
	}
	if err := settle(ctx, m.opts.SettleDelay); err != nil {
		return nil, err
	}

	m.mu.Lock()
	b.rec.ID = sb.ID
	b.sb = sb
	b.creating = false
	m.mu.Unlock()
	if err := m.saveRecord(b); err != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "save sandbox state: %v", err)
	}
	m.recordMountTelemetry(ctx, b, plan, !in.req.NoSnapshot)
	m.lifecycle(ctx, b, auditPhase(sb.Status.Phase), audit.SandboxTriggerCreate, false, nil, nil)
	m.startWatch(b)
	m.refreshEgress()
	view := m.viewOf(b)
	return &view, nil
}

// createFailed reports a failed create after its rollback.
func (m *Manager) createFailed(ctx context.Context, b *box, name string, err error) {
	m.logf("%s: create %s: %v", gatewaylog.ErrCodeOpenShellSandboxFailed, name, err)
	m.mu.Lock()
	id := b.identity()
	emitted := b.phase != ""
	m.mu.Unlock()
	if emitted {
		m.lifecycle(context.WithoutCancel(ctx), b, audit.SandboxPhaseDeleted, audit.SandboxTriggerCreate, false, nil, nil)
	}
	_ = m.tel.RecordSandboxHealth(context.WithoutCancel(ctx), audit.SandboxHealthEvent{
		Sandbox: id, State: audit.SandboxHealthFailed, ErrorCode: errorToken(gatewaylog.ErrCodeOpenShellSandboxFailed),
		ErrorSummary: truncate(err.Error(), 512), Timestamp: m.now(),
	})
}

// providers creates the sandbox's OpenShell providers and returns their
// names plus env that must be set directly (token_delivery: env).
func (m *Manager) providers(ctx context.Context, gw *Gateway, cfg *config.Config, rec *record, token string,
	llm *llmPlan, creds []credentialPlan, rb *rollback) ([]string, map[string]string, error) {
	env := map[string]string{}
	var names []string
	create := func(role string, i int, profileID string, credentials map[string]string) error {
		pname := providerName(rec.Name, role, i)
		p := &openshell.Provider{
			Name: pname, Type: profileID,
			Labels: map[string]string{LabelManaged: "true", LabelOwner: m.opts.Owner, LabelSandbox: rec.Name, LabelRole: role},
			Spec:   openshell.ProviderSpec{Credentials: credentials},
		}
		if _, err := gw.Client.CreateProvider(ctx, p); err != nil {
			if !openshell.IsAlreadyExists(err) {
				return upstream("create provider "+pname, err)
			}
			// A provider left behind by an interrupted create of the same
			// name: replace it. Provider names are gateway-global, so one
			// that is not this data dir's (another daemon creating a
			// sandbox of this name right now, or not DefenseClaw's at all)
			// is never touched.
			have, gerr := gw.Client.GetProvider(ctx, pname)
			if gerr != nil {
				return upstream("look up provider "+pname, gerr)
			}
			if have.Labels[LabelManaged] != "true" || have.Labels[LabelOwner] != m.opts.Owner {
				return sandboxapi.Errorf(sandboxapi.CodeConflict,
					"an OpenShell provider named %s already exists and is not this DefenseClaw's; pick another sandbox name", pname)
			}
			if _, err := gw.Client.EnsureProvider(ctx, p); err != nil {
				return upstream("replace provider "+pname, err)
			}
		}
		rb.add("delete provider "+pname, func(ctx context.Context) error {
			_, err := gw.Client.DeleteProvider(ctx, pname)
			return err
		})
		names = append(names, pname)
		return nil
	}

	if rec.TokenDelivery == config.OpenShellTokenDeliveryEnv {
		env[openshell.EnvSandboxToken] = token
	} else {
		ingress, err := profiles.Render(profiles.IngressID, profiles.Input{IngressPort: m.opts.IngressPort})
		if err != nil {
			return nil, nil, sandboxapi.Errorf(sandboxapi.CodeInternal, "render the ingress profile: %v", err)
		}
		// This listener's own profile (profiles.IngressProfileID): daemons
		// on other ports keep theirs, so none re-points another's sandboxes.
		if err := m.ensureProfile(ctx, gw, ingress, nil); err != nil {
			return nil, nil, err
		}
		if err := create(roleIngress, 0, ingress.ID, map[string]string{openshell.EnvSandboxToken: token}); err != nil {
			return nil, nil, err
		}
	}
	if llm != nil {
		region := rec.BedrockRegion
		render := func(binaries []string) (profiles.Profile, error) {
			p, err := profiles.Render(llm.profile.Template, profiles.Input{Binaries: binaries, BedrockRegion: region})
			if err != nil {
				return profiles.Profile{}, sandboxapi.Errorf(sandboxapi.CodeInternal, "render profile %s: %v", llm.profile.ID, err)
			}
			return p, nil
		}
		if err := m.ensureProfile(ctx, gw, llm.profile, render); err != nil {
			return nil, nil, err
		}
		if err := create(roleLLM, 0, llm.profile.ID, llm.credentials); err != nil {
			return nil, nil, err
		}
	}
	for i, c := range creds {
		if err := m.credentialProvider(ctx, gw, c, func() error {
			return create(roleCredential, i, c.profile.ID, map[string]string{c.binding.Name: c.binding.Value})
		}); err != nil {
			return nil, nil, err
		}
	}
	rec.Providers = names
	return names, env, nil
}

// credentialProvider imports a --credential profile and creates the
// provider that uses it (create), holding credentialGC shared in between so
// this daemon's collection of unused profiles never removes it under the
// create. Another daemon on the gateway may still delete it in that window
// (it saw no provider using it); the create then imports it again, once.
func (m *Manager) credentialProvider(ctx context.Context, gw *Gateway, c credentialPlan, create func() error) error {
	m.credentialGC.RLock()
	defer m.credentialGC.RUnlock()
	for attempt := 0; ; attempt++ {
		if err := m.ensureProfile(ctx, gw, c.profile, nil); err != nil {
			return err
		}
		err := create()
		if err == nil || attempt > 0 {
			return err
		}
		if _, gerr := gw.Client.GetProfile(ctx, c.profile.ID); !openshell.IsNotFound(gerr) {
			return err
		}
		m.logf("provider profile %s went away while its provider was created; importing it again", c.profile.ID)
	}
}

// image resolves the harness overlay image for this host user.
func (m *Manager) image(ctx context.Context, cfg *config.Config, spec *harness.Spec, build bool) (image.Record, error) {
	if m.opts.Images == nil {
		return image.Record{}, sandboxapi.Errorf(sandboxapi.CodeImageUnavailable, "no image builder is configured")
	}
	uid, gid := m.runAs()
	bs := image.BuildSpec{
		Harness: spec, HarnessVersion: cfg.OpenShell.Image.HarnessVersions[spec.Name], BaseImage: cfg.OpenShell.Image.Base,
		UID: uid, GID: gid, IngressPort: m.opts.IngressPort, FailMode: connector.SandboxFailMode,
		DefenseClawVersion: m.opts.DefenseClawVersion,
	}
	rec, err := m.opts.Images.Resolve(ctx, bs, build)
	switch {
	case errors.Is(err, ErrImageMissing):
		return image.Record{}, sandboxapi.Errorf(sandboxapi.CodeImageUnavailable,
			"no verified %s sandbox image is built; run `defenseclaw sandbox image build %s`", spec.DisplayName, spec.Name)
	case err != nil:
		m.logf("%s: %s: %v", gatewaylog.ErrCodeOpenShellImageBuildFailed, spec.Name, err)
		return image.Record{}, &sandboxapi.Error{Code: sandboxapi.CodeImageUnavailable, Message: "the " + spec.DisplayName + " sandbox image is not usable", Detail: err.Error()}
	}
	return rec, nil
}

// runAs is the one source of a sandbox's run-as identity: the numeric host
// uid/gid, in mount and copy mode alike. The overlay image is built for it
// (image.BuildSpec chowns /sandbox to it, and the hook-fire probe runs as
// it), and the policy runs the workload as the uid/gid the image record
// carries, which create checks against it, so the two cannot drift apart.
func (m *Manager) runAs() (uid, gid int) {
	return m.host.UID, m.host.GID
}

// credentialNames lists the environment variables OpenShell delivers to the
// sandbox as provider placeholders.
func credentialNames(llm *llmPlan, creds []credentialPlan) []string {
	var names []string
	if llm != nil {
		for name := range llm.credentials {
			names = append(names, name)
		}
	}
	for _, c := range creds {
		names = append(names, c.binding.Name)
	}
	sort.Strings(names)
	return names
}

// mintBinding mints the sandbox's ingress binding, replacing a stale one
// an interrupted create or delete left for the same name.
func (m *Manager) mintBinding(spec sandboxauth.Spec) (sandboxauth.Binding, string, error) {
	binding, token, err := m.opts.Bindings.Mint(spec)
	if errors.Is(err, sandboxauth.ErrExists) {
		if stale, lerr := m.opts.Bindings.Lookup(spec.SandboxName); lerr == nil {
			_ = m.revokeBinding(stale.ID)
			binding, token, err = m.opts.Bindings.Mint(spec)
		}
	}
	if err != nil {
		return sandboxauth.Binding{}, "", sandboxapi.Errorf(sandboxapi.CodeInternal, "mint the sandbox binding: %v", err)
	}
	return binding, token, nil
}

func (m *Manager) revokeBinding(id string) error {
	err := m.opts.Bindings.Revoke(id)
	if errors.Is(err, sandboxauth.ErrNotFound) {
		err = nil
	}
	if m.opts.ForgetBinding != nil {
		m.opts.ForgetBinding(id)
	}
	m.toolCalls.Forget(id)
	return err
}

// principal is the egress identity of a sandbox, carrying the sandbox's own
// decider (egressDecider) and large-upload threshold, so the proxy decides
// and counts it by its policy alone.
func (m *Manager) principal(bindingID, sandboxID, name string, d *egress.Decider, eff *packs.Effective) egress.Principal {
	return egress.Principal{BindingID: bindingID, SandboxID: sandboxID, SandboxName: name, Decider: d,
		LargeUploadBytes: largeUploadBytes(eff)}
}

// reserve claims name for a create.
// reserve claims name for a create of project in the given workdir mode.
func (m *Manager) reserve(name, project, mode string) (*box, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.boxes[name]; ok {
		if old.retained {
			return nil, sandboxapi.Errorf(sandboxapi.CodeConflict,
				"the name %s holds the kept undo snapshot of a deleted sandbox; `defenseclaw sandbox delete %s` drops it (undo first to restore the folder)", name, name)
		}
		return nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "a sandbox named %s already exists", name)
	}
	b := &box{rec: record{Name: name, Project: project, WorkdirMode: mode}, creating: true, seenChunks: map[string]struct{}{}}
	m.boxes[name] = b
	return b, nil
}

// sharingMount returns another sandbox that mounts project, or a folder
// inside or around it, live; with running, only one whose workload may
// still run (not stopped, and not only a kept snapshot). Callers must not
// hold Manager.mu: the comparison reads the filesystem.
func (m *Manager) sharingMount(b *box, project string, running bool) string {
	type share struct{ name, project string }
	var others []share
	m.mu.Lock()
	for _, o := range m.boxes {
		if o == b || o.deleted || o.retained || o.rec.WorkdirMode != config.OpenShellWorkdirMount || o.rec.Project == "" {
			continue
		}
		if running && !o.creating && stoppedAuditPhase(o) {
			continue
		}
		others = append(others, share{o.rec.Name, o.rec.Project})
	}
	m.mu.Unlock()
	sort.Slice(others, func(i, j int) bool { return others[i].name < others[j].name })
	for _, o := range others {
		if workspace.Overlaps(project, o.project) {
			return o.name
		}
	}
	return ""
}

// stoppedAuditPhase reports a box whose workload does not run. Callers hold
// Manager.mu.
func stoppedAuditPhase(b *box) bool {
	phase := b.phase
	if phase == "" {
		phase = audit.SandboxPhase(b.rec.Phase)
	}
	switch phase {
	case audit.SandboxPhaseStopped, audit.SandboxPhaseCompleted, audit.SandboxPhaseError, audit.SandboxPhaseDeleted:
		return true
	}
	return false
}

func (m *Manager) release(name string, b *box) {
	m.mu.Lock()
	if m.boxes[name] == b {
		delete(m.boxes, name)
	}
	m.mu.Unlock()
	_ = m.removeRecord(b)
}

func realProject(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || !filepath.IsAbs(p) {
		return "", sandboxapi.Errorf(sandboxapi.CodeInvalid, "project must be an absolute host path")
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", sandboxapi.Errorf(sandboxapi.CodeInvalid, "project %s: %v", p, err)
	}
	info, err := os.Stat(real)
	if err != nil || !info.IsDir() {
		return "", sandboxapi.Errorf(sandboxapi.CodeInvalid, "project %s is not a folder", p)
	}
	return real, nil
}

func workspaceError(err error) error {
	switch {
	case errors.Is(err, workspace.ErrNeedsCopy):
		return &sandboxapi.Error{Code: sandboxapi.CodeNeedsCopy, Message: "this project cannot be mounted live; run it with --copy", Detail: err.Error()}
	case errors.Is(err, workspace.ErrUnsafeSource):
		return &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation, Message: "DefenseClaw refuses to mount this folder", Detail: err.Error()}
	case errors.Is(err, workspace.ErrScanIncomplete):
		return &sandboxapi.Error{Code: sandboxapi.CodeConflict, Message: "the secret scan could not check the whole project; run it with --copy or --unmask what it could not read", Detail: err.Error()}
	case errors.Is(err, workspace.ErrTooLarge):
		return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: "the project is too large", Detail: err.Error()}
	default:
		return &sandboxapi.Error{Code: sandboxapi.CodeInternal, Message: "prepare the project folder", Detail: err.Error()}
	}
}

func upstream(op string, err error) error {
	code := sandboxapi.CodeUpstream
	switch {
	case openshell.IsUnavailable(err):
		code = sandboxapi.CodeUnavailable
	case openshell.IsAlreadyExists(err), openshell.IsConflict(err):
		code = sandboxapi.CodeConflict
	case openshell.IsNotFound(err):
		code = sandboxapi.CodeNotFound
	case openshell.IsInvalidArgument(err):
		code = sandboxapi.CodeInvalid
	}
	return &sandboxapi.Error{Code: code, Message: "OpenShell: " + op + " failed", Detail: err.Error()}
}

// settle waits for OpenShell's first settings poll after a start.
func settle(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func joinNoProxy(existing string, extra []string) string {
	seen := map[string]bool{}
	var out []string
	for _, h := range append(strings.Split(existing, ","), extra...) {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// templateResources renders a resource request as the sandbox template's
// resources, in the Kubernetes requirements shape OpenShell drivers read.
func templateResources(r packs.Resources) map[string]any {
	limits := map[string]any{}
	if r.CPU != "" {
		limits["cpu"] = r.CPU
	}
	if r.Memory != "" {
		limits["memory"] = r.Memory
	}
	if len(limits) == 0 {
		return nil
	}
	return map[string]any{"limits": limits}
}

// recordMountTelemetry emits the workspace records of a new mount: the
// masks it applied and the snapshot it took.
func (m *Manager) recordMountTelemetry(ctx context.Context, b *box, plan *workspace.MountPlan, snapshot bool) {
	if plan == nil {
		return
	}
	m.mu.Lock()
	id := b.identity()
	name := b.rec.Name
	m.mu.Unlock()
	if len(plan.Masked) > 0 {
		n := int64(len(plan.Masked))
		_ = m.tel.RecordSandboxWorkspace(ctx, audit.SandboxWorkspaceEvent{
			Sandbox: id, Operation: audit.SandboxWorkspaceMask, Initiator: "operator", FileCount: &n,
			Paths: plan.MaskedRels(), Timestamp: m.now(),
		})
	}
	if !snapshot {
		return
	}
	snap, err := m.ws.LoadSnapshot(m.opts.DataDir, name)
	if err != nil || snap == nil {
		return
	}
	ev := audit.SandboxWorkspaceEvent{Sandbox: id, Operation: audit.SandboxWorkspaceSnapshot, Initiator: "operator",
		SnapshotKind: snapshotKind(snap.Kind), Timestamp: m.now()}
	if snap.Git != nil {
		ev.SnapshotRef = snap.Git.Ref
	}
	_ = m.tel.RecordSandboxWorkspace(ctx, ev)
}

func snapshotKind(k workspace.SnapshotKind) string {
	if k == workspace.SnapshotGit {
		return audit.SandboxSnapshotGit
	}
	return audit.SandboxSnapshotFilesystem
}
