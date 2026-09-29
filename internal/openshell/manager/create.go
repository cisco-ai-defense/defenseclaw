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
	"slices"
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
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
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
	// What the sandbox is sent depends on the driver the gateway runs
	// now, which a restart since the connection may have changed.
	gw, err := m.driverGateway(ctx)
	if err != nil {
		return nil, err
	}
	flags := runFlags{
		Pack: req.Pack, Profile: req.Profile, Copy: req.Copy, Safe: req.Safe, Yolo: req.Yolo,
		Unmask: req.Unmask, HostPorts: req.HostPorts, NoMCP: req.NoMCP, Learn: req.Learn,
		CPU: req.CPU, Memory: req.Memory, Context: req.Context,
	}
	eff, violations, err := m.resolve(cfg, flags.packs(harnessName, project, gatewayFacts{Port: gw.Port, Driver: gw.Driver}))
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
	// Before anything is made, on the host or on the gateway.
	if err := driverRefusal(gw.Driver, spec, eff, req.Copy); err != nil {
		return nil, err
	}
	resources, v := m.driverResources(gw.Driver, eff.Resources)
	if v != nil {
		return nil, m.violationError(ctx, v, req.Name)
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		if name, err = GenerateName(project); err != nil {
			return nil, err
		}
	}
	if !openshell.ValidNewSandboxName(name) || workspace.ValidateName(name) != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid,
			"sandbox name %q must be lowercase letters, digits and '-', at most %d characters", name, openshell.MaxSandboxNameLen)
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
				"sandbox %s already mounts %s (or a folder inside or around it) live, stopped or not, and a folder takes one live mount "+
					"(each would undo the other's work); run this one with --copy, or delete %s first: `defenseclaw sandbox delete %s`",
				other, project, other, other)
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
		resources: resources,
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
	// resources is what the sandbox is limited to (driverResources).
	resources *packs.Resources
}

func (m *Manager) create(ctx context.Context, gw *Gateway, b *box, in createInput, rb *rollback) (*sandboxapi.Sandbox, error) {
	cfg := m.config()
	eff, spec, name := in.eff, in.harness, in.name
	egressDec, err := m.egressDecider(cfg, eff)
	if err != nil {
		return nil, err
	}

	img, err := m.image(ctx, cfg, spec, gw.Driver, !in.req.NoBuild)
	if err != nil {
		return nil, err
	}
	if !gw.Driver.HostsFile && !img.MicroVMVerified {
		return nil, microVMRefusal(spec, img)
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
	if llm != nil {
		for _, ep := range llm.profile.Spec.Endpoints {
			if err := modelEndpointRefusal(eff, triage.NormalizeHost(ep.Host)); err != nil {
				return nil, m.violationError(ctx, err, name)
			}
		}
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
	rec.Gateway, rec.GatewayEndpoint, rec.GatewayWorkspace = gw.Name, gw.Endpoint, gw.Client.Workspace()
	rec.Driver = string(gw.Driver.Name)
	rec.Resources = in.resources
	if note := limitsNote(gw.Driver, eff); note != "" {
		rec.Warnings = append(rec.Warnings, note)
	}
	rec.Verify = verifyExpectation(img, spec, arts)
	rec.ProviderEndpoints = providerEndpoints(name, llm, creds)
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
	for _, c := range creds {
		rec.Credentials = append(rec.Credentials, sandboxapi.CredentialGrant{Name: c.binding.Name, Host: c.binding.Host, Port: c.binding.Port})
	}
	rec.HostPorts = slices.Clone(eff.MCP.HostPorts)
	workdir := sandboxauth.Workdir{Mode: sandboxauth.WorkdirMode(in.mode)}
	var plan *workspace.MountPlan
	if in.mode == config.OpenShellWorkdirMount {
		// The pins and mask files a mount plan writes on the host, and the
		// snapshot, are for a live mount only.
		if !gw.Driver.HostMounts {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInternal,
				"sandbox %s: a live mount was planned on a gateway whose compute driver mounts no host folders", name)
		}
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
	// mode and the MCP servers the run brings along, mounted read-only, or
	// baked into the run image on a driver without host mounts.
	var modelProvider *connector.SandboxModelProvider
	if llm != nil {
		modelProvider = llm.cp.ModelProvider
	}
	credNames := credentialNames(llm, creds)
	rc, err := m.planRunConfig(ctx, runConfigInput{
		spec: spec, target: target, eff: eff, yolo: eff.Yolo, env: envOut, credentials: credNames,
		provider: modelProvider, workdir: runWorkdir(gw.Driver, rec.Workdir), project: in.project, baked: gw.Driver.RunFilesInImage,
	})
	if err != nil {
		return nil, err
	}
	rb.add("remove run configuration", func(context.Context) error { return m.removeRunConfig(name) })
	delivered, err := m.deliverRunConfig(ctx, gw.Driver, name, img, rc, in.req.Env)
	if err != nil {
		return nil, err
	}
	if rc != nil {
		rec.MCP = rc.mcp
		rec.Warnings = append(rec.Warnings, rc.notices...)
		rec.RunConfig = &runConfigRecord{Files: rc.paths(), Credentials: credNames, ModelProvider: modelProvider, Safe: !eff.Yolo,
			Delivery: delivered.how, Digest: delivered.digest}
		rec.Verify = withRunFileChecks(rec.Verify, img.UID, img.GID, runFileChecks(rc.files, delivered.how, img.UID, img.GID))
	}
	if ri := delivered.runImage; ri != nil {
		rec.RunImage, rec.RunImageID = ri.Tag, ri.ImageID
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
	tmpl := &openshell.SandboxTemplate{Image: delivered.image}
	if plan != nil {
		tmpl.DriverConfig = plan.DriverConfig()
	}
	tmpl.DriverConfig = withRunConfigMounts(tmpl.DriverConfig, delivered.mounts)
	if res := templateResources(eff.Resources); res != nil && gw.Driver.SandboxLimits {
		tmpl.Resources = res
	}
	// driverRefusal keeps host mounts away from a driver without them; this
	// keeps any other path from sending one.
	if !gw.Driver.HostMounts && tmpl.DriverConfig != nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInternal,
			"sandbox %s: host mounts were planned on a gateway whose compute driver mounts none", name)
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
	// Registered before the request: a failure that leaves open whether
	// OpenShell created the sandbox (the gateway restarting under the
	// call, a deadline) must not leave one behind that holds the project
	// mount and providers with no record.
	rb.add("delete sandbox", func(ctx context.Context) error { return m.deleteCreated(ctx, gw, name) })
	if _, err := gw.Client.CreateSandbox(ctx, name, sbSpec, openshell.CreateSandboxOptions{Labels: labels}); err != nil {
		m.dropGateway(gw, err)
		return nil, upstream("create sandbox "+name, err)
	}
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
	// Before the sandbox is saved and watched: one that does not run as
	// prepared is rolled back like one OpenShell rejected.
	var hostname string
	if !gw.Driver.SkipWorkloadCheck {
		facts, err := m.verifyWorkload(ctx, gw, name, *rec.Verify)
		if err != nil {
			return nil, err
		}
		hostname = facts.Hostname
	}

	m.mu.Lock()
	b.rec.ID = sb.ID
	b.rec.Hostname = hostname
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

// driverRefusal refuses a create the gateway's compute driver cannot carry
// out as DefenseClaw prepares it: without host mounts (the MicroVM driver)
// a sandbox cannot take a live mount of the project, and unless the driver
// takes them baked into an image it cannot take the per-run managed
// harness files either, which reach a docker sandbox as read-only bind
// mounts and keep the harness's settings and MCP servers locked down. It
// runs before anything is made, so a refused create leaves nothing behind.
//
// A project the policy runs on a copy only because the driver cannot mount
// it (packs.ConstraintComputeDriver) needs a copy the caller staged: when
// the request did not ask for one (an older CLI, or one that explained the
// run before the daemon knew the driver), the create is refused with
// CodeNeedsCopy, which the CLI answers by staging the copy and asking
// again. No copy sandbox is made that nobody uploads to.
func driverRefusal(d openshell.Driver, spec *harness.Spec, eff *packs.Effective, copyAsked bool) error {
	if d.HostMounts {
		return nil
	}
	why := d.MountRefusal
	if why == "" {
		why = "the gateway's compute driver mounts no host folders"
	}
	if _, runFiles := spec.Provider.(connector.SandboxRunConfigProvider); runFiles && !d.RunFilesInImage {
		return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable,
			Message: spec.DisplayName + " sandboxes cannot run on this gateway: DefenseClaw delivers their per-run harness configuration as read-only host mounts",
			Detail:  why}
	}
	if eff.Workspace.Mode == config.OpenShellWorkdirMount {
		return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable,
			Message: "the project cannot be mounted live on this gateway", Detail: why + "; run it with --copy"}
	}
	if s, _ := eff.Setting("workdir.mode"); s.Origin == packs.ConstraintComputeDriver && !copyAsked {
		return &sandboxapi.Error{Code: sandboxapi.CodeNeedsCopy, Message: "this project cannot be mounted live; run it with --copy",
			Detail: "the project cannot be mounted live: " + why}
	}
	return nil
}

// driverResources is what a sandbox on a gateway running d is limited to,
// as its record keeps it (record.Resources). A driver that enforces the
// template's limits gets the resolved request, which the resolver held to
// openshell.admin.max_resources already. One that does not (the vm driver)
// gives every sandbox the gateway-wide cpu and memory: those are recorded
// (nil when they cannot be read), and an administrator's maximum is judged
// against them, failing closed like every other admin constraint: they
// must be known and within it.
func (m *Manager) driverResources(d openshell.Driver, requested packs.Resources) (*packs.Resources, *packs.Violation) {
	if d.SandboxLimits {
		return &requested, nil
	}
	var shared *packs.Resources
	if m.opts.GatewayResources != nil {
		if res, err := m.opts.GatewayResources(); err == nil {
			shared = &res
		} else {
			m.logf("read the cpu and memory the %s driver gives every sandbox: %v", d.Name, err)
		}
	}
	return shared, sharedResourcesViolation(d, shared, m.config().OpenShell.Admin.MaxResources)
}

// sharedResourcesViolation refuses the gateway-wide cpu and memory every
// sandbox of d gets when they exceed an administrator's maximum or, with a
// maximum set, are unknown (nil).
func sharedResourcesViolation(d openshell.Driver, shared *packs.Resources, max config.OpenShellResourcesConfig) *packs.Violation {
	if strings.TrimSpace(max.CPU) == "" && strings.TrimSpace(max.Memory) == "" {
		return nil
	}
	table := "[openshell.drivers." + string(d.Name) + "]"
	fix := "every sandbox on the " + string(d.Name) + " driver gets the gateway-wide vcpus and mem_mib; lower them under " + table +
		" in the gateway's gateway.toml (`defenseclaw sandbox doctor --fix`)"
	if shared == nil {
		return &packs.Violation{Key: "resources", Source: packs.SourceUser, Attempted: "unknown",
			Constraint: "openshell.admin.max_resources", Fatal: true,
			Message: "your organization caps sandbox cpu and memory, and the gateway-wide vcpus and mem_mib every sandbox on the " +
				string(d.Name) + " driver gets cannot be read",
			Detail: fix}
	}
	v := resourceViolation(shared, max)
	if v == nil {
		return nil
	}
	what, key := strings.TrimPrefix(v.Key, "resources."), "vcpus"
	if what == "memory" {
		key = "mem_mib"
	}
	v.Message = "your organization caps sandbox " + what + " at " + v.Enforced + ", and every sandbox on the " + string(d.Name) +
		" driver gets " + v.Attempted + " (" + table + " " + key + ")"
	v.Detail = fix
	return v
}

// limitsNote says that the cpu and memory limits asked for (a flag, or
// openshell.resources) do nothing on a driver that sets no per-sandbox
// limits (the vm driver); "" otherwise. The CLI prints the same text
// before the create (sandboxcli's limitsIgnoredText) and does not repeat
// this one.
func limitsNote(d openshell.Driver, eff *packs.Effective) string {
	if d.SandboxLimits {
		return ""
	}
	for _, key := range []string{"resources.cpu", "resources.memory"} {
		if s, _ := eff.Setting(key); s.Source == packs.SourceUser || s.Source == packs.SourceFlag {
			return "cpu/memory limits have no effect on the OpenShell " + string(d.Name) + " driver: every MicroVM gets " +
				"[openshell.drivers." + string(d.Name) + "] vcpus and mem_mib"
		}
	}
	return ""
}

// deleteCreated is a failed create's rollback of its sandbox: it deletes
// the sandbox of that name when it carries this data dir's labels (create
// checked that none existed before, so it is the one this create made),
// and leaves a sandbox someone else created under the name alone.
func (m *Manager) deleteCreated(ctx context.Context, gw *Gateway, name string) error {
	gw = m.liveGateway(ctx, gw)
	sb, err := gw.Client.GetSandbox(ctx, name)
	switch {
	case openshell.IsNotFound(err):
		return nil
	case err != nil:
		return err
	case !m.ownsLabels(sb.Labels):
		return nil
	}
	if _, err := gw.Client.DeleteSandbox(ctx, name); err != nil && !openshell.IsNotFound(err) {
		return err
	}
	return gw.Client.WaitDeleted(ctx, name)
}

// liveGateway is the connection for a step that must not fail only because
// gw was dropped meanwhile (a rollback after the gateway went away under
// the create): the current connection, redialled when there is none, else
// gw.
func (m *Manager) liveGateway(ctx context.Context, gw *Gateway) *Gateway {
	if cur, err := m.gateway(ctx); err == nil {
		return cur
	}
	return gw
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
			_, err := m.liveGateway(ctx, gw).Client.DeleteProvider(ctx, pname)
			if openshell.IsNotFound(err) {
				err = nil
			}
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
	if len(creds) > 0 {
		// Rolled back after the providers (steps run newest first): the
		// --credential profiles this create imported are collected once no
		// provider uses them, as a delete collects them.
		ids := make([]string, 0, len(creds))
		for _, c := range creds {
			ids = append(ids, c.profile.ID)
		}
		rb.add("release credential profiles", func(ctx context.Context) error {
			m.releaseCredentialProfiles(ctx, m.liveGateway(ctx, gw), ids)
			return nil
		})
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

// image resolves the harness overlay image for this host user and the
// compute driver d the sandbox runs on: an image for the MicroVM driver
// answers localhost itself (image.MicroVMTarget).
func (m *Manager) image(ctx context.Context, cfg *config.Config, spec *harness.Spec, d openshell.Driver, build bool) (image.Record, error) {
	if m.opts.Images == nil {
		return image.Record{}, sandboxapi.Errorf(sandboxapi.CodeImageUnavailable, "no image builder is configured")
	}
	uid, gid := m.runAs()
	bs := image.BuildSpec{
		Harness: spec, HarnessVersion: cfg.OpenShell.Image.HarnessVersions[spec.Name], BaseImage: cfg.OpenShell.Image.Base,
		UID: uid, GID: gid, IngressPort: m.opts.IngressPort, FailMode: connector.SandboxFailMode,
		DefenseClawVersion: m.opts.DefenseClawVersion, MicroVM: image.MicroVMTarget(d),
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

// microVMRefusal refuses a sandbox on a gateway whose driver writes no
// /etc/hosts (openshell.Driver.HostsFile: a MicroVM) when its image did not
// pass the hook-fire probe's MicroVM scenario: the harness would exit at
// once, as Antigravity CLI did when localhost did not resolve. A harness
// the scenario found to resolve names on its own cannot start; an image
// whose scenario settled nothing, or never ran, is not checked yet. Each
// refusal names the command that checks the image again.
func microVMRefusal(spec *harness.Spec, img image.Record) error {
	recheck := "`defenseclaw sandbox image build " + spec.Name + " --force`"
	if img.MicroVMProblem != "" {
		return &sandboxapi.Error{Code: sandboxapi.CodeImageUnavailable,
			Message: spec.DisplayName + " cannot start in an OpenShell MicroVM (the vm driver this gateway runs)",
			Detail: img.MicroVMProblem + ". A gateway on the docker driver (Linux), whose sandboxes get Docker's /etc/hosts, runs " + spec.DisplayName +
				"; to check the image again: " + recheck}
	}
	detail := "its image " + img.Tag + " was not checked with a MicroVM's name resolution (OpenShell 0.1.1 gives a MicroVM an empty /etc/hosts); " +
		"check it: " + recheck
	if img.MicroVMInconclusive != "" {
		detail = "its image " + img.Tag + " was run with a MicroVM's name resolution, which settled nothing: " + img.MicroVMInconclusive +
			"; check it again: " + recheck + " (a run without --no-build checks it first, too)"
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeImageUnavailable,
		Message: spec.DisplayName + "'s image is not checked for an OpenShell MicroVM (the vm driver this gateway runs)", Detail: detail}
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
