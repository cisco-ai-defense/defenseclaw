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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// BaseFloor is the floor a run under cfg gets without a managed floor
// (Flags.Floor nil): openshell.admin. A run's own floor is
// Effective.Floor. BaseFloor is for the readers that have no run to ask:
// Resolve's OSS default, and the configuration views that show the
// organization's constraints without resolving one (the sandbox CLI's
// explain, doctor and banner texts, and the gateway's asset digest, which
// fingerprints the configuration). On a managed host those CLI views move
// to the daemon's Status.Managed (L7), which carries the caller's own
// floor; BaseFloor goes once they have.
func BaseFloor(cfg *config.Config) config.OpenShellAdminConfig {
	if cfg == nil {
		return config.OpenShellAdminConfig{}
	}
	return cfg.OpenShell.Admin
}

// DefaultPackFor is the pack a run under cfg gets when neither the
// configuration nor a flag selects one: ManagedDefaultPack on a
// managed_enterprise computer, DefaultPack elsewhere.
func DefaultPackFor(cfg *config.Config) string {
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return ManagedDefaultPack
	}
	return DefaultPack
}

// defaultPack is DefaultPackFor the configuration being resolved.
func (r *resolver) defaultPack() string {
	if r.managed {
		return ManagedDefaultPack
	}
	return DefaultPack
}

// Floor is F, the floor the run was clamped by: Flags.Floor, or
// openshell.admin when none was given. The caller gets its own copy.
func (e *Effective) Floor() config.OpenShellAdminConfig {
	if e == nil {
		return config.OpenShellAdminConfig{}
	}
	return cloneFloor(e.admin)
}

// MaxResources is the floor's max_resources (the workload check's and the
// start's limits); zero, which limits nothing, on a nil Effective.
func (e *Effective) MaxResources() config.OpenShellResourcesConfig {
	if e == nil {
		return config.OpenShellResourcesConfig{}
	}
	return e.admin.MaxResources
}

// AllowYolo reports whether the floor leaves skip-permissions mode allowed
// (allow_yolo is not false). A required pack can still keep the harness
// prompts (Allow with ActionYolo answers for the run). A nil Effective
// allows nothing.
func (e *Effective) AllowYolo() bool {
	return e != nil && !isFalse(e.admin.AllowYolo)
}

// Digest is the effective sandbox policy digest, "sha256:<hex>" over the
// canonical JSON of the floor and the resolved posture (digestView). It is
// the digest a user is shown: it covers only the user's own policy, and
// leaves out the host's own names, its reserved ports and file paths, so
// two runs under the same policy share it.
func (e *Effective) Digest() string {
	if e == nil {
		return ""
	}
	return e.digest
}

// digestView is what Digest covers. Every field is part of the policy a
// sandbox runs under; host facts and paths stay out.
type digestView struct {
	V int `json:"v"`
	// Floor is the floor's wire form (floorJSON): openshell.admin's key
	// names, keys in order, unset keys left out.
	Floor            json.RawMessage `json:"floor"`
	Pack             string          `json:"pack"`
	PackDigest       string          `json:"pack_digest"`
	PackChain        []string        `json:"pack_chain,omitempty"`
	RequiredPack     bool            `json:"required_pack"`
	RepoDigest       string          `json:"repo_digest,omitempty"`
	RepoTightened    []string        `json:"repo_tightened,omitempty"`
	Profile          string          `json:"profile"`
	NetworkMode      string          `json:"network_mode"`
	Approvals        string          `json:"approvals"`
	Yolo             bool            `json:"yolo"`
	Harness          string          `json:"harness,omitempty"`
	AnyHarness       bool            `json:"any_harness"`
	AllowedHarnesses []string        `json:"allowed_harnesses"`
	ProcessTree      bool            `json:"process_tree"`
	Workspace        Workspace       `json:"workspace"`
	Egress           Egress          `json:"egress"`
	MCP              MCP             `json:"mcp"`
	Resources        Resources       `json:"resources"`
	Learn            bool            `json:"learn"`
	HookFailMode     string          `json:"hook_fail_mode"`
	HookOnTamper     string          `json:"hook_on_tamper"`
	HookOnSilence    string          `json:"hook_on_silence"`
	HookSilenceAfter time.Duration   `json:"hook_silence_after"`
}

// computeDigest digests the resolved posture (Digest).
func (e *Effective) computeDigest() (string, error) {
	floor, err := floorJSON(e.admin)
	if err != nil {
		return "", err
	}
	view := digestView{
		V: 1, Floor: floor, RequiredPack: e.requiredPack,
		RepoTightened: e.RepoTightened,
		Profile:       e.Profile, NetworkMode: e.NetworkMode, Approvals: e.Approvals, Yolo: e.Yolo,
		Harness: e.Harness, AnyHarness: e.AnyHarness, AllowedHarnesses: e.AllowedHarnesses, ProcessTree: e.ProcessTree,
		Workspace: e.Workspace, Egress: e.Egress, MCP: e.MCP, Resources: e.Resources, Learn: e.Learn,
		HookFailMode: e.HookFailMode, HookOnTamper: e.HookOnTamper, HookOnSilence: e.HookOnSilence,
		HookSilenceAfter: e.HookSilenceAfter,
	}
	if p := e.Pack; p != nil {
		view.Pack, view.PackDigest = p.Name, p.Digest
		for _, link := range p.Chain {
			view.PackChain = append(view.PackChain, link.Digest)
		}
	}
	if rp := e.RepoPolicy; rp != nil {
		view.RepoDigest = rp.Digest
	}
	data, err := json.Marshal(view)
	if err != nil {
		return "", fmt.Errorf("sandbox policy: digest: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// cloneFloor copies f with its own lists and switches, so a caller cannot
// change the floor an Effective holds.
func cloneFloor(f config.OpenShellAdminConfig) config.OpenShellAdminConfig {
	for _, list := range []*[]string{
		&f.AllowedHarnesses, &f.EgressBlock, &f.EgressAllowOnly, &f.RequireCopyFor, &f.Locked,
		&f.RequiredFor, &f.AllowedCredentials,
	} {
		*list = slices.Clone(*list)
	}
	for _, flag := range []**bool{
		&f.AllowYolo, &f.AllowMount, &f.AllowHostPorts, &f.AllowUnblock, &f.AllowLearnMode,
		&f.Allowed, &f.ProcessTree, &f.AllowUpstreamTelemetry,
	} {
		if *flag != nil {
			v := **flag
			*flag = &v
		}
	}
	return f
}

// adminStatusFor is AdminStatusFor for the floor a run is clamped by.
func adminStatusFor(cfg *config.Config, floor config.OpenShellAdminConfig) AdminStatus {
	status := AdminStatus{Authority: AuthorityAdvisory}
	if cfg == nil {
		status.Detail = "no configuration"
		return status
	}
	status.Configured = !floor.IsZero()
	switch {
	case managed.IsManagedEnterprise(cfg.DeploymentMode):
		status.Authority = AuthorityAuthoritative
		if status.Configured {
			status.Detail = "openshell.admin is authoritative: config.yaml is administrator-owned (managed_enterprise)"
		} else {
			status.Detail = "no openshell.admin constraints in the administrator-owned config.yaml"
		}
	case status.Configured:
		status.Detail = "openshell.admin is enforced but advisory: you own config.yaml and can edit it"
	default:
		status.Detail = "no openshell.admin constraints"
	}
	return status
}

// applyFloor applies the floor keys that tighten the resolved posture
// itself: allowed (no sandbox at all), process_tree, on_silence and
// max_silence_after. The others act where they apply: required_for and
// when_unavailable on the host's hooks, user_approvals and
// allowed_credentials in the sandbox manager, request_access in messages.
func (r *resolver) applyFloor() error {
	f := r.admin
	if isFalse(f.Allowed) {
		r.violate(Violation{
			Key: "sandbox", Source: SourceUser, Attempted: "run", Constraint: "openshell.admin.allowed", Fatal: true,
			Detail: "your organization does not let you run sandboxes",
		})
	}
	if f.ProcessTree != nil && *f.ProcessTree && !r.eff.ProcessTree {
		r.eff.ProcessTree = true
		r.setClamped("observe.process_tree", "true", "false", "openshell.admin.process_tree")
	}
	if f.OnSilence == OnSilenceStop && r.eff.HookOnSilence != OnSilenceStop {
		r.setClamped("hooks.on_silence", OnSilenceStop, r.eff.HookOnSilence, "openshell.admin.on_silence")
		r.eff.HookOnSilence = OnSilenceStop
	}
	if s := strings.TrimSpace(f.MaxSilenceAfter); s != "" {
		limit, err := time.ParseDuration(s)
		if err != nil || limit <= 0 {
			return fmt.Errorf("sandbox policy: openshell.admin.max_silence_after %q is not a duration", s)
		}
		limit = max(limit, MinSilenceAfter)
		if r.eff.HookSilenceAfter <= 0 || r.eff.HookSilenceAfter > limit {
			requested := r.eff.settings["hooks.silence_after"].Value
			r.eff.HookSilenceAfter = limit
			r.setClamped("hooks.silence_after", ShortDuration(limit), requested, "openshell.admin.max_silence_after")
		}
	}
	return nil
}

func init() { config.SandboxProfilePackCheck = ProfilePackCheck }

// ProfilePackCheck refuses a guardrail profile's sandbox.required_pack
// (profilePack, pinned by profileDigest when set) that does not load, does
// not match its pin, or is looser in any setting (looserPackKey) than the
// organization's pack (basePack, openshell.admin.required_pack) or, with no
// organization pack, than the default pack (openshell.pack, else balanced),
// as Resolve does at each create given Flags.Floor. It has the signature of
// config.SandboxProfilePackCheck, the hook the configuration load (and so
// `ensure`) calls for every profile floor with a pack or a pin of its own;
// the packs load as the process loading the configuration.
// It is registered in this package's init, so every process that links the
// resolver (the gateway, `ensure`) checks profile packs at load.
func ProfilePackCheck(cfg *config.Config, basePack, profilePack, profileDigest string) error {
	if cfg == nil {
		return errors.New("sandbox policy: no configuration")
	}
	base := cfg.OpenShell.Admin
	if strings.TrimSpace(basePack) != strings.TrimSpace(base.RequiredPack) {
		// The pin belongs to openshell.admin's own pack.
		base.RequiredPack, base.RequiredPackDigest = basePack, ""
	}
	// A profile's pack comes with its own pin (TightenOpenShellAdmin).
	floor := base
	floor.RequiredPack, floor.RequiredPackDigest = profilePack, strings.TrimSpace(profileDigest)
	r := &resolver{admin: floor, subject: callerSubject(), managed: managed.IsManagedEnterprise(cfg.DeploymentMode)}
	return r.checkFloorPack(cfg.OpenShell, base)
}

// checkFloorPack refuses a floor (r.admin) that drops base's required pack,
// names a pack that does not match the floor's own pin, or names one looser
// than base's pack, or, when base has none, than the default pack
// (openshell.pack, else balanced).
// A profile's sandbox section only tightens, and a pack is the one floor key
// whose strictness is in its content: extends: is an authoring aid, not a
// guarantee, so the packs are compared setting by setting. It fails closed:
// a pack that does not load refuses.
func (r *resolver) checkFloorPack(o config.OpenShellConfig, base config.OpenShellAdminConfig) error {
	baseRef := strings.TrimSpace(base.RequiredPack)
	ref := strings.TrimSpace(r.admin.RequiredPack)
	var basePack *Pack
	switch {
	case baseRef == "" && ref == "":
		return nil
	case baseRef == "":
		// No organization pack: users otherwise get the default pack (the
		// administrator's openshell.pack, else balanced), and a profile's
		// pack may only tighten it (GAP-0268).
		var err error
		if def := strings.TrimSpace(o.Pack); def != "" {
			basePack, err = r.loadPack(def, o.PackDir, r.managed)
		} else {
			basePack, err = Builtin(config.OpenShellProfileBalanced)
		}
		if err != nil {
			return fmt.Errorf("sandbox policy: the default pack: %w", err)
		}
	case ref == "":
		return fmt.Errorf("sandbox policy: your sandbox policy drops the organization's required pack %s", baseRef)
	default:
		loaded, err := r.loadPack(baseRef, o.PackDir, r.managed)
		if err != nil {
			return fmt.Errorf("sandbox policy: openshell.admin.required_pack: %w", err)
		}
		if digest := strings.TrimSpace(base.RequiredPackDigest); digest != "" && loaded.Digest != digest {
			return fmt.Errorf("sandbox policy: openshell.admin.required_pack %s has digest %s, not the pinned openshell.admin.required_pack_digest %s",
				loaded.Name, loaded.Digest, digest)
		}
		basePack = loaded
	}
	// Managed computers run every sandbox on a copy of the project (SPEC
	// D2): the default pack they judge a profile's pack against works on a
	// copy too, so a profile pack that mounts the project live is looser
	// than it (GAP-0473).
	baseline := basePack
	if baseRef == "" && r.managed && basePack.Workspace.Mode != config.OpenShellWorkdirCopy {
		copied := *basePack
		copied.Workspace.Mode = config.OpenShellWorkdirCopy
		baseline = &copied
	}
	pack := basePack
	if ref != baseRef {
		loaded, err := r.loadPack(ref, o.PackDir, r.managed)
		if err != nil {
			return fmt.Errorf("sandbox policy: the required pack of your sandbox policy: %w", err)
		}
		pack = loaded
	}
	if pin := strings.TrimSpace(r.admin.RequiredPackDigest); pin != "" && pack.Digest != pin {
		return fmt.Errorf("sandbox policy: the required pack %s of your sandbox policy has digest %s, not its pinned required_pack_digest %s",
			pack.Name, pack.Digest, pin)
	}
	if pack.Digest == basePack.Digest && baseline == basePack {
		return nil
	}
	if key := looserPackKey(pack, baseline, networkForProfile(pack.Profile())); key != "" {
		against := "the organization's required pack " + basePack.Name
		if baseRef == "" {
			against = "the default pack " + basePack.Name
		}
		why := ""
		if key == "workspace.mode" && baseline != basePack {
			why = " (managed computers run sandboxes on a copy of the project: set workspace.mode: copy in the pack)"
		}
		return fmt.Errorf("sandbox policy: the required pack %s of your sandbox policy is looser than %s in %s%s", pack.Name, against, key, why)
	}
	return nil
}
