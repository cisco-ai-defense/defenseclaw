// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package packs

import (
	"errors"
	"maps"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ResolvedRun owns one host resolution and the exact configuration and flags
// that produced it. It is immutable and host-confidential. A wire policy view
// cannot construct one, and runtime adapters must not resolve its sources again.
type ResolvedRun struct {
	config     *config.Config
	flags      Flags
	effective  *Effective
	violations []Violation
}

// ResolveRun freezes the inputs before resolving once with the existing pack,
// repository, floor and host-fact evaluator. Inputs must stay stable during this
// call. Subsequent ExecutionInputs calls never load policy sources or host facts.
func ResolveRun(cfg *config.Config, flags Flags) (*ResolvedRun, []Violation, error) {
	if cfg == nil {
		return nil, nil, errors.New("sandbox policy: no configuration")
	}
	owned, err := cfg.DeepCopy()
	if err != nil {
		return nil, nil, err
	}
	owned.OpenShell, err = owned.EffectiveSandboxPolicy()
	if err != nil {
		return nil, nil, err
	}
	if err := owned.ValidateOpenShell(); err != nil {
		return nil, nil, err
	}
	flags = copyRunFlags(flags)
	effective, violations, err := Resolve(owned, flags)
	if err != nil {
		return nil, slices.Clone(violations), err
	}
	// The immutable observability plan is read only by Resolve to capture
	// reserved ports. Keep that captured authority, not a caller plan pointer.
	flags.Observability = nil
	return &ResolvedRun{config: owned, flags: flags, effective: effective,
		violations: slices.Clone(violations)}, slices.Clone(violations), nil
}

func (*ResolvedRun) MarshalJSON() ([]byte, error) {
	return nil, errors.New("sandbox policy: a host resolution cannot be serialized")
}

func (*ResolvedRun) UnmarshalJSON([]byte) error {
	return errors.New("sandbox policy: resolve the run on the trusted host")
}

// ExecutionInputs returns an independent host-owned copy of the complete
// resolution tuple. Its Effective retains runtime authority, unlike a JSON
// inspection view. Treat every result as immutable and keep it inside the host.
func (r *ResolvedRun) ExecutionInputs() (*config.Config, Flags, *Effective, []Violation, error) {
	if r == nil || r.config == nil || r.effective == nil {
		return nil, Flags{}, nil, nil, errors.New("sandbox policy: no owned host resolution")
	}
	cfg, err := r.config.DeepCopy()
	if err != nil {
		return nil, Flags{}, nil, nil, err
	}
	effective, err := r.effective.cloneAuthority()
	if err != nil {
		return nil, Flags{}, nil, nil, err
	}
	return cfg, copyRunFlags(r.flags), effective, slices.Clone(r.violations), nil
}

func copyRunFlags(flags Flags) Flags {
	flags.Unmask = slices.Clone(flags.Unmask)
	flags.HostPorts = slices.Clone(flags.HostPorts)
	flags.UserPack = slices.Clone(flags.UserPack)
	flags.RepoPolicy = cloneRepoPolicy(flags.RepoPolicy)
	if flags.Subject != nil {
		subject := *flags.Subject
		flags.Subject = &subject
	}
	if flags.Floor != nil {
		floor := cloneFloor(*flags.Floor)
		flags.Floor = &floor
	}
	return flags
}

// cloneAuthority is deliberately private: only an opaque ResolvedRun binds
// these host facts to the matching config and flags. JSON is never involved.
func (e *Effective) cloneAuthority() (*Effective, error) {
	if e == nil || e.view || e.digest == "" || e.decider == nil {
		return nil, errors.New("sandbox policy: a complete host resolution is required")
	}
	digest, err := e.computeDigest()
	if err != nil || digest != e.digest {
		return nil, errors.New("sandbox policy: resolved policy changed before freezing")
	}
	out := *e
	out.Pack = cloneResolvedPack(e.Pack)
	if e.requiredLoaded == e.Pack {
		out.requiredLoaded = out.Pack
	} else {
		out.requiredLoaded = cloneResolvedPack(e.requiredLoaded)
	}
	out.AllowedHarnesses = slices.Clone(e.AllowedHarnesses)
	out.Workspace.Masks = slices.Clone(e.Workspace.Masks)
	out.Workspace.Unmask = slices.Clone(e.Workspace.Unmask)
	out.Workspace.Review = slices.Clone(e.Workspace.Review)
	out.Egress.Feeds = slices.Clone(e.Egress.Feeds)
	out.Egress.Block = slices.Clone(e.Egress.Block)
	out.Egress.AdminBlock = slices.Clone(e.Egress.AdminBlock)
	out.Egress.Allow = slices.Clone(e.Egress.Allow)
	out.Egress.AllowOnly = slices.Clone(e.Egress.AllowOnly)
	out.Egress.Ports = slices.Clone(e.Egress.Ports)
	out.MCP.HostPorts = slices.Clone(e.MCP.HostPorts)
	out.MCP.BlockedTools = slices.Clone(e.MCP.BlockedTools)
	out.RepoPolicy = cloneRepoPolicy(e.RepoPolicy)
	out.RepoTightened = slices.Clone(e.RepoTightened)
	out.admin = cloneFloor(e.admin)
	out.reservedPorts = maps.Clone(e.reservedPorts)
	out.policySources = slices.Clone(e.policySources)
	out.hostNames = slices.Clone(e.hostNames)
	out.settings = maps.Clone(e.settings)
	out.firewallBlock = slices.Clone(e.firewallBlock)
	out.curatedAllow = slices.Clone(e.curatedAllow)
	// egress.Decider is immutable and safe for concurrent use. Sharing this
	// already-resolved evaluator preserves its feed and rule authority. Its
	// process-wide local-address guard retains the existing refresh behavior;
	// this copy does not create a new time-frozen host-address snapshot.
	return &out, nil
}

func cloneResolvedPack(pack *Pack) *Pack {
	if pack == nil {
		return nil
	}
	out := *pack
	out.Egress.Feeds = slices.Clone(pack.Egress.Feeds)
	out.Egress.Block = slices.Clone(pack.Egress.Block)
	out.Egress.Allow = slices.Clone(pack.Egress.Allow)
	out.Egress.Ports = slices.Clone(pack.Egress.Ports)
	out.Workspace.Masks = slices.Clone(pack.Workspace.Masks)
	out.Workspace.Unmask = slices.Clone(pack.Workspace.Unmask)
	out.Workspace.Review = slices.Clone(pack.Workspace.Review)
	out.Harness.Allowed = slices.Clone(pack.Harness.Allowed)
	out.MCP.BlockedTools = slices.Clone(pack.MCP.BlockedTools)
	out.Chain = slices.Clone(pack.Chain)
	out.builtinAllow = slices.Clone(pack.builtinAllow)
	return &out
}

func cloneRepoPolicy(policy *RepoPolicy) *RepoPolicy {
	if policy == nil {
		return nil
	}
	out := *policy
	out.Content = slices.Clone(policy.Content)
	out.Ports = slices.Clone(policy.Ports)
	out.Block = slices.Clone(policy.Block)
	out.Masks = slices.Clone(policy.Masks)
	out.Review = slices.Clone(policy.Review)
	out.BlockedTools = slices.Clone(policy.BlockedTools)
	out.Refused = slices.Clone(policy.Refused)
	return &out
}
