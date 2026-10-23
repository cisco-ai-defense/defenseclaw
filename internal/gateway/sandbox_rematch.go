// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Re-matching registered sandboxes (plan §5.6).
//
// A registration is matched again when the sandbox policy it was last
// matched under changed (its policy key, a content digest that is the same
// in every gateway process, so a restart neither hides a change nor causes
// one), or when the caller's directory facts changed: a regroup, an
// identity refresh, or a provisional create whose lookup has now resolved.
// The match runs lazily, on the registration's next relayed call or
// policy/current poll (the daemon polls every 60 s), so an idle
// registration costs nothing.
//
//   - The profile, match, digests and provisional flag are rewritten in
//     place; live fields switch at once because every answer reads the
//     registration's floor: the current profile's, tightened by the floor
//     of the profile the sandbox was created under, so a re-match never
//     loosens a running sandbox (sandboxRegistrationFloor, GAP-0242).
//   - Facts that have not resolved (a slow or failed lookup) never change
//     the registration's match: it keeps its last proven profile. Calls
//     whose assignments need those facts refuse until they are confirmed.
//   - After a verified match, a create-time field the sandbox now violates
//     (sandboxes no longer allowed, its harness no longer allowed, a fatal
//     violation of its run) revokes the registration at once, so it admits
//     no relayed call and no relaxation of the policy brings it back
//     (GAP-0623, GAP-0644). The stop reason and next step are kept in the
//     registration's run record, which the daemon is told when it polls, and
//     survives a restart.
//   - A different account behind the uid is not a re-match: the subject
//     check revokes the registration (sandboxCheckSubject).

// sandboxRematchStopReason is the revoked_reason of a sandbox revoked
// because it outlived the stop a re-match asked for.
const sandboxRematchStopReason = sandboxreg.ReasonPolicyChanged

// What a re-match stop names as no longer allowed.
const (
	sandboxStopFieldSettings  = "the settings this sandbox was started with"
	sandboxStopFieldSandbox   = "sandboxes"
	sandboxStopFieldHarness   = "this agent in a sandbox"
	sandboxStopFieldHostPorts = "host ports"
)

// sandboxRematchIfDue re-matches reg when it is due and returns the
// registration as stored afterwards (revoked when it outlived its stop).
// A failure keeps reg as it was; callers check the current identity decision
// and refuse when it needs missing facts. A stop it could not store still
// refuses the call (GAP-0657).
func (a *APIServer) sandboxRematchIfDue(ctx context.Context, auth *sandboxAuthority, peer managedHookPeer, reg sandboxreg.Registration) sandboxreg.Registration {
	if reg.State == sandboxreg.StateRevoked {
		return reg
	}
	unlock := auth.rematch.lock(reg.ID)
	defer unlock()
	if fresh, ok, err := auth.store.Get(peer.UID, reg.ID); err == nil && ok {
		reg = fresh
	}
	if reg.State == sandboxreg.StateRevoked {
		return reg
	}
	run, hasRun, err := auth.store.Run(peer.UID, reg.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] re-match uid=%d registration=%s: %v\n", peer.UID, reg.ID, err)
		return reg
	}
	if reg = a.sandboxRevokeIfStopped(auth, peer, reg, run); reg.State == sandboxreg.StateRevoked {
		return reg
	}
	cfg := a.liveBaseConfig(ctx)
	key := a.sandboxPolicyKey(ctx, cfg)
	match := a.sandboxMatchPeer(ctx, peer, reg.Connector, 0)
	if len(match.decision.Unproven) > 0 {
		// No candidate profile is proven to be this caller's policy. Keep
		// the registration's last bound profile while relay calls refuse,
		// or, where every candidate only observes, observe.
		match.resolved = false
	}
	factsDigest := sandboxFactsDigest(auth.key, match.facts, match.resolved)
	if hasRun && key != "" && key == run.PolicyKey && (!match.resolved || factsDigest == reg.FactsDigest) {
		return reg
	}
	next := reg
	if next.CreateProfile == nil && !reg.Provisional {
		// Made before floors were pinned at create (GAP-0242): the profile
		// it was last matched under stands for the one it was created under.
		created := reg.Profile
		next.CreateProfile = &created
	}
	next.Generation = a.sandboxHostGeneration(ctx)
	if match.resolved {
		next.Profile, next.ProfileMatch, next.MatchedGroup = match.decision.Name, match.decision.Match, match.decision.MatchedGroup
		next.ProfileDigest, next.Provisional, next.FactsDigest = match.decision.Digest, match.provisional, factsDigest
	} else {
		// The policy key moves on below without a match under it: the
		// next resolved facts must re-match, whatever their digest.
		next.FactsDigest = ""
		if digest, ok := a.sandboxProfileDigest(ctx, reg.Profile); ok {
			next.ProfileDigest = digest
		}
	}
	if next.CreateProfile == nil && match.resolved && !next.Provisional {
		// Created under a provisional match: the first verified match is
		// the person's profile, and it pins the floor from now on.
		created := next.Profile
		next.CreateProfile = &created
	}
	floor, floorDigest, err := sandboxRegistrationFloor(cfg, next)
	if err != nil {
		// Keep the registration and its policy key: the next call retries.
		fmt.Fprintf(os.Stderr, "[sandbox-authority] re-match uid=%d registration=%s: %v\n", peer.UID, reg.ID, err)
		return reg
	}
	stopText := ""
	if hasRun {
		if eff, stopField := sandboxRematchResolve(cfg, peer, next, run, floor); eff != nil {
			next.EffectiveDigest = sandboxEffectiveDigest(eff)
			if stopField != "" && match.resolved && !next.Provisional {
				stopText = sandboxapi.ProfileStop(stopField, next.Harness, floor.RequestAccess)
			}
		}
	}
	verified := match.resolved && !next.Provisional
	switch {
	case verified && floor.Allowed != nil && !*floor.Allowed:
		stopText = sandboxapi.ProfileStop(sandboxStopFieldSandbox, next.Harness, floor.RequestAccess)
	case verified && !sandboxHarnessAllowed(floor, next.Harness):
		stopText = sandboxapi.ProfileStop(sandboxStopFieldHarness, next.Harness, floor.RequestAccess)
	}
	nextRun := run
	nextRun.PolicyKey, nextRun.FloorDigest = key, floorDigest
	switch {
	case stopText == "":
		nextRun.StopAt, nextRun.StopText = time.Time{}, ""
	case nextRun.StopAt.IsZero():
		nextRun.StopAt, nextRun.StopText = auth.clock(), stopText
	}
	changed := sandboxRematchChanges(reg, next)
	if run.FloorDigest != "" && run.FloorDigest != floorDigest {
		changed = append(changed, "floor")
	}
	if len(changed) > 0 {
		// The policy the user sees changed now (GAP-0690).
		next.PolicyAt = auth.clock()
	}
	if err := auth.store.UpdateRun(peer.UID, next, &nextRun); err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] re-match uid=%d registration=%s: %v\n", peer.UID, reg.ID, err)
		if stopText != "" {
			// The policy no longer allows this sandbox: refuse this call
			// although the stop was not stored (GAP-0657). The next call
			// matches again and stores it.
			return sandboxRevokedInMemory(auth, reg)
		}
		return reg
	}
	action := "live"
	if stopText != "" {
		action = "stop"
	}
	if len(changed) > 0 || action == "stop" {
		sandboxRecordRematched(a, reg, next, changed, action)
	}
	if stopText != "" {
		next = a.sandboxRevokeIfStopped(auth, peer, next, nextRun)
	}
	return next
}

// sandboxProfileDigest is the current digest of profile in the request's
// profile set.
func (a *APIServer) sandboxProfileDigest(ctx context.Context, profile string) (string, bool) {
	set := a.guardrailProfileSet()
	if g := pinnedGeneration(ctx); g.published() {
		set = g.Profiles
	}
	if set == nil || profile == "" {
		return "", false
	}
	derived, ok := set.derivedProfile(profile)
	return derived.Digest, ok
}

// sandboxRematchResolve resolves a registration's run (its run record)
// again under floor. stopField names what the running sandbox now has that
// the policy no longer allows ("" for nothing): a fatal violation of its
// settings, or a host port its create opened that the policy no longer
// opens; the forward is part of the running sandbox, so only a stop takes
// it back (GAP-0467). A run that can't be resolved returns nil and keeps
// the effective digest.
func sandboxRematchResolve(cfg *config.Config, peer managedHookPeer, reg sandboxreg.Registration, run sandboxreg.Run, floor config.OpenShellAdminConfig) (*packs.Effective, string) {
	in, err := sandboxRunInput(reg, run)
	if err != nil {
		return nil, ""
	}
	in.Subject = sandboxSubject(peer)
	eff, violations, err := sandboxResolveEffective(cfg, floor, in)
	if err != nil {
		return nil, ""
	}
	return eff, sandboxRematchStopField(violations, run.HostPorts, eff.MCP.HostPorts)
}

// sandboxHostPortsKey is the violation key of a host port.
const sandboxHostPortsKey = "mcp.host_ports"

// sandboxRematchStopField names what a re-matched run violates ("" for
// nothing): host ports when they are all it violates, a host port its
// create opened that the policy no longer opens (opened, open) or a refused
// --host-port, which a managed computer makes fatal (GAP-0558); its settings
// in general for any other fatal violation. A host-port stop said only "the
// settings this sandbox was started with" on a managed computer, where the
// refused --host-port is fatal (GAP-0078).
func sandboxRematchStopField(violations []packs.Violation, opened, open []int) string {
	hostPorts := slices.ContainsFunc(opened, func(port int) bool { return !slices.Contains(open, port) })
	for _, v := range violations {
		if !v.Fatal {
			continue
		}
		if v.Key != sandboxHostPortsKey {
			return sandboxStopFieldSettings
		}
		hostPorts = true
	}
	if hostPorts {
		return sandboxStopFieldHostPorts
	}
	return ""
}

// sandboxRunInput is the resolve input of reg's run record.
func sandboxRunInput(reg sandboxreg.Registration, run sandboxreg.Run) (sandboxResolveInput, error) {
	in := sandboxResolveInput{Req: sandboxrelay.ResolveRequest{
		V: sandboxrelay.WireVersion, Harness: reg.Harness, Connector: reg.Connector, ProjectReal: reg.ProjectReal,
		Flags: run.Flags, RepoOverlay: run.RepoOverlay, UserPack: run.UserPack,
	}, Profile: reg.Profile}
	if len(run.RepoOverlay) > 0 {
		repo, err := packs.ParseRepoPolicy(run.RepoOverlay, sandboxRepoPolicySrc)
		if err != nil {
			return sandboxResolveInput{}, err
		}
		in.Repo = repo
	}
	return in, nil
}

// sandboxRevokeIfStopped revokes reg when a re-match asked its sandbox to
// stop (run's stop): the registration admits no relayed call from then on,
// and a later relaxation of the policy does not revive it. A revoke that
// failed is tried again by the next call; until it is stored, every call
// is refused as revoked all the same (GAP-0657): a stop is never weakened
// by a failed write.
func (a *APIServer) sandboxRevokeIfStopped(auth *sandboxAuthority, peer managedHookPeer, reg sandboxreg.Registration, run sandboxreg.Run) sandboxreg.Registration {
	if run.StopAt.IsZero() || reg.State == sandboxreg.StateRevoked {
		return reg
	}
	if err := auth.store.Revoke(peer.UID, reg.ID, sandboxRematchStopReason); err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] revoke uid=%d registration=%s: %v\n", peer.UID, reg.ID, err)
		return sandboxRevokedInMemory(auth, reg)
	}
	before := reg
	reg.State, reg.RevokedReason, reg.RevokedAt = sandboxreg.StateRevoked, sandboxRematchStopReason, auth.clock()
	sandboxRecordRematched(a, before, reg, []string{"state"}, "revoke")
	return reg
}

// sandboxRevokedInMemory is reg as a stored revoke would leave it, for a
// stop whose write failed: the call is refused, and the store keeps the
// registration live only until the next call stores the revoke.
func sandboxRevokedInMemory(auth *sandboxAuthority, reg sandboxreg.Registration) sandboxreg.Registration {
	reg.State, reg.RevokedReason, reg.RevokedAt = sandboxreg.StateRevoked, sandboxRematchStopReason, auth.clock()
	return reg
}

// sandboxRematchChanges names the match fields a re-match changed.
func sandboxRematchChanges(before, after sandboxreg.Registration) []string {
	var changed []string
	for _, field := range []struct {
		name string
		diff bool
	}{
		{"profile", before.Profile != after.Profile},
		{"profile_match", before.ProfileMatch != after.ProfileMatch},
		{"matched_group", before.MatchedGroup != after.MatchedGroup},
		{"profile_digest", before.ProfileDigest != after.ProfileDigest},
		{"effective_digest", before.EffectiveDigest != after.EffectiveDigest},
		{"provisional", before.Provisional != after.Provisional},
	} {
		if field.diff {
			changed = append(changed, field.name)
		}
	}
	return changed
}
