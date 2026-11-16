// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// #1199 (GAP-0607, GAP-0561, rel GAP-0168): after a regroup the gateway
// re-matched the registration, and `policy explain` named the new profile,
// but `sandbox status NAME` named no organization profile at all and the
// refusals named the old one. The views of a sandbox now carry the profile
// and digest of the registration's current match, and the refusals' profile
// lookup gives the same profile.
func TestSandboxViewsNameTheRematchedProfile(t *testing.T) {
	c := newClosedFloorFixture(t)
	ctx := context.Background()
	if err := c.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Profile: "engineering", Digest: "sha256:old",
		Floor: closedFloorRegFloor, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	c.sandboxDaemonFixture.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:contractors", Profile: "contractors",
			Floor: &closedFloorRegFloor}, nil
	}
	c.d.pollOnce(ctx)
	for _, v := range c.statusAndList(t, "dc-a") {
		if v.OrganizationProfile != "contractors" || v.PolicyDigest != "sha256:contractors" || v.StopReason != "" {
			t.Fatalf("after the regroup: profile %q digest %q stop %q", v.OrganizationProfile, v.PolicyDigest, v.StopReason)
		}
	}
	if profile, ok := c.d.decisionsClient().SandboxProfile("dc-a"); !ok || profile != "contractors" {
		t.Fatalf("the refusals' profile = %q, %v", profile, ok)
	}
}

// A real managed gateway of this release answers policy/current with the
// complete floor. An answer without one (an older or broken gateway) is
// never applied: it does not confirm a registration, does not change its
// floor, and does not move the profile, digest or provisional state that
// status and the refusals show, so it can neither loosen the sandbox nor
// make its views claim a policy the daemon does not enforce.
func TestSandboxDaemonIgnoresAnAnswerWithoutAFloor(t *testing.T) {
	c := newClosedFloorFixture(t)
	ctx := context.Background()
	if err := c.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Profile: "contractors", Digest: "sha256:contractors",
		Provisional: true, Floor: closedFloorRegFloor, Generation: 3, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	before, _ := c.d.regs.get("dc-a")
	verified := false
	noFloor := sandboxrelay.CurrentPolicy{V: 1, Generation: 9, Digest: "sha256:open", Profile: "open", Provisional: &verified}
	if c.d.regs.applyLive("dc-a", noFloor) {
		t.Fatal("an answer without a floor was applied")
	}
	// The fake relay passes the answer on as it is (rawCurrent), instead of
	// completing it with an empty floor.
	c.sandboxDaemonFixture.relay.rawCurrent = true
	c.sandboxDaemonFixture.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) { return noFloor, nil }
	c.d.pollOnce(ctx)
	after, _ := c.d.regs.get("dc-a")
	if !reflect.DeepEqual(after.Floor, before.Floor) || after.Profile != "contractors" || after.Digest != "sha256:contractors" ||
		!after.Provisional || after.Generation != 3 {
		t.Fatalf("an answer without a floor moved the registration: %+v", after)
	}
	for _, v := range c.statusAndList(t, "dc-a") {
		if v.OrganizationProfile != "contractors" || v.PolicyDigest != "sha256:contractors" || !v.Provisional {
			t.Fatalf("the views follow an answer without a floor: profile %q digest %q provisional %v",
				v.OrganizationProfile, v.PolicyDigest, v.Provisional)
		}
	}

	// A registration loaded from the account's file stays unconfirmed.
	loaded, err := loadDaemonRegistrations(c.d.regs.path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.applyLive("dc-a", noFloor) {
		t.Fatal("an answer without a floor confirmed a loaded registration")
	}
	if r, _ := loaded.get("dc-a"); r.Confirmed || !reflect.DeepEqual(r.Floor, config.OpenShellAdminConfig{}) {
		t.Fatalf("loaded registration after an answer without a floor: %+v", r)
	}
}

// #1199 review: the views copied the provisional flag the registration got
// at create, while the profile and digest followed the current match, so a
// sandbox created during a directory outage kept saying the organization's
// default applies after a re-match had verified it under its group's
// profile. The flag now follows the gateway's current match both ways, and
// an answer that does not carry it (an older gateway) leaves it as it is.
func TestSandboxViewsFollowTheProvisionalMatch(t *testing.T) {
	c := newClosedFloorFixture(t)
	ctx := context.Background()
	if err := c.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Profile: "offline-floor", Digest: "sha256:floor",
		Provisional: true, Floor: closedFloorRegFloor, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	answer := func(profile, digest string, provisional *bool) {
		c.sandboxDaemonFixture.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
			return sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: digest, Profile: profile, Provisional: provisional,
				Floor: &closedFloorRegFloor}, nil
		}
		c.d.pollOnce(ctx)
	}
	want := func(step, profile, digest string, provisional bool) {
		t.Helper()
		for _, v := range c.statusAndList(t, "dc-a") {
			if v.OrganizationProfile != profile || v.PolicyDigest != digest || v.Provisional != provisional {
				t.Fatalf("%s: profile %q digest %q provisional %v, want %q %q %v", step, v.OrganizationProfile, v.PolicyDigest,
					v.Provisional, profile, digest, provisional)
			}
		}
		again, err := loadDaemonRegistrations(c.d.regs.path)
		if err != nil {
			t.Fatal(err)
		}
		if r, _ := again.get("dc-a"); r.Provisional != provisional {
			t.Fatalf("%s: saved provisional %v, want %v", step, r.Provisional, provisional)
		}
	}
	verified, provisional := false, true
	answer("contractors", "sha256:contractors", &verified)
	want("the directory answered again", "contractors", "sha256:contractors", false)
	answer("offline-floor", "sha256:floor", &provisional)
	want("a later match is provisional", "offline-floor", "sha256:floor", true)
	answer("offline-floor", "sha256:floor", nil)
	want("an answer without the flag", "offline-floor", "sha256:floor", true)
	// Only the flag moves (same profile and digest): still applied.
	answer("offline-floor", "sha256:floor", &verified)
	want("only the flag moved", "offline-floor", "sha256:floor", false)
}

// #1199 (GAP-0560, rel GAP-0417): a stop a re-match asked for (the profile
// no longer allows host ports) ended the session with "stopped from outside
// this session" and the activity feed with a 403 hook line. The daemon keeps
// the managed gateway's words for the revoke, the sandbox's views give them,
// and the feed says them when the daemon stops the sandbox.
func TestRematchStopKeepsTheOrganizationsWords(t *testing.T) {
	c := newClosedFloorFixture(t)
	ctx := context.Background()
	stop := sandboxapi.ProfileStop("host ports", "codex", "it-help@example.com")
	c.sandboxDaemonFixture.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Revoked: true, RevokedReason: stop}, nil
	}
	revoked := c.d.pollRegistrations(ctx, false)
	if len(revoked) != 1 || revoked[0].StopText != stop {
		t.Fatalf("revoked = %+v", revoked)
	}
	if r, _ := c.d.regs.get("dc-a"); !r.Revoked || r.StopText != stop {
		t.Fatalf("registration = %+v", r)
	}
	for _, v := range c.statusAndList(t, "dc-a") {
		if v.StopReason != stop || v.OrganizationProfile != "" {
			t.Fatalf("after the stop: stop %q profile %q", v.StopReason, v.OrganizationProfile)
		}
	}
	c.d.notePolicyStop(revoked[0])
	events := c.d.rt.manager.ActivitySince(0, "dc-a")
	if !slices.ContainsFunc(events, func(e sandboxapi.ActivityEvent) bool {
		return e.Reason == sandboxPolicyStopReason && e.Message == stop
	}) {
		t.Fatalf("activity = %+v", events)
	}

	// A refusal that ended the registration (404, 410, 409) carries a
	// reason code, not words: the views add nothing then.
	g := newClosedFloorFixture(t)
	g.sandboxDaemonFixture.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{}, &sandboxrelay.Error{Status: 410, Reason: "revoked"}
	}
	g.d.pollOnce(ctx)
	if r, _ := g.d.regs.get("dc-a"); !r.Revoked || r.StopText != "" {
		t.Fatalf("registration after a 410 = %+v", r)
	}
	for _, v := range g.statusAndList(t, "dc-a") {
		if v.StopReason != "" {
			t.Fatalf("a reason code shown as the stop: %q", v.StopReason)
		}
	}
}

// #1199 (GAP-0600): after a daemon restart the stopped sandbox's list entry
// lost its required pack and read strict (pack balanced), the closed
// start-up floor's resolution. While the managed gateway does not answer the
// list says the policy is being confirmed; once it answers, the entry has
// the required pack the gateway's answer carries (the account's
// registrations file never does, GAP-0182) and its network profile.
func TestColdStoppedSandboxKeepsItsRequiredPack(t *testing.T) {
	packDir := t.TempDir()
	file := filepath.Join(packDir, "contractors-b10", packs.PackFileName)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("version: 1\nname: contractors-b10\nextends: balanced\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.OpenShell.Admin.RequiredPack = file
	eff, _, err := packs.Resolve(cfg, packs.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(eff)
	if err != nil {
		t.Fatal(err)
	}
	var carried struct {
		Pack *packs.Pack `json:"pack"`
	}
	if err := json.Unmarshal(wire, &carried); err != nil || carried.Pack == nil {
		t.Fatalf("pack wire form: %v", err)
	}
	packRaw, err := json.Marshal(carried.Pack)
	if err != nil {
		t.Fatal(err)
	}
	// The account cannot read the administrator's pack folder.
	if err := os.RemoveAll(filepath.Dir(file)); err != nil {
		t.Fatal(err)
	}
	floor := config.OpenShellAdminConfig{RequiredPack: file, RequestAccess: "it-help@example.com"}

	var answers atomic.Bool
	created := map[string]any{"pack": "contractors-b10", "profile": "balanced", "network_mode": "allowlist", "approvals": "triage"}
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		seedSandboxRecord(t, o.StateDir, "dc-a", created)
		o.listPhases = func(context.Context) (map[string]string, bool) { return map[string]string{"dc-a": "stopped"}, true }
		// The registrations file the daemon left before its restart.
		doc := map[string]any{"v": 1, "registrations": []daemonRegistration{{ID: "reg-1", Sandbox: "dc-a", Profile: "contractors",
			Digest: "sha256:contractors", Floor: floor, UpdatedAt: time.Now().UTC()}}}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(o.StateDir, sandboxDaemonRegistrationsFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		if !answers.Load() {
			return sandboxrelay.CurrentPolicy{}, errors.New("connect: connection refused")
		}
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:contractors", Profile: "contractors",
			Floor: &floor, RequiredPack: packRaw}, nil
	}
	runPastRevalidate(t, f)
	f.d.rt.manager.RefreshPolicies()
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	ctx := context.Background()
	list, err := ctl.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if v := list[0]; !slices.Contains(v.Warnings, sandboxConfirmingNote) || v.Pack != "contractors-b10" || v.Profile != "balanced" {
		t.Fatalf("while confirming: pack %q profile %q warnings %q", v.Pack, v.Profile, v.Warnings)
	}
	answers.Store(true)
	list, err = ctl.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if v := list[0]; v.Pack != "contractors-b10" || v.Profile != "balanced" || v.NetworkMode == "deny" ||
		slices.Contains(v.Warnings, sandboxConfirmingNote) || v.OrganizationProfile != "contractors" {
		t.Fatalf("after the confirmation: pack %q profile %q/%s org %q warnings %q", v.Pack, v.Profile, v.NetworkMode,
			v.OrganizationProfile, v.Warnings)
	}
}

// GAP-0079: a re-match stopped a sandbox created under balanced (allowlist)
// for its host ports; after the daemon restarted, its list entry and status
// read profile strict and network deny, the closed start-up floor's, which
// stays closed because a revoked registration's floor is never adopted. The
// views now show the policy it was created with, next to the organization's
// words for the stop, and the floor stays closed.
func TestColdRevokedSandboxShowsThePolicyItHad(t *testing.T) {
	stop := sandboxapi.ProfileStop("host ports", "claudecode", "it-help@example.com")
	created := map[string]any{"pack": "balanced", "profile": "balanced", "network_mode": "allowlist", "approvals": "triage"}
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		seedSandboxRecord(t, o.StateDir, "dc-a", created)
		o.listPhases = func(context.Context) (map[string]string, bool) { return map[string]string{"dc-a": "stopped"}, true }
		doc := map[string]any{"v": 1, "registrations": []daemonRegistration{{ID: "reg-1", Sandbox: "dc-a", Profile: "noports",
			Digest: "sha256:noports", Floor: closedFloorRegFloor, Confirmed: true, Revoked: true,
			RevokedReason: stop, StopText: stop, UpdatedAt: time.Now().UTC()}}}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(o.StateDir, sandboxDaemonRegistrationsFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{V: 1, Revoked: true, RevokedReason: stop}, nil
	}
	runPastRevalidate(t, f)
	f.d.rt.manager.RefreshPolicies()
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	ctx := context.Background()
	list, err := ctl.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	sb, err := ctl.Get(ctx, "dc-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []sandboxapi.Sandbox{list[0], *sb} {
		if v.Pack != "balanced" || v.Profile != "balanced" || v.NetworkMode != "allowlist" || v.StopReason != stop ||
			slices.ContainsFunc(v.Violations, closedFloorDeny) || slices.Contains(v.Warnings, sandboxConfirmingNote) {
			t.Fatalf("cold view: pack %q profile %q network %q stop %q violations %+v warnings %q", v.Pack, v.Profile,
				v.NetworkMode, v.StopReason, v.Violations, v.Warnings)
		}
	}
	if !f.d.floorClosed() {
		t.Fatal("a revoked registration's floor was adopted")
	}
}

// newRunningRegroupFixture is a daemon restarted with the sandbox dc-a
// (created balanced, allowlist) and its registration reg-1 under
// engineering on file, whose policy/current answer is answer (counted in
// calls); the start-up confirmation has run.
func newRunningRegroupFixture(t *testing.T, answer *atomic.Pointer[sandboxrelay.CurrentPolicy], calls *atomic.Int32) (*sandboxDaemonFixture, *managedSandboxController) {
	t.Helper()
	created := map[string]any{"pack": "balanced", "profile": "balanced", "network_mode": "allowlist", "approvals": "triage"}
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		seedSandboxRecord(t, o.StateDir, "dc-a", created)
		o.listPhases = func(context.Context) (map[string]string, bool) { return map[string]string{"dc-a": "ready"}, true }
		doc := map[string]any{"v": 1, "registrations": []daemonRegistration{{ID: "reg-1", Sandbox: "dc-a", Profile: "engineering",
			Digest: "sha256:engineering", Floor: closedFloorRegFloor, UpdatedAt: time.Now().UTC()}}}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(o.StateDir, sandboxDaemonRegistrationsFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		calls.Add(1)
		return *answer.Load(), nil
	}
	runPastRevalidate(t, f)
	if r, _ := f.d.regs.get("dc-a"); !r.Confirmed || r.Profile != "engineering" {
		t.Fatalf("the start-up confirmation: %+v", r)
	}
	return f, &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
}

// GAP-0080: after a verified regroup `sandbox policy explain` named the new
// profile, but `sandbox status NAME` of the running sandbox kept the old one
// until the daemon's next poll (up to a minute). A status now asks the
// managed gateway for the registration's current policy first; other views
// of the sandbox (the session's own reads, list) do not.
func TestSandboxStatusConfirmsTheRegroupedProfile(t *testing.T) {
	var answer atomic.Pointer[sandboxrelay.CurrentPolicy]
	var calls atomic.Int32
	answer.Store(&sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:engineering", Profile: "engineering",
		Floor: &closedFloorRegFloor})
	f, ctl := newRunningRegroupFixture(t, &answer, &calls)
	ctx := context.Background()

	answer.Store(&sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:contractors", Profile: "contractors",
		Floor: &closedFloorRegFloor})
	before := calls.Load()
	if sb, err := ctl.Get(ctx, "dc-a"); err != nil || sb.OrganizationProfile != "engineering" || calls.Load() != before {
		t.Fatalf("a plain Get asked the gateway or moved: %+v %v (calls %d -> %d)", sb, err, before, calls.Load())
	}
	sb, err := ctl.Get(withSandboxPolicyConfirm(ctx), "dc-a")
	if err != nil || sb.OrganizationProfile != "contractors" || sb.PolicyDigest != "sha256:contractors" || calls.Load() != before+1 {
		t.Fatalf("status after the regroup: %+v %v (calls %d -> %d)", sb, err, before, calls.Load())
	}
	if r, _ := f.d.regs.get("dc-a"); r.Profile != "contractors" || r.Revoked {
		t.Fatalf("registration = %+v", r)
	}

	// A gateway that does not answer leaves the status as the daemon has it.
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		return sandboxrelay.CurrentPolicy{}, errors.New("connect: connection refused")
	}
	if sb, err := ctl.Get(withSandboxPolicyConfirm(ctx), "dc-a"); err != nil || sb.OrganizationProfile != "contractors" || sb.StopReason != "" {
		t.Fatalf("status with the gateway away: %+v %v", sb, err)
	}
}

// GAP-0080: when the regroup's profile no longer allows the sandbox's
// settings, the status shows the stop and its words instead of the old
// profile: the confirmation marks the registration revoked and stops the
// sandbox, as the poll does, once.
func TestSandboxStatusShowsTheRegroupStop(t *testing.T) {
	var answer atomic.Pointer[sandboxrelay.CurrentPolicy]
	var calls atomic.Int32
	answer.Store(&sandboxrelay.CurrentPolicy{V: 1, Generation: 3, Digest: "sha256:engineering", Profile: "engineering",
		Floor: &closedFloorRegFloor})
	f, ctl := newRunningRegroupFixture(t, &answer, &calls)
	ctx := context.Background()
	stop := sandboxapi.ProfileStop("host ports", "codex", "it-help@example.com")
	answer.Store(&sandboxrelay.CurrentPolicy{V: 1, Revoked: true, RevokedReason: stop})
	sb, err := ctl.Get(withSandboxPolicyConfirm(ctx), "dc-a")
	if err != nil || sb.StopReason != stop || sb.OrganizationProfile == "engineering" {
		t.Fatalf("status after the regroup stop: %+v %v", sb, err)
	}
	if r, _ := f.d.regs.get("dc-a"); !r.Revoked || r.StopText != stop {
		t.Fatalf("registration = %+v", r)
	}
	// The poll that comes next does not stop it again.
	if revoked := f.d.pollRegistrations(ctx, false); len(revoked) != 0 {
		t.Fatalf("the poll stopped it again: %+v", revoked)
	}
	stops := 0
	for _, e := range f.d.rt.manager.ActivitySince(0, "dc-a") {
		if e.Reason == sandboxPolicyStopReason && e.Message == stop {
			stops++
		}
	}
	if stops > 1 {
		t.Fatalf("%d policy stops in the feed", stops)
	}
}
