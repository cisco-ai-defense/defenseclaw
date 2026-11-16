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

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// ownPeer is a managed peer of this test process's own account: the
// managed gateway resolves a peer's run with the pack files that peer or
// root owns, and a test cannot write a root-owned one.
func ownPeer(t *testing.T) managedHookPeer {
	t.Helper()
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("needs an account other than root as the sandbox user")
	}
	return managedHookPeer{UID: uid, Name: "test-own@directory.example"}
}

// writeRequiredPack writes the custom sandbox pack name (extending balanced)
// under dir and returns its file.
func writeRequiredPack(t *testing.T, dir, name string) string {
	t.Helper()
	file := filepath.Join(dir, name, packs.PackFileName)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("version: 1\nname: "+name+"\nextends: balanced\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// GAP-0058: a sandbox that runs the organization's custom required pack
// itself (no stricter pack in its place) gets its complete policy from
// policy/current and the state report, the pack included, as one whose
// stricter pack stands in for it does. Before, both answered
// policy_unloadable, and the daemon kept the floor of the sandbox's create.
func TestSandboxCurrentCarriesTheRequiredPackTheSandboxRuns(t *testing.T) {
	peer := ownPeer(t)
	gate := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	gate.setGroups(peer, "dc-sbx-devs")
	file := writeRequiredPack(t, t.TempDir(), "r103-pack")
	gate.cfg.OpenShell.Admin.RequiredPack = file
	resp := gate.live(peer, 1)
	floor, err := managedResolveFloor(resp)
	if err != nil || floor.RequiredPack != file {
		t.Fatalf("resolve floor = %+v, %v", floor, err)
	}
	pack, err := useAuthorityPack(resp, floor)
	if err != nil || pack == nil || pack.Name != "r103-pack" {
		t.Fatalf("the resolve answer's pack: %+v, %v", pack, err)
	}
	id := resp.Registration.ID
	for _, report := range []bool{false, true} {
		var code int
		var cp sandboxrelay.CurrentPolicy
		if report {
			code, cp = gate.report(peer, id, true)
		} else {
			code, cp = gate.current(peer, id)
		}
		if code != http.StatusOK || cp.Floor == nil || cp.Floor.RequiredPack != file || len(cp.RequiredPack) == 0 {
			t.Fatalf("report %v: %d floor %+v pack %d bytes", report, code, cp.Floor, len(cp.RequiredPack))
		}
		var got packs.Pack
		if err := json.Unmarshal(cp.RequiredPack, &got); err != nil || got.Name != pack.Name || got.Digest != pack.Digest {
			t.Fatalf("report %v: carried pack %s %s, want %s %s (%v)", report, got.Name, got.Digest, pack.Name, pack.Digest, err)
		}
		if err := useCurrentPack(cp); err != nil {
			t.Fatalf("report %v: the daemon refuses the answer: %v", report, err)
		}
	}
}

// GAP-0058 (T8, TST-2216): the organization changes foreign_sandboxes from
// alert to stop while a managed sandbox that runs the custom required pack
// is registered. Through the real routes the next poll gives the
// registration the stricter floor, so the next reconcile judges foreign
// sandboxes under stop (the manager's side is
// TestManagedForeignStopAfterTheRegistrationFloorTightens). The sandbox was
// created under the same profile, so the organization's later alert
// applies to it again: no create profile pins it stricter
// (TestSandboxAuthorityForeignSandboxesOnlyTighten has that case).
func TestSandboxDaemonForeignStopReachesALiveRegistration(t *testing.T) {
	peer := ownPeer(t)
	file := writeRequiredPack(t, t.TempDir(), "r103-pack")
	f, _, gate, gateway := upgradeFloorFixtureWith(t, false, peer, func(g *sandboxFixture) {
		g.cfg.OpenShell.Admin.RequiredPack = file
		g.cfg.OpenShell.Admin.ForeignSandboxes = config.OpenShellForeignSandboxesAlert
	})
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) {
		rec := gate.do(peer, http.MethodGet, sandboxrelay.PathSettings, nil, nil)
		if rec.Code != http.StatusOK {
			return sandboxrelay.DaemonSettings{}, &sandboxrelay.Error{Status: rec.Code}
		}
		var s sandboxrelay.DaemonSettings
		err := json.Unmarshal(rec.Body.Bytes(), &s)
		return s, err
	}
	// The real answers, not the fake relay's empty-floor fill.
	f.relay.rawCurrent = true
	ctx := context.Background()
	gateway(true)
	f.d.revalidate(ctx)
	f.d.pollOnce(ctx)
	if f.d.floorClosed() {
		t.Fatal("policy/current did not confirm the registration of a sandbox that runs the required pack")
	}
	foreign := func(want string) {
		t.Helper()
		reg, ok := f.d.regs.get("dc-claude-1")
		if !ok || !reg.Confirmed || reg.Floor.ForeignSandboxes != want || reg.Floor.RequiredPack != file {
			t.Fatalf("registration = %+v, want confirmed with foreign_sandboxes %q and the required pack", reg, want)
		}
		if got := f.d.configForSandbox("dc-claude-1").OpenShell.Admin.ForeignSandboxes; got != want {
			t.Fatalf("the sandbox resolves under foreign_sandboxes %q, want %q", got, want)
		}
	}
	foreign(config.OpenShellForeignSandboxesAlert)

	gate.cfg.OpenShell.Admin.ForeignSandboxes = config.OpenShellForeignSandboxesStop
	f.d.pollOnce(ctx)
	foreign(config.OpenShellForeignSandboxesStop)

	gate.cfg.OpenShell.Admin.ForeignSandboxes = config.OpenShellForeignSandboxesAlert
	f.d.pollOnce(ctx)
	foreign(config.OpenShellForeignSandboxesAlert)
}

// GAP-0058: a managed gateway that answers it cannot load a registration's
// policy is not an outage. The floor confirmed before may be looser than
// the organization's now, so the sandbox resolves under the closed floor
// (and its new connections are refused) until an answer carries its policy
// again. An unreachable gateway keeps the confirmed floor, as before.
func TestSandboxDaemonUnloadablePolicyClosesTheFloor(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	alert := config.OpenShellAdminConfig{ForeignSandboxes: config.OpenShellForeignSandboxesAlert, RequestAccess: "it-help@example.com"}
	r := daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Profile: "engineering", Digest: "sha256:v1", Generation: 4,
		Floor: alert, UpdatedAt: time.Now().UTC(), Confirmed: true}
	if err := f.d.regs.put(r); err != nil {
		t.Fatal(err)
	}
	var answer error
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
		if answer != nil {
			return sandboxrelay.CurrentPolicy{}, answer
		}
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 5, Digest: "sha256:v1", Profile: "engineering", Floor: &alert}, nil
	}
	ctx := context.Background()

	answer = sandboxrelay.ErrGatewayUnreachable
	if ans := f.d.askPolicy(ctx, r, false, false); ans.err == nil {
		t.Fatal("an unreachable gateway answered")
	}
	if got, _ := f.d.regs.get("dc-a"); !got.Confirmed {
		t.Fatal("an unreachable gateway put the sandbox on the closed floor")
	}

	answer = &sandboxrelay.Error{Status: http.StatusServiceUnavailable, Reason: sandboxrelay.ReasonPolicyUnloadable}
	before := f.d.regs.changeCount()
	if ans := f.d.askPolicy(ctx, r, false, false); ans.err == nil {
		t.Fatal("an unloadable answer was applied")
	}
	if got, _ := f.d.regs.get("dc-a"); got.Confirmed {
		t.Fatal("the sandbox kept the floor it confirmed before the gateway could not load its policy")
	}
	if f.d.regs.changeCount() == before {
		t.Fatal("closing the floor is not a change the next adoption re-resolves")
	}
	admin := f.d.configForSandbox("dc-a").OpenShell.Admin
	if admin.ForeignSandboxes == config.OpenShellForeignSandboxesAlert || admin.Allowed == nil || *admin.Allowed {
		t.Fatalf("after the unloadable answer the sandbox resolves under %+v, want the closed floor", admin)
	}
	if changed, off, failed := f.d.confirmOnce(ctx, r, false); changed || off == nil || !failed {
		t.Fatalf("a new connection after the unloadable answer: changed %v off %+v failed %v, want refused", changed, off, failed)
	}

	answer = nil
	if ans := f.d.askPolicy(ctx, r, false, false); ans.err != nil {
		t.Fatal(ans.err)
	}
	if got, _ := f.d.regs.get("dc-a"); !got.Confirmed || got.Floor.ForeignSandboxes != config.OpenShellForeignSandboxesAlert {
		t.Fatalf("the next answer did not confirm the registration again: %+v", got)
	}
}
