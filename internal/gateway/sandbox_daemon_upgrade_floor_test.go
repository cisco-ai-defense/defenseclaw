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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// rc1RegistrationJSON has the v:1, snake-case daemon fields and every Go
// field name in Floor that rc.1 saveLocked wrote. The oldest registration
// file this release needs to load is rc.1: 1.0.0 and 1.0.1 did not have the
// managed sandbox daemon. The id and time come from the in-process gateway.
const rc1RegistrationJSON = `{"v":1,"registrations":[{
"id":%q,"sandbox":"dc-claude-1","profile":"engineering","digest":"old-digest","generation":3,
"floor":{
"RequiredPack":"","RequiredPackDigest":"","MinProfile":"balanced",
"AllowYolo":null,"AllowMount":null,"AllowHostPorts":null,"AllowUnblock":null,"AllowLearnMode":null,
"AllowedHarnesses":null,"EgressBlock":null,"EgressAllowOnly":null,"BlockLargeUploads":false,
"RequireCopyFor":null,"MaxResources":{"CPU":"","Memory":""},"Locked":null,"Allowed":null,
"RequiredFor":null,"WhenUnavailable":"","UserApprovals":"","AllowedCredentials":null,
"OnSilence":"","MaxSilenceAfter":"","ProcessTree":null,"ForeignSandboxes":"",
"AllowUpstreamTelemetry":null,"DeleteStoppedAfter":"","RequestAccess":"it-help@example.com",
"DriverFallback":""},
"driver":"docker","driver_reason":"configured","updated_at":%q}]}`

// A directory-style account name exercises the subject key on both the
// rc.1 bind and the current state route without using a real account.
var upgradeFloorPeer = managedHookPeer{UID: 94409901, Name: "test-engineer@directory.example"}

func upgradeFloorFixture(t *testing.T, rc1 bool) (*sandboxDaemonFixture, *managedSandboxController, *sandboxFixture, func(bool)) {
	t.Helper()
	gate := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	gate.setGroups(upgradeFloorPeer, "dc-sbx-devs")
	gate.cfg.OpenShell.Admin = closedFloorRegFloor
	resp := gate.live(upgradeFloorPeer, 1)
	id := resp.Registration.ID
	var answer bool
	created := map[string]any{"pack": "balanced", "profile": "balanced", "network_mode": "allowlist", "approvals": "triage"}
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		seedSandboxRecord(t, o.StateDir, "dc-claude-1", created)
		recPath := filepath.Join(o.StateDir, "sandboxes", "manager", "dc-claude-1.json")
		data, err := os.ReadFile(recPath)
		if err != nil {
			t.Fatal(err)
		}
		var rec map[string]any
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatal(err)
		}
		rec["registration_id"] = id
		data, err = json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		registrationsPath := filepath.Join(o.StateDir, sandboxDaemonRegistrationsFile)
		if rc1 {
			at := time.Now().UTC()
			raw := []byte(fmt.Sprintf(rc1RegistrationJSON, id, at.Format(time.RFC3339Nano)))
			if err := os.WriteFile(registrationsPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		} else {
			current := daemonRegistration{ID: id, Sandbox: "dc-claude-1", Profile: "engineering", Floor: closedFloorRegFloor,
				Generation: 3, Driver: "docker", DriverReason: "configured", UpdatedAt: time.Now().UTC()}
			writer := &daemonRegistrations{path: registrationsPath, byName: map[string]daemonRegistration{}}
			if err := writer.put(current); err != nil {
				t.Fatal(err)
			}
		}
		o.listPhases = func(context.Context) (map[string]string, bool) {
			return map[string]string{"dc-claude-1": "stopped"}, true
		}
	})
	f.relay.current = func(gotID string) (sandboxrelay.CurrentPolicy, error) {
		if gotID != id {
			t.Errorf("reported registration %q, want %q", gotID, id)
		}
		if !answer {
			return sandboxrelay.CurrentPolicy{}, sandboxrelay.ErrGatewayUnreachable
		}
		code, cp := gate.report(upgradeFloorPeer, id, false)
		if code != http.StatusOK {
			return sandboxrelay.CurrentPolicy{}, &sandboxrelay.Error{Status: code}
		}
		return cp, nil
	}
	reg, ok := f.d.regs.get("dc-claude-1")
	if !ok || reg.ID != id || reg.Confirmed || reg.Revoked || reg.Floor.MinProfile != "balanced" {
		t.Fatalf("loaded registration = %+v, present %v", reg, ok)
	}
	ctl := &managedSandboxController{sandboxRuntimeController: f.d.rt.manager, d: f.d}
	return f, ctl, gate, func(up bool) { answer = up }
}

func assertUpgradeFloorView(t *testing.T, f *sandboxDaemonFixture, ctl *managedSandboxController) {
	t.Helper()
	if f.d.floorClosed() {
		t.Fatal("the gateway confirmed the registration, but the floor stayed closed")
	}
	if got := f.relay.reported(); !slices.Contains(got, f.d.regs.list()[0].ID+"=stopped") {
		t.Fatalf("reports = %v, want a stopped-state report", got)
	}
	raw, err := f.d.rt.manager.Get(context.Background(), "dc-claude-1")
	if err != nil {
		t.Fatal(err)
	}
	assertOrganizationPolicy(t, "the manager's stopped view", *raw)
	assertUpgradePolicyFields(t, "the manager's stopped view", *raw)
	sb, err := ctl.Get(context.Background(), "dc-claude-1")
	if err != nil {
		t.Fatal(err)
	}
	assertOrganizationPolicy(t, "stopped status", *sb)
	assertUpgradePolicyFields(t, "stopped status", *sb)
	list, err := ctl.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	assertOrganizationPolicy(t, "stopped list", list[0])
	assertUpgradePolicyFields(t, "stopped list", list[0])
}

func assertUpgradePolicyFields(t *testing.T, what string, v sandboxapi.Sandbox) {
	t.Helper()
	if v.Pack != "balanced" || v.Profile != "balanced" || v.NetworkMode != "allowlist" || v.Approvals != "triage" {
		t.Fatalf("%s policy = %s/%s/%s/%s, want balanced/balanced/allowlist/triage", what, v.Pack, v.Profile, v.NetworkMode, v.Approvals)
	}
}

func TestSandboxDaemonUpgradeFloorFromRC1Registration(t *testing.T) {
	f, ctl, _, gateway := upgradeFloorFixture(t, true)
	// New built its manager while the gateway was unavailable and the floor
	// was closed. The real stopped-state route becomes available at restart.
	gateway(true)
	f.d.revalidate(context.Background())
	f.d.pollOnce(context.Background())
	assertUpgradeFloorView(t, f, ctl)
}

func TestSandboxDaemonUpgradeFloorFromCurrentRegistration(t *testing.T) {
	f, ctl, _, gateway := upgradeFloorFixture(t, false)
	gateway(true)
	f.d.revalidate(context.Background())
	f.d.pollOnce(context.Background())
	assertUpgradeFloorView(t, f, ctl)
}

func TestSandboxDaemonUpgradeFloorAfterGatewayReturns(t *testing.T) {
	for _, tc := range []struct {
		name string
		rc1  bool
	}{{"rc.1", true}, {"current", false}} {
		t.Run(tc.name, func(t *testing.T) {
			f, ctl, _, gateway := upgradeFloorFixture(t, tc.rc1)
			f.d.revalidate(context.Background())
			if !f.d.floorClosed() {
				t.Fatal("adopted a floor while the gateway was down")
			}
			assertUpgradeConfirming(t, f, ctl)
			gateway(true)
			f.d.pollOnce(context.Background())
			assertUpgradeFloorView(t, f, ctl)
		})
	}
}

func assertUpgradeConfirming(t *testing.T, f *sandboxDaemonFixture, ctl *managedSandboxController) {
	t.Helper()
	if !f.d.floorClosed() {
		t.Fatal("opened a floor without a confirmation")
	}
	raw, err := f.d.rt.manager.Get(context.Background(), "dc-claude-1")
	if err != nil {
		t.Fatal(err)
	}
	assertClosedFloorDeny(t, "the unconfirmed manager view", *raw)
	for _, get := range []func() (*sandboxapi.Sandbox, error){
		func() (*sandboxapi.Sandbox, error) { return ctl.Get(context.Background(), "dc-claude-1") },
		func() (*sandboxapi.Sandbox, error) {
			list, err := ctl.List(context.Background())
			if err != nil || len(list) != 1 {
				return nil, fmt.Errorf("list = %+v, %v", list, err)
			}
			return &list[0], nil
		},
	} {
		v, err := get()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(v.Warnings, sandboxConfirmingNote) ||
			v.Pack != "balanced" || v.Profile != "balanced" || v.NetworkMode != "allowlist" || v.Approvals != "triage" ||
			slices.ContainsFunc(v.Violations, closedFloorDeny) {
			t.Fatalf("unconfirmed status = %+v", v)
		}
	}
}

func TestSandboxDaemonUpgradeFloorRequiresGatewayConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *sandboxDaemonFixture)
	}{
		{"gateway down", func(*testing.T, *sandboxDaemonFixture) {}},
		{"gateway refuses 403", func(_ *testing.T, f *sandboxDaemonFixture) {
			f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
				return sandboxrelay.CurrentPolicy{}, &sandboxrelay.Error{Status: http.StatusForbidden}
			}
		}},
		{"gateway refuses 503", func(_ *testing.T, f *sandboxDaemonFixture) {
			f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) {
				return sandboxrelay.CurrentPolicy{}, &sandboxrelay.Error{Status: http.StatusServiceUnavailable}
			}
		}},
		{"file claims a permissive floor and confirmation", func(t *testing.T, f *sandboxDaemonFixture) {
			r, _ := f.d.regs.get("dc-claude-1")
			yes := true
			r.Floor = config.OpenShellAdminConfig{MinProfile: "open", Allowed: &yes}
			if err := f.d.regs.put(r); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.d.opts.StateDir, sandboxDaemonRegistrationsFile)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// The file is user-owned. Its attempted claim cannot persist
			// Confirmed, even when it spells the Go field name.
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			entry := doc["registrations"].([]any)[0].(map[string]any)
			entry["Confirmed"] = true
			raw, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadDaemonRegistrations(path)
			if err != nil {
				t.Fatal(err)
			}
			f.d.regs = loaded
			if got, _ := loaded.get("dc-claude-1"); got.Confirmed {
				t.Fatal("the user-owned file persisted confirmation")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ctl, _, _ := upgradeFloorFixture(t, true)
			tc.change(t, f)
			f.d.revalidate(context.Background())
			f.d.pollOnce(context.Background())
			assertUpgradeConfirming(t, f, ctl)
		})
	}
}

func TestSandboxDaemonUpgradeFloorRevokedRegistration(t *testing.T) {
	f, ctl, _, gateway := upgradeFloorFixture(t, true)
	f.d.regs.markRevoked("dc-claude-1", "profile removed")
	gateway(true)
	f.d.pollOnce(context.Background())
	if !f.d.floorClosed() {
		t.Fatal("adopted a revoked registration's floor")
	}
	raw, err := ctl.Get(context.Background(), "dc-claude-1")
	if err != nil {
		t.Fatal(err)
	}
	assertClosedFloorDeny(t, "the revoked registration", *raw)
	if slices.Contains(raw.Warnings, sandboxConfirmingNote) {
		t.Fatal("a revoked registration was presented as awaiting confirmation")
	}
}

func TestSandboxDaemonUpgradeFloorKeepsGatewayOrganizationDeny(t *testing.T) {
	f, ctl, gate, gateway := upgradeFloorFixture(t, true)
	no := false
	// The registration was bound while allowed. The real managed route
	// re-matches the changed organization floor, revokes this stopped run,
	// and reports that revocation instead of confirming its old floor.
	gate.cfg.OpenShell.Admin.Allowed = &no
	gateway(true)
	f.d.pollOnce(context.Background())
	if reg, _ := f.d.regs.get("dc-claude-1"); !reg.Revoked || !f.d.floorClosed() {
		t.Fatalf("the gateway's organization deny was not kept: %+v", reg)
	}
	v, err := ctl.Get(context.Background(), "dc-claude-1")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(v.Violations, closedFloorDeny) || slices.Contains(v.Warnings, sandboxConfirmingNote) {
		t.Fatalf("the gateway's organization deny changed: %+v", v)
	}
}
