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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// requiredPackAnswer is a managed gateway's resolve answer for a floor that
// requires the custom pack at <dir>/<name>/pack.yaml, and that file, which
// is then removed: the account cannot read the administrator's pack folder.
func requiredPackAnswer(t *testing.T, dir, name string) (sandboxrelay.ResolveResponse, string) {
	t.Helper()
	file := filepath.Join(dir, name, packs.PackFileName)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("version: 1\nname: "+name+"\nextends: strict\n"), 0o644); err != nil {
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
	if err := os.RemoveAll(filepath.Dir(file)); err != nil {
		t.Fatal(err)
	}
	return sandboxrelay.ResolveResponse{V: 1, Registration: sandboxrelay.RegistrationView{ID: "reg-" + name}, Effective: wire}, file
}

// The daemon resolves a required-pack run with the pack the managed
// gateway's answer carries, never the root-only file, and installs it again
// from its registrations after a restart; a pack off the floor's pin fails
// closed (GAP-0440).
func TestSandboxDaemonUsesTheGatewaysRequiredPack(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	resp, file := requiredPackAnswer(t, t.TempDir(), "contractors")
	floor, err := managedResolveFloor(resp)
	if err != nil || floor.RequiredPack != file {
		t.Fatalf("floor = %+v, %v", floor, err)
	}
	pinned := floor
	pinned.RequiredPackDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := useAuthorityPack(resp, pinned); err == nil {
		t.Fatal("a pack off the pin was taken")
	}
	pack, err := useAuthorityPack(resp, floor)
	if err != nil || pack == nil {
		t.Fatalf("authority pack: %v, %v", pack, err)
	}
	eff, _, err := packs.Resolve(f.d.configWithFloor(floor), packs.Flags{Harness: "claudecode"})
	if err != nil || eff.Pack.Name != "contractors" {
		t.Fatalf("resolve under the required pack: %v", err)
	}

	// A restarted daemon: the pack comes from the registrations file.
	resp, file = requiredPackAnswer(t, t.TempDir(), "vendors")
	floor, err = managedResolveFloor(resp)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := packs.Resolve(f.d.configWithFloor(floor), packs.Flags{}); err == nil {
		t.Fatal("resolved a pack nobody handed over")
	}
	var wire struct {
		Pack *packs.Pack `json:"pack"`
	}
	if err := json.Unmarshal(resp.Effective, &wire); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registrations.json")
	regs, err := loadDaemonRegistrations(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := regs.put(daemonRegistration{ID: "reg-vendors", Sandbox: "dc-claude-v", Floor: floor, RequiredPack: wire.Pack}); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDaemonRegistrations(path); err != nil {
		t.Fatal(err)
	}
	if eff, _, err := packs.Resolve(f.d.configWithFloor(floor), packs.Flags{}); err != nil || eff.Pack.Name != "vendors" || eff.Pack.Source != file {
		t.Fatalf("resolve after a restart: %v", err)
	}
}
