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

//go:build !windows

package packs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The required pack a managed gateway's answer carries is the pack the file
// holds (its built-in ancestor's curated allowlist included), is held to the
// floor's pin, and once installed stands in for the root-only file a
// trusted load would read (GAP-0440).
// GAP-0563: on a managed computer a stricter --pack runs in place of the
// required pack, so the answer's pack is the built-in one; the required pack
// travels beside it and is what the daemon installs.
func TestAuthorityPackOfAStricterRun(t *testing.T) {
	trustAllPacks(t)
	root := t.TempDir()
	dir := writePack(t, root, "contractors", "version: 1\nname: contractors\nextends: balanced\negress: {allow: [artifacts.example.com]}\n")
	file := filepath.Join(dir, PackFileName)
	cfg := managedTestConfig(func(o *config.OpenShellConfig) {
		o.PackDir = root
		o.Admin.RequiredPack = file
	})
	floor := cfg.OpenShell.Admin
	eff, violations := mustResolve(t, cfg, Flags{Subject: ownSubject(t, t.TempDir()), Floor: &floor, FloorProfile: "contractors", Pack: "strict"})
	wantViolations(t, violations)
	if eff.Pack.Name != "strict" {
		t.Fatalf("run pack = %s, want strict", eff.Pack.Name)
	}
	required := eff.RequiredPackContent()
	if required == nil || required.Name != "contractors" {
		t.Fatalf("required pack content = %+v", required)
	}
	wire, err := json.Marshal(eff)
	if err != nil {
		t.Fatal(err)
	}
	requiredWire, err := json.Marshal(required)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorityPack(wire, nil, floor); err == nil {
		t.Fatal("the stricter pack stood in for the required one")
	}
	want, err := Load(file, root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AuthorityPack(wire, requiredWire, floor)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("authority pack = %+v, %v\nwant %+v", got, err, want)
	}
	pinned := floor
	pinned.RequiredPackDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := AuthorityPack(wire, requiredWire, pinned); err == nil || !strings.Contains(err.Error(), "required_pack_digest") {
		t.Fatalf("a required pack off the pin: %v", err)
	}
	// A run that uses the required pack itself sends nothing extra.
	plain, _ := mustResolve(t, cfg, Flags{Subject: ownSubject(t, t.TempDir()), Floor: &floor, FloorProfile: "contractors"})
	if plain.RequiredPackContent() != nil {
		t.Fatal("the required pack was sent beside itself")
	}
}

// GAP-0563: a pack the subject may not use is a refusal they can act on, not
// an organization-side load failure.
func TestSubjectPackRefusalIsAnInputError(t *testing.T) {
	trustAllPacks(t)
	root := t.TempDir()
	writePack(t, root, "contractors", "version: 1\nname: contractors\nextends: balanced\n")
	cfg := managedTestConfig(func(o *config.OpenShellConfig) { o.PackDir = root })
	floor := config.OpenShellAdminConfig{}
	_, _, err := Resolve(cfg, Flags{Subject: ownSubject(t, t.TempDir()), Floor: &floor, Pack: "contractors"})
	var input *InputError
	if !errors.As(err, &input) || !strings.Contains(err.Error(), "is not a pack this computer can load for you") {
		t.Fatalf("--pack contractors = %v", err)
	}
}

func TestAuthorityPackStandsInForTheRootOnlyFile(t *testing.T) {
	root := t.TempDir()
	dir := writePack(t, root, "contractors", "version: 1\nname: contractors\nextends: balanced\negress: {allow: [artifacts.example.com]}\n")
	file := filepath.Join(dir, PackFileName)
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.PackDir = root
		o.Admin.RequiredPack = file
	})
	eff, _ := mustResolve(t, cfg, Flags{})
	wire, err := json.Marshal(eff)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Load(file, root)
	if err != nil {
		t.Fatal(err)
	}
	floor := cfg.OpenShell.Admin
	got, err := AuthorityPack(wire, nil, floor)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("authority pack = %+v, %v\nwant %+v", got, err, want)
	}
	pinned := floor
	pinned.RequiredPackDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := AuthorityPack(wire, nil, pinned); err == nil || !strings.Contains(err.Error(), "required_pack_digest") {
		t.Fatalf("a pack off the pin: %v", err)
	}
	if err := UseAuthorityPack(pinned, got); err == nil {
		t.Fatal("a pack off the pin was installed")
	}
	if _, err := AuthorityPack([]byte(`{"v":1}`), nil, floor); err == nil {
		t.Fatal("an answer without the pack was taken")
	}

	if err := UseAuthorityPack(floor, got); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		authorityPacks.mu.Lock()
		delete(authorityPacks.byRef, file)
		authorityPacks.mu.Unlock()
	})
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if p, err := loadTrusted(callerSubject(), file, root); err != nil || !reflect.DeepEqual(p, want) {
		t.Fatalf("trusted load = %+v, %v", p, err)
	}
}
