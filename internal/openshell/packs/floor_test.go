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
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
)

// ownSubject is the account running the test as an explicit subject: the
// files the test writes are its own.
func ownSubject(t *testing.T, home string) *Subject {
	t.Helper()
	return &Subject{UID: os.Getuid(), Home: home}
}

// denyPack is a custom pack stricter than customPack in network.mode and
// workspace.mode.
func denyPack(name string) string {
	return strings.NewReplacer("network: {mode: open}", "network: {mode: deny}", "workspace: {mode: mount}", "workspace: {mode: copy}").
		Replace(customPack(name))
}

// The managed gateway resolves for the peer: "~/" is the peer's home, and
// a pack counts as the user's own when the peer owns it, whoever runs the
// resolution.
func TestResolveExplicitSubject(t *testing.T) {
	callerHome, peerHome := t.TempDir(), t.TempDir()
	withHome(t, callerHome)
	peerPack := writePack(t, filepath.Join(peerHome, "packs"), "team", customPack("team"))
	const peerUID = 5151
	fakeOwners(t, func(fs.FileInfo) int { return peerUID })
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.PackDir, o.Pack = "~/packs", "team"
		o.Admin.RequireCopyFor = []string{"~/customer-*"}
	})
	peer := &Subject{UID: peerUID, Home: peerHome}

	eff, _ := mustResolve(t, cfg, Flags{Subject: peer, Project: filepath.Join(peerHome, "customer-acme")})
	if eff.Pack.Name != "team" || eff.Pack.Source != filepath.Join(peerPack, PackFileName) {
		t.Fatalf("pack %s from %s", eff.Pack.Name, eff.Pack.Source)
	}
	wantClamped(t, eff, "workdir.mode", config.OpenShellWorkdirCopy, config.OpenShellWorkdirMount, "openshell.admin.require_copy_for")
	if sources := eff.PolicySources(); !reflect.DeepEqual(sources, []string{filepath.Join(peerHome, "packs"), filepath.Join(peerPack, PackFileName)}) {
		t.Fatalf("policy sources %v", sources)
	}

	// For the caller's own account "~/" is its own home, and the peer's
	// file is not its own.
	if _, _, err := Resolve(cfg, Flags{}); err == nil || !strings.Contains(err.Error(), "no built-in or custom pack") {
		t.Fatalf("caller's home: %v", err)
	}
	_, _, err := Resolve(cfg, Flags{Pack: peerPack})
	wantPackError(t, err, "foreign_owner", "")
	// A subject without a home cannot use "~/".
	if _, _, err := Resolve(cfg, Flags{Subject: &Subject{UID: peerUID}}); err == nil ||
		!strings.Contains(err.Error(), "cannot resolve the home directory") {
		t.Fatalf("no home: %v", err)
	}
	for _, bad := range []Subject{{UID: -1, Home: peerHome}, {UID: peerUID, Home: "relative/home"}} {
		if _, _, err := Resolve(cfg, Flags{Subject: &bad}); err == nil || !strings.Contains(err.Error(), "subject") {
			t.Fatalf("subject %+v: %v", bad, err)
		}
	}
}

// For an explicit subject this process reads only the administrator's own
// pack references; everything else the subject names arrives as the bytes
// the daemon read as the subject, from the subject's own file (GAP-0079,
// GAP-0080).
func TestResolveSubjectReadsOnlyTheAdministratorsPacks(t *testing.T) {
	root := t.TempDir()
	packDir := filepath.Join(root, "packs")
	policyPacks := filepath.Join(root, "policy", "sandbox")
	contractors := writePack(t, packDir, "contractors", customPack("contractors"))
	writePack(t, packDir, "corp", customPack("corp"))
	writePack(t, packDir, "strictcorp", denyPack("strictcorp"))
	// The administrator's packs are root's, so this process could read them
	// all; the subject's own file is the subject's.
	fakeOwners(t, func(fs.FileInfo) int { return 0 })
	var inspected []string
	owner := fileOwner
	fileOwner = func(info fs.FileInfo) (int, bool) {
		inspected = append(inspected, info.Name())
		return owner(info)
	}
	cfg := testConfig(func(o *config.OpenShellConfig) { o.PackDir, o.Pack = packDir, "corp" })
	cfg.PolicyDir = filepath.Join(root, "policy")
	carolHome := t.TempDir()
	carol := &Subject{UID: 5151, Home: carolHome}
	required := config.OpenShellAdminConfig{RequiredPack: "strictcorp"}
	const refused = "is not a pack this computer can load for you"

	for _, ref := range []string{
		"contractors", filepath.Join(contractors, PackFileName), contractors, "no-such-pack", "/nonexistent/pack.yaml",
		"~/packs/team/pack.yaml",
	} {
		inspected = nil
		_, _, err := Resolve(cfg, Flags{Subject: carol, Pack: ref})
		if err == nil || !strings.Contains(err.Error(), refused) || strings.Contains(err.Error(), "uid") {
			t.Fatalf("--pack %s without bytes: %v", ref, err)
		}
		if len(inspected) != 0 {
			t.Fatalf("--pack %s inspected %v", ref, inspected)
		}
	}
	// The administrator's own references load here.
	if eff, _ := mustResolve(t, cfg, Flags{Subject: carol, Pack: "corp"}); eff.Pack.Name != "corp" {
		t.Fatalf("openshell.pack: %s", eff.Pack.Name)
	}
	eff, violations := mustResolve(t, cfg, Flags{Subject: carol, Floor: &required, Pack: "strictcorp"})
	wantViolations(t, violations)
	if eff.Pack.Name != "strictcorp" {
		t.Fatalf("required pack: %s", eff.Pack.Name)
	}

	// Bytes never take a pack_dir name, nor a file in an administrator's
	// pack folder: they would wear an administrator's pack's name and source.
	body := []byte(customPack("mine"))
	for _, ref := range []string{
		"corp", "contractors", filepath.Join(packDir, "corp", PackFileName), filepath.Join(policyPacks, "x", PackFileName),
	} {
		if _, _, err := Resolve(cfg, Flags{Subject: carol, Pack: ref, UserPack: body}); err == nil || !strings.Contains(err.Error(), refused) {
			t.Fatalf("bytes for %s: %v", ref, err)
		}
	}
	mine := filepath.Join(carolHome, "packs", "mine", PackFileName)
	eff, _ = mustResolve(t, cfg, Flags{Subject: carol, Pack: "~/packs/mine/pack.yaml", UserPack: body})
	if eff.Pack.Name != "mine" || eff.Pack.Source != mine {
		t.Fatalf("own bytes: %s from %s", eff.Pack.Name, eff.Pack.Source)
	}

	// The bytes extend a built-in pack or the pack the subject's policy runs
	// without --pack, never another profile's.
	extends := func(parent string) []byte {
		return []byte("version: 1\nname: mine\nextends: " + parent + "\n")
	}
	for _, tc := range []struct {
		parent string
		ok     bool
	}{
		{"strict", true},
		{"corp", true},
		{"contractors", false},
		{"strictcorp", false},
	} {
		_, _, err := Resolve(cfg, Flags{Subject: carol, Pack: mine, UserPack: extends(tc.parent)})
		if tc.ok != (err == nil) {
			t.Fatalf("extends %s: %v", tc.parent, err)
		}
		if !tc.ok {
			wantPackError(t, err, "extends_not_offered", "extends")
		}
	}
	// Under a required pack the offered chain is that pack's, and any
	// other --pack is a violation: the required pack runs.
	r := &resolver{admin: required, subject: *carol, explicit: true}
	if !r.offeredParent(cfg.OpenShell, "strictcorp") || r.offeredParent(cfg.OpenShell, "corp") {
		t.Fatal("offered parents under a required pack")
	}
	_, violations = mustResolve(t, cfg, Flags{Subject: carol, Floor: &required, Pack: mine, UserPack: extends("contractors")})
	wantViolations(t, violations, Violation{Key: "pack", Constraint: requiredPackConstraint})
}

// Only the managed gateway has a floor or pack bytes, and it always names
// the account it resolves for (GAP-0082).
func TestResolveFloorAndBytesNeedASubject(t *testing.T) {
	cfg := testConfig(nil)
	floor := config.OpenShellAdminConfig{AllowYolo: boolPtr(false)}
	if _, _, err := Resolve(cfg, Flags{Floor: &floor}); err == nil || !strings.Contains(err.Error(), "floor needs the account") {
		t.Fatalf("floor without a subject: %v", err)
	}
	if _, _, err := Resolve(cfg, Flags{Pack: "/x/pack.yaml", UserPack: []byte(customPack("team"))}); err == nil ||
		!strings.Contains(err.Error(), "need the account") {
		t.Fatalf("bytes without a subject: %v", err)
	}
}

// A --pack that openshell.admin.locked drops takes its bytes with it: the
// run falls back to the administrator's file for openshell.pack, never to
// bytes that claim its reference (GAP-0073).
func TestResolveLockedPackIgnoresBytesForTheConfiguredPack(t *testing.T) {
	root := t.TempDir()
	corp := filepath.Join(writePack(t, filepath.Join(root, "admin"), "corp", denyPack("corp")), PackFileName)
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.PackDir, o.Pack = filepath.Join(root, "packs"), corp
		o.Admin.Locked = []string{"pack"}
	})
	cfg.DeploymentMode = "managed_enterprise"
	want, err := Load(corp, "")
	if err != nil {
		t.Fatal(err)
	}
	forged := []byte(customPack("corp")) // open network, mount mode
	eff, violations := mustResolve(t, cfg, Flags{Subject: ownSubject(t, root), Pack: corp, UserPack: forged})
	wantViolations(t, violations, Violation{Key: "pack", Constraint: lockedConstraint})
	if eff.Pack.Digest != want.Digest || eff.NetworkMode != NetworkDeny || eff.Workspace.Mode != config.OpenShellWorkdirCopy {
		t.Fatalf("ran pack %s (%s) network %s workspace %s, want the configured file", eff.Pack.Name, eff.Pack.Digest, eff.NetworkMode, eff.Workspace.Mode)
	}
	// Bytes with the file's own content are not a loosening.
	same, err := os.ReadFile(corp)
	if err != nil {
		t.Fatal(err)
	}
	eff, violations = mustResolve(t, cfg, Flags{Subject: ownSubject(t, root), Pack: corp, UserPack: same})
	wantViolations(t, violations)
	if eff.Pack.Digest != want.Digest {
		t.Fatalf("same content: %s", eff.Pack.Digest)
	}
}

// require_copy_for matches the project as the daemon resolved it
// (Flags.ProjectReal), and still as this process resolves it.
func TestResolveProjectRealRequireCopy(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "src", "customer-acme")
	if err := os.MkdirAll(filepath.Join(real, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.Admin.RequireCopyFor = []string{filepath.Join(root, "src", "customer-*")}
	})
	// A link in the user's home this process cannot follow.
	hidden := "/nonexistent-defenseclaw-test/link/app"
	mode := func(flags Flags) string {
		t.Helper()
		eff, _ := mustResolve(t, cfg, flags)
		return eff.Workspace.Mode
	}
	if got := mode(Flags{Project: hidden}); got != config.OpenShellWorkdirMount {
		t.Fatalf("unresolvable project without ProjectReal: %s", got)
	}
	eff, _ := mustResolve(t, cfg, Flags{Project: hidden, ProjectReal: filepath.Join(real, "app")})
	wantClamped(t, eff, "workdir.mode", config.OpenShellWorkdirCopy, config.OpenShellWorkdirMount, "openshell.admin.require_copy_for")
	if err := eff.Allow(Action{Kind: ActionMount, Path: hidden}); err == nil || !strings.Contains(err.Error(), "copy mode") {
		t.Fatalf("mount of the project: %v", err)
	}
	if got := mode(Flags{ProjectReal: filepath.Join(real, "app")}); got != config.OpenShellWorkdirCopy {
		t.Fatalf("ProjectReal alone: %s", got)
	}
	// A link this process can follow counts whatever the daemon says.
	if got := mode(Flags{Project: link, ProjectReal: "/elsewhere"}); got != config.OpenShellWorkdirCopy {
		t.Fatalf("symlinked project: %s", got)
	}
	if _, _, err := Resolve(cfg, Flags{ProjectReal: "relative"}); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative ProjectReal: %v", err)
	}
}

// The --pack bytes the daemon read as the user stand in for the file at the
// --pack path, which this process never reads.
func TestResolveUserPack(t *testing.T) {
	root := t.TempDir()
	packDir := filepath.Join(root, "packs")
	me := ownSubject(t, root)
	cfg := testConfig(func(o *config.OpenShellConfig) { o.PackDir = packDir })
	mine := filepath.Join(root, "mine", PackFileName)
	body := []byte(customPack("team"))
	for _, ref := range []string{mine, "~/mine/pack.yaml"} {
		eff, violations := mustResolve(t, cfg, Flags{Subject: me, Pack: ref, UserPack: body})
		wantViolations(t, violations)
		if eff.Pack.Name != "team" || eff.Pack.Source != mine {
			t.Fatalf("%s: pack %s from %s", ref, eff.Pack.Name, eff.Pack.Source)
		}
		wantSetting(t, eff, "pack", "team", SourceFlag, "--pack")
	}

	_, _, err := Resolve(cfg, Flags{Subject: me, Pack: "/x/pack.yaml", UserPack: []byte(customPack("strict"))})
	wantPackError(t, err, "reserved_name", "name")
	_, _, err = Resolve(cfg, Flags{Subject: me, Pack: mine, UserPack: bytes.Repeat([]byte("#"), MaxPackBytes+1)})
	wantPackError(t, err, "too_large", "")
	_, _, err = Resolve(cfg, Flags{Subject: me, Pack: "relative/pack.yaml", UserPack: body})
	wantPackError(t, err, "relative_path", "")
	for _, ref := range []string{"", "strict"} {
		if _, _, err := Resolve(cfg, Flags{Subject: me, Pack: ref, UserPack: body}); err == nil || !strings.Contains(err.Error(), "custom pack") {
			t.Fatalf("pack bytes for %q: %v", ref, err)
		}
	}

	// A custom parent the bytes extend (the pack the policy runs) must be
	// the administrator's in managed_enterprise.
	writePack(t, packDir, "base", customPack("base"))
	child := []byte("version: 1\nname: child\nextends: base\nharness: {yolo: false}\n")
	offered := testConfig(func(o *config.OpenShellConfig) { o.PackDir, o.Pack = packDir, "base" })
	if eff, _ := mustResolve(t, offered, Flags{Subject: me, Pack: mine, UserPack: child}); eff.Pack.Extends != "base" {
		t.Fatalf("extends %q", eff.Pack.Extends)
	}
	offered.DeploymentMode = "managed_enterprise"
	_, _, err = Resolve(offered, Flags{Subject: me, Pack: mine, UserPack: child})
	wantPackError(t, err, "untrusted", "")

	// Under a required pack, bytes with its content are not a loosening.
	writePack(t, packDir, "corp", customPack("corp"))
	required := testConfig(func(o *config.OpenShellConfig) { o.PackDir, o.Admin.RequiredPack = packDir, "corp" })
	elsewhere := filepath.Join(t.TempDir(), "corp.yaml")
	_, violations := mustResolve(t, required, Flags{Subject: me, Pack: elsewhere, UserPack: []byte(customPack("corp"))})
	wantViolations(t, violations)
	_, violations = mustResolve(t, required, Flags{Subject: me, Pack: elsewhere, UserPack: []byte(strings.Replace(customPack("corp"), "yolo: true", "yolo: false", 1))})
	wantViolations(t, violations, Violation{Key: "pack", Constraint: requiredPackConstraint})
}

// Flags.Floor replaces openshell.admin in every clamp, and the floor keys
// that shape the posture itself apply.
func TestResolveFloor(t *testing.T) {
	cfg := testConfig(nil)
	me := ownSubject(t, t.TempDir())
	floor := config.OpenShellAdminConfig{
		AllowYolo:       boolPtr(false),
		MaxResources:    config.OpenShellResourcesConfig{CPU: "2"},
		ProcessTree:     boolPtr(true),
		OnSilence:       OnSilenceStop,
		MaxSilenceAfter: "30s",
	}
	eff, violations := mustResolve(t, cfg, Flags{Subject: me, Floor: &floor, Yolo: true, Harness: "claudecode"})
	wantViolations(t, violations, Violation{Key: "yolo", Constraint: "openshell.admin.allow_yolo"})
	if eff.Yolo || eff.AllowYolo() || eff.MaxResources().CPU != "2" || eff.Resources.CPU != "2" || !eff.Admin.Configured {
		t.Fatalf("yolo %v allow %v max %+v cpu %q admin %+v", eff.Yolo, eff.AllowYolo(), eff.MaxResources(), eff.Resources.CPU, eff.Admin)
	}
	if !reflect.DeepEqual(eff.Floor(), floor) {
		t.Fatalf("floor %+v", eff.Floor())
	}
	if !eff.ProcessTree || eff.HookOnSilence != OnSilenceStop || eff.HookSilenceAfter != MinSilenceAfter {
		t.Fatalf("process tree %v silence %s after %s", eff.ProcessTree, eff.HookOnSilence, eff.HookSilenceAfter)
	}
	wantClamped(t, eff, "observe.process_tree", "true", "false", "openshell.admin.process_tree")
	wantClamped(t, eff, "hooks.on_silence", OnSilenceStop, OnSilenceAlert, "openshell.admin.on_silence")
	wantClamped(t, eff, "hooks.silence_after", "1m", "10m", "openshell.admin.max_silence_after")
	// The configuration's own openshell.admin is not the floor any more.
	if base, _ := mustResolve(t, cfg, Flags{Yolo: true}); !base.Yolo || base.Admin.Configured {
		t.Fatalf("base yolo %v admin %+v", base.Yolo, base.Admin)
	}

	denied := config.OpenShellAdminConfig{Allowed: boolPtr(false)}
	_, violations = mustResolve(t, cfg, Flags{Subject: me, Floor: &denied})
	if v := FirstFatal(violations); v == nil || v.Constraint != "openshell.admin.allowed" || !v.Admin() {
		t.Fatalf("allowed false: %+v", violations)
	}
	bad := config.OpenShellAdminConfig{MaxSilenceAfter: "soon"}
	if _, _, err := Resolve(cfg, Flags{Subject: me, Floor: &bad}); err == nil || !strings.Contains(err.Error(), "max_silence_after") {
		t.Fatalf("bad max_silence_after: %v", err)
	}
	// The floor a caller gets is its own copy.
	got := eff.Floor()
	*got.AllowYolo = true
	if eff.AllowYolo() {
		t.Fatal("changing a returned floor changed the Effective")
	}
	var none *Effective
	if none.AllowYolo() || none.Digest() != "" || none.MaxResources() != (config.OpenShellResourcesConfig{}) || !none.Floor().IsZero() {
		t.Fatal("a nil Effective must allow nothing and report nothing")
	}
}

// A profile's required pack must be at least as strict as the
// organization's in every setting: Resolve re-checks it at each create, and
// ProfilePackCheck (the configuration load's hook) refuses it at load.
func TestResolveFloorPackStrictness(t *testing.T) {
	cfg := testConfig(func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "balanced" })
	me := ownSubject(t, t.TempDir())
	for _, tc := range []struct {
		name, pack, err string
	}{
		{"stricter", "strict", ""},
		{"same", "balanced", ""},
		{"looser", "open", "looser than the organization's required pack balanced in network.mode"},
		{"dropped", "", "drops the organization's required pack balanced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			floor := config.OpenShellAdminConfig{RequiredPack: tc.pack}
			_, _, err := Resolve(cfg, Flags{Subject: me, Floor: &floor})
			check := ProfilePackCheck(cfg, "balanced", tc.pack, "")
			for _, got := range []error{err, check} {
				if (tc.err == "") != (got == nil) || (got != nil && !strings.Contains(got.Error(), tc.err)) {
					t.Fatalf("error %v, want %q", got, tc.err)
				}
			}
			if tc.err == "" {
				if eff, _ := mustResolve(t, cfg, Flags{Subject: me, Floor: &floor}); eff.Pack.Name != tc.pack {
					t.Fatalf("pack %s", eff.Pack.Name)
				}
			}
		})
	}
	// The organization's pin holds under a profile's own pack, and the
	// profile's pack comes with its own pin (TightenOpenShellAdmin).
	pinned := testConfig(func(o *config.OpenShellConfig) {
		o.Admin.RequiredPack, o.Admin.RequiredPackDigest = "balanced", "sha256:"+strings.Repeat("0", 64)
	})
	floor := config.OpenShellAdminConfig{RequiredPack: "strict"}
	for _, err := range []error{
		func() error { _, _, err := Resolve(pinned, Flags{Subject: me, Floor: &floor}); return err }(),
		ProfilePackCheck(pinned, "balanced", "strict", ""),
	} {
		if err == nil || !strings.Contains(err.Error(), "required_pack_digest") {
			t.Fatalf("base pin: %v", err)
		}
	}
	// The pin is the base pack's own: against another base pack it does
	// not apply.
	if err := ProfilePackCheck(pinned, "open", "strict", ""); err != nil {
		t.Fatalf("pin of another pack: %v", err)
	}
	if err := ProfilePackCheck(nil, "balanced", "strict", ""); err == nil {
		t.Fatal("no configuration")
	}
}

// GAP-0268, GAP-0380, GAP-0401: with no organization pack a profile's pack
// may only tighten the default pack (balanced), and it must match its own
// pin; the configuration load (ensure) and every create refuse otherwise.
func TestProfilePackTightensTheDefaultPackAndMatchesItsPin(t *testing.T) {
	me := ownSubject(t, t.TempDir())
	strict, err := Builtin("strict")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	loose := writePack(t, dir, "contractors-loose", "version: 1\nname: contractors-loose\nextends: balanced\n"+
		"network: {mode: open}\napprovals: {mode: auto}\nworkspace: {mode: mount}\nhooks: {on_silence: alert}\n")
	tighter := writePack(t, dir, "contractors", "version: 1\nname: contractors\nextends: balanced\n"+
		"approvals: {mode: manual}\nworkspace: {mode: copy}\nmcp: {project_servers: block}\nhooks: {on_silence: stop, silence_after: 10m}\n")
	zeros := "sha256:" + strings.Repeat("0", 64)
	for _, tc := range []struct {
		name, pack, digest, err string
	}{
		{"strict", "strict", "", ""},
		{"strict with its pin", "strict", strict.Digest, ""},
		{"a tighter custom pack", tighter, "", ""},
		{"looser than the default pack", loose, "", "looser than the default pack balanced in network.mode"},
		{"open", "open", "", "looser than the default pack balanced in network.mode"},
		{"a wrong pin", "strict", zeros, "not its pinned required_pack_digest " + zeros},
		{"a wrong pin on a custom pack", tighter, zeros, "not its pinned required_pack_digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(nil)
			floor := config.OpenShellAdminConfig{RequiredPack: tc.pack, RequiredPackDigest: tc.digest}
			_, _, resolveErr := Resolve(cfg, Flags{Subject: me, Floor: &floor})
			cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"contractors": {Sandbox: &floor}}
			loadErr := cfg.ValidateGuardrailProfiles()
			for _, got := range []error{resolveErr, ProfilePackCheck(cfg, "", tc.pack, tc.digest), loadErr} {
				if (tc.err == "") != (got == nil) || (got != nil && !strings.Contains(got.Error(), tc.err)) {
					t.Fatalf("error %v, want %q", got, tc.err)
				}
			}
		})
	}
}

// Digest covers the floor and the posture, not the host or the account.
func TestEffectiveDigest(t *testing.T) {
	cfg := testConfig(nil)
	me := ownSubject(t, t.TempDir())
	digest := func(flags Flags) string {
		t.Helper()
		eff, _ := mustResolve(t, cfg, flags)
		if d := eff.Digest(); !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
			t.Fatalf("digest %q", d)
		}
		return eff.Digest()
	}
	base := digest(Flags{Harness: "claudecode"})
	if again := digest(Flags{Harness: "claudecode"}); again != base {
		t.Fatalf("digest changed between runs: %s %s", base, again)
	}
	if other := digest(Flags{Harness: "claudecode", Subject: &Subject{UID: 7, Home: t.TempDir()}}); other != base {
		t.Fatalf("digest depends on the account: %s %s", base, other)
	}
	floor := config.OpenShellAdminConfig{EgressBlock: []string{"files.example.net"}}
	for _, changed := range []Flags{
		{Harness: "codex"},
		{Harness: "claudecode", Copy: true},
		{Harness: "claudecode", Subject: me, Floor: &floor},
		{Harness: "claudecode", Subject: me, Floor: &config.OpenShellAdminConfig{RequestAccess: "ask the help desk"}},
	} {
		if d := digest(changed); d == base {
			t.Fatalf("flags %+v kept digest %s", changed, d)
		}
	}
}

// The wire form carries what the accessors answer from: a decoded policy
// keeps its floor, its digest and its pack content, and the managed
// daemon's reader of the "floor" member gets openshell.admin's keys
// (GAP-0081).
func TestEffectiveWireRoundTrip(t *testing.T) {
	cfg := testConfig(nil)
	floor := config.OpenShellAdminConfig{
		RequiredPack:    "strict",
		AllowYolo:       boolPtr(false),
		AllowMount:      boolPtr(false),
		MaxResources:    config.OpenShellResourcesConfig{CPU: "2", Memory: "4Gi"},
		EgressBlock:     []string{"files.example.net"},
		Allowed:         boolPtr(true),
		RequiredFor:     []string{"claudecode"},
		ProcessTree:     boolPtr(true),
		OnSilence:       OnSilenceStop,
		MaxSilenceAfter: "5m",
		RequestAccess:   "ask the IT help desk",
	}
	eff, _ := mustResolve(t, cfg, Flags{Subject: ownSubject(t, t.TempDir()), Floor: &floor, Harness: "claudecode", Yolo: true})
	data, err := json.Marshal(eff)
	if err != nil {
		t.Fatal(err)
	}
	var got Effective
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, data)
	}
	if !reflect.DeepEqual(got.Floor(), floor) || got.AllowYolo() || got.MaxResources() != floor.MaxResources ||
		got.Digest() != eff.Digest() || got.Digest() == "" {
		t.Fatalf("floor %+v allow_yolo %v max %+v digest %s, want %s", got.Floor(), got.AllowYolo(), got.MaxResources(), got.Digest(), eff.Digest())
	}
	if got.Pack == nil || got.Pack.Name != "strict" || got.Pack.Digest != eff.Pack.Digest || !got.requiredPack ||
		got.HookSilenceAfter != eff.HookSilenceAfter || !reflect.DeepEqual(got.Explain(), eff.Explain()) {
		t.Fatalf("decoded pack %+v required %v silence %s", got.Pack, got.requiredPack, got.HookSilenceAfter)
	}
	// A view decides no runtime action.
	if err := got.Allow(Action{Kind: ActionYolo}); !errors.Is(err, errViewOnly) {
		t.Fatalf("Allow on a view: %v", err)
	}
	if _, err := got.EgressDecider(nil); !errors.Is(err, errViewOnly) {
		t.Fatalf("decider of a view: %v", err)
	}
	// The daemon reads only "floor", with a YAML decoder.
	var wire struct {
		Floor *config.OpenShellAdminConfig `yaml:"floor"`
	}
	if err := yaml.Unmarshal(data, &wire); err != nil || wire.Floor == nil || !reflect.DeepEqual(*wire.Floor, floor) {
		t.Fatalf("yaml floor %+v: %v", wire.Floor, err)
	}
	// Content that does not reproduce the digest, an unknown floor key, a
	// missing floor and another version are refused.
	for name, bad := range map[string][]byte{
		"tampered":      bytes.Replace(data, []byte("ask the IT help desk"), []byte("ask nobody"), 1),
		"unknown key":   bytes.Replace(data, []byte(`"request_access"`), []byte(`"request_acces"`), 1),
		"no floor":      bytes.Replace(data, []byte(`"floor":`), []byte(`"floors":`), 1),
		"other version": bytes.Replace(data, []byte(`"v":1`), []byte(`"v":2`), 1),
	} {
		if bytes.Equal(bad, data) {
			t.Fatalf("%s: the wire form changed shape", name)
		}
		var e Effective
		if err := json.Unmarshal(bad, &e); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
	if data, err := json.Marshal((*Effective)(nil)); err != nil || string(data) != "null" {
		t.Fatalf("nil: %s %v", data, err)
	}
}

// cloneFloor copies every list and switch: a new floor key that is a slice
// or a pointer fails here until cloneFloor copies it.
func TestCloneFloorCopiesEveryReference(t *testing.T) {
	fill := func() config.OpenShellAdminConfig {
		var f config.OpenShellAdminConfig
		v := reflect.ValueOf(&f).Elem()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			switch field.Kind() {
			case reflect.Slice:
				field.Set(reflect.MakeSlice(field.Type(), 1, 1))
			case reflect.Pointer:
				field.Set(reflect.New(field.Type().Elem()))
			}
		}
		return f
	}
	orig, want := fill(), fill()
	clone := cloneFloor(orig)
	v := reflect.ValueOf(&clone).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		switch field.Kind() {
		case reflect.Slice:
			field.Index(0).Set(reflect.ValueOf("changed").Convert(field.Type().Elem()))
		case reflect.Pointer:
			field.Elem().Set(reflect.ValueOf(true).Convert(field.Type().Elem()))
		}
	}
	if !reflect.DeepEqual(orig, want) {
		t.Fatalf("cloneFloor shares references: %+v", orig)
	}
}

// GAP-0675: a managed daemon has no config file, so the configured value
// of a locked openshell.pack must reach it in the floor. Resolved by the
// gateway and again by the daemon (no openshell.pack of its own, the
// floor the gateway sent), a run that passes a looser --pack runs the
// locked pack on both sides.
func TestManagedFloorCarriesALockedPack(t *testing.T) {
	gateway := testConfig(func(o *config.OpenShellConfig) {
		o.Pack, o.Admin.Locked = "strict", []string{"pack"}
	})
	daemonWith := func(floor config.OpenShellAdminConfig) *config.Config {
		return testConfig(func(o *config.OpenShellConfig) { o.Admin = floor })
	}
	flags := func(floor config.OpenShellAdminConfig) Flags {
		return Flags{Subject: ownSubject(t, t.TempDir()), Floor: &floor, Harness: "claudecode", Pack: "open"}
	}
	plain, _, err := gateway.SandboxFloor("")
	if err != nil {
		t.Fatal(err)
	}
	if eff, _ := mustResolve(t, daemonWith(plain), flags(plain)); eff.Pack.Name == "strict" {
		t.Fatal("the plain floor already carries the locked pack; the test no longer shows the divergence")
	}
	floor, _, err := gateway.SandboxManagedFloor("")
	if err != nil {
		t.Fatal(err)
	}
	if floor.RequiredPack != "strict" {
		t.Fatalf("managed floor = %+v, want required_pack strict", floor)
	}
	atGateway, _ := mustResolve(t, gateway, flags(floor))
	atDaemon, _ := mustResolve(t, daemonWith(floor), flags(floor))
	for side, eff := range map[string]*Effective{"gateway": atGateway, "daemon": atDaemon} {
		if eff.Pack == nil || eff.Pack.Name != "strict" || eff.NetworkMode != atGateway.NetworkMode {
			t.Fatalf("%s runs pack %+v network %s, want strict %s", side, eff.Pack, eff.NetworkMode, atGateway.NetworkMode)
		}
	}
	// Without the lock the configured pack is only a default: no floor change.
	unlocked := testConfig(func(o *config.OpenShellConfig) { o.Pack = "strict" })
	if f, _, err := unlocked.SandboxManagedFloor(""); err != nil || f.RequiredPack != "" {
		t.Fatalf("unlocked managed floor = %+v %v", f, err)
	}
}

// r102 GAP-0562: a pack locked only by a profile's sandbox section was
// refused naming openshell.admin.locked. The refusal names the lock that
// applies; the organization's own lock keeps its name.
func TestLockedRefusalNamesTheProfileLock(t *testing.T) {
	for _, tc := range []struct {
		name         string
		baseLocked   []string
		want, detail string
	}{
		{"profile lock", nil, `guardrail.profiles["engineering"].sandbox.locked`, "your profile engineering locks pack"},
		{"organization lock", []string{"pack"}, lockedConstraint, "your organization locked pack"},
	} {
		cfg := testConfig(func(o *config.OpenShellConfig) {
			o.Pack, o.Admin.Locked = "strict", tc.baseLocked
		})
		floor := config.OpenShellAdminConfig{Locked: []string{"pack"}}
		_, violations := mustResolve(t, cfg, Flags{Subject: ownSubject(t, t.TempDir()), Floor: &floor, FloorProfile: "engineering",
			Harness: "claudecode", Pack: "open"})
		wantViolations(t, violations, Violation{Key: "pack", Constraint: tc.want, Detail: tc.detail})
	}
}
