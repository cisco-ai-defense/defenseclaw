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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/resolve_matrix.golden")

// TestResolveMatrix pins the posture of every combination of an
// organization floor (openshell.admin), a guardrail profile's sandbox
// section over it (Flags.Floor), the pack a user selects (none, a built-in,
// the --pack bytes of a custom one), the run flags and a repository policy.
// Run with -update after a deliberate change and review the diff.
func TestResolveMatrix(t *testing.T) {
	root := t.TempDir()
	packDir := filepath.Join(root, "packs")
	// openshell.pack of the "locked" base: an administrator's file outside
	// the pack folder, stricter than the bytes "forged" sends for it.
	corp := filepath.Join(writePack(t, filepath.Join(root, "admin"), "corp", denyPack("corp")), PackFileName)
	balanced, err := Builtin(config.OpenShellProfileBalanced)
	if err != nil {
		t.Fatal(err)
	}
	bases := []struct {
		name string
		edit func(*config.OpenShellConfig)
	}{
		{"none", func(*config.OpenShellConfig) {}},
		{"org", func(o *config.OpenShellConfig) {
			a := &o.Admin
			a.AllowYolo = boolPtr(false)
			a.EgressBlock = []string{"exfil.example.net"}
			a.MaxResources = config.OpenShellResourcesConfig{CPU: "2"}
			a.RequireCopyFor = []string{"/src/customer-*"}
		}},
		// A pinned required pack: a profile's own pack must be at least as
		// strict, and comes with its own pin.
		{"pinned", func(o *config.OpenShellConfig) {
			o.Admin.RequiredPack, o.Admin.RequiredPackDigest = config.OpenShellProfileBalanced, balanced.Digest
		}},
		// A locked configured pack: bytes that claim its file never run.
		{"locked", func(o *config.OpenShellConfig) {
			o.Pack = corp
			o.Admin.Locked = []string{"pack"}
		}},
	}
	profiles := []struct {
		name    string
		overlay func(*config.OpenShellAdminConfig) // nil: no profile floor
	}{
		{"none", nil},
		{"contractors", func(a *config.OpenShellAdminConfig) {
			a.MinProfile = config.OpenShellProfileBalanced
			a.AllowMount = boolPtr(false)
			a.AllowLearnMode = boolPtr(false)
			a.EgressAllowOnly = []string{"api.example.com", "*.example.org"}
			a.AllowedHarnesses = []string{"claudecode", "codex"}
			a.OnSilence, a.MaxSilenceAfter = OnSilenceStop, "5m"
			a.ProcessTree = boolPtr(true)
			a.RequestAccess = "ask the IT help desk"
		}},
		{"lockdown", func(a *config.OpenShellAdminConfig) {
			// A profile's pack replaces the base pack and its pin together
			// (TightenOpenShellAdmin).
			a.RequiredPack, a.RequiredPackDigest = "strict", ""
			a.AllowUnblock = boolPtr(false)
			a.Locked = []string{"pack", "profile", "resources"}
		}},
	}
	userPacks := []struct {
		name  string
		flags Flags
	}{
		{"default", Flags{}},
		{"strict", Flags{Pack: "strict"}},
		{"team-bytes", Flags{Pack: filepath.Join(root, "home", "team", PackFileName), UserPack: []byte(customPack("team"))}},
		{"forged", Flags{Pack: corp, UserPack: []byte(customPack("corp"))}},
	}
	subject := &Subject{UID: os.Getuid(), Home: filepath.Join(root, "home")}
	runs := []struct {
		name  string
		flags Flags
	}{
		{"plain", Flags{Harness: "claudecode", Project: "/src/customer-acme/app"}},
		{"loose", Flags{Harness: "opencode", Project: "/src/other", Yolo: true, Profile: config.OpenShellProfileOpen,
			CPU: "4", Learn: true, HostPorts: []int{5432}}},
	}
	repos := []struct {
		name string
		doc  string
	}{
		{"none", ""},
		{"tight", "version: 1\nnetwork: {mode: allowlist}\nworkspace: {mode: copy}\nhooks: {on_silence: stop}\n"},
	}

	var out strings.Builder
	for _, base := range bases {
		for _, profile := range profiles {
			for _, pack := range userPacks {
				for _, run := range runs {
					for _, repo := range repos {
						cfg := testConfig(func(o *config.OpenShellConfig) { o.PackDir = packDir })
						base.edit(&cfg.OpenShell)
						flags := run.flags
						flags.Pack, flags.UserPack = pack.flags.Pack, pack.flags.UserPack
						if profile.overlay != nil || flags.UserPack != nil {
							// The managed gateway, resolving for a peer.
							flags.Subject = subject
						}
						if profile.overlay != nil {
							floor := cloneFloor(cfg.OpenShell.Admin)
							profile.overlay(&floor)
							flags.Floor = &floor
						}
						if repo.doc != "" {
							flags.RepoPolicy = mustRepoPolicy(t, repo.doc)
						}
						fmt.Fprintf(&out, "%s/%s/%s/%s/%s: %s\n", base.name, profile.name, pack.name, run.name, repo.name,
							matrixLine(cfg, flags, root))
					}
				}
			}
		}
	}
	got := out.String()
	golden := filepath.Join("testdata", "resolve_matrix.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got != string(want) {
		gotLines, wantLines := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < max(len(gotLines), len(wantLines)); i++ {
			g, w := "", ""
			if i < len(gotLines) {
				g = gotLines[i]
			}
			if i < len(wantLines) {
				w = wantLines[i]
			}
			if g != w {
				t.Errorf("line %d:\n got  %s\n want %s", i+1, g, w)
			}
		}
		t.Fatal("the resolve matrix changed; run with -update after a deliberate change and review the diff")
	}
}

func matrixLine(cfg *config.Config, flags Flags, root string) string {
	eff, violations, err := Resolve(cfg, flags)
	if err != nil {
		return "error: " + strings.ReplaceAll(err.Error(), root, "<root>")
	}
	var vs []string
	for _, v := range violations {
		s := v.Key + ":" + v.Constraint
		if v.Fatal {
			s += "!"
		}
		vs = append(vs, s)
	}
	allowed := "any"
	if !eff.AnyHarness {
		allowed = strings.Join(eff.AllowedHarnesses, ",")
	}
	return fmt.Sprintf("pack=%s profile=%s approvals=%s yolo=%v mode=%s harness=%s allowed=%s learn=%v ports=%v"+
		" process_tree=%v on_silence=%s silence_after=%s cpu=%s allow_only=%s violations=[%s] digest=%s",
		eff.Pack.Name, eff.Profile, eff.Approvals, eff.Yolo, eff.Workspace.Mode, eff.Harness, allowed, eff.Learn,
		slices.Clone(eff.MCP.HostPorts), eff.ProcessTree, eff.HookOnSilence, ShortDuration(eff.HookSilenceAfter),
		eff.Resources.CPU, strings.Join(eff.Egress.AllowOnly, ","), strings.Join(vs, " "), eff.Digest()[:19])
}
