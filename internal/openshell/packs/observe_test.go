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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The process tree is opt-in: every built-in pack leaves it off.
func TestBuiltinPacksLeaveTheProcessTreeOff(t *testing.T) {
	for _, name := range BuiltinNames() {
		pack, err := Builtin(name)
		if err != nil {
			t.Fatal(err)
		}
		if pack.Observe.ProcessTree {
			t.Fatalf("pack %s turns the process tree on", name)
		}
	}
}

func TestParseObserveProcessTree(t *testing.T) {
	if pack := mustParse(t, minimalPack); pack.Observe.ProcessTree {
		t.Fatal("a pack without observe turns the process tree on")
	}
	if pack := mustParse(t, minimalPack+"observe: {process_tree: true}\n"); !pack.Observe.ProcessTree {
		t.Fatal("observe.process_tree: true is not read")
	}
	for _, doc := range []string{"observe: {process_tree: sometimes}\n", "observe: {processes: true}\n"} {
		if _, err := Parse([]byte(minimalPack+doc), "test"); err == nil {
			t.Fatalf("%q accepted", doc)
		}
	}
}

// The pack decides; --process-tree turns the tree on, never off; a required
// pack that has it on holds it on.
func TestResolveProcessTree(t *testing.T) {
	eff, violations := mustResolve(t, testConfig(nil), Flags{})
	wantViolations(t, violations)
	if eff.ProcessTree {
		t.Fatal("the default pack turns the process tree on")
	}
	wantSetting(t, eff, "observe.process_tree", "false", SourcePack, "pack open")

	eff, _ = mustResolve(t, testConfig(nil), Flags{ProcessTree: true})
	if !eff.ProcessTree {
		t.Fatal("--process-tree does not turn the process tree on")
	}
	wantSetting(t, eff, "observe.process_tree", "true", SourceFlag, "--process-tree")

	root := t.TempDir()
	watching := writePack(t, root, "watching", strings.Replace(customPack("watching"), "hooks: {fail_mode: closed}",
		"hooks: {fail_mode: closed}\nobserve: {process_tree: true}", 1))
	eff, _ = mustResolve(t, testConfig(func(o *config.OpenShellConfig) { o.PackDir, o.Pack = root, "watching" }), Flags{})
	if !eff.ProcessTree {
		t.Fatal("the pack's observe.process_tree is not applied")
	}
	wantSetting(t, eff, "observe.process_tree", "true", SourcePack, "pack watching")

	eff, violations = mustResolve(t, testConfig(func(o *config.OpenShellConfig) {
		o.PackDir, o.Admin.RequiredPack = root, watching
	}), Flags{})
	wantViolations(t, violations)
	if !eff.ProcessTree {
		t.Fatal("a required pack's process tree is not held on")
	}
	found := false
	for _, s := range eff.Explain() {
		found = found || s.Key == "observe.process_tree"
	}
	if !found {
		t.Fatal("policy explain does not list observe.process_tree")
	}
}
