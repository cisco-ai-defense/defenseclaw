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

package harness

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenCodeImageRecordsItsPluginPackage (cert opencode:OC-3): the image
// build records @opencode-ai/plugin, at the pinned version, as installed in
// the image HOME's OpenCode config directory, the way OpenCode 1.18.31's
// start-up install check reads it (a node_modules, and every package.json
// dependency plus @opencode-ai/plugin in the lock's root package), so a new
// sandbox does not download it; no package is written.
func TestOpenCodeImageRecordsItsPluginPackage(t *testing.T) {
	steps, err := OpenCode.InstallSteps("")
	if err != nil {
		t.Fatal(err)
	}
	var run string
	for _, s := range steps {
		if strings.Contains(s.Run, "package-lock.json") {
			run = s.Run
		}
	}
	quoted := "d=" + shellQuote(OpenCodeGlobalConfigDir) + ";"
	if run == "" || !strings.Contains(run, quoted) {
		t.Fatalf("no install step records the plugin package in %s:\n%v", OpenCodeGlobalConfigDir, steps)
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is required")
	}
	dir := filepath.Join(t.TempDir(), ".config", "opencode")
	cmd := exec.Command("/bin/sh", "-c", strings.Replace(run, quoted, "d="+shellQuote(dir)+";", 1))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the step failed: %v\n%s", err, out)
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "node_modules")); err != nil || len(entries) != 0 {
		t.Fatalf("node_modules = %v (%v), want an empty directory", entries, err)
	}
	type deps struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	read := func(name string, v any) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, raw)
		}
	}
	var pkg deps
	var lock struct {
		Packages map[string]deps `json:"packages"`
	}
	read("package.json", &pkg)
	read("package-lock.json", &lock)
	root := lock.Packages[""]
	locked := map[string]bool{}
	for _, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.PeerDependencies, root.OptionalDependencies} {
		for name := range m {
			locked[name] = true
		}
	}
	wanted := []string{"@opencode-ai/plugin"}
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies, pkg.OptionalDependencies} {
		for name := range m {
			wanted = append(wanted, name)
		}
	}
	for _, name := range wanted {
		if !locked[name] {
			t.Errorf("the lock's root package lacks %s: OpenCode would install it at start", name)
		}
	}
	if pkg.Dependencies["@opencode-ai/plugin"] != openCodePin.Version || root.Dependencies["@opencode-ai/plugin"] != openCodePin.Version {
		t.Errorf("the record is not pinned to OpenCode %s: package.json %q, lock %q", openCodePin.Version,
			pkg.Dependencies["@opencode-ai/plugin"], root.Dependencies["@opencode-ai/plugin"])
	}
}
