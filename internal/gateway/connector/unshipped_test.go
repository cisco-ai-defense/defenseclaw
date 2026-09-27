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

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

const unshippedExample = "retired-example"

func TestRegistryNotShipped(t *testing.T) {
	reg := NewDefaultRegistry()
	if reg.NotShipped("codex") {
		t.Fatal("a built-in connector is shipped")
	}
	if !reg.NotShipped(unshippedExample) {
		t.Fatal("a name nothing provides must be reported as not shipped")
	}
	if reg.NotShipped("  ") {
		t.Fatal("an empty name is never droppable")
	}

	pluginDir := t.TempDir()
	unshippedMkdir(t, filepath.Join(pluginDir, "broken-plugin"))
	unshippedWrite(t, filepath.Join(pluginDir, "broken-plugin", "plugin.yaml"), "name: fancy\nentry: fancy.so\n")
	unshippedMkdir(t, filepath.Join(pluginDir, "unparsed"))
	unshippedWrite(t, filepath.Join(pluginDir, "unparsed", "plugin.yaml"), ":\n  - [\n")
	reg.mu.Lock()
	reg.pluginDir, reg.pluginDiscoveryErr = pluginDir, nil
	reg.mu.Unlock()
	for _, name := range []string{"fancy", "FANCY", "broken-plugin", "unparsed"} {
		if reg.NotShipped(name) {
			t.Fatalf("%q is declared by a plugin directory that failed to load; it must be retained", name)
		}
	}
	if !reg.NotShipped(unshippedExample) {
		t.Fatal("an undeclared name stays droppable when discovery succeeded")
	}

	reg.mu.Lock()
	reg.pluginDiscoveryErr = errors.New("plugin root unsafe")
	reg.mu.Unlock()
	if reg.NotShipped(unshippedExample) {
		t.Fatal("a failed plugin discovery must keep every unresolved name")
	}
}

func TestRegistryNotShippedAfterDiscoveryError(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "plugins")
	unshippedWrite(t, notADir, "not a directory\n")
	reg := NewDefaultRegistry()
	if err := reg.DiscoverPlugins(notADir); err == nil {
		t.Fatal("DiscoverPlugins on a regular file must fail")
	}
	if reg.NotShipped(unshippedExample) {
		t.Fatal("NotShipped must be false after DiscoverPlugins reported an error")
	}
}

func TestRemoveUnshippedConnectorFiles(t *testing.T) {
	dataDir := t.TempDir()
	hooks := filepath.Join(dataDir, "hooks")
	unshippedMkdir(t, hooks)
	owned := []string{
		filepath.Join(hooks, unshippedExample+"-hook.sh"),
		filepath.Join(hooks, unshippedExample+"-hook.ps1"),
		filepath.Join(hooks, ".otlp-"+unshippedExample+".token"),
	}
	kept := []string{
		filepath.Join(hooks, "codex-hook.sh"),
		filepath.Join(hooks, "claude-code-hook.sh"),
		filepath.Join(hooks, ".otlp-codex.token"),
		filepath.Join(hooks, "inspect-tool.sh"),
	}
	for _, path := range append(append([]string(nil), owned...), kept...) {
		unshippedWrite(t, path, "#!/bin/sh\n")
	}
	reg := NewDefaultRegistry()

	removed, err := reg.RemoveUnshippedConnectorFiles(dataDir, unshippedExample)
	if err != nil {
		t.Fatalf("RemoveUnshippedConnectorFiles: %v", err)
	}
	sort.Strings(removed)
	want := append([]string(nil), owned...)
	sort.Strings(want)
	if len(removed) != len(want) {
		t.Fatalf("removed = %v, want %v", removed, want)
	}
	for i := range want {
		if removed[i] != want[i] {
			t.Fatalf("removed = %v, want %v", removed, want)
		}
	}
	for _, path := range owned {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived: %v", path, err)
		}
	}

	// Shipped names, names whose file a shipped connector claims, shared
	// helpers and unsafe names never lose a file.
	for _, name := range []string{"codex", "claude-code", "../hooks", "Codex", ""} {
		if got, err := reg.RemoveUnshippedConnectorFiles(dataDir, name); err != nil || len(got) != 0 {
			t.Fatalf("RemoveUnshippedConnectorFiles(%q) = %v, %v; want nothing removed", name, got, err)
		}
	}
	for _, path := range kept {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s must be kept: %v", path, err)
		}
	}

	// A second run is a no-op.
	if got, err := reg.RemoveUnshippedConnectorFiles(dataDir, unshippedExample); err != nil || len(got) != 0 {
		t.Fatalf("second run = %v, %v; want no-op", got, err)
	}

	// While plugin discovery is failing nothing is removed.
	unshippedWrite(t, owned[0], "#!/bin/sh\n")
	reg.mu.Lock()
	reg.pluginDiscoveryErr = errors.New("plugin root unsafe")
	reg.mu.Unlock()
	if got, err := reg.RemoveUnshippedConnectorFiles(dataDir, unshippedExample); err != nil || len(got) != 0 {
		t.Fatalf("with failed discovery = %v, %v; want nothing removed", got, err)
	}
}

func unshippedMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func unshippedWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
