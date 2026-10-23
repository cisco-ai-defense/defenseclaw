// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package openshell_test

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The fixtures are the bootstrap files of one live Docker sandbox
// (rel-1-0-4 GAP-0300, reproduced on defenseclaw-dev with the official
// release binaries): testdata/docker-bootstrap/0.1.3 as OpenShell 0.1.3's
// docker driver wrote them at its create, and testdata/docker-bootstrap/0.1.5
// as OpenShell 0.1.5 rewrote them at its first start after
// MigrateDockerBootstrap. Before the migration, OpenShell 0.1.5 refused
// that start with "decode Docker sandbox bootstrap for authentication
// rotation: unknown field `outer_fence`"; after it, the sandbox started,
// stopped and started again with its files, and survived a gateway
// restart.
var dockerBootstrapFiles = []string{"boundary-bootstrap.json", "runtime-descriptor.json"}

func readBootstrap(t *testing.T, release, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "docker-bootstrap", release, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func bootstrapFields(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func sameJSON(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// TestADockerSandboxOf013GetsTheBootstrap015Reads: each file of a 0.1.3
// sandbox comes out with exactly the fields OpenShell 0.1.5 writes (it
// decodes them with no unknown field), outer_fence out and
// provisioning_evidence in, every other field as it was.
func TestADockerSandboxOf013GetsTheBootstrap015Reads(t *testing.T) {
	for _, name := range dockerBootstrapFiles {
		old := readBootstrap(t, "0.1.3", name)
		out, changed, err := openshell.MigrateDockerBootstrapJSON(old)
		if err != nil || !changed {
			t.Fatalf("%s: changed %v, %v", name, changed, err)
		}
		got, was, want := bootstrapFields(t, out), bootstrapFields(t, old), bootstrapFields(t, readBootstrap(t, "0.1.5", name))
		if k := slices.Sorted(maps.Keys(got)); !slices.Equal(k, slices.Sorted(maps.Keys(want))) {
			t.Fatalf("%s: fields %v, OpenShell 0.1.5 writes %v", name, k, slices.Sorted(maps.Keys(want)))
		}
		for k, v := range was {
			if k == "outer_fence" {
				continue
			}
			if !sameJSON(t, got[k], v) {
				t.Errorf("%s: %s changed: %s -> %s", name, k, v, got[k])
			}
		}
		var ev struct {
			Generation     string `json:"generation"`
			EvidenceDigest string `json:"evidence_digest"`
		}
		var gen string
		if json.Unmarshal(got["provisioning_evidence"], &ev) != nil || json.Unmarshal(got["generation"], &gen) != nil || ev.Generation != gen || len(ev.EvidenceDigest) != 64 {
			t.Errorf("%s: provisioning_evidence %s for generation %s", name, got["provisioning_evidence"], got["generation"])
		}
		// A file OpenShell 0.1.5 wrote is left as it is.
		if again, changed, err := openshell.MigrateDockerBootstrapJSON(out); err != nil || changed || string(again) != string(out) {
			t.Errorf("%s: a second pass changed %v, %v", name, changed, err)
		}
	}
}

// TestTheEvidenceIsTheOneOpenShell015Computes: provisioning_evidence is the
// digest OpenShell 0.1.5's docker driver binds to the container and the
// generation. The 0.1.5 fixture, given an outer_fence again in place of
// its evidence, gets back the very evidence 0.1.5 wrote for it.
func TestTheEvidenceIsTheOneOpenShell015Computes(t *testing.T) {
	for _, name := range dockerBootstrapFiles {
		written := bootstrapFields(t, readBootstrap(t, "0.1.5", name))
		legacy := maps.Clone(written)
		delete(legacy, "provisioning_evidence")
		legacy["outer_fence"] = bootstrapFields(t, readBootstrap(t, "0.1.3", name))["outer_fence"]
		in, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		out, changed, err := openshell.MigrateDockerBootstrapJSON(in)
		if err != nil || !changed {
			t.Fatalf("%s: changed %v, %v", name, changed, err)
		}
		if got := bootstrapFields(t, out)["provisioning_evidence"]; !sameJSON(t, got, written["provisioning_evidence"]) {
			t.Fatalf("%s: evidence %s, OpenShell 0.1.5 wrote %s", name, got, written["provisioning_evidence"])
		}
	}
}

// stageBootstrap puts the 0.1.3 files of the sandbox id in the docker
// driver's folder for namespace under a new state folder.
func stageBootstrap(t *testing.T, namespace, id string) (stateHome, dir string) {
	t.Helper()
	stateHome = t.TempDir()
	dir = filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", namespace, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range dockerBootstrapFiles {
		if err := os.WriteFile(filepath.Join(dir, name), readBootstrap(t, "0.1.3", name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return stateHome, dir
}

// TestMigrateDockerBootstrapInTheStateFolder: the files of the sandbox are
// rewritten in place, owner-only as before and with nothing left over, in
// whatever namespace keeps them; a second pass and a sandbox the driver
// keeps nothing for change nothing.
func TestMigrateDockerBootstrapInTheStateFolder(t *testing.T) {
	const id = "173db0f1-f401-4104-b94b-aaec75789fc3"
	stateHome, dir := stageBootstrap(t, "defenseclaw-u1000", id)
	if err := os.MkdirAll(filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", "default", "another-sandbox"), 0o700); err != nil {
		t.Fatal(err)
	}
	moved, kept, err := openshell.MigrateDockerBootstrap(stateHome, id)
	if err != nil || !kept || len(moved) != 2 {
		t.Fatalf("moved %v, %v", moved, err)
	}
	for _, name := range dockerBootstrapFiles {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if doc := bootstrapFields(t, data); doc["outer_fence"] != nil || doc["provisioning_evidence"] == nil {
			t.Fatalf("%s was not moved: %s", name, data)
		}
		if fi, err := os.Stat(path); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, %v", name, fi.Mode(), err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != len(dockerBootstrapFiles) {
		t.Fatalf("left in the folder: %v", entries)
	}
	if moved, kept, err := openshell.MigrateDockerBootstrap(stateHome, id); err != nil || !kept || len(moved) != 0 {
		t.Fatalf("second pass moved %v, %v", moved, err)
	}
	if moved, kept, err := openshell.MigrateDockerBootstrap(stateHome, "no-such-sandbox"); err != nil || kept || len(moved) != 0 {
		t.Fatalf("a sandbox with no folder: %v, %v", moved, err)
	}
	if moved, kept, err := openshell.MigrateDockerBootstrap(t.TempDir(), id); err != nil || kept || len(moved) != 0 {
		t.Fatalf("a state folder the docker driver never used: %v, %v", moved, err)
	}
}

// TestABootstrapThatCannotBeMovedIsLeftAsItWas: a file that is not one
// DefenseClaw can rewrite refuses with ErrDockerBootstrap, and stays as
// it was.
func TestABootstrapThatCannotBeMovedIsLeftAsItWas(t *testing.T) {
	const id = "173db0f1-f401-4104-b94b-aaec75789fc3"
	edit := func(t *testing.T, mutate func(map[string]json.RawMessage)) []byte {
		doc := bootstrapFields(t, readBootstrap(t, "0.1.3", "boundary-bootstrap.json"))
		mutate(doc)
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, tc := range []struct {
		name string
		data func(t *testing.T) []byte
	}{
		{"not JSON", func(*testing.T) []byte { return []byte("{\"outer_fence\":") }},
		{"no generation", func(t *testing.T) []byte {
			return edit(t, func(d map[string]json.RawMessage) { delete(d, "generation") })
		}},
		{"no container claim", func(t *testing.T) []byte {
			return edit(t, func(d map[string]json.RawMessage) { d["resource_claims"] = json.RawMessage(`{}`) })
		}},
		{"both fields", func(t *testing.T) []byte {
			return edit(t, func(d map[string]json.RawMessage) {
				d["provisioning_evidence"] = json.RawMessage(`{"generation":"g","evidence_digest":"00"}`)
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateHome, dir := stageBootstrap(t, "default", id)
			path := filepath.Join(dir, "boundary-bootstrap.json")
			data := tc.data(t)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := openshell.MigrateDockerBootstrap(stateHome, id); !errors.Is(err, openshell.ErrDockerBootstrap) {
				t.Fatalf("err = %v", err)
			}
			if got, _ := os.ReadFile(path); string(got) != string(data) {
				t.Fatalf("the file changed: %s", got)
			}
		})
	}
	if runtime.GOOS != "windows" {
		t.Run("a link", func(t *testing.T) {
			stateHome, dir := stageBootstrap(t, "default", id)
			path := filepath.Join(dir, "boundary-bootstrap.json")
			target := filepath.Join(t.TempDir(), "elsewhere.json")
			if err := os.WriteFile(target, readBootstrap(t, "0.1.3", "boundary-bootstrap.json"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			if _, _, err := openshell.MigrateDockerBootstrap(stateHome, id); !errors.Is(err, openshell.ErrDockerBootstrap) {
				t.Fatalf("err = %v", err)
			}
			if got, _ := os.ReadFile(target); string(got) != string(readBootstrap(t, "0.1.3", "boundary-bootstrap.json")) {
				t.Fatal("the file the link names changed")
			}
		})
	}
	for _, bad := range []struct{ home, id string }{{"relative", id}, {t.TempDir(), "../x"}, {t.TempDir(), ""}, {t.TempDir(), ".."}} {
		if _, _, err := openshell.MigrateDockerBootstrap(bad.home, bad.id); !errors.Is(err, openshell.ErrDockerBootstrap) {
			t.Errorf("MigrateDockerBootstrap(%q, %q) = %v", bad.home, bad.id, err)
		}
	}
}

// TestAStateFolderThatCannotBeListedIsNotTheSandboxsBootstrap: a
// docker-sandbox-tokens folder, or a namespace of it, that cannot be read
// says nothing about the sandbox's bootstrap: ErrDockerStateUnreadable,
// not ErrDockerBootstrap, when the sandbox is in no namespace that could
// be, and the sandbox's files move when another namespace keeps them.
func TestAStateFolderThatCannotBeListedIsNotTheSandboxsBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs folder modes that deny their owner")
	}
	const id = "173db0f1-f401-4104-b94b-aaec75789fc3"
	lock := func(t *testing.T, dir string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	}
	stateHome := t.TempDir()
	lock(t, filepath.Join(stateHome, "openshell", "docker-sandbox-tokens"), 0)
	moved, kept, err := openshell.MigrateDockerBootstrap(stateHome, id)
	if !errors.Is(err, openshell.ErrDockerStateUnreadable) || errors.Is(err, openshell.ErrDockerBootstrap) || kept || len(moved) != 0 {
		t.Fatalf("a tokens folder that cannot be listed: %v, %v, %v", moved, kept, err)
	}

	stateHome, _ = stageBootstrap(t, "defenseclaw-u1000", id)
	lock(t, filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", "default"), 0o600)
	if moved, kept, err := openshell.MigrateDockerBootstrap(stateHome, id); err != nil || !kept || len(moved) != 2 {
		t.Fatalf("a namespace that cannot be searched, the sandbox in another: %v, %v, %v", moved, kept, err)
	}
	if moved, kept, err := openshell.MigrateDockerBootstrap(stateHome, "no-such-sandbox"); !errors.Is(err, openshell.ErrDockerStateUnreadable) || kept || len(moved) != 0 {
		t.Fatalf("a sandbox in no namespace that could be searched: %v, %v, %v", moved, kept, err)
	}
}
