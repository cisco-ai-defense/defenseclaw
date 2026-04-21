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

package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type stubScanner struct {
	name    string
	version string
}

func (s *stubScanner) Name() string                { return s.name }
func (s *stubScanner) Version() string             { return s.version }
func (s *stubScanner) SupportedTargets() []string  { return []string{"skill", "mcp"} }
func (s *stubScanner) Scan(_ context.Context, target string) (*ScanResult, error) {
	return &ScanResult{
		Scanner:   s.name,
		Target:    target,
		Timestamp: time.Now(),
		Findings:  nil,
	}, nil
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if len(r.Scanners()) != 0 {
		t.Errorf("new registry should have 0 scanners, got %d", len(r.Scanners()))
	}
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()
	s := &stubScanner{name: "test-scanner", version: "1.0.0"}
	r.Register(s)

	if len(r.Scanners()) != 1 {
		t.Fatalf("expected 1 scanner, got %d", len(r.Scanners()))
	}
	if r.Scanners()[0].Name() != "test-scanner" {
		t.Errorf("scanner name = %q, want test-scanner", r.Scanners()[0].Name())
	}
}

func TestRegistry_RegisterMultiple(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubScanner{name: "alpha", version: "1.0"})
	r.Register(&stubScanner{name: "beta", version: "2.0"})

	if len(r.Scanners()) != 2 {
		t.Fatalf("expected 2 scanners, got %d", len(r.Scanners()))
	}
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubScanner{name: "test-scanner", version: "1.0"})

	t.Run("found", func(t *testing.T) {
		s := r.Get("test-scanner")
		if s == nil {
			t.Fatal("expected scanner, got nil")
		}
		if s.Name() != "test-scanner" {
			t.Errorf("name = %q", s.Name())
		}
	})

	t.Run("case_insensitive", func(t *testing.T) {
		s := r.Get("TEST-SCANNER")
		if s == nil {
			t.Fatal("Get should be case-insensitive")
		}
	})

	t.Run("not_found", func(t *testing.T) {
		s := r.Get("nonexistent")
		if s != nil {
			t.Error("expected nil for unknown scanner")
		}
	})
}

func TestRegistry_Discover(t *testing.T) {
	dir := t.TempDir()

	// Create two plugin directories with manifests
	for _, name := range []string{"scanner-a", "scanner-b"} {
		pluginDir := filepath.Join(dir, name)
		if err := os.MkdirAll(pluginDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte("name: "+name+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create a directory without a manifest (should be ignored)
	if err := os.MkdirAll(filepath.Join(dir, "not-a-plugin"), 0755); err != nil {
		t.Fatal(err)
	}

	r := NewRegistry()
	found, err := r.Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) != 2 {
		t.Errorf("expected 2 discovered plugins, got %d: %v", len(found), found)
	}
}

func TestRegistry_Discover_EmptyDir(t *testing.T) {
	r := NewRegistry()
	found, err := r.Discover(t.TempDir())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("expected 0 plugins in empty dir, got %d", len(found))
	}
}

func TestRegistry_Discover_EmptyPath(t *testing.T) {
	r := NewRegistry()
	_, err := r.Discover("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestRegistry_Discover_NotADir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(f, []byte("x"), 0644)

	r := NewRegistry()
	_, err := r.Discover(f)
	if err == nil {
		t.Error("expected error for non-directory path")
	}
}

func TestRegistry_Discover_NonexistentDir(t *testing.T) {
	r := NewRegistry()
	_, err := r.Discover("/nonexistent/path/12345")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestStubScanner_Scan(t *testing.T) {
	s := &stubScanner{name: "test", version: "1.0"}
	result, err := s.Scan(context.Background(), "test-target")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.Scanner != "test" {
		t.Errorf("scanner = %q", result.Scanner)
	}
	if result.Target != "test-target" {
		t.Errorf("target = %q", result.Target)
	}
	if result.Findings != nil {
		t.Errorf("expected nil findings for stub")
	}
}
