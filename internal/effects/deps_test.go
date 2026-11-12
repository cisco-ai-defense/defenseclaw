// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPureParseStepHasNoForbiddenImports enforces the OS-independence
// invariant (owner steer, EFFECTS.md section 3): the pure effects package must
// not import os, runtime, path/filepath, net, or the OS-coupled analysis
// packages internal/actionfacts and internal/hookpaths. Only package fsres may
// touch the filesystem and the OS.
func TestPureParseStepHasNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		`"os"`, `"runtime"`, `"path/filepath"`, `"net"`, `"os/exec"`,
		`"github.com/defenseclaw/defenseclaw/internal/actionfacts"`,
		`"github.com/defenseclaw/defenseclaw/internal/hookpaths"`,
		`"github.com/defenseclaw/defenseclaw/internal/gateway"`,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			for _, bad := range forbidden {
				if imp.Path.Value == bad {
					t.Errorf("%s imports forbidden package %s (pure parse step must be OS-agnostic)", name, bad)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
}
