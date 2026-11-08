// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The watch list is the allow-list and nothing else. Lock files that DefenseClaw
// itself holds with no sharing, temp files, relax records, connectors whose
// hook does not read the folder, links and anything deeper are never listed.
func TestWindowsHookRuntimeWatchListIsTheAllowListOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "DefenseClaw-HookRuntime")
	write := func(rel string) string {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	want := []string{
		write("machine-policy.json"),
		write(".defenseclaw-hot-config-undo-closed"),
		write("copilot/enrollment.json"),
		write("copilot/.defenseclaw-managed-runtime-selector.state"),
		write("kiro/enrollment.json"),
	}
	for _, rel := range []string{
		// DefenseClaw's own writers hold these with no sharing.
		"copilot/.defenseclaw-enrollment.lock",
		"copilot/.defenseclaw-managed-runtime-selector.lock",
		"kiro/.defenseclaw-enrollment.lock",
		".defenseclaw-enrollment.lock",
		// Temp files (the writer's real name is .defenseclaw-policy-*.tmp; the old .tmp- forms stay excluded too) and relax records of the writers.
		".defenseclaw-policy-123.tmp",
		"copilot/.defenseclaw-policy-456.tmp",
		"copilot/.defenseclaw-policy-789.tmp.bak",
		"copilot/.tmp-enrollment-1",
		"copilot/enrollment.json.tmp-9",
		"copilot/.defenseclaw-setup-relax-S-1-5-21-1.json",
		// Names the hook reads only in another place, or never.
		"enrollment.json",
		"copilot/machine-policy.json",
		"amp/enrollment.json",
		"claudecode/selector.json",
		"copilot/sub/enrollment.json",
		"other/enrollment.json",
		"copilot/Enrollment.json.bak",
	} {
		write(rel)
	}
	got := windowsHookRuntimeWatchList(dir)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("watch list\n got  %v\n want %v", got, want)
	}
	for _, path := range got {
		base := strings.ToLower(filepath.Base(path))
		if strings.HasSuffix(base, ".lock") || strings.HasSuffix(base, ".tmp") || strings.Contains(base, ".tmp-") || strings.HasPrefix(base, ".tmp-") {
			t.Fatalf("%s is a lock or temp file", path)
		}
	}
	if list := windowsHookRuntimeWatchList(""); len(list) != 0 {
		t.Fatalf("an empty folder name listed %v", list)
	}
	if list := windowsHookRuntimeWatchList(filepath.Join(dir, "missing")); len(list) != 0 {
		t.Fatalf("a missing folder listed %v", list)
	}
	// A directory with an allow-listed name, and a link, are not files to watch.
	if err := os.MkdirAll(filepath.Join(dir, "devin", "enrollment.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(want[0], filepath.Join(dir, "hermes-link")); err == nil {
		if err := os.Symlink(filepath.Join(dir, "copilot"), filepath.Join(dir, "opencode")); err == nil {
			if list := windowsHookRuntimeWatchList(dir); !reflect.DeepEqual(list, want) {
				t.Fatalf("with a directory and links in the folder: %v, want %v", list, want)
			}
		}
	}
}

// Every allow-listed name has a reader on the hook path: the chain of code
// from the hook command down to the constant that holds the name exists in the
// source, link by link, and the constant has this value. A name that nothing on
// a hook start reads fails here, so it cannot stay on the list.
func TestWindowsHookRuntimeFilesAreReadOnTheHookPath(t *testing.T) {
	requireInternalSources(t)
	if len(windowsHookRuntimeFiles) == 0 {
		t.Fatal("the allow-list is empty")
	}
	seen := map[string]bool{}
	for _, entry := range windowsHookRuntimeFiles {
		entry := entry
		t.Run(entry.Name, func(t *testing.T) {
			if seen[strings.ToLower(entry.Name)] {
				t.Fatalf("%s is listed twice", entry.Name)
			}
			seen[strings.ToLower(entry.Name)] = true
			if strings.HasSuffix(entry.Name, ".lock") || strings.HasSuffix(entry.Name, ".tmp") || strings.Contains(entry.Name, ".tmp-") || strings.Contains(entry.Name, "*") || strings.Contains(entry.Name, "relax") {
				t.Fatalf("%s is a lock, temp or relax file, which the hook never reads", entry.Name)
			}
			if len(entry.Path) == 0 {
				t.Fatal("no reader is cited")
			}
			if !strings.HasPrefix(entry.Path[0].File, "cli/") {
				t.Fatalf("the path starts in %s, not in the hook command", entry.Path[0].File)
			}
			for i, hop := range entry.Path {
				if err := sourceDeclMentions(hop.File, hop.Decl, hop.Uses); err != nil {
					t.Errorf("hop %d: %v", i, err)
				}
				if i > 0 && entry.Path[i-1].Uses != hop.Decl {
					t.Errorf("hop %d starts at %s but hop %d reaches %s", i, hop.Decl, i-1, entry.Path[i-1].Uses)
				}
			}
			if last := entry.Path[len(entry.Path)-1]; last.Uses != entry.NameConst {
				t.Errorf("the path ends at %s, not at the constant %s", last.Uses, entry.NameConst)
			}
			value, err := sourceStringConst(entry.NameFile, entry.NameConst)
			if err != nil {
				t.Fatal(err)
			}
			if value != entry.Name {
				t.Fatalf("%s in %s is %q, not %q", entry.NameConst, entry.NameFile, value, entry.Name)
			}
		})
	}
}

// The connector folders are the ones whose hook start resolves a per-user
// runtime: the cases of ResolveWindowsManagedHookRuntime that call
// resolveWindowsPerUserManagedHookRuntime.
func TestWindowsHookRuntimeConnectorsAreTheResolverCases(t *testing.T) {
	requireInternalSources(t)
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "enterprisehooks", "managed_runtime_windows.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ResolveWindowsManagedHookRuntime" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok {
				return true
			}
			perUser := false
			for _, stmt := range clause.Body {
				ast.Inspect(stmt, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok && id.Name == "resolveWindowsPerUserManagedHookRuntime" {
						perUser = true
					}
					return true
				})
			}
			if !perUser {
				return true
			}
			for _, expr := range clause.List {
				if lit, ok := expr.(*ast.BasicLit); ok {
					name, _ := strconv.Unquote(lit.Value)
					got = append(got, name)
				}
			}
			return true
		})
	}
	want := append([]string(nil), windowsHookRuntimeConnectors...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) == 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("resolver cases %v, connector folders %v", got, want)
	}
}

// requireInternalSources skips a test that reads the source of the other
// packages when the test binary runs away from the repository (the native
// Windows run copies the compiled binary to a host without the source).
func requireInternalSources(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(filepath.Join("..", "enterprisehooks")); err != nil {
		t.Skip("the internal/ source tree is not next to the test binary")
	}
}

// sourceDeclMentions says whether the top-level declaration decl (a function,
// or a variable or constant) in file, a path relative to internal/, mentions
// the identifier uses.
func sourceDeclMentions(file, decl, uses string) error {
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", filepath.FromSlash(file)), nil, 0)
	if err != nil {
		return err
	}
	mentions := func(node ast.Node) bool {
		found := false
		ast.Inspect(node, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == uses {
				found = true
			}
			return !found
		})
		return found
	}
	for _, d := range parsed.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.Name == decl && d.Body != nil {
				if mentions(d.Body) {
					return nil
				}
				return &sourceError{file, decl + " does not mention " + uses}
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range value.Names {
					if name.Name != decl {
						continue
					}
					if i < len(value.Values) && mentions(value.Values[i]) {
						return nil
					}
					return &sourceError{file, decl + " does not mention " + uses}
				}
			}
		}
	}
	return &sourceError{file, "has no declaration " + decl}
}

// sourceStringConst is the string value of the constant name in file.
func sourceStringConst(file, name string) (string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", filepath.FromSlash(file)), nil, 0)
	if err != nil {
		return "", err
	}
	for _, d := range parsed.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			for i, n := range value.Names {
				if n.Name != name || i >= len(value.Values) {
					continue
				}
				lit, ok := value.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return "", &sourceError{file, name + " is not a string literal"}
				}
				return strconv.Unquote(lit.Value)
			}
		}
	}
	return "", &sourceError{file, "has no constant " + name}
}

type sourceError struct{ file, text string }

func (e *sourceError) Error() string { return e.file + ": " + e.text }
