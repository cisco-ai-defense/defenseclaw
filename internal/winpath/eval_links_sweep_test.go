// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The packages that resolve a path and then check it is below a root resolve
// it with EvalLinks (or a reader built on it), never with
// filepath.EvalSymlinks, in every file Go builds for Windows: there
// filepath.EvalSymlinks leaves a junction unfollowed, so a path that leaves
// the root through a junction would pass (rel-1-0-10:GAP-2182). The check
// reads the sources, so it runs on every CI runner.
func TestRootGuardPackagesDoNotUseEvalSymlinksOnWindows(t *testing.T) {
	ctx := build.Default
	ctx.GOOS = "windows"
	ctx.GOARCH = "amd64"
	ctx.CgoEnabled = false
	for _, dir := range []string{"../gateway", "../inventory", "../hookpaths"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if name == "testdata" || (strings.HasPrefix(name, ".") && path != dir) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			if ok, err := ctx.MatchFile(filepath.Dir(path), name); err != nil || !ok {
				return err
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			local := ""
			for _, spec := range file.Imports {
				if p, _ := strconv.Unquote(spec.Path.Value); p == "path/filepath" {
					local = "filepath"
					if spec.Name != nil {
						local = spec.Name.Name
					}
				}
			}
			if local == "" {
				return nil
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "EvalSymlinks" {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == local {
					t.Errorf("%s: filepath.EvalSymlinks in a file built for Windows; use winpath.EvalLinks", fset.Position(sel.Pos()))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
	}
}
