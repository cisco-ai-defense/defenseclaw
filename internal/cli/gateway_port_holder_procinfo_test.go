// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// GAP-0629/GAP-0687: a second hand-made proc_pidpath call read the syscall
// result as the path length, which the kernel never returns, so the macOS
// foreground gateway proof never resolved. internal/procimage owns the one
// call (a leaf package: internal/enterpriseunix imports internal/openshell, so
// openshell cannot import enterpriseunix); every other package uses
// procimage.Path, or enterpriseunix.ProcessImagePath, which wraps it.
func TestGAP0687ProcPIDPathInfoHasOneResolver(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found from %s: %v", root, err)
	}
	const owner = "internal/procimage/path_darwin.go"
	procInfo := regexp.MustCompile(`(?i)pid_?path_?info|SYS_PROC_INFO`)
	var owners []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "Syscall") && procInfo.Match(data) {
			rel, _ := filepath.Rel(root, path)
			owners = append(owners, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != owner {
		t.Fatalf("proc_info PROC_PIDPATHINFO callers = %v; want only %s (use procimage.Path)", owners, owner)
	}
}
