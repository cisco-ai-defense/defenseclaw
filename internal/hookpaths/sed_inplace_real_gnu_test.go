// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSedGNUWritesMatchTheRealSed runs GNU sed on scratch files (neutral
// names, nothing protected) over operands typed with and without a directory
// part and over suffixes with and without "*", and holds sedGNUWrites to
// what sed wrote (rel-1-0-10:GAP-0414, GAP-0496 cases HLR4-SFX-*). A suffix
// whose backup sed can write: the set of paths sed wrote is the set the model
// names. A suffix sed refuses (rc != 0): every path sed created is still one
// the model names. The test skips when sed is not GNU sed.
func TestSedGNUWritesMatchTheRealSed(t *testing.T) {
	out, err := exec.Command("sed", "--version").Output()
	if err != nil || !strings.Contains(string(out), "GNU sed") {
		t.Skip("no GNU sed")
	}
	walk := func(root string) map[string]bool {
		files := map[string]bool{}
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				files[p] = true
			}
			return nil
		})
		return files
	}
	operands := []string{"f", "./f", "d/f", "d/e/f", "ABS/d/f"}
	suffixes := []string{".bak", "*.bak", "pre*", "*_*", "b/*", "b/*.o", "../*", "*/x", "/x", "b/x", "pre*.o"}
	for _, operand := range operands {
		for _, suffix := range suffixes {
			root := t.TempDir()
			cwd := filepath.Join(root, "w")
			for _, dir := range []string{"w/d/e", "w/b/d/e", "w/d/b", "w/d/e/b", "w/pre/d", "w/preABS", "b", "w/d/f.dir"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			typed := operand
			if strings.HasPrefix(operand, "ABS/") {
				typed = filepath.Join(cwd, operand[len("ABS/"):])
			}
			target := typed
			if !filepath.IsAbs(target) {
				target = filepath.Join(cwd, typed)
			}
			if err := os.WriteFile(target, []byte("a\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			before := walk(root)
			cmd := exec.Command("sed", "-i"+suffix, "s/a/b/", typed)
			cmd.Dir = cwd
			runErr := cmd.Run()
			made := map[string]bool{target: true}
			for path := range walk(root) {
				if !before[path] {
					made[path] = true
				}
			}
			model := map[string]bool{}
			for _, name := range sedGNUWrites([]string{"sed", "-i" + suffix, "s/a/b/", typed}) {
				if !filepath.IsAbs(name) {
					name = filepath.Join(cwd, name)
				}
				model[filepath.Clean(name)] = true
			}
			for path := range made {
				if !model[path] {
					t.Errorf("sed -i%s %s: sed wrote %s, model has %v", suffix, typed, path, keysOf(model))
				}
			}
			if runErr == nil {
				for path := range model {
					if !made[path] {
						t.Errorf("sed -i%s %s: model names %s, sed did not write it (wrote %v)", suffix, typed, path, keysOf(made))
					}
				}
			}
		}
	}
}

func keysOf(set map[string]bool) []string {
	var keys []string
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
