// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// realBackupWalk lists the regular files below root.
func realBackupWalk(root string) map[string]bool {
	files := map[string]bool{}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			files[p] = true
		}
		return nil
	})
	return files
}

// realBackupScratch is a scratch tree (neutral names, nothing protected)
// with the folders the suffix grids name.
func realBackupScratch(t *testing.T) (root, cwd string) {
	t.Helper()
	root = t.TempDir()
	cwd = filepath.Join(root, "w")
	for _, dir := range []string{"w/d/e", "w/b/d/e", "w/d/b", "w/d/e/b", "w/pre/d", "w/preABS", "b", "w/d/f.dir", "w/dot", "w/sub"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root, cwd
}

// TestPerlBackupWritesMatchTheRealPerl runs perl -i on scratch files over
// operands typed with and without a directory part and over suffixes with
// and without "*", and holds the perl model (perlInPlace and
// starBackupName) to what perl wrote (rel-1-0-10:GAP-0543): every "*" is the
// operand as typed. A suffix perl cannot write (rc != 0 or a skipped file):
// every path perl created is still one the model names. Skips when there is
// no perl.
func TestPerlBackupWritesMatchTheRealPerl(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("no perl")
	}
	operands := []string{"f", "./f", "d/f", "d/e/f", "ABS/d/f"}
	suffixes := []string{".bak", "*.bak", "pre*", "*_*", "b/*", "b/*.o", "../*", "*/x", "/x", "b/x", "pre*.o", "a*b*"}
	for _, operand := range operands {
		for _, suffix := range suffixes {
			root, cwd := realBackupScratch(t)
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
			before := realBackupWalk(root)
			words := []string{"perl", "-pi" + suffix, "-e", "s/a/b/", typed}
			cmd := exec.Command("perl", words[1:]...)
			cmd.Dir = cwd
			runErr := cmd.Run()
			made := map[string]bool{target: true}
			for path := range realBackupWalk(root) {
				if !before[path] {
					made[path] = true
				}
			}
			model := map[string]bool{}
			files, modelSuffix, ok := perlInPlace(words)
			if !ok || len(files) != 1 || files[0] != typed || modelSuffix != suffix {
				t.Fatalf("perl -pi%s: perlInPlace = %v %q %v", suffix, files, modelSuffix, ok)
			}
			for _, name := range []string{typed, starBackupName(typed, suffix)} {
				if !filepath.IsAbs(name) {
					name = filepath.Join(cwd, name)
				}
				model[filepath.Clean(name)] = true
			}
			for path := range made {
				if !model[path] {
					t.Errorf("perl -pi%s %s: perl wrote %s, model has %v", suffix, typed, path, keysOf(model))
				}
			}
			if runErr == nil {
				for path := range model {
					if !made[path] {
						t.Errorf("perl -pi%s %s: model names %s, perl did not write it (wrote %v)", suffix, typed, path, keysOf(made))
					}
				}
			}
		}
	}
}

// TestSedFollowedBackupMatchesTheRealSed runs GNU sed --follow-symlinks on
// scratch links (a relative link, a link in a folder, an absolute link, a
// chain) and holds the followed name and its backup (sedFollowedName,
// sedBackupName) to what sed wrote (rel-1-0-10:GAP-0541): GNU sed names the
// backup after the file the link leads to, built from the link text joined
// to the folder of the link. The test skips when sed is not GNU sed.
func TestSedFollowedBackupMatchesTheRealSed(t *testing.T) {
	out, err := exec.Command("sed", "--version").Output()
	if err != nil || !strings.Contains(string(out), "GNU sed") {
		t.Skip("no GNU sed")
	}
	suffixes := []string{".bak", "*.bak", "pre*", "dot/*", "../*", "*_*"}
	for _, link := range []string{"lnk", "sub/up", "abs", "chain", "dotted"} {
		for _, suffix := range suffixes {
			root, cwd := realBackupScratch(t)
			if err := os.WriteFile(filepath.Join(cwd, "target"), []byte("a\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cwd, "sub", "t2"), []byte("a\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			for name, to := range map[string]string{
				"lnk": "target", "sub/up": "../target", "abs": filepath.Join(cwd, "sub", "t2"), "chain": "lnk", "dotted": "sub/../target",
			} {
				testSymlink(t, to, filepath.Join(cwd, name))
			}
			before := realBackupWalk(root)
			cmd := exec.Command("sed", "--follow-symlinks", "-i"+suffix, "s/a/b/", link)
			cmd.Dir = cwd
			runErr := cmd.Run()
			made := map[string]bool{}
			for path := range realBackupWalk(root) {
				if !before[path] {
					made[path] = true
				}
			}
			followed, ok := sedFollowedName(link, cwd)
			if !ok {
				t.Fatalf("%s: sedFollowedName failed", link)
			}
			model := map[string]bool{}
			for _, name := range []string{followed, sedBackupName(sedGNUKind, followed, suffix)} {
				if !filepath.IsAbs(name) {
					name = cwd + "/" + name
				}
				model[filepath.Clean(name)] = true
			}
			for path := range made {
				if !model[path] {
					t.Errorf("sed --follow-symlinks -i%s %s: sed created %s, model has %v", suffix, link, path, keysOf(model))
				}
			}
			if runErr == nil {
				for path := range model {
					if _, statErr := os.Stat(path); statErr != nil {
						t.Errorf("sed --follow-symlinks -i%s %s: model names %s, sed left no such file", suffix, link, path)
					}
				}
			}
		}
	}
}
