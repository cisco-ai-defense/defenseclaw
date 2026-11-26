// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// rel-1-0-10:GAP-1074 review 1 (Codex review r1 of s7/g1074fix-r2 38f1519dde,
// TestCXRV1074SwapBetweenGateAndRead): the share gate walked a path and the
// reader then opened the name again, so a path that was changed between the
// two to lead to a share on another machine was opened, and on Windows that
// open is the SMB contact the gate exists to prevent. The gate and the read
// are now about the same file: the read opens the path the walk resolved
// (not the name), a stat is the walk's own read of the last component, and
// a read that follows the last component holds it as the walk read it and
// refuses it when it has become a link.
//
// Each row is a reader of the gate (stat, pinned stat, open, read file, link
// resolution, folder listing, root open) on a local file or folder that the
// test changes, after the share decision, to lead to a folder the test fakes
// as a share on another machine:
//   - swap: the operand itself is moved away and a link to the share takes
//     its name (the review's row);
//   - retarget: the operand is a link to a local file, and the link is
//     pointed at the share.
//
// The change is made at one of two moments: right after the walk read the
// last component (after-walk), or when the reader hands the path to the file
// system (at-read, the review's trigger). A row passes when the reader did
// not return the share's file: it returned the local file, or refused.
// Controls read the same paths with no change and must return the local
// file. On Windows a standard user creates no symbolic link, so the file
// rows skip there and the folder rows use a junction.
func TestCXRV1074SwapBetweenGateAndRead(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(base, "remote")
	if err := os.MkdirAll(filepath.Join(remote, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remote, "file"), []byte("longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remote, "dir", "remote-marker"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	restoreShares := overrideNetworkShares(func(path string) string {
		if path == remote || strings.HasPrefix(path, remote+string(filepath.Separator)) {
			return `\\g1074-review.invalid\share`
		}
		return ""
	}, func(string) { asked.Add(1) }, func(string) bool { return false })
	defer restoreShares()

	type reader struct {
		id  string
		dir bool
		// read returns what the reader saw: the size, body, entries or final
		// name of the path, or "refused".
		read func(path string) string
	}
	statSize := func(stat func(string) (os.FileInfo, error)) func(string) string {
		return func(path string) string {
			info, err := stat(path)
			if err != nil {
				return "refused"
			}
			return map[int64]string{3: "local", 6: "share"}[info.Size()]
		}
	}
	body := func(raw []byte, err error) string {
		switch {
		case err != nil:
			return "refused"
		case string(raw) == "one":
			return "local"
		case string(raw) == "longer":
			return "share"
		}
		return "other:" + string(raw)
	}
	openBody := func(open func(string) (*os.File, error)) func(string) string {
		return func(path string) string {
			file, err := open(path)
			if err != nil {
				return "refused"
			}
			defer file.Close()
			return body(io.ReadAll(file))
		}
	}
	finalName := func(resolve func(string) (string, error)) func(string) string {
		return func(path string) string {
			resolved, err := resolve(path)
			if err != nil {
				return "refused"
			}
			if strings.HasPrefix(resolved, remote) {
				return "share"
			}
			return "local"
		}
	}
	listing := func(names []string) string {
		sort.Strings(names)
		switch strings.Join(names, ",") {
		case "local-marker":
			return "local"
		case "remote-marker":
			return "share"
		}
		return "other:" + strings.Join(names, ",")
	}
	readDir := func(list func(string) ([]os.DirEntry, error)) func(string) string {
		return func(path string) string {
			entries, err := list(path)
			if err != nil {
				return "refused"
			}
			var names []string
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			return listing(names)
		}
	}
	// Row ids name a folder each, so they differ in more than case (the
	// Windows and macOS file systems ignore case).
	readers := []reader{
		{"stat", false, statSize(pathStat)},
		{"stat-pinned", false, statSize(pathStatPinned)},
		{"export-stat", false, statSize(Stat)},
		{"open", false, openBody(pathOpen)},
		{"export-open", false, openBody(Open)},
		{"export-readfile", false, func(path string) string { return body(ReadFile(path)) }},
		{"evalsymlinks", false, finalName(pathEvalSymlinks)},
		{"export-evalsymlinks", false, finalName(EvalSymlinks)},
		{"readdir", true, readDir(pathReadDir)},
		{"export-readdir", true, readDir(ReadDir)},
		{"readdir-limit", true, readDir(func(path string) ([]os.DirEntry, error) { return pathReadDirLimit(path, 10) })},
		{"openroot", true, func(path string) string {
			root, err := pathOpenRoot(path)
			if err != nil {
				return "refused"
			}
			defer root.Close()
			entries, err := fs.ReadDir(root.FS(), ".")
			if err != nil {
				return "refused"
			}
			var names []string
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			return listing(names)
		}},
	}

	symlinks := os.Symlink(remote, filepath.Join(base, "probe-link")) == nil
	rows := 0
	for _, kind := range []string{"swap", "retarget"} {
		for _, moment := range []string{"after-walk", "at-read", "control"} {
			for _, r := range readers {
				id := kind + "/" + moment + "/" + r.id
				t.Run(id, func(t *testing.T) {
					dir := filepath.Join(base, strings.NewReplacer("/", "-").Replace(id))
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if !r.dir && !symlinks {
						t.Skip("no symbolic link here (a standard Windows user); the folder rows use a junction")
					}
					share := filepath.Join(remote, "file")
					if r.dir {
						share = filepath.Join(remote, "dir")
					}
					// local is the file the gate decides on; operand is the
					// name the reader is given.
					local := filepath.Join(dir, "local")
					if r.dir {
						if err := os.Mkdir(local, 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(local, "local-marker"), nil, 0o600); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(local, []byte("one"), 0o600); err != nil {
						t.Fatal(err)
					}
					operand := local
					if kind == "retarget" {
						operand = filepath.Join(dir, "link")
						makeSwapLink(t, local, operand, r.dir)
					}
					// change runs inside the reader (a read hook), so it records
					// its failure for the test to report after the read.
					var changed atomic.Bool
					var changeErr atomic.Value
					change := func() {
						if !changed.CompareAndSwap(false, true) {
							return
						}
						if kind == "swap" {
							if err := os.Rename(local, local+".old"); err != nil {
								// Held by the reader (Windows): it cannot be replaced.
								t.Logf("CXROW|%s|change refused: %v", id, err)
								return
							}
						} else if err := os.Remove(operand); err != nil {
							t.Logf("CXROW|%s|change refused: %v", id, err)
							return
						}
						if err := linkTo(share, operand, r.dir); err != nil {
							changeErr.Store(err.Error())
						}
					}
					forgetPlainFolders()
					switch moment {
					case "after-walk":
						restore := pathidentity.SetPinnedStatHookForTest(func(path string) {
							if path == local {
								change()
							}
						})
						defer restore()
					case "at-read":
						restore := fixturefs.ObserveForTest(func(path string) {
							if path == operand {
								change()
							}
						})
						defer restore()
					}
					got := r.read(operand)
					t.Logf("CXROW|%s|changed=%v|got=%s", id, changed.Load(), got)
					if err, _ := changeErr.Load().(string); err != "" {
						t.Fatalf("the change after the gate failed: %s", err)
					}
					switch {
					case moment == "control" && got != "local":
						t.Fatalf("control read %s, want the local file", got)
					case got == "share":
						t.Fatalf("the reader read the share's file: the path was changed after the share gate and the read opened it (changed=%v)", changed.Load())
					case got != "local" && got != "refused":
						t.Fatalf("the reader read %s, want the local file or a refusal", got)
					}
				})
				rows++
			}
		}
	}
	if rows != 72 {
		t.Fatalf("ran %d rows, want 72", rows)
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("the share on another machine was asked %d times; the gate never asks one", n)
	}
}

// makeSwapLink is linkTo for the setup of a row.
func makeSwapLink(t *testing.T, target, link string, dir bool) {
	t.Helper()
	if err := linkTo(target, link, dir); err != nil {
		t.Fatal(err)
	}
}

// linkTo makes link a symbolic link to target or, on Windows where a
// standard user makes none, a junction to a target folder.
func linkTo(target, link string, dir bool) error {
	err := os.Symlink(target, link)
	if err == nil || runtime.GOOS != "windows" || !dir {
		return err
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		return fmt.Errorf("create junction: %v: %s", err, out)
	}
	return nil
}
