// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// rel-1-0-10:GAP-1263: a FOLDER ABOVE the operand (one or two levels up)
// renamed away and replaced by a junction to a share on another machine,
// after the share walk read the path (after-walk) or when the reader hands
// the path to the file system (at-read). The hold covered only the last
// component and opened the path by name, so after-walk the swapped folder
// was followed and the share's file read. The hold now opens the path once
// following no link on the way: a folder that became a link is refused, and
// while the hold is open no folder above can be renamed (at-read: the
// change is refused). A row passes when the reader did not return the
// share's file. The share is faked as in TestCXRV1074SwapBetweenGateAndRead.
func TestGAP1263FolderAboveSwappedBetweenGateAndRead(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(base, "remote")
	if err := os.MkdirAll(filepath.Join(remote, "tree", "sub", "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remote, "tree", "sub", "file"), []byte("longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remote, "tree", "sub", "d", "remote-marker"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	restoreShares := overrideNetworkShares(func(path string) string {
		if path == remote || strings.HasPrefix(path, remote+string(filepath.Separator)) {
			return `\\g1263-review.invalid\share`
		}
		return ""
	}, func(string) { asked.Add(1) }, func(string) bool { return false })
	defer restoreShares()

	body := func(raw []byte, err error) string {
		switch {
		case err != nil:
			return "refused"
		case string(raw) == "one":
			return "local"
		case string(raw) == "longer":
			return "share"
		}
		return "other"
	}
	listing := func(entries []os.DirEntry, err error) string {
		if err != nil {
			return "refused"
		}
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		switch strings.Join(names, ",") {
		case "local-marker":
			return "local"
		case "remote-marker":
			return "share"
		}
		return "other"
	}
	readers := []struct {
		id   string
		dir  bool
		read func(string) string
	}{
		{"stat-pinned", false, func(p string) string {
			info, err := pathStatPinned(p)
			if err != nil {
				return "refused"
			}
			return map[int64]string{3: "local", 6: "share"}[info.Size()]
		}},
		{"open", false, func(p string) string {
			file, err := pathOpen(p)
			if err != nil {
				return "refused"
			}
			defer file.Close()
			return body(io.ReadAll(file))
		}},
		{"export-readfile", false, func(p string) string { return body(ReadFile(p)) }},
		{"readbounded", false, func(p string) string { return body(ReadRegularFileBounded(p, 1<<10)) }},
		{"readdir", true, func(p string) string { return listing(pathReadDir(p)) }},
	}
	for _, level := range []string{"above1", "above2"} {
		for _, moment := range []string{"after-walk", "at-read", "control"} {
			for _, r := range readers {
				id := level + "/" + moment + "/" + r.id
				t.Run(id, func(t *testing.T) {
					dir := filepath.Join(base, strings.ReplaceAll(id, "/", "-"))
					sub := filepath.Join(dir, "tree", "sub")
					if err := os.MkdirAll(filepath.Join(sub, "d"), 0o700); err != nil {
						t.Fatal(err)
					}
					local := filepath.Join(sub, "file")
					if err := os.WriteFile(local, []byte("one"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(sub, "d", "local-marker"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
					operand := local
					if r.dir {
						operand = filepath.Join(sub, "d")
					}
					swapped, target := sub, filepath.Join(remote, "tree", "sub")
					if level == "above2" {
						swapped, target = filepath.Join(dir, "tree"), filepath.Join(remote, "tree")
					}
					var changed atomic.Bool
					var changeErr atomic.Value
					change := func() {
						if !changed.CompareAndSwap(false, true) {
							return
						}
						if err := os.Rename(swapped, swapped+"-away"); err != nil {
							t.Logf("GAP1263ROW|%s|change refused", id)
							return
						}
						if err := linkTo(target, swapped, true); err != nil {
							changeErr.Store(err.Error())
						}
					}
					forgetPlainFolders()
					switch moment {
					case "after-walk":
						restore := pathidentity.SetPinnedStatHookForTest(func(path string) {
							if path == operand {
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
					t.Logf("GAP1263ROW|%s|changed=%v|got=%s", id, changed.Load(), got)
					if err, _ := changeErr.Load().(string); err != "" {
						t.Fatalf("the change failed: %s", err)
					}
					switch {
					case got == "share":
						t.Fatalf("%s read the share's file through a folder swapped for a link after the share gate (changed=%v)", r.id, changed.Load())
					case moment == "control" && got != "local":
						t.Fatalf("control read %s, want the local file", got)
					case got != "local" && got != "refused":
						t.Fatalf("read %s, want the local file or a refusal", got)
					}
				})
			}
		}
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("the share on another machine was asked %d times; the gate never asks one", n)
	}
}
