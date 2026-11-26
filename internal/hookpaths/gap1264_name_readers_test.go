// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// rel-1-0-10:GAP-1264 (1): ReadRegularFileBounded read the name again after
// the share decision (safefile.ReadRegularFileBounded(name)), not the path
// the gate read. A folder link above the operand that the walk resolved to
// a local folder, and that is pointed at a share on another machine after
// the walk (after-walk) or when the reader hands the path on (at-read), was
// followed: the share's file was read. The read is now the gate's read; a
// name the walk read through a link is refused before anything opens it.
// The test fakes the share as TestCXRV1074SwapBetweenGateAndRead does. A
// name with no link on the way is read as before.
func TestGAP1264ReadRegularFileBoundedReadsTheGatedPath(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(base, "remote")
	if err := os.MkdirAll(filepath.Join(remote, "tree", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remote, "tree", "sub", "file"), []byte("longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	restoreShares := overrideNetworkShares(func(path string) string {
		if path == remote || strings.HasPrefix(path, remote+string(filepath.Separator)) {
			return `\\g1264-review.invalid\share`
		}
		return ""
	}, func(string) { asked.Add(1) }, func(string) bool { return false })
	defer restoreShares()
	read := func(path string) string {
		raw, err := ReadRegularFileBounded(path, 1<<10)
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
	for _, kind := range []string{"ancestor-link", "plain"} {
		for _, moment := range []string{"after-walk", "at-read", "control"} {
			id := kind + "/" + moment
			t.Run(id, func(t *testing.T) {
				dir := filepath.Join(base, strings.ReplaceAll(id, "/", "-"))
				tree := filepath.Join(dir, "tree")
				if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o700); err != nil {
					t.Fatal(err)
				}
				local := filepath.Join(tree, "sub", "file")
				if err := os.WriteFile(local, []byte("one"), 0o600); err != nil {
					t.Fatal(err)
				}
				operand := local
				link := filepath.Join(dir, "link")
				if kind == "ancestor-link" {
					makeSwapLink(t, tree, link, true)
					operand = filepath.Join(link, "sub", "file")
				}
				var changed atomic.Bool
				var changeErr atomic.Value
				change := func() {
					if kind != "ancestor-link" || !changed.CompareAndSwap(false, true) {
						return
					}
					if err := os.Remove(link); err != nil {
						t.Logf("GAP1264ROW|%s|change refused: %v", id, err)
						return
					}
					if err := linkTo(filepath.Join(remote, "tree"), link, true); err != nil {
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
						if path == operand || path == local {
							change()
						}
					})
					defer restore()
				}
				got := read(operand)
				t.Logf("GAP1264ROW|%s|changed=%v|got=%s", id, changed.Load(), got)
				if err, _ := changeErr.Load().(string); err != "" {
					t.Fatalf("the change after the gate failed: %s", err)
				}
				switch {
				case got == "share":
					t.Fatalf("ReadRegularFileBounded read the share's file through a link pointed at it after the share gate (changed=%v)", changed.Load())
				case kind == "plain" && got != "local":
					t.Fatalf("a name with no link on the way read %s, want the local file", got)
				case got != "local" && got != "refused":
					t.Fatalf("read %s, want the local file or a refusal", got)
				}
			})
		}
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("the share on another machine was asked %d times; the gate never asks one", n)
	}
}
