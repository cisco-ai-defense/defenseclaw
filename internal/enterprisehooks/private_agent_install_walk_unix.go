// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// privateInstallWalkDefaultMaxEntries is the home walk's entry bound on
// Linux and macOS. Real developer homes are far larger than the 524,288 the
// walk first allowed, so every developer account was reported NOT COVERED
// (agent_install_scan_incomplete, home_unreadable). Measured 2026-10-26: a
// developer Mac lists 1.92 million entries outside its privacy-protected
// folders and 0.64 million once the tool-owned trees below are pruned, and
// the macOS 15 GitHub runner account failed the 1.0.4 release upgrade gate
// on the same bound. 2,097,152 leaves that pruned home three times its
// size. The walk reads directory entries only, never their metadata
// (120,630 entries of an EC2 Mac home took 0.43 s), and the scan deadline
// still bounds its time: a home it cannot list in time stays incomplete.
const privateInstallWalkDefaultMaxEntries = 1 << 21

// unixPrivateWalkPrunedHomeTrees are trees below a home, by path from the
// home, that the walk does not list: language toolchains and the package
// stores and caches their own tools manage. npm never installs a runnable
// prefix there, and together they are most of a developer home (on a
// developer Mac: the Go module cache 257,148 entries, the pnpm store
// 100,079, uv's Pythons 100,282). An agent copied into one of them on
// purpose is not found, as one copied anywhere outside node_modules is not
// found: application control covers that.
var unixPrivateWalkPrunedHomeTrees = append([]string{
	"go/pkg/mod", ".cargo/registry", ".cargo/git", ".rustup", ".gradle", ".m2/repository",
	".nuget/packages", ".dotnet", ".npm/_cacache", ".bun/install/cache",
	".local/share/pnpm/store", ".local/share/uv",
}, unixPrivateWalkPlatformPrunedHomeTrees...)

// unixPrivateWalkCacheRoots hold data an app can recreate (the XDG cache
// folder, and ~/Library/Caches on macOS). The walk lists them but enters
// only pnpm's folder, whose dlx cache holds runnable npm installs ("pnpm
// dlx @openai/codex"); npx keeps its own in ~/.npm/_npx, which is walked.
// The rest (uv, pip, Homebrew, browsers, build caches) are the largest
// trees of a developer home: on the Mac above ~/Library/Caches held 341,064
// entries and ~/.cache/uv 341,008.
var unixPrivateWalkCacheRoots = append([]string{".cache"}, unixPrivateWalkPlatformCacheRoots...)

const unixPrivateWalkCacheKept = "pnpm"

// errPrivateWalkPruned is the open of a pruned tree: it hides nothing the
// walk inspects, so the walk stays complete.
var errPrivateWalkPruned = errors.New("the walk does not list this tool-owned tree")

// unixHomeRelative is dir as a path below home, and false for home itself
// and for a path outside it. A folder of home whose name starts with ".."
// (such as "..cache") is below home.
func unixHomeRelative(home, dir string) (string, bool) {
	rel, err := filepath.Rel(home, filepath.Clean(dir))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// unixPrivateWalkPruned reports a folder of home the walk does not list:
// a pruned tree, a cache other than pnpm's, or a version-control store
// (.git) at any depth. fold compares the names without case, as the home's
// volume does (unixHomeCaseInsensitive).
func unixPrivateWalkPruned(home, dir string, fold bool) bool {
	rel, ok := unixHomeRelative(home, dir)
	if !ok {
		return false
	}
	rel = filepath.ToSlash(rel)
	same := func(a, b string) bool {
		if fold {
			return strings.EqualFold(a, b)
		}
		return a == b
	}
	name := path.Base(rel)
	if same(name, ".git") {
		return true
	}
	for _, tree := range unixPrivateWalkPrunedHomeTrees {
		if same(rel, tree) {
			return true
		}
	}
	parent := path.Dir(rel)
	for _, root := range unixPrivateWalkCacheRoots {
		if same(parent, root) && !same(name, unixPrivateWalkCacheKept) {
			return true
		}
	}
	return false
}

// unixPrivateWalkOpenTimeout bounds one directory open of the home walk.
// Tests lower it.
var unixPrivateWalkOpenTimeout = 3 * time.Second

// unixPrivateWalkOpenFile is the open the home walk makes. Tests replace it.
var unixPrivateWalkOpenFile = os.Open

// errPrivateWalkOpenTimedOut is a directory open that did not return within
// unixPrivateWalkOpenTimeout: the walk is then incomplete, never clean.
var errPrivateWalkOpenTimedOut = errors.New("the folder did not open in time")

// unixPrivateWalkOpener is the open of the Unix home walk below home.
//
// A system call that never returns never observes the scan's context. On
// macOS an open() of a folder the privacy controls (TCC) protect, such as
// ~/Desktop, ~/Documents or ~/Downloads, waits for a decision no one can give
// to a background worker, so a managed reinstall timed out every discovery
// worker and left the supported installed Hermes unenrolled (GAP-1413).
// Those folders are not opened: they are treated as the walk treats a
// privacy denial (EPERM), which hides nothing DefenseClaw could inspect
// without Full Disk Access. Any other open that does not return in time (a
// hung network mount, a privacy-protected folder not on the list) makes the
// walk incomplete; its goroutine closes the folder if the open returns later.
func unixPrivateWalkOpener(home string) func(string) (*os.File, error) {
	home = filepath.Clean(home)
	// Read once, before the walk starts its goroutines: an open that is
	// abandoned at the timeout can still start after the walk returned.
	openFile, timeout := unixPrivateWalkOpenFile, unixPrivateWalkOpenTimeout
	fold := unixHomeCaseInsensitive(home)
	return func(dir string) (*os.File, error) {
		if unixPrivateWalkPrivacyProtected(home, dir) {
			return nil, &os.PathError{Op: "open", Path: dir, Err: syscall.EPERM}
		}
		if unixPrivateWalkPruned(home, dir, fold) {
			return nil, &os.PathError{Op: "open", Path: dir, Err: errPrivateWalkPruned}
		}
		type opened struct {
			f   *os.File
			err error
		}
		result := make(chan opened, 1)
		abandoned := make(chan struct{})
		go func() {
			f, err := openFile(dir)
			select {
			case result <- opened{f, err}:
			case <-abandoned:
				if f != nil {
					_ = f.Close()
				}
			}
		}()
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case r := <-result:
			return r.f, r.err
		case <-timer.C:
			close(abandoned)
			select {
			case r := <-result:
				// It returned as the timer fired.
				return r.f, r.err
			default:
			}
			return nil, fmt.Errorf("open %s: %w", dir, errPrivateWalkOpenTimedOut)
		}
	}
}

// unixPrivateWalkPrivacyProtected reports a folder of home that
// unixPrivacyProtectedHomeFolders names, compared as the case-insensitive
// macOS file system does.
func unixPrivateWalkPrivacyProtected(home, dir string) bool {
	rel, ok := unixHomeRelative(home, dir)
	if !ok {
		return false
	}
	for _, protected := range unixPrivacyProtectedHomeFolders {
		if strings.EqualFold(rel, protected) {
			return true
		}
	}
	return false
}
