// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisestatus

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// launchDirIdentity is a directory's device and inode.
type launchDirIdentity struct {
	dev, ino uint64
	dir      bool
}

// launchPathLookupTimeout bounds one lookup of a directory a launch named.
// The path is the user's choice (HERMES_HOME, XDG_CONFIG_HOME, ...): one on a
// stalled network mount must not hang elevated status or verify.
var launchPathLookupTimeout = 2 * time.Second

// errLaunchPathLookupTimeout is the lookup error of a path that did not
// answer in time. The directory is not proven, so the launch stays reported.
var errLaunchPathLookupTimeout = errors.New("the directory lookup did not answer in time")

// launchPathStat looks a path up. Replaceable in tests.
var launchPathStat = lookupLaunchPathOutOfProcess

// launchPathStatProgram is the system stat(1) the lookup runs. A lookup on a
// stalled FUSE or NFS mount blocks in the kernel and cannot be interrupted:
// made by a thread of status or verify, it kept the process from exiting
// after it had printed its answer (GAP-1714). Made by a child, only the
// child is stuck; status stops waiting for it and exits. Replaceable in
// tests; when it is missing the lookup runs in this process.
var launchPathStatProgram = "/usr/bin/stat"

// launchPathsBlocked holds the paths whose lookup timed out and has not
// returned yet: a status run with many sessions naming one stalled mount
// waits for it once, and the path is looked up again once it answers.
var launchPathsBlocked = struct {
	sync.Mutex
	paths map[string]bool
}{paths: map[string]bool{}}

func statLaunchPath(path string) (launchDirIdentity, error) {
	launchPathsBlocked.Lock()
	blocked := launchPathsBlocked.paths[path]
	launchPathsBlocked.Unlock()
	if blocked {
		return launchDirIdentity{}, errLaunchPathLookupTimeout
	}
	type answer struct {
		id  launchDirIdentity
		err error
	}
	done := make(chan answer, 1)
	stat := launchPathStat
	go func() {
		id, err := stat(path)
		done <- answer{id, err}
		launchPathsBlocked.Lock()
		delete(launchPathsBlocked.paths, path)
		launchPathsBlocked.Unlock()
	}()
	timer := time.NewTimer(launchPathLookupTimeout)
	defer timer.Stop()
	select {
	case got := <-done:
		return got.id, got.err
	case <-timer.C:
	}
	launchPathsBlocked.Lock()
	defer launchPathsBlocked.Unlock()
	select {
	case got := <-done:
		return got.id, got.err
	default:
		launchPathsBlocked.paths[path] = true
		return launchDirIdentity{}, errLaunchPathLookupTimeout
	}
}

// lookupLaunchPathOutOfProcess follows links as os.Stat does, in a stat(1)
// child (launchPathStatProgram). Its caller (statLaunchPath) stops waiting
// at launchPathLookupTimeout; a child stuck in the kernel is left behind
// and never holds this process.
func lookupLaunchPathOutOfProcess(path string) (launchDirIdentity, error) {
	if info, err := os.Lstat(launchPathStatProgram); err != nil || !info.Mode().IsRegular() {
		return lookupLaunchPathInProcess(path)
	}
	format := []string{"-L", "-c", "%d %i %f", "--", path}
	if runtime.GOOS == "darwin" {
		format = []string{"-L", "-f", "%d %i %Xp", "--", path}
	}
	cmd := exec.Command(launchPathStatProgram, format...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		text := stderr.String()
		switch {
		case strings.Contains(text, "No such file or directory"):
			return launchDirIdentity{}, &fs.PathError{Op: "stat", Path: path, Err: syscall.ENOENT}
		case strings.Contains(text, "Not a directory"):
			return launchDirIdentity{}, &fs.PathError{Op: "stat", Path: path, Err: syscall.ENOTDIR}
		}
		return launchDirIdentity{}, fmt.Errorf("stat %s: %w", path, err)
	}
	id, err := parseLaunchPathStat(stdout.String())
	if errors.Is(err, errLaunchPathStatLink) {
		// BSD stat -L falls back to lstat for a dangling link and answers
		// with the link itself; os.Stat and GNU stat give ENOENT (GAP-1754).
		return launchDirIdentity{}, &fs.PathError{Op: "stat", Path: path, Err: syscall.ENOENT}
	}
	return id, err
}

// errLaunchPathStatLink is the answer of a followed lookup that names a
// link: the link leads nowhere.
var errLaunchPathStatLink = errors.New("the followed lookup answered with a link")

// parseLaunchPathStat reads "device inode mode", the mode in hexadecimal.
func parseLaunchPathStat(out string) (launchDirIdentity, error) {
	fields := strings.Fields(out)
	if len(fields) != 3 {
		return launchDirIdentity{}, fmt.Errorf("unexpected stat output %q", out)
	}
	dev, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return launchDirIdentity{}, fmt.Errorf("unexpected stat device %q", fields[0])
	}
	ino, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return launchDirIdentity{}, fmt.Errorf("unexpected stat inode %q", fields[1])
	}
	mode, err := strconv.ParseUint(fields[2], 16, 32)
	if err != nil {
		return launchDirIdentity{}, fmt.Errorf("unexpected stat mode %q", fields[2])
	}
	if mode&syscall.S_IFMT == syscall.S_IFLNK {
		return launchDirIdentity{}, errLaunchPathStatLink
	}
	return launchDirIdentity{dev: dev, ino: ino, dir: mode&syscall.S_IFMT == syscall.S_IFDIR}, nil
}

func lookupLaunchPathInProcess(path string) (launchDirIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return launchDirIdentity{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return launchDirIdentity{}, fmt.Errorf("stat %s: no device and inode", path)
	}
	// Dev is int32 on darwin and uint64 on Linux.
	dev, err := strconv.ParseUint(fmt.Sprint(st.Dev), 10, 64)
	if err != nil {
		return launchDirIdentity{}, fmt.Errorf("stat %s: device %v", path, st.Dev)
	}
	return launchDirIdentity{dev: dev, ino: st.Ino, dir: info.IsDir()}, nil
}

func sameLaunchDirIdentity(a, b launchDirIdentity) bool {
	return a.dir && b.dir && a.dev == b.dev && a.ino == b.ino
}
