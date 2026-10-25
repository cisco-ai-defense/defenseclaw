// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisestatus

import (
	"errors"
	"os"
	"sync"
	"time"
)

type launchDirIdentity = os.FileInfo

// launchPathLookupTimeout bounds one lookup of a directory a launch named.
// The path is the user's choice (HERMES_HOME, XDG_CONFIG_HOME, ...): one on a
// stalled network mount must not hang elevated status or verify.
var launchPathLookupTimeout = 2 * time.Second

// errLaunchPathLookupTimeout is the lookup error of a path that did not
// answer in time. The directory is not proven, so the launch stays reported.
var errLaunchPathLookupTimeout = errors.New("the directory lookup did not answer in time")

// launchPathStat is replaceable in tests.
var launchPathStat = os.Stat

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
		return nil, errLaunchPathLookupTimeout
	}
	type answer struct {
		info os.FileInfo
		err  error
	}
	done := make(chan answer, 1)
	stat := launchPathStat
	go func() {
		info, err := stat(path)
		done <- answer{info, err}
		launchPathsBlocked.Lock()
		delete(launchPathsBlocked.paths, path)
		launchPathsBlocked.Unlock()
	}()
	timer := time.NewTimer(launchPathLookupTimeout)
	defer timer.Stop()
	select {
	case got := <-done:
		return got.info, got.err
	case <-timer.C:
	}
	launchPathsBlocked.Lock()
	defer launchPathsBlocked.Unlock()
	select {
	case got := <-done:
		return got.info, got.err
	default:
		launchPathsBlocked.paths[path] = true
		return nil, errLaunchPathLookupTimeout
	}
}

func sameLaunchDirIdentity(a, b launchDirIdentity) bool {
	return a.IsDir() && b.IsDir() && os.SameFile(a, b)
}
