// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisestatus

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A directory a launch names on a stalled mount must not hang status or
// verify: the lookup gives up, the launch stays reported, later sessions
// naming the same path do not wait again, and the path is looked up again
// once it answers.
func TestLaunchPathLookupIsBounded(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	stalled := filepath.Join(t.TempDir(), "nfs", "config")
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	oldStat, oldTimeout := launchPathStat, launchPathLookupTimeout
	launchPathStat = func(path string) (os.FileInfo, error) {
		if path == stalled {
			mu.Lock()
			calls++
			mu.Unlock()
			<-release
		}
		return os.Stat(path)
	}
	launchPathLookupTimeout = 100 * time.Millisecond
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		launchPathStat, launchPathLookupTimeout = oldStat, oldTimeout
	})
	env := map[string]string{"HOME": home, "XDG_CONFIG_HOME": stalled}
	check := func(label string) string {
		t.Helper()
		done := make(chan string, 1)
		go func() { done <- PluginLaunchCoverage("amp", []string{"amp"}, env, true, home) }()
		select {
		case reason := <-done:
			return reason
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: launch coverage did not answer 5s after a 100ms lookup bound", label)
			return ""
		}
	}
	if reason := check("first session"); reason != "amp_plugin_config_relocated" {
		t.Fatalf("a launch whose config directory cannot be looked up must stay reported, got %q", reason)
	}
	started := time.Now()
	if reason := check("second session"); reason != "amp_plugin_config_relocated" {
		t.Fatalf("second session: got %q", reason)
	}
	mu.Lock()
	if calls != 1 || time.Since(started) > time.Second {
		mu.Unlock()
		t.Fatalf("a path still blocked must not be looked up again: %d lookups, second check took %s", calls, time.Since(started))
	}
	mu.Unlock()
	// Once the mount answers, the path is looked up again.
	close(release)
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for {
		launchPathsBlocked.Lock()
		blocked := launchPathsBlocked.paths[stalled]
		launchPathsBlocked.Unlock()
		if !blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the path stayed marked blocked after its lookup returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reason := check("after the mount answers"); reason != "amp_plugin_config_relocated" {
		t.Fatalf("a missing XDG directory elsewhere is still relocated, got %q", reason)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("the path must be looked up again once it answers: %d lookups", calls)
	}
}
