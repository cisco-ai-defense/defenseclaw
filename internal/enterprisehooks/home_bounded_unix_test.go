//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// hangHomeProbes makes every probe of hung block until the test ends and
// counts the blocking calls that were started.
func hangHomeProbes(t *testing.T, hung string) *atomic.Int32 {
	t.Helper()
	release := make(chan struct{})
	var started atomic.Int32
	origCheck, origLstat, origTimeout := unixHomeCheckProbe, unixHomeLstatProbe, unixHomeProbeTimeout
	unixHomeCheckProbe = func(home string, uid int) HomeCheck {
		if filepath.Clean(home) == hung {
			started.Add(1)
			<-release
		}
		return origCheck(home, uid)
	}
	unixHomeLstatProbe = func(path string) (os.FileInfo, error) {
		if filepath.Clean(path) == hung {
			started.Add(1)
			<-release
		}
		return origLstat(path)
	}
	unixHomeProbeTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		close(release)
		// Let the released probes finish before the next test replaces the
		// package state they read.
		deadline := time.Now().Add(5 * time.Second)
		for {
			unixHomeProbesMu.Lock()
			idle := len(unixHomeProbes) == 0
			unixHomeProbesMu.Unlock()
			if idle || time.Now().After(deadline) {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		unixHomeCheckProbe, unixHomeLstatProbe, unixHomeProbeTimeout = origCheck, origLstat, origTimeout
	})
	return &started
}

func TestBoundedCheckUnixTargetHomeStartsOneProbePerHungHome(t *testing.T) {
	root := trustedTestDir(t)
	hung := makeHome(t, root, "nfs")
	started := hangHomeProbes(t, hung)
	begin := time.Now()
	for i := 0; i < 20; i++ {
		if check := BoundedCheckUnixTargetHome(hung, os.Getuid(), 50*time.Millisecond); check.State != HomePending {
			t.Fatalf("a hung home is pending: %+v", check)
		}
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("a home already known to be hung must answer at once; 20 checks took %s", elapsed)
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("a still-blocked home check must not be started again: %d blocking calls", got)
	}
	if _, err := BoundedLstat(hung, 50*time.Millisecond); !PendingTargetError(err) {
		t.Fatalf("a hung lstat must be a pending error: %v", err)
	}
	healthy := makeHome(t, root, "local")
	if check := BoundedCheckUnixTargetHome(healthy, os.Getuid(), time.Second); check.State != HomeAvailable {
		t.Fatalf("a healthy home is unaffected: %+v", check)
	}
}

// A hung home stalled the whole enumerator: the manifest was never
// republished while the process stayed alive.
func TestEnumerateUnixDoesNotStallOnAHungHome(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	nfs := makeHome(t, homes, "nfsuser")
	local := makeHome(t, homes, "localuser")
	started := hangHomeProbes(t, nfs)
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			"nfsuser":   {Name: "nfsuser", UID: uid, GID: gid, Home: nfs, Shell: "/bin/bash"},
			"localuser": {Name: "localuser", UID: uid, GID: gid, Home: local, Shell: "/bin/bash"},
		},
		listed: []string{"nfsuser", "localuser"},
	}
	opts := UnixEnumerateOptions{
		Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"codex": "0.150.0"}, nil, nil
		},
	}
	type outcome struct {
		manifest Manifest
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		manifest, _, err := EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), opts)
		done <- outcome{manifest, err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if len(got.manifest.Targets) != 1 || got.manifest.Targets[0].User != "localuser" {
			t.Fatalf("the healthy user must still be enrolled: %+v", got.manifest.Targets)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the enumerator stalled on a hung home")
	}
	if got := started.Load(); got > 2 {
		t.Fatalf("one blocking check and one owner-scan lstat at most, got %d", got)
	}
}
