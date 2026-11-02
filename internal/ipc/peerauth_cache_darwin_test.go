// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package ipc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const signedCodesignOutput = "Executable=/usr/local/bin/client\nIdentifier=com.cisco.secureclient.gui\nTeamIdentifier=DE8Y96K9QP\n"

func stubCodesignLookup(t *testing.T, key *peerProcessKey, outputs ...func() ([]byte, bool)) (*int, *[]string) {
	t.Helper()
	calls := 0
	previousRun, previousIdentity, previousSink := runCodesign, peerProcessIdentity, managed.ReportResilienceEvent
	runCodesign = func(int32) ([]byte, bool) {
		next := outputs[len(outputs)-1]
		if calls < len(outputs) {
			next = outputs[calls]
		}
		calls++
		return next()
	}
	peerProcessIdentity = func(pid int32) (peerProcessKey, bool) {
		k := *key
		k.pid = pid
		return k, true
	}
	var events []string
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		events = append(events, managed.FormatResilienceEvent(marker, fields))
	}
	t.Cleanup(func() {
		runCodesign, peerProcessIdentity, managed.ReportResilienceEvent = previousRun, previousIdentity, previousSink
	})
	return &calls, &events
}

func signed() ([]byte, bool)   { return []byte(signedCodesignOutput), false }
func timedOut() ([]byte, bool) { return nil, true }

func TestPeerCodesignCacheReusesIdentityPerProcessStart(t *testing.T) {
	key := peerProcessKey{startSec: 100, comm: "client"}
	calls, _ := stubCodesignLookup(t, &key, signed)
	cache := &peerCodesignCache{now: time.Now}

	for i := 0; i < 3; i++ {
		team, signing, _, _, _ := cache.read(42)
		if team != "DE8Y96K9QP" || signing != "com.cisco.secureclient.gui" {
			t.Fatalf("identity = %q %q", team, signing)
		}
	}
	if *calls != 1 {
		t.Fatalf("codesign ran %d times, want once for one process image", *calls)
	}
	key.startSec = 200 // pid reused by a new process
	cache.read(42)
	if *calls != 2 {
		t.Fatalf("a reused pid was served from the cache (calls = %d)", *calls)
	}
	key.comm = "other" // exec in the same process
	cache.read(42)
	if *calls != 3 {
		t.Fatalf("an exec'd process was served from the cache (calls = %d)", *calls)
	}
	key.exe = "/tmp/other/" + key.comm // exec of a different binary with the same basename
	cache.read(42)
	if *calls != 4 {
		t.Fatalf("a same-named exec was served from the cache (calls = %d)", *calls)
	}
	key.exeIno++ // the file at the same path was replaced
	cache.read(42)
	if *calls != 5 {
		t.Fatalf("a replaced executable was served from the cache (calls = %d)", *calls)
	}
}

func TestPeerProcessIdentityOnlyKeysImmutableExecutables(t *testing.T) {
	// This test binary lives in a user-owned temp folder: anyone who owns
	// that folder could swap the file, so the process is never keyed.
	if _, ok := peerProcessIdentity(int32(os.Getpid())); ok {
		t.Fatal("an executable on a user-writable path was keyed")
	}
	path, ok := peerExecutablePath(int32(os.Getpid()))
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfInfo, _ := os.Stat(self)
	pathInfo, statErr := os.Stat(path)
	if !ok || statErr != nil || !os.SameFile(selfInfo, pathInfo) {
		t.Fatalf("kern.procargs2 path = %q (%v), want this test binary %q", path, statErr, self)
	}
	if st, ok := peerImmutableExecutable("/bin/ls"); !ok || st.Ino == 0 {
		t.Fatal("a root-owned system binary was not accepted")
	}
	link := filepath.Join(t.TempDir(), "ls")
	if err := os.Symlink("/bin/ls", link); err != nil {
		t.Fatal(err)
	}
	if _, ok := peerImmutableExecutable(link); ok {
		t.Fatal("a symlinked executable path was accepted")
	}
}

func TestPeerCodesignCacheExpires(t *testing.T) {
	key := peerProcessKey{startSec: 100, comm: "client"}
	calls, _ := stubCodesignLookup(t, &key, signed)
	now := time.Now()
	cache := &peerCodesignCache{now: func() time.Time { return now }}
	cache.read(42)
	now = now.Add(peerCodesignCacheTTL + time.Second)
	cache.read(42)
	if *calls != 2 {
		t.Fatalf("an expired identity was reused (calls = %d)", *calls)
	}
}

func TestPeerCodesignLookupRetriesTimeoutOnce(t *testing.T) {
	key := peerProcessKey{startSec: 100, comm: "client"}
	calls, events := stubCodesignLookup(t, &key, timedOut, signed)
	cache := &peerCodesignCache{now: time.Now}
	team, _, _, _, _ := cache.read(42)
	if team != "DE8Y96K9QP" || *calls != 2 {
		t.Fatalf("team = %q after %d calls, want the retried identity", team, *calls)
	}
	if len(*events) != 0 {
		t.Fatalf("a recovered timeout was logged as degraded: %v", *events)
	}
}

func TestPeerCodesignLookupDoubleTimeoutStaysEmptyAndLogsOncePerStreak(t *testing.T) {
	key := peerProcessKey{startSec: 100, comm: "client"}
	calls, events := stubCodesignLookup(t, &key, timedOut)
	cache := &peerCodesignCache{now: time.Now}
	for i := 0; i < 2; i++ {
		team, signing, _, _, _ := cache.read(42)
		if team != "" || signing != "" {
			t.Fatalf("a timed-out lookup produced an identity: %q %q", team, signing)
		}
	}
	if *calls != 4 {
		t.Fatalf("calls = %d, want one retry per lookup and nothing cached", *calls)
	}
	if len(*events) != 1 || !strings.Contains((*events)[0], "codesign_timeout") {
		t.Fatalf("events = %v, want one codesign_timeout line", *events)
	}
}

func TestPeerCodesignCacheSkipsUnsignedPeers(t *testing.T) {
	key := peerProcessKey{startSec: 100, comm: "client"}
	calls, _ := stubCodesignLookup(t, &key, func() ([]byte, bool) { return []byte("Executable=/tmp/x\n"), false })
	cache := &peerCodesignCache{now: time.Now}
	cache.read(42)
	cache.read(42)
	if *calls != 2 {
		t.Fatalf("an empty identity was cached (calls = %d)", *calls)
	}
}
