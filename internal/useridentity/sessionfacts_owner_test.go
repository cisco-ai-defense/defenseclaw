// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A FILE or DIR cache named by the user must belong to that user before its
// principal is used as a session claim.
func TestCredentialCacheFileRequiresEffectiveOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krb5cc")
	if err := os.WriteFile(path, []byte{5, 4, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !regularFileOwnedByUID(info, os.Geteuid()) {
		t.Fatal("own regular cache was rejected")
	}
	if regularFileOwnedByUID(info, os.Geteuid()+1) {
		t.Fatal("another user cache was accepted")
	}
}

// GAP-0582: a credential cache on a mount that stopped answering costs one
// hook a short bound, not the whole session-facts deadline, and the hooks
// after it send the session variables alone without touching the cache.
func TestSessionFactsSkipAStalledCredentialCache(t *testing.T) {
	// The session-facts cache, where a stalled read is remembered, lives in
	// the DefenseClaw folder, which the cache no longer creates (GAP-0654).
	sessionFactsHomeForTest(t)
	t.Setenv("KRB5CCNAME", "FILE:/stalled-mount/krb5cc")
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.1 22")
	t.Setenv("SSH_TTY", "")
	t.Setenv("XDG_SESSION_ID", "")
	var stats atomic.Int32
	previous := ccacheStat
	t.Cleanup(func() { ccacheStat = previous })
	// The stat never returns, like one on a stopped sshfs mount.
	ccacheStat = func(string) (os.FileInfo, error) {
		stats.Add(1)
		select {}
	}
	now := time.Now()
	for call := 1; call <= 2; call++ {
		started := time.Now()
		got := currentSessionFactsHeader(now)
		if elapsed := time.Since(started); elapsed >= 2*time.Second {
			t.Fatalf("call %d waited %v on the stalled credential cache", call, elapsed)
		}
		if got != "v1;k=ssh;ca=192.0.2.10" {
			t.Fatalf("call %d: header = %q, want the SSH facts alone", call, got)
		}
	}
	if n := stats.Load(); n != 1 {
		t.Fatalf("the credential cache was stat'ed %d times, want once", n)
	}
}

// GAP-0582: a KCM that accepts and never answers (a hung sssd-kcm) costs one
// hook at most the session-facts bound, which leaves managed OpenCode (about
// 1.8 s of its own) inside the 3.5 s hook answer budget; the hooks after it
// do not ask the KCM again.
func TestSessionFactsBoundAHungKCM(t *testing.T) {
	// The session-facts cache, where a stalled read is remembered, lives in
	// the DefenseClaw folder, which the cache no longer creates (GAP-0654).
	sessionFactsHomeForTest(t)
	t.Setenv("KRB5CCNAME", "KCM:")
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.1 22")
	t.Setenv("SSH_TTY", "")
	t.Setenv("XDG_SESSION_ID", "")
	socket := filepath.Join(t.TempDir(), "kcm")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("no unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	previous := kcmSocketPaths
	t.Cleanup(func() { kcmSocketPaths = previous })
	kcmSocketPaths = []string{socket}
	now := time.Now()
	for call, bound := range []time.Duration{1500 * time.Millisecond, 200 * time.Millisecond} {
		started := time.Now()
		got := currentSessionFactsHeader(now)
		if elapsed := time.Since(started); elapsed >= bound {
			t.Fatalf("call %d waited %v on the hung KCM, want under %v", call+1, elapsed, bound)
		}
		if got != "v1;k=ssh;ca=192.0.2.10" {
			t.Fatalf("call %d: header = %q, want the SSH facts alone", call+1, got)
		}
	}
	if n := accepted.Load(); n != 1 {
		t.Fatalf("the KCM was asked %d times, want once", n)
	}
}

// The krb5.conf read (and every include it names) is inside the session-facts
// bound: an include on a stalled path costs one hook the bound, and the hooks
// after it do not read the file again.
func TestSessionFactsBoundAStalledKrb5Conf(t *testing.T) {
	// The session-facts cache, where a stalled read is remembered, lives in
	// the DefenseClaw folder, which the cache no longer creates (GAP-0654).
	sessionFactsHomeForTest(t)
	t.Setenv("KRB5CCNAME", "")
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.1 22")
	t.Setenv("SSH_TTY", "")
	t.Setenv("XDG_SESSION_ID", "")
	var reads atomic.Int32
	previous := krb5ConfDefaultCCache
	t.Cleanup(func() { krb5ConfDefaultCCache = previous })
	krb5ConfDefaultCCache = func() string {
		reads.Add(1)
		time.Sleep(4 * time.Second)
		return ""
	}
	now := time.Now()
	for call := 1; call <= 2; call++ {
		started := time.Now()
		got := currentSessionFactsHeader(now)
		if elapsed := time.Since(started); elapsed >= 1500*time.Millisecond {
			t.Fatalf("call %d waited %v on the stalled krb5.conf", call, elapsed)
		}
		if got != "v1;k=ssh;ca=192.0.2.10" {
			t.Fatalf("call %d: header = %q, want the SSH facts alone", call, got)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("krb5.conf was read %d times, want once", n)
	}
}

// sessionFactsHomeForTest points HOME at a new folder with the DefenseClaw
// folder an installed account has.
func sessionFactsHomeForTest(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".defenseclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
}
