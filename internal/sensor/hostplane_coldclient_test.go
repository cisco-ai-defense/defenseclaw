// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// cowork-1-0-8 GAP-0065: the first client exec of a version after a gateway
// start finds its release manifest not cached; the fetch starts on that exec.
// Its record waits for the manifest and is dropped only when the signed
// manifest lists the image digest. A failed fetch, a digest the manifest does
// not list, the Secure Client profile and a client the identity would not
// lift are reported.
func TestColdClientExecWaitsForTheReleaseManifest(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	const prompt = `/sessions/cwk-v1/.local/bin/claude -p use @modelcontextprotocol/server-filesystem`
	for _, tc := range []struct {
		name          string
		cmdline       string
		digest        [32]byte
		fetched       bool // the manifest arrives during the hold
		keepClientMCP bool
		heldAtFirst   bool
		want          int64
	}{
		{"manifest arrives and lists the image", prompt, release, true, false, true, 0},
		{"manifest arrives without the image", prompt, other, true, false, true, 1},
		{"fetch fails", prompt, release, false, false, true, 1},
		{"Secure Client profile", prompt, release, true, true, false, 1},
		{"client starts a positional server", `claude @modelcontextprotocol/server-filesystem /w`, release, true, false, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.coldHold, host.coldPoll = 60*time.Millisecond, 5*time.Millisecond
			host.indicators.KeepClientMCP = tc.keepClientMCP
			var cached atomic.Bool
			host.clientChecksums = func(version string) ([][32]byte, bool) {
				if version != "2.1.317" || !cached.Load() {
					return nil, false
				}
				return [][32]byte{release}, true
			}
			uid := os.Getuid() + 1000
			host.handle(plane.Event{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: tc.cmdline,
				UID: &uid, ImageSHA256: hex.EncodeToString(tc.digest[:]), ImageVersion: "2.1.317"})
			classified, _, _, _ := host.stats()
			if held := classified == 0; held != tc.heldAtFirst {
				t.Fatalf("classified=%d right after the exec, want held=%t", classified, tc.heldAtFirst)
			}
			if tc.fetched {
				cached.Store(true)
			}
			time.Sleep(4 * host.coldHold)
			classified, _, _, _ = host.stats()
			host.mu.Lock()
			held := len(host.coldClients)
			host.mu.Unlock()
			if classified != tc.want || held != 0 {
				t.Fatalf("classified=%d held=%d, want %d and 0", classified, held, tc.want)
			}
		})
	}
}

// A signed manifest already cached decides at once: no record is held.
func TestWarmClientExecIsNotHeld(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	host := newHost(newFake(fullCoverage()))
	host.coldHold = time.Hour
	host.clientChecksums = func(string) ([][32]byte, bool) { return [][32]byte{release}, true }
	uid := os.Getuid() + 1000
	host.handle(plane.Event{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude",
		Cmdline: `claude -p use @modelcontextprotocol/server-filesystem`, UID: &uid,
		ImageSHA256: hex.EncodeToString(release[:]), ImageVersion: "2.1.317"})
	host.mu.Lock()
	held := len(host.coldClients)
	host.mu.Unlock()
	if classified, _, _, _ := host.stats(); classified != 0 || held != 0 {
		t.Fatalf("classified=%d held=%d, want 0 and 0", classified, held)
	}
}
