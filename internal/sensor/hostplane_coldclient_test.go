// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// bubbled runs a hold test in a synctest bubble. The hold timers, polls and
// sleeps use the bubble's fake clock, which moves only when every goroutine
// of the test is blocked, so a loaded runner cannot end a hold before the
// test's events are handled or after its sleep (r108-sensorflake: the 20 ms
// wrapper hold ran out between two execs on CI).
func bubbled(f func(t *testing.T)) func(t *testing.T) {
	return func(t *testing.T) { synctest.Test(t, f) }
}

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
		t.Run(tc.name, bubbled(func(t *testing.T) {
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
		}))
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

// cowork-1-0-8 GAP-0055 after a gateway start: the wrapped client's release
// manifest is not cached when its exec settles the held wrapper. The wrapper
// waits with the client's cold hold and follows its outcome: dropped only
// when the signed manifest lists the client image, recorded on every other
// way the hold ends.
func TestWrapperOfAColdClientWaitsForItsManifest(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	signed, unsigned := hex.EncodeToString(release[:]), hex.EncodeToString(other[:])
	const client = `/sessions/cwk-v1/.local/bin/claude -p --dangerously-skip-permissions Add a project-scoped MCP server named docs running npx -y @modelcontextprotocol/server-filesystem`
	type exec struct {
		pid, ppid     int
		name, cmdline string
		digest        string
	}
	const agent, wrapper, child = 500, 501, 502
	timeoutFork := []exec{
		{wrapper, agent, "timeout", "timeout 300 " + client, ""},
		{child, wrapper, "timeout", "timeout 300 " + client, ""},
		{child, wrapper, "claude", client, signed},
	}
	for _, tc := range []struct {
		name          string
		execs         []exec
		fetched       bool // the manifest arrives during the hold
		fullCold      bool // maxHeldWrappers other cold clients are held already
		fullWrappers  bool // maxHeldWrappers other wrappers are held already
		keepClientMCP bool
		heldAtFirst   bool // nothing recorded before the manifest is in
		want          int64
	}{
		{"timeout fork, manifest lists the image", timeoutFork, true, false, false, false, true, 0},
		{"nice in place, manifest lists the image", []exec{
			{wrapper, agent, "nice", "nice -n 10 " + client, ""},
			{wrapper, agent, "claude", client, signed},
		}, true, false, false, false, true, 0},
		{"manifest does not list the image", []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, ""},
			{child, wrapper, "claude", client, unsigned},
		}, true, false, false, false, true, 2},
		// The fork record and the wrapper are both recorded with the client.
		{"fetch fails", timeoutFork, false, false, false, false, true, 3},
		{"cold holds full", []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, ""},
			{child, wrapper, "claude", client, signed},
		}, true, true, false, false, false, 2},
		{"wrapper holds full", []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, ""},
			{child, wrapper, "claude", client, signed},
		}, true, false, true, false, false, 1},
		{"child argv is not the tail", []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, ""},
			{child, wrapper, "claude", client + " --extra", signed},
		}, true, false, false, false, false, 1},
		{"Secure Client profile", []exec{
			{wrapper, agent, "timeout", "timeout 300 " + client, ""},
			{child, wrapper, "claude", client, signed},
		}, true, false, false, true, false, 2},
		{"timeout 300 nice chain, manifest lists the image", []exec{
			{wrapper, agent, "timeout", "timeout 300 nice " + client, ""},
			{child, wrapper, "timeout", "timeout 300 nice " + client, ""},
			{child, wrapper, "nice", "nice " + client, ""},
			{child, wrapper, "claude", client, signed},
		}, true, false, false, false, true, 0},
		{"timeout 300 nice chain, fetch fails", []exec{
			{wrapper, agent, "timeout", "timeout 300 nice " + client, ""},
			{child, wrapper, "timeout", "timeout 300 nice " + client, ""},
			{child, wrapper, "nice", "nice " + client, ""},
			{child, wrapper, "claude", client, signed},
		}, false, false, false, false, true, 4},
	} {
		t.Run(tc.name, bubbled(func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			// The wrapper's own hold is shorter than the time the manifest
			// takes: a linked wrapper waits for the client, not its timer.
			// The bubble's clock stands still while the execs are handled, so
			// the wrapper hold cannot end before its child links it.
			host.wrapperHold = 20 * time.Millisecond
			host.coldHold, host.coldPoll = 300*time.Millisecond, 5*time.Millisecond
			host.indicators.KeepClientMCP = tc.keepClientMCP
			var cached atomic.Bool
			host.clientChecksums = func(version string) ([][32]byte, bool) {
				if version != "2.1.317" || !cached.Load() {
					return nil, false
				}
				return [][32]byte{release}, true
			}
			host.mu.Lock()
			if tc.fullCold {
				host.coldClients = make(map[int]*heldWrapper)
				for i := range maxHeldWrappers {
					host.coldClients[10_000+i] = &heldWrapper{timer: time.NewTimer(time.Hour)}
				}
			}
			if tc.fullWrappers {
				host.wrappers = make(map[int]*heldWrapper)
				for i := range maxHeldWrappers {
					host.wrappers[20_000+i] = &heldWrapper{cmdline: "x", tail: "y", timer: time.NewTimer(time.Hour)}
				}
			}
			host.mu.Unlock()
			uid := os.Getuid() + 1000
			host.handle(plane.Event{Kind: plane.KindExec, PID: agent, PPID: 1, Name: "claude", Cmdline: "claude", UID: &uid})
			for _, e := range tc.execs {
				version := ""
				if e.digest != "" {
					version = "2.1.317"
				}
				host.handle(plane.Event{Kind: plane.KindExec, PID: e.pid, PPID: e.ppid, Name: e.name, Cmdline: e.cmdline,
					UID: &uid, ImageSHA256: e.digest, ImageVersion: version})
			}
			time.Sleep(4 * host.wrapperHold)
			classified, _, _, _ := host.stats()
			if held := classified == 0; held != tc.heldAtFirst {
				t.Fatalf("classified=%d past the wrapper hold, want held=%t", classified, tc.heldAtFirst)
			}
			if tc.fetched {
				cached.Store(true)
			}
			time.Sleep(2 * host.coldHold)
			classified, _, _, _ = host.stats()
			host.mu.Lock()
			wrappers, cold, linked := len(host.wrappers), len(host.coldClients), host.linkedWrappers
			if tc.fullWrappers {
				wrappers -= maxHeldWrappers
			}
			if tc.fullCold {
				cold -= maxHeldWrappers
			}
			host.mu.Unlock()
			if classified != tc.want || wrappers != 0 || cold != 0 || linked != 0 {
				t.Fatalf("classified=%d held wrappers=%d cold=%d linked=%d, want %d and 0, 0, 0",
					classified, wrappers, cold, linked, tc.want)
			}
		}))
	}
}
