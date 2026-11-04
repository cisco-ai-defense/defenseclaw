// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// R108-COWORK-3 (cowork-1-0-8 GAP-0006): a Claude Code client whose own
// arguments name an MCP package is a client, not a local MCP server, and the
// host plane decides that from the exec event alone. The gateway in the
// Cowork VM is unprivileged and the sessions run as other accounts, and on
// Windows the record is read a poll after the exec, so these events name a
// pid that does not exist, an image under an unreadable home and another
// account: only the digest the source read at exec time identifies the image.
func TestClaudeClientClassifiesFromExecTimeImageDigest(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	sessionUID := os.Getuid() + 1000
	for _, tc := range []struct {
		name, cmdline, digest, version string
		keepClientMCP                  bool
		classified                     int64
	}{
		{"print prompt", `claude -p "use @modelcontextprotocol/server-filesystem"`, hex.EncodeToString(release[:]), "2.1.317", false, 0},
		{"configuration values", `claude --mcp-config first.json mcp_server.json`, hex.EncodeToString(release[:]), "2.1.317", false, 0},
		{"positional server twin", `claude @modelcontextprotocol/server-filesystem /workspace`, hex.EncodeToString(release[:]), "2.1.317", false, 1},
		{"other image", `claude -p "use @modelcontextprotocol/server-filesystem"`, hex.EncodeToString(other[:]), "2.1.317", false, 1},
		{"image not read", `claude -p "use @modelcontextprotocol/server-filesystem"`, "", "", false, 1},
		{"release of another version", `claude -p "use @modelcontextprotocol/server-filesystem"`, hex.EncodeToString(release[:]), "2.1.318", false, 1},
		{"Secure Client profile", `claude -p "use @modelcontextprotocol/server-filesystem"`, hex.EncodeToString(release[:]), "2.1.317", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.indicators.KeepClientMCP = tc.keepClientMCP
			host.clientChecksums = func(version string) ([][32]byte, bool) {
				if version != "2.1.317" {
					return nil, false
				}
				return [][32]byte{release}, true
			}
			host.handle(plane.Event{
				Kind: plane.KindExec, PID: 1 << 30, PPID: 1,
				// The process name is the parent's: identity is the digest.
				Name: "indicator-task", Exe: "/sessions/cwk-v1/.local/share/claude/versions/" + tc.version,
				Cmdline: tc.cmdline, UID: &sessionUID, At: time.Unix(1_760_000_000, 0),
				ImageSHA256: tc.digest, ImageVersion: tc.version,
			})
			classified, _, _, _ := host.stats()
			if classified != tc.classified {
				t.Fatalf("classified=%d, want %d", classified, tc.classified)
			}
		})
	}
}

// R108-COWORK-3 review 1: the manifest lookup never runs on the event
// consumer. A burst of execs naming versions that were never released, with a
// fetch that does not return, must not delay unrelated events; each is
// classified as before (detection fires) and only a bounded number of fetches
// start.
func TestForgedClientVersionsNeverStallTheHostPlane(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	block := make(chan struct{})
	var fetches atomic.Int32
	manifests := newReleaseManifests(func(string) ([][32]byte, bool) {
		fetches.Add(1)
		<-block
		return nil, false
	})
	defer func() {
		close(block)
		manifests.fetches.Wait()
	}()
	host := newHost(newFake(fullCoverage()))
	host.clientChecksums = manifests.checksums
	uid := os.Getuid() + 1000
	started := time.Now()
	for i := range 200 {
		version := fmt.Sprintf("9.%d.%d", i/100, i%100)
		host.handle(plane.Event{
			Kind: plane.KindExec, PID: 1<<30 + i, PPID: 1, Name: version,
			Cmdline: `claude -p "use @modelcontextprotocol/server-filesystem"`, UID: &uid,
			ImageSHA256: hex.EncodeToString(release[:]), ImageVersion: version,
		})
	}
	host.handle(plane.Event{Kind: plane.KindExec, PID: 1<<30 + 500, PPID: 1, Name: "cat",
		Cmdline: "cat /home/u/.aws/credentials", UID: &uid})
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("201 events took %v with the manifest fetch blocked", elapsed)
	}
	if classified, _, _, _ := host.stats(); classified < 200 || host.handled.Load() != 201 {
		t.Fatalf("classified=%d handled=%d, want the 200 forged versions reported as servers and 201 handled",
			classified, host.handled.Load())
	}
	// The blocking fetch is reached (in the background), and bounded.
	for deadline := time.Now().Add(2 * time.Second); fetches.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if got := fetches.Load(); got < 1 || got > maxManifestFetches {
		t.Fatalf("%d fetches started, want 1..%d", got, maxManifestFetches)
	}
}

func TestReleaseManifestsCacheSignedVersionsAndBoundFailures(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	now := time.Unix(1_800_000_000, 0)
	var calls atomic.Int32
	manifests := newReleaseManifests(func(version string) ([][32]byte, bool) {
		calls.Add(1)
		if version == "2.1.317" {
			return [][32]byte{release}, true
		}
		return nil, false
	})
	manifests.now = func() time.Time { return now }
	if _, ok := manifests.checksums("2.1.317"); ok {
		t.Fatal("an uncached version was answered before its manifest was fetched")
	}
	manifests.fetches.Wait()
	if checksums, ok := manifests.checksums("2.1.317"); !ok || !signedClaudeRelease(hex.EncodeToString(release[:]), checksums) {
		t.Fatalf("signed version not cached: %v %t", checksums, ok)
	}
	for i := range 3 * maxFailedManifests {
		now = now.Add(unknownManifestInterval)
		manifests.checksums(fmt.Sprintf("9.9.%d", i))
		manifests.fetches.Wait()
	}
	if manifests.failed.Len() != maxFailedManifests || len(manifests.failedAt) != maxFailedManifests {
		t.Fatalf("failed versions cached = %d, want %d", manifests.failed.Len(), maxFailedManifests)
	}
	// A failed version is not fetched again before its retry time, and an
	// unknown one waits for the rate limit.
	last := fmt.Sprintf("9.9.%d", 3*maxFailedManifests-1)
	now = now.Add(unknownManifestInterval)
	before := calls.Load()
	manifests.checksums(last)
	manifests.fetches.Wait()
	if calls.Load() != before {
		t.Fatal("a failed version was fetched again before its retry time")
	}
	manifests.checksums("9.8.1")
	manifests.checksums("9.8.2")
	manifests.fetches.Wait()
	if got := calls.Load() - before; got != 1 {
		t.Fatalf("%d unknown versions fetched within one interval, want 1", got)
	}
}
