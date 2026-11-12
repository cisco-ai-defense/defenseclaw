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

// cowork-1-0-8 GAP-0067: the first client exec after a gateway start can
// reach the host plane while the helper still reads its image, with the
// version and no digest (state pending). Its record waits within the cold
// hold's bounds for the digest the helper sends once the read ends, and is
// dropped only when that digest is one the signed manifest lists. Every
// other end records it.
func TestPendingClientDigestIsAwaited(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	signed, unsigned := hex.EncodeToString(release[:]), hex.EncodeToString(other[:])
	const prompt = `/sessions/cwk-v1/.local/bin/claude -p use @modelcontextprotocol/server-filesystem`
	at := time.Unix(1_760_000_000, 0)
	digestOf := func(pid int, when time.Time, version, sum string, state plane.DigestState) plane.Event {
		return plane.Event{Kind: plane.KindImageDigest, PID: pid, At: when, ImageVersion: version,
			ImageSHA256: sum, ImageDigestState: state}
	}
	read := func(sum string) plane.Event { return digestOf(500, at, "2.1.317", sum, plane.DigestRead) }
	for _, tc := range []struct {
		name          string
		cmdline       string
		state         plane.DigestState
		later         []plane.Event // after the exec
		manifestLate  bool          // the manifest is cached only after the digest
		fullCold      bool
		keepClientMCP bool
		heldAtFirst   bool
		atOnce        bool // decided right after the last later event
		want          int64
		dropped       int64
	}{
		{"digest listed, manifest cached", prompt, plane.DigestPending,
			[]plane.Event{read(signed)}, false, false, false, true, true, 0, 1},
		{"digest listed, manifest comes after it", prompt, plane.DigestPending,
			[]plane.Event{read(signed)}, true, false, false, true, false, 0, 1},
		{"digest the manifest does not list", prompt, plane.DigestPending,
			[]plane.Event{read(unsigned)}, false, false, false, true, true, 1, 0},
		{"read failed", prompt, plane.DigestPending,
			[]plane.Event{digestOf(500, at, "2.1.317", "", plane.DigestFailed)}, false, false, false, true, true, 1, 0},
		{"no digest before the hold ends", prompt, plane.DigestPending, nil, false, false, false, true, false, 1, 0},
		{"digest of another exec of the pid", prompt, plane.DigestPending,
			[]plane.Event{digestOf(500, at.Add(time.Second), "2.1.317", signed, plane.DigestRead)}, false, false, false, true, false, 1, 0},
		{"digest of another pid", prompt, plane.DigestPending,
			[]plane.Event{digestOf(501, at, "2.1.317", signed, plane.DigestRead)}, false, false, false, true, false, 1, 0},
		{"digest for another version", prompt, plane.DigestPending,
			[]plane.Event{digestOf(500, at, "2.1.318", signed, plane.DigestRead)}, false, false, false, true, false, 1, 0},
		{"later exec of the pid replaces the hold", prompt, plane.DigestPending, []plane.Event{
			{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: prompt, At: at.Add(time.Second),
				ImageVersion: "2.1.317", ImageDigestState: plane.DigestPending},
			digestOf(500, at.Add(time.Second), "2.1.317", signed, plane.DigestRead),
		}, false, false, false, true, true, 1, 1},
		{"holds full", prompt, plane.DigestPending, nil, false, true, false, false, true, 1, 0},
		{"digest not coming", prompt, plane.DigestFailed, nil, false, false, false, false, true, 1, 0},
		{"helper that predates the state", prompt, "", nil, false, false, false, false, true, 1, 0},
		{"Secure Client profile", prompt, plane.DigestPending, nil, false, false, true, false, true, 1, 0},
		{"credential read in the client's arguments", prompt + " then cat /home/u/.aws/credentials",
			plane.DigestPending, nil, false, false, false, false, true, 1, 0},
		{"client starts a positional server", `claude @modelcontextprotocol/server-filesystem /w`,
			plane.DigestPending, nil, false, false, false, false, true, 1, 0},
	} {
		t.Run(tc.name, bubbled(func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.coldHold, host.coldPoll = 80*time.Millisecond, 5*time.Millisecond
			host.indicators.KeepClientMCP = tc.keepClientMCP
			var cached atomic.Bool
			cached.Store(!tc.manifestLate)
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
			host.mu.Unlock()
			uid := os.Getuid() + 1000
			host.handle(plane.Event{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: tc.cmdline,
				UID: &uid, At: at, ImageVersion: "2.1.317", ImageDigestState: tc.state})
			classified, _, _, _ := host.stats()
			if held := classified == 0; held != tc.heldAtFirst {
				t.Fatalf("classified=%d right after the exec, want held=%t", classified, tc.heldAtFirst)
			}
			for _, event := range tc.later {
				if event.Kind == plane.KindExec {
					event.UID = &uid
				}
				host.handle(event)
			}
			if tc.atOnce {
				if classified, _, _, _ = host.stats(); classified != tc.want {
					t.Fatalf("classified=%d right after the digest, want %d", classified, tc.want)
				}
			}
			if tc.manifestLate {
				cached.Store(true)
			}
			time.Sleep(3 * host.coldHold)
			classified, _, _, _ = host.stats()
			host.mu.Lock()
			held := len(host.coldClients)
			if tc.fullCold {
				held -= maxHeldWrappers
			}
			host.mu.Unlock()
			if classified != tc.want || held != 0 {
				t.Fatalf("classified=%d held=%d, want %d and 0", classified, held, tc.want)
			}
			if dropped := host.clientExecs.digestDropped.Load(); dropped != tc.dropped {
				t.Fatalf("pending records dropped = %d, want %d", dropped, tc.dropped)
			}
		}))
	}
}

// cowork-1-0-8 GAP-0067 as the live run named it: the first client exec
// after a gateway start carries its digest (state read), the release
// manifest is not cached when the exec is classified, and the fetch that
// lookup started ends before the hold is taken. The client is then decided
// with the manifest now cached, not recorded because it was not cached a
// moment earlier.
func TestManifestCachedDuringTheClientExecIsUsed(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	const prompt = `/sessions/cwk-v1/.local/bin/claude -p use @modelcontextprotocol/server-filesystem`
	for _, tc := range []struct {
		name   string
		digest [32]byte
		want   int64
	}{
		{"manifest lists the image", release, 0},
		{"manifest does not list the image", other, 1},
	} {
		t.Run(tc.name, bubbled(func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.coldHold, host.coldPoll = time.Hour, time.Hour
			var lookups atomic.Int64
			host.clientChecksums = func(string) ([][32]byte, bool) {
				// The first lookup starts the fetch; it is in by the next.
				if lookups.Add(1) == 1 {
					return nil, false
				}
				return [][32]byte{release}, true
			}
			uid := os.Getuid() + 1000
			host.handle(plane.Event{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: prompt, UID: &uid,
				ImageVersion: "2.1.317", ImageSHA256: hex.EncodeToString(tc.digest[:]), ImageDigestState: plane.DigestRead})
			classified, _, _, _ := host.stats()
			host.mu.Lock()
			held := len(host.coldClients)
			host.mu.Unlock()
			if classified != tc.want || held != 0 {
				t.Fatalf("classified=%d held=%d right after the exec, want %d and 0", classified, held, tc.want)
			}
		}))
	}
}

// cowork-1-0-8 GAP-0067, the cause: the helper read the fork event of the
// client's process after the child exec'd, so that event already carried the
// client image, its digest and argv; the exec's own event followed for the
// same pid. With the manifest not cached yet (the first client exec after a
// gateway start) both were held, and the second hold recorded the first as
// a replaced exec. A current helper flags the fork
// (TestForkOfAClientIsNeverAClientExec); from a helper that predates the
// flag (no digest state either) the same exec seen twice waits as one
// record, and two real execs (another argv, image, exec id or start time)
// never merge.
func TestClientExecSeenTwiceWaitsAsOneRecord(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	other := sha256.Sum256([]byte("another program"))
	signed, unsigned := hex.EncodeToString(release[:]), hex.EncodeToString(other[:])
	const prompt = `/sessions/cwk-v1/.local/bin/claude -p use @modelcontextprotocol/server-filesystem`
	for _, tc := range []struct {
		name             string
		cmdline, digest  string
		state            plane.DigestState
		execIDs          [2]string
		starts           [2]int64
		want, duplicates int64
	}{
		{"fork read after the exec, then the exec (old helper)", prompt, signed, "", [2]string{}, [2]int64{}, 0, 1},
		{"same exec id and start time (old helper)", prompt, signed, "", [2]string{"e1", "e1"}, [2]int64{7, 7}, 0, 1},
		{"a later exec of the pid with other arguments", prompt + " again", signed, "", [2]string{}, [2]int64{}, 1, 0},
		{"a later exec of the pid with another image", prompt, unsigned, "", [2]string{}, [2]int64{}, 2, 0},
		{"two execs with other exec ids", prompt, signed, "", [2]string{"e1", "e2"}, [2]int64{}, 1, 0},
		{"two execs with other start times", prompt, signed, "", [2]string{}, [2]int64{7, 8}, 1, 0},
		{"a current helper's two unflagged execs", prompt, signed, plane.DigestRead, [2]string{}, [2]int64{}, 1, 0},
	} {
		t.Run(tc.name, bubbled(func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.coldHold, host.coldPoll = 300*time.Millisecond, 5*time.Millisecond
			var cached atomic.Bool
			host.clientChecksums = func(string) ([][32]byte, bool) {
				if !cached.Load() {
					return nil, false
				}
				return [][32]byte{release}, true
			}
			uid := os.Getuid() + 1000
			at := time.Unix(1_760_000_000, 0)
			for i, e := range []struct{ cmdline, digest string }{{prompt, signed}, {tc.cmdline, tc.digest}} {
				host.handle(plane.Event{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: e.cmdline,
					UID: &uid, At: at.Add(time.Duration(i) * time.Millisecond), ImageVersion: "2.1.317",
					ImageSHA256: e.digest, ImageDigestState: tc.state, ExecID: tc.execIDs[i], StartNS: tc.starts[i]})
			}
			time.Sleep(50 * time.Millisecond)
			cached.Store(true)
			time.Sleep(2 * host.coldHold)
			classified, _, _, _ := host.stats()
			host.mu.Lock()
			held := len(host.coldClients)
			host.mu.Unlock()
			if classified != tc.want || held != 0 || host.clientExecs.duplicates.Load() != tc.duplicates {
				t.Fatalf("classified=%d held=%d duplicates=%d, want %d, 0, %d",
					classified, held, host.clientExecs.duplicates.Load(), tc.want, tc.duplicates)
			}
		}))
	}
}

// cowork-1-0-8 GAP-0067 at the source: a current helper flags the kernel's
// fork, so the fork of a process into or out of a Claude release image is
// never a client exec of its own: never classified, never held. The exec
// that follows is the one that counts, also while its digest is pending
// (review 2 N2: no merge needed). The tracker still learns the fork.
func TestForkOfAClientIsNeverAClientExec(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	signed := hex.EncodeToString(release[:])
	const prompt = `/sessions/cwk-v1/.local/bin/claude -p use @modelcontextprotocol/server-filesystem`
	at := time.Unix(1_760_000_000, 0)
	for _, tc := range []struct {
		name    string
		events  []plane.Event
		cached  bool // the manifest is cached from the start
		want    int64
		replace int64
	}{
		{"fork read after the exec, then the exec, digest pending", []plane.Event{
			{Kind: plane.KindExec, Fork: true, PID: 500, PPID: 1, Name: "claude", Cmdline: prompt, At: at,
				ImageVersion: "2.1.317", ImageDigestState: plane.DigestFailed},
			{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: prompt, At: at.Add(time.Millisecond),
				ImageVersion: "2.1.317", ImageDigestState: plane.DigestPending},
			{Kind: plane.KindImageDigest, PID: 500, At: at.Add(time.Millisecond), ImageVersion: "2.1.317",
				ImageSHA256: signed, ImageDigestState: plane.DigestRead},
		}, true, 0, 0},
		{"fork read after the exec, manifest not cached yet", []plane.Event{
			{Kind: plane.KindExec, Fork: true, PID: 500, PPID: 1, Name: "claude", Cmdline: prompt, At: at,
				ImageVersion: "2.1.317", ImageSHA256: signed, ImageDigestState: plane.DigestRead},
			{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: prompt, At: at.Add(time.Millisecond),
				ImageVersion: "2.1.317", ImageSHA256: signed, ImageDigestState: plane.DigestRead},
		}, false, 0, 0},
		{"a fork alone, digest read, manifest not cached: never held", []plane.Event{
			{Kind: plane.KindExec, Fork: true, PID: 500, PPID: 1, Name: "claude", Cmdline: prompt, At: at,
				ImageVersion: "2.1.317", ImageSHA256: signed, ImageDigestState: plane.DigestRead},
		}, false, 0, 0},
	} {
		t.Run(tc.name, bubbled(func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.coldHold, host.coldPoll = 300*time.Millisecond, 5*time.Millisecond
			var cached atomic.Bool
			cached.Store(tc.cached)
			host.clientChecksums = func(string) ([][32]byte, bool) {
				if !cached.Load() {
					return nil, false
				}
				return [][32]byte{release}, true
			}
			uid := os.Getuid() + 1000
			for _, event := range tc.events {
				if event.Kind == plane.KindExec {
					event.UID = &uid
				}
				host.handle(event)
				if event.Fork {
					host.mu.Lock()
					held := len(host.coldClients)
					host.mu.Unlock()
					if classified, _, _, _ := host.stats(); classified != 0 || held != 0 {
						t.Fatalf("fork: classified=%d held=%d, want 0 and 0", classified, held)
					}
				}
			}
			time.Sleep(50 * time.Millisecond)
			cached.Store(true)
			time.Sleep(2 * host.coldHold)
			classified, _, _, _ := host.stats()
			host.mu.Lock()
			held := len(host.coldClients)
			host.mu.Unlock()
			if classified != tc.want || held != 0 || host.clientExecs.replaced.Load() != tc.replace ||
				host.clientExecs.forks.Load() != 1 {
				t.Fatalf("classified=%d held=%d replaced=%d forks=%d, want %d, 0, %d, 1", classified, held,
					host.clientExecs.replaced.Load(), host.clientExecs.forks.Load(), tc.want, tc.replace)
			}
			if _, attributed := host.tracker.Lineage(500, ""); !attributed {
				t.Fatal("the tracker lost the fork's lineage")
			}
		}))
	}
}

// S1 review 3 F2: the Secure Client profile classifies a client's own argv,
// so a flagged fork is classified there as before.
func TestForkIsStillClassifiedUnderSecureClient(t *testing.T) {
	host := newHost(newFake(fullCoverage()))
	host.indicators.KeepClientMCP = true
	uid := os.Getuid() + 1000
	host.handle(plane.Event{Kind: plane.KindExec, Fork: true, PID: 500, PPID: 1, Name: "claude", UID: &uid,
		Cmdline:      `/sessions/cwk-v1/.local/bin/claude -p use @modelcontextprotocol/server-filesystem`,
		ImageVersion: "2.1.317", ImageDigestState: plane.DigestFailed})
	if classified, _, _, _ := host.stats(); classified != 1 || host.clientExecs.forks.Load() != 0 {
		t.Fatalf("classified=%d forks skipped=%d, want 1 and 0", classified, host.clientExecs.forks.Load())
	}
}

// A wrapper whose client child is waiting for its image digest waits with
// it: both are dropped when the signed manifest lists the digest, and both
// are recorded when the read fails.
func TestWrapperOfAPendingClientWaitsForItsDigest(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	const client = `/sessions/cwk-v1/.local/bin/claude -p --dangerously-skip-permissions Add a project-scoped MCP server named docs running npx -y @modelcontextprotocol/server-filesystem`
	at := time.Unix(1_760_000_000, 0)
	for _, tc := range []struct {
		name  string
		state plane.DigestState
		sum   string
		want  int64
	}{
		{"digest listed", plane.DigestRead, hex.EncodeToString(release[:]), 0},
		// The wrapper, its fork and the client.
		{"read failed", plane.DigestFailed, "", 3},
	} {
		t.Run(tc.name, bubbled(func(t *testing.T) {
			host := newHost(newFake(fullCoverage()))
			host.wrapperHold = 20 * time.Millisecond
			host.coldHold, host.coldPoll = 300*time.Millisecond, 5*time.Millisecond
			host.clientChecksums = func(version string) ([][32]byte, bool) {
				return [][32]byte{release}, version == "2.1.317"
			}
			uid := os.Getuid() + 1000
			for _, event := range []plane.Event{
				{Kind: plane.KindExec, PID: 500, PPID: 1, Name: "claude", Cmdline: "claude"},
				{Kind: plane.KindExec, PID: 501, PPID: 500, Name: "timeout", Cmdline: "timeout 300 " + client},
				{Kind: plane.KindExec, PID: 502, PPID: 501, Name: "timeout", Cmdline: "timeout 300 " + client},
				{Kind: plane.KindExec, PID: 502, PPID: 501, Name: "claude", Cmdline: client,
					ImageVersion: "2.1.317", ImageDigestState: plane.DigestPending},
			} {
				event.UID, event.At = &uid, at
				host.handle(event)
			}
			time.Sleep(4 * host.wrapperHold)
			if classified, _, _, _ := host.stats(); classified != 0 {
				t.Fatalf("classified=%d past the wrapper hold, want all held", classified)
			}
			host.handle(plane.Event{Kind: plane.KindImageDigest, PID: 502, At: at, ImageVersion: "2.1.317",
				ImageSHA256: tc.sum, ImageDigestState: tc.state})
			classified, _, _, _ := host.stats()
			host.mu.Lock()
			wrappers, cold, linked := len(host.wrappers), len(host.coldClients), host.linkedWrappers
			host.mu.Unlock()
			if classified != tc.want || wrappers != 0 || cold != 0 || linked != 0 {
				t.Fatalf("classified=%d held wrappers=%d cold=%d linked=%d, want %d and 0, 0, 0",
					classified, wrappers, cold, linked, tc.want)
			}
		}))
	}
}

// The counters name the digest state of the client execs a live run saw,
// and of the ones it recorded.
func TestClientExecCountsByDigestState(t *testing.T) {
	release := sha256.Sum256([]byte("claude release image"))
	host := newHost(newFake(fullCoverage()))
	host.coldHold = 0
	host.clientChecksums = func(string) ([][32]byte, bool) { return [][32]byte{release}, true }
	uid := os.Getuid() + 1000
	at := time.Unix(1_760_000_000, 0)
	const prompt = `claude -p use @modelcontextprotocol/server-filesystem`
	for i, state := range []plane.DigestState{plane.DigestRead, plane.DigestFailed, "", plane.DigestPending} {
		sum := ""
		if state == plane.DigestRead {
			sum = hex.EncodeToString(release[:])
		}
		host.handle(plane.Event{Kind: plane.KindExec, PID: 500 + i, PPID: 1, Name: "claude", Cmdline: prompt,
			UID: &uid, At: at, ImageVersion: "2.1.317", ImageSHA256: sum, ImageDigestState: state})
	}
	want := map[string]int64{"read": 1, "failed": 1, "failed_reported": 1, "unstated": 1, "unstated_reported": 1,
		"pending": 1, "pending_reported": 1}
	got := host.clientExecs.counts()
	if len(got) != len(want) {
		t.Fatalf("counts %v, want %v", got, want)
	}
	for name, value := range want {
		if got[name] != value {
			t.Fatalf("counts %v, want %v", got, want)
		}
	}
}
