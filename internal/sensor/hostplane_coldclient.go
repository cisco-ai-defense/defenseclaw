// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

const (
	// coldClientHold is how long the record of a client exec waits for its
	// release manifest when that is not cached yet (cowork-1-0-8 GAP-0065),
	// or for its image digest when the source was still reading the image
	// as the exec's event went out (GAP-0067). The manifest is fetched on
	// that exec, in the background, within releaseManifests' bounds: one
	// fetch of 3 s at most, spaced by unknownManifestInterval. The digest
	// comes in a KindImageDigest event once the source's read ends (about
	// 1.5 s for a release image). A manifest or digest still missing when
	// the hold ends leaves the exec reported.
	coldClientHold = 8 * time.Second
	// coldClientPoll is how often a held record looks at the cache.
	coldClientPoll = 250 * time.Millisecond
)

// holdColdClientLocked keeps the record of an attributed exec of a Claude
// release image that the verified client would not be reported for, while
// what identifies it is not in yet: the release manifest of its version
// (not cached), or its image digest (the source says the read is pending).
// The record is dropped only when its digest is in and the signed manifest
// lists it. Every other end records it: a digest the manifest does not list,
// a read that failed, a fetch that failed, no digest or manifest before the
// hold ends, a later exec of the same pid. An exec whose source says no
// digest is coming (failed, or a source that predates the state) is never
// held. The gateway cannot prefetch the manifest at start: in the Cowork VM
// it runs unprivileged and cannot list the session homes, and the image
// prewarm runs in the root helper. It returns the held record, which held
// wrapper records of this exec can be linked to, or nil when the record is
// to be made now.
func (h *hostPlane) holdColdClientLocked(
	event plane.Event, lineage agentchain.Lineage, match tactics.Match, at time.Time, instance agentchain.Instance,
	observation tactics.Observation,
) *heldWrapper {
	if h.coldHold <= 0 || event.Kind != plane.KindExec || event.PID <= 0 || h.indicators.KeepClientMCP ||
		h.clientChecksums == nil || !plane.IsClaudeReleaseVersion(event.ImageVersion) ||
		len(h.coldClients) >= maxHeldWrappers {
		return nil
	}
	// An exec with a digest is held even when the manifest is cached by
	// now: the fetch the classification's lookup started can end before
	// this runs, and returning here recorded the very client that cached
	// manifest verifies (GAP-0067: the first client exec after a gateway
	// start, digest read, recorded). The caller decides such a hold at once
	// with settleColdClientLocked.
	if event.ImageSHA256 == "" && event.ImageDigestState != plane.DigestPending {
		return nil
	}
	observation.ClaudeClient = true
	if _, ok := tactics.Classify(observation, h.indicators); ok {
		return nil
	}
	pid := event.PID
	if previous := h.coldClients[pid]; previous != nil {
		if sameClientExecOfAnOldHelper(previous, event) {
			// The same exec seen twice (GAP-0067): the event of a fork
			// that the source read after the child exec'd carries the
			// exec's own image and argv, and the exec's event follows.
			// One record waits; this one is not made. A current helper
			// flags the fork, which never reaches the hold.
			h.clientExecs.duplicates.Add(1)
			return previous
		}
		h.clientExecs.replaced.Add(1)
		h.releaseColdClientLocked(pid, previous)
	}
	if h.coldClients == nil {
		h.coldClients = make(map[int]*heldWrapper)
	}
	held := &heldWrapper{event: event, lineage: lineage, match: match, at: at, instance: instance,
		digest: event.ImageSHA256}
	deadline := time.Now().Add(h.coldHold)
	var check func()
	check = func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.coldClients[pid] != held {
			return
		}
		if !h.settleColdClientLocked(pid, held, !time.Now().Before(deadline)) {
			held.timer = time.AfterFunc(h.coldPoll, check)
		}
	}
	held.timer = time.AfterFunc(h.coldPoll, check)
	h.coldClients[pid] = held
	return held
}

// settleColdClientLocked ends a held client record that can be decided: it
// is dropped when its digest is in and the cached signed manifest lists it,
// and recorded when the manifest is cached without it or the hold is over.
// It reports whether the hold ended.
func (h *hostPlane) settleColdClientLocked(pid int, held *heldWrapper, over bool) bool {
	if held.digest != "" {
		checksums, cached := h.clientChecksums(held.event.ImageVersion)
		switch {
		case cached && signedClaudeRelease(held.digest, checksums):
			delete(h.coldClients, pid)
			if held.event.ImageSHA256 == "" {
				h.clientExecs.digestDropped.Add(1)
			}
			h.finishHeldLocked(held, false)
			return true
		case cached:
			h.releaseColdClientLocked(pid, held)
			return true
		}
	}
	if over {
		h.releaseColdClientLocked(pid, held)
	}
	return over
}

// settleImageDigestLocked takes the image digest of an exec whose event went
// out while its source still read the image (KindImageDigest) to that
// exec's held record: same pid, same exec time and version, and still
// waiting for a digest. A read that failed records it at once; a digest is
// decided against the signed manifest as the hold's own polls would. A
// digest for any other exec (one not held, a later exec of the pid) changes
// nothing.
func (h *hostPlane) settleImageDigestLocked(event plane.Event) {
	held := h.coldClients[event.PID]
	if held == nil || held.digest != "" || !held.event.At.Equal(event.At) ||
		held.event.ImageVersion != event.ImageVersion {
		return
	}
	if event.ImageDigestState != plane.DigestRead || event.ImageSHA256 == "" {
		h.releaseColdClientLocked(event.PID, held)
		return
	}
	held.digest = event.ImageSHA256
	h.settleColdClientLocked(event.PID, held, false)
}

// sameClientExecOfAnOldHelper reports a held client exec and a later exec
// event of its pid that are one exec seen twice, from a helper that predates
// the fork flag and the digest state (neither event states one): the same
// digest, version and argv, and the same exec id and start time wherever
// both events carry them, so two real execs never merge. Kept until every
// supported helper flags forks (1.0.9 helpers and later do); remove in 1.0.10.
func sameClientExecOfAnOldHelper(previous *heldWrapper, event plane.Event) bool {
	was := previous.event
	if was.ImageDigestState != "" || event.ImageDigestState != "" || event.Fork ||
		previous.digest == "" || previous.digest != event.ImageSHA256 ||
		was.ImageVersion != event.ImageVersion || was.Cmdline != event.Cmdline {
		return false
	}
	if was.ExecID != "" && event.ExecID != "" && was.ExecID != event.ExecID {
		return false
	}
	return was.StartNS == 0 || event.StartNS == 0 || was.StartNS == event.StartNS
}

func (h *hostPlane) releaseColdClientLocked(pid int, held *heldWrapper) {
	delete(h.coldClients, pid)
	h.finishHeldLocked(held, true)
}

// clientExecCounts counts the attributed exec events of Claude release
// images by the digest state they came with, the ones recorded, and the
// records a later image digest dropped (GAP-0067). A live run reads them to
// name the event behind a client record.
type clientExecCounts struct {
	seen, reported [4]atomic.Int64
	digestDropped  atomic.Int64
	// duplicates are client execs seen twice while held (a fork read after
	// its exec, then the exec); replaced are held records a later held exec
	// of the same pid recorded.
	duplicates, replaced atomic.Int64
	// forks are fork events of release images, never classified.
	forks atomic.Int64
}

var digestStateNames = [4]string{"read", "pending", "failed", "unstated"}

func digestStateIndex(state plane.DigestState) int {
	switch state {
	case plane.DigestRead:
		return 0
	case plane.DigestPending:
		return 1
	case plane.DigestFailed:
		return 2
	}
	return 3
}

// counts is the non-zero counters by name ("pending", "pending_reported",
// "pending_dropped", ...), or nil.
func (c *clientExecCounts) counts() map[string]int64 {
	var counts map[string]int64
	put := func(name string, value int64) {
		if value == 0 {
			return
		}
		if counts == nil {
			counts = make(map[string]int64)
		}
		counts[name] = value
	}
	for i, name := range digestStateNames {
		put(name, c.seen[i].Load())
		put(name+"_reported", c.reported[i].Load())
	}
	put("pending_dropped", c.digestDropped.Load())
	put("held_duplicate", c.duplicates.Load())
	put("held_replaced", c.replaced.Load())
	put("fork_skipped", c.forks.Load())
	return counts
}
