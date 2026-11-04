// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

const (
	// coldClientHold is how long the record of a client exec whose release
	// manifest is not cached yet waits for it (cowork-1-0-8 GAP-0065). The
	// manifest is fetched on that exec, in the background, within
	// releaseManifests' bounds: one fetch of 3 s at most, spaced by
	// unknownManifestInterval. A manifest still missing when the hold ends
	// leaves the exec reported.
	coldClientHold = 8 * time.Second
	// coldClientPoll is how often a held record looks at the cache.
	coldClientPoll = 250 * time.Millisecond
)

// holdColdClientLocked keeps the record of an exec whose source read a
// Claude release image digest, when the release manifest of its version is
// not cached yet and the verified client would not be reported for it, until
// the manifest is in. The record is dropped only when the signed manifest
// lists the digest; a digest it does not list, a fetch that failed or no
// manifest before the hold ends records it. The gateway cannot prefetch the
// manifest at start: in the Cowork VM it runs unprivileged and cannot list
// the session homes, and the image prewarm runs in the root helper. It
// reports false when the record is to be made now.
func (h *hostPlane) holdColdClientLocked(
	event plane.Event, lineage agentchain.Lineage, match tactics.Match, at time.Time, instance agentchain.Instance,
	observation tactics.Observation,
) bool {
	if h.coldHold <= 0 || event.Kind != plane.KindExec || event.PID <= 0 || h.indicators.KeepClientMCP ||
		h.clientChecksums == nil || event.ImageSHA256 == "" || !plane.IsClaudeReleaseVersion(event.ImageVersion) ||
		len(h.coldClients) >= maxHeldWrappers {
		return false
	}
	if _, cached := h.clientChecksums(event.ImageVersion); cached {
		return false
	}
	observation.ClaudeClient = true
	if _, ok := tactics.Classify(observation, h.indicators); ok {
		return false
	}
	pid, version, digest := event.PID, event.ImageVersion, event.ImageSHA256
	if previous := h.coldClients[pid]; previous != nil {
		h.releaseColdClientLocked(pid, previous)
	}
	if h.coldClients == nil {
		h.coldClients = make(map[int]*heldWrapper)
	}
	held := &heldWrapper{event: event, lineage: lineage, match: match, at: at, instance: instance}
	deadline := time.Now().Add(h.coldHold)
	var check func()
	check = func() {
		checksums, cached := h.clientChecksums(version)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.coldClients[pid] != held {
			return
		}
		switch {
		case cached && signedClaudeRelease(digest, checksums):
			delete(h.coldClients, pid)
		case cached || !time.Now().Before(deadline):
			h.releaseColdClientLocked(pid, held)
		default:
			held.timer = time.AfterFunc(h.coldPoll, check)
		}
	}
	held.timer = time.AfterFunc(h.coldPoll, check)
	h.coldClients[pid] = held
	return true
}

func (h *hostPlane) releaseColdClientLocked(pid int, held *heldWrapper) {
	held.timer.Stop()
	delete(h.coldClients, pid)
	h.recordLocked(held.event, held.lineage, held.match, held.at, held.instance)
}
