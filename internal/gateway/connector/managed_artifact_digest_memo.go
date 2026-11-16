// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The managed connector digest and the Windows guardian share this memo for
// the administrator-owned hook binary. Every call opens a deny-write handle
// and checks identity, links and reparse attributes. The target is read in
// full when its stamp changes or its last read is ten minutes old; a guarded
// full read needs one data pass. On a volume without a usable change journal,
// the same handle supplies an attribute-only stamp with a ten-minute backstop.
// An administrator who forges every attribute can hide a change until that
// backstop, as with the guardian's former cache. Journaled checks are unchanged.

// managedArtifactDigestMaxAge is the one shared full-read backstop for the
// target and for a protected copy in attribute-only mode.
const managedArtifactDigestMaxAge = 10 * time.Minute

// managedArtifactStamp is what the file system reports about one version of
// an open file without reading its data: volume, file id, size, link count,
// last-write and change times, attributes and change-journal number.
type managedArtifactStamp struct {
	Volume     uint32
	ID         uint64
	Size       int64
	Links      uint32
	Written    int64
	Changed    int64
	USN        int64
	Attributes uint32
}

type managedArtifactDigestEntry struct {
	stamp              managedArtifactStamp
	digest             string
	at                 time.Time
	attributeOnly      bool
	fullStampAvailable bool
}

// managedArtifactDigests is the digest of each memoized artifact with the
// stamp it had when it was read in full. now is replaced in tests.
var managedArtifactDigests = struct {
	sync.Mutex
	entries map[string]managedArtifactDigestEntry
	now     func() time.Time
}{now: time.Now}

// Separate paths may be read concurrently, but callers of one path serialize
// the lookup, guarded open and full read. A waiter still takes its own handle
// and checks the stamp before using the first caller's result.
var managedArtifactDigestPathLocks sync.Map // map[string]*sync.Mutex

// A notice is emitted once for each degraded path in this process. Tests
// replace the logger and map without writing to the process logger.
var managedArtifactDigestDegradedNotices = &sync.Map{}
var managedArtifactDigestDegradedNotice = func(path string) {
	log.Printf("managed hook artifact %s: no usable change journal; unchanged files are re-read every ten minutes", path)
}

func noticeManagedArtifactDegraded(path string) {
	if _, loaded := managedArtifactDigestDegradedNotices.LoadOrStore(managedArtifactDigestKey(path), struct{}{}); !loaded {
		managedArtifactDigestDegradedNotice(path)
	}
}

func managedArtifactDigestPathLock(path string) *sync.Mutex {
	key := managedArtifactDigestKey(path)
	lock, _ := managedArtifactDigestPathLocks.LoadOrStore(key, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

// managedArtifactDigestRead is replaced by portable tests to count data
// passes. Stamp and identity checks do not call it.
var managedArtifactDigestRead = func(dst io.Writer, file *os.File, maxBytes int64) (int64, error) {
	return io.Copy(dst, io.LimitReader(file, maxBytes+1))
}

func managedArtifactDigestKey(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

// rememberedManagedArtifactDigest returns the digest for this stamp and mode.
// A zero maxAge never expires a full journaled stamp, but attribute-only
// entries always use the shared ten-minute backstop.
func rememberedManagedArtifactDigest(path string, stamp managedArtifactStamp, maxAge time.Duration, attributeOnly, fullStampAvailable bool) (string, bool) {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	entry, ok := managedArtifactDigests.entries[managedArtifactDigestKey(path)]
	if attributeOnly {
		maxAge = managedArtifactDigestMaxAge
	}
	if !ok || entry.stamp != stamp || entry.attributeOnly != attributeOnly ||
		(attributeOnly && entry.fullStampAvailable != fullStampAvailable) ||
		(maxAge > 0 && managedArtifactDigests.now().Sub(entry.at) >= maxAge) {
		return "", false
	}
	return entry.digest, true
}

func rememberManagedArtifactDigest(path string, stamp managedArtifactStamp, digest string, attributeOnly, fullStampAvailable bool) {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	if managedArtifactDigests.entries == nil {
		managedArtifactDigests.entries = map[string]managedArtifactDigestEntry{}
	}
	managedArtifactDigests.entries[managedArtifactDigestKey(path)] = managedArtifactDigestEntry{
		stamp:              stamp,
		digest:             digest,
		at:                 managedArtifactDigests.now(),
		attributeOnly:      attributeOnly,
		fullStampAvailable: fullStampAvailable,
	}
}

// managedArtifactStampMovedOnlyInJournal reports whether later differs from
// before only in its change-journal number. Another process's full read of
// the same file writes a close record (endManagedArtifactChangeEpoch), which
// moves that number without a write, a rename or an attribute change.
func managedArtifactStampMovedOnlyInJournal(before, later managedArtifactStamp) bool {
	if before.USN == later.USN {
		return false
	}
	before.USN, later.USN = 0, 0
	return before == later
}

func forgetManagedArtifactDigest(path string) {
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	delete(managedArtifactDigests.entries, managedArtifactDigestKey(path))
}

// managedArtifactDigestMemoWanted reports whether the digest of path may be
// memoized: only the enterprise hook binary, never a file of the connector
// data dir, which its user can reach.
func managedArtifactDigestMemoWanted(dataDir, path string) bool {
	return !pathInsideConnectorDataDir(dataDir, path) && managedArtifactDigestMemoEligible(path)
}

// ManagedEnterpriseHookBinarySHA256Hex gives the guardian the same verified
// target digest as managedHookScriptDigests, without a second cache or clock.
// Only the administrator-owned enterprise hook binary is memo-eligible; all
// other paths keep the bounded two-pass digest.
func ManagedEnterpriseHookBinarySHA256Hex(path string) (string, error) {
	// The guardian previously hashed any nonempty target, including one made
	// larger than the connector's 1 GB artifact limit. It still has to see
	// that wrong hash and restore the recorded release.
	return managedHookBinarySHA256Hex(path, managedArtifactDigestMemoEligible(path), math.MaxInt64-1, managedArtifactDigestMaxAge)
}

// ManagedProtectedHookCopySHA256Hex checks the guardian's protected restore
// copy through the same guarded memo. A full journaled stamp has no periodic
// expiry: the copy is never executed and a restore checks its bytes afresh.
// Without a usable journal, the copy has the shared ten-minute backstop;
// a forged attribute-only stamp can hide a change for at most that long.
func ManagedProtectedHookCopySHA256Hex(path string) (string, error) {
	return managedHookBinarySHA256Hex(path, managedProtectedHookCopyEligible(path), managedProtectedArtifactMaxBytes, 0)
}

func managedHookBinarySHA256Hex(path string, memoize bool, maxBytes int64, maxAge time.Duration) (string, error) {
	digest, exists, err := stableManagedArtifactDigestWithAge(
		path, "managed hook runtime artifact", maxBytes, "", memoize, maxAge,
	)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", os.ErrNotExist
	}
	return strings.TrimPrefix(digest, "sha256:"), nil
}

// openManagedArtifactForDigest opens path for the stable digest. With
// memoize it first opens a handle no writer can share: guarded reports it.
// No handle could write the file when that one opened and none can while it
// is open, so a stamp taken on it names the bytes read through it. A later
// write does not always change the change-journal number: while any other
// handle keeps the change epoch of the file open, a second change of the
// same kind keeps it. A full read therefore ends the epoch on this handle
// (endManagedArtifactChangeEpoch) before it takes the stamp it remembers;
// the next change then gets a new number. Another process's full read ends
// the epoch the same way; when only the journal number moved during a read,
// the read is confirmed by a second pass and not memoized. While a writer
// holds the file a shared read-only open is used and nothing is memoized;
// it, like the guarded one, lets an installer replace the file (GAP-0200).
func openManagedArtifactForDigest(path string, memoize bool) (*os.File, bool, error) {
	if memoize {
		if file, err := openManagedArtifactExclusive(path); err == nil {
			return file, true, nil
		}
	}
	file, err := openNativeReadOnly(path)
	return file, false, err
}
