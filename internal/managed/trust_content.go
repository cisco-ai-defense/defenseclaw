// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// A permission repair proves nothing about content. When a protected file had
// an untrusted writer, restamping its owner and DACL makes the strict check
// pass, but the bytes may be the ones that writer left, and a write handle
// opened during the drift keeps working after the DACL changes. Where the
// standalone profile repairs a policy or data file before using it
// (StandaloneRepairNeedsProvenance), RepairWithContentProof runs the repair
// only while no other handle can write or delete the file, and only when its
// bytes match what this process last read while the file passed the strict
// check (RecordTrustedContent). Otherwise the repair does not run: the file
// keeps the descriptor the strict check refuses, so every process, a fresh
// one included, refuses it until a trusted writer (Setup /repair) rewrites
// it (GAP-0561 reviews 1 and 2).

// trustedContentMaxBytes bounds the read; a larger file has no provenance and
// is never repaired. It is above every managed file a gate here reads (the
// managed-hook journals allow 32 MiB).
const trustedContentMaxBytes = 64 << 20

var trustedContentDigests sync.Map

func trustedContentKey(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

func trustedContentDigestOf(reader io.Reader) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(reader, trustedContentMaxBytes+1))
	if err != nil || n > trustedContentMaxBytes {
		return digest, false
	}
	copy(digest[:], hash.Sum(nil))
	return digest, true
}

func trustedContentDigest(path string) ([sha256.Size]byte, bool) {
	file, err := os.Open(path) // #nosec G304 -- a managed file the caller just validated.
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	defer file.Close()
	return trustedContentDigestOf(file)
}

// RecordTrustedContent remembers the digest of path's current bytes. Call it
// only right after path passed the strict check.
func RecordTrustedContent(path string) {
	key := trustedContentKey(path)
	if digest, ok := trustedContentDigest(path); ok {
		trustedContentDigests.Store(key, digest)
		return
	}
	trustedContentDigests.Delete(key)
}

// TrustedContentUnchanged reports whether path's bytes are the ones this
// process last recorded with RecordTrustedContent.
func TrustedContentUnchanged(path string) bool {
	recorded, ok := trustedContentDigests.Load(trustedContentKey(path))
	if !ok {
		return false
	}
	digest, ok := trustedContentDigest(path)
	return ok && digest == recorded.([sha256.Size]byte)
}

func recordedTrustedContent(path string) ([sha256.Size]byte, bool) {
	recorded, ok := trustedContentDigests.Load(trustedContentKey(path))
	if !ok {
		return [sha256.Size]byte{}, false
	}
	return recorded.([sha256.Size]byte), true
}
