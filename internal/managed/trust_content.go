// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// A permission repair proves nothing about content. When a protected file had
// an untrusted writer, restamping its owner and DACL makes the strict check
// pass, but the bytes may be the ones that writer left. Where the standalone
// profile repairs a policy or data file before using it
// (StandaloneRepairNeedsProvenance), the bytes must match what this process
// last read while the file passed the strict check; otherwise the file is
// refused with the strict verdict and left unrepaired, so every other
// process, which has only the descriptor to go on, refuses it too until
// Setup /repair rewrites it (GAP-0561 review 1).

// trustedContentMaxBytes bounds the read; a larger file has no provenance.
const trustedContentMaxBytes = 16 << 20

var (
	trustedContentDigests sync.Map
	// taintedContentDigests holds bytes that changed while a repair was
	// restamping the file: the descriptor is canonical now, so the strict
	// check alone would accept them on the next read.
	taintedContentDigests sync.Map
)

func trustedContentKey(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

func trustedContentDigest(path string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	file, err := os.Open(path) // #nosec G304 -- a managed file the caller just validated.
	if err != nil {
		return digest, false
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, trustedContentMaxBytes+1))
	if err != nil || n > trustedContentMaxBytes {
		return digest, false
	}
	copy(digest[:], hash.Sum(nil))
	return digest, true
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

// MarkContentUntrusted records path's current bytes as ones an untrusted
// writer may have left: a repair restamped the descriptor over them.
func MarkContentUntrusted(path string) {
	if digest, ok := trustedContentDigest(path); ok {
		taintedContentDigests.Store(trustedContentKey(path), digest)
	}
}

// AcceptTrustedContent is the standalone step after path passed the strict
// check: it refuses bytes MarkContentUntrusted recorded and otherwise records
// them with RecordTrustedContent.
func AcceptTrustedContent(path string) error {
	key := trustedContentKey(path)
	if tainted, ok := taintedContentDigests.Load(key); ok {
		if digest, read := trustedContentDigest(path); !read || digest == tainted.([sha256.Size]byte) {
			return fmt.Errorf("%s changed while an untrusted principal could write it; run Setup /repair to rewrite it", path)
		}
		taintedContentDigests.Delete(key)
	}
	RecordTrustedContent(path)
	return nil
}
