// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package skilldigest is the one definition of a skill folder's content
// digest (substrate-1 GAP-0164, GAP-0039), shared by the template build
// (attest, which records it for every skill it admits), the actor kit (whose
// folder fingerprint it is) and the gateway (which computes it from the files
// the kit attaches, binds scan receipts to it and trusts attested folders by
// it). Standard library only: the kit links it.
package skilldigest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// The folder content the digest covers, the same the kit attaches: regular
// files at most MaxDepth folders deep, at most MaxFiles of them, each at most
// MaxFileBytes. A folder past any of these has no digest, so it is never
// trusted or given a receipt; the gateway's fail mode decides for it.
const (
	MaxFiles     = 64
	MaxDepth     = 3
	MaxFileBytes = 1 << 20
)

// Digest digests a folder's files: relative slash path to content. It is ""
// when the folder has no files, more than MaxFiles, a file deeper than
// MaxDepth folders or larger than MaxFileBytes, or a path that is absolute or
// climbs.
func Digest(files map[string][]byte) string {
	if len(files) == 0 || len(files) > MaxFiles {
		return ""
	}
	names := make([]string, 0, len(files))
	for n, b := range files {
		if n == "" || strings.HasPrefix(n, "/") || strings.Contains("/"+n+"/", "/../") || strings.Count(n, "/") > MaxDepth || len(b) > MaxFileBytes {
			return ""
		}
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	h.Write([]byte("defenseclaw skill folder v1\n"))
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		h.Write([]byte(n + "\x00" + hex.EncodeToString(sum[:]) + "\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
