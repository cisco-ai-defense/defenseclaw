// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sort"
)

// CheckFiles checks the bundle content against files[]: every listed file
// is present (file_missing) with the listed size and SHA-256
// (file_hash_mismatch), and no other file is present (file_extra). These
// hashes, covered by the manifest signature, are the integrity guarantee of
// everything but the manifest.
func CheckFiles(m *Manifest, b *Bundle) error {
	listed := make(map[string]bool, len(m.Files))
	for _, file := range m.Files {
		listed[file.Path] = true
		data, ok := b.Files[file.Path]
		if !ok {
			return refuse(CodeFileMissing, file.Path, "listed in files[] but not in the bundle")
		}
		sum := sha256.Sum256(data)
		want, err := hex.DecodeString(file.SHA256)
		if err != nil || int64(len(data)) != file.Size || subtle.ConstantTimeCompare(sum[:], want) != 1 {
			return refuse(CodeFileHashMismatch, file.Path, "size or SHA-256 differs from files[]")
		}
	}
	for _, name := range b.Paths() {
		if !listed[name] {
			return refuse(CodeFileExtra, name, "in the bundle but not listed in files[]")
		}
	}
	return nil
}

// FileEntries lists every file of b as files[] entries, sorted by path, for
// bundle sign.
func FileEntries(b *Bundle) []FileEntry {
	entries := make([]FileEntry, 0, len(b.Files))
	for _, name := range b.Paths() {
		sum := sha256.Sum256(b.Files[name])
		entries = append(entries, FileEntry{Path: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b.Files[name]))})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}
