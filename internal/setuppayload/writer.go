// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"unicode/utf8"
)

// WriteTrailer appends the archive + manifest + footer to w in the
// canonical order. Entries are sorted alphabetically by Name so two
// callers that supply the same set of files in different orders produce
// byte-identical output. The manifest bytes are written verbatim; the
// assembler already emits deterministic manifest.json via
// writeSortedJSON, so the trailer contributes no additional variance.
//
// Reproducibility invariants exercised in writer_test.go:
//   - No timestamps in per-entry headers.
//   - Entry order is fixed (alphabetical by Name) regardless of input order.
//   - Fixed-width name field is NUL-padded, never truncated (a name over
//     MaxNameLen returns ErrEntryOversize).
//   - Multi-byte integers are always little-endian.
//   - CRC32 seeds the standard IEEE polynomial.
func WriteTrailer(w io.Writer, entries []Entry, manifestJSON []byte) error {
	if uint64(len(manifestJSON)) > MaxManifestBytes {
		return fmt.Errorf("setuppayload: manifest %d bytes exceeds cap %d", len(manifestJSON), MaxManifestBytes)
	}
	archive, err := encodeArchive(entries)
	if err != nil {
		return err
	}
	if int64(len(archive)) > MaxArchiveBytes {
		return fmt.Errorf("setuppayload: archive %d bytes exceeds cap %d", len(archive), MaxArchiveBytes)
	}
	// CRC32-IEEE over archive || manifest. Standard polynomial so a
	// third-party inspector can validate the trailer without our code.
	crc := crc32.NewIEEE()
	crc.Write(archive)
	crc.Write(manifestJSON)
	footer := Footer{
		ArchiveLen:  uint64(len(archive)),
		ManifestLen: uint32(len(manifestJSON)),
		CRC32:       crc.Sum32(),
	}
	if _, err := w.Write(archive); err != nil {
		return fmt.Errorf("setuppayload: write archive: %w", err)
	}
	if _, err := w.Write(manifestJSON); err != nil {
		return fmt.Errorf("setuppayload: write manifest: %w", err)
	}
	if _, err := w.Write(footer.Encode()); err != nil {
		return fmt.Errorf("setuppayload: write footer: %w", err)
	}
	return nil
}

// encodeArchive builds the archive body: sorted list of per-file
// records. Each record is
//
//	[name (MaxNameLen bytes, NUL-padded, ASCII)]
//	[size (uint64 LE)]
//	[sha256 (32 bytes, raw digest — NOT hex)]
//	[contents (size bytes)]
//
// Names must be non-empty, unique, valid UTF-8, and no longer than
// MaxNameLen bytes. Callers that pass a Windows-invalid character
// (slashes, colons, etc.) get an error rather than silent corruption at
// runtime extraction time.
func encodeArchive(entries []Entry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("setuppayload: refusing empty entry set")
	}
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	seen := make(map[string]struct{}, len(sorted))
	var buf bytes.Buffer
	for _, e := range sorted {
		if err := validateName(e.Name); err != nil {
			return nil, err
		}
		if _, dup := seen[e.Name]; dup {
			return nil, fmt.Errorf("setuppayload: duplicate entry name %q", e.Name)
		}
		seen[e.Name] = struct{}{}

		nameBuf := make([]byte, MaxNameLen)
		copy(nameBuf, e.Name)
		buf.Write(nameBuf)

		var size [8]byte
		byteOrder.PutUint64(size[:], uint64(len(e.Contents)))
		buf.Write(size[:])

		digest := sha256.Sum256(e.Contents)
		buf.Write(digest[:])

		buf.Write(e.Contents)
	}
	return buf.Bytes(), nil
}

// validateName rejects names the runtime archive would not be able to
// extract to a filesystem safely. Windows path semantics are the
// strictest of the platforms the outer EXE targets, so we validate
// against them.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("setuppayload: empty entry name")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("setuppayload: entry name %q exceeds %d bytes: %w", name, MaxNameLen, ErrEntryOversize)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("setuppayload: entry name is not valid UTF-8: %q", name)
	}
	// A trailer entry is a flat file — no subdirectories, no path
	// separators. Reject the platform-hostile characters up front so
	// the runtime's extractPayloadFile never has to defend against them.
	for _, r := range name {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|', 0:
			return fmt.Errorf("setuppayload: entry name %q contains illegal character %q", name, r)
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("setuppayload: entry name %q reserved", name)
	}
	return nil
}
