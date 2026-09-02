// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"testing/fstest"
	"time"
)

// ReadResult holds the trailer contents pulled off the tail of a Setup
// EXE. Fields are shared by the assembler (to round-trip a trailer it
// just wrote) and by the runtime (to reconstruct an fs.FS the existing
// enterprise-setup loader can consume).
type ReadResult struct {
	// Manifest is the manifest.json bytes exactly as they were embedded.
	// The caller decodes them; this package intentionally does not know
	// the schema.
	Manifest []byte
	// Entries is the ordered set of payload files pulled from the
	// archive body. Order matches on-disk order (alphabetical by Name).
	Entries []Entry
}

// Read pulls the trailer off the end of ra. `size` is the total byte
// length of the underlying artefact (`ra.Size()` for an *os.File, or
// stat().Size() for a caller that has the value already). Runtime code
// under cmd/defenseclaw-enterprise-setup calls this with the running
// EXE's own file handle.
//
// Failure modes are surfaced as sentinel errors so callers can
// distinguish the "no trailer at all" case (ErrTrailerMissing — the EXE
// was never assembled) from the "trailer exists but is broken" case
// (ErrTrailerCorrupt — someone tampered with the EXE, or the CRC
// diverged after signing).
func Read(ra io.ReaderAt, size int64) (ReadResult, error) {
	if size < FooterSize {
		return ReadResult{}, ErrTrailerMissing
	}

	// Read the fixed 24-byte footer at the very tail.
	footerBuf := make([]byte, FooterSize)
	if _, err := ra.ReadAt(footerBuf, size-FooterSize); err != nil {
		return ReadResult{}, fmt.Errorf("setuppayload: read footer: %w", err)
	}
	footer, err := DecodeFooter(footerBuf)
	if err != nil {
		return ReadResult{}, err
	}

	if uint64(footer.ManifestLen) > MaxManifestBytes {
		return ReadResult{}, fmt.Errorf("setuppayload: manifest length %d exceeds cap %d: %w", footer.ManifestLen, MaxManifestBytes, ErrTrailerCorrupt)
	}
	if footer.ArchiveLen > uint64(MaxArchiveBytes) {
		return ReadResult{}, fmt.Errorf("setuppayload: archive length %d exceeds cap %d: %w", footer.ArchiveLen, MaxArchiveBytes, ErrTrailerCorrupt)
	}
	// archive_start + archive_len + manifest_len + FooterSize must equal `size`.
	// If any component is corrupt, this arithmetic prevents an out-of-
	// range ReadAt that could panic or read into unrelated PE bytes.
	trailerLen := int64(footer.ArchiveLen) + int64(footer.ManifestLen) + int64(FooterSize)
	if trailerLen > size {
		return ReadResult{}, fmt.Errorf("setuppayload: trailer length %d exceeds artefact size %d: %w", trailerLen, size, ErrTrailerCorrupt)
	}
	archiveStart := size - trailerLen
	manifestStart := archiveStart + int64(footer.ArchiveLen)

	archive := make([]byte, footer.ArchiveLen)
	if _, err := ra.ReadAt(archive, archiveStart); err != nil {
		return ReadResult{}, fmt.Errorf("setuppayload: read archive: %w", err)
	}
	manifest := make([]byte, footer.ManifestLen)
	if _, err := ra.ReadAt(manifest, manifestStart); err != nil {
		return ReadResult{}, fmt.Errorf("setuppayload: read manifest: %w", err)
	}

	// CRC32-IEEE over archive || manifest, matching WriteTrailer.
	crc := crc32.NewIEEE()
	crc.Write(archive)
	crc.Write(manifest)
	if crc.Sum32() != footer.CRC32 {
		return ReadResult{}, fmt.Errorf("setuppayload: crc32 mismatch: %w", ErrTrailerCorrupt)
	}

	entries, err := decodeArchive(archive)
	if err != nil {
		return ReadResult{}, err
	}
	return ReadResult{Manifest: manifest, Entries: entries}, nil
}

// ReadFile is a thin wrapper that opens path, statss it, and invokes
// Read. Provided for the common runtime case (open running EXE by
// path). Closes the file on both success and failure paths.
func ReadFile(path string) (ReadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return ReadResult{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return ReadResult{}, err
	}
	return Read(f, info.Size())
}

// decodeArchive parses the archive body written by encodeArchive. Names
// are trimmed at the first NUL byte so the fixed-width field round-trips
// through a shorter Go string. Per-file SHA-256 is verified against the
// declared size + contents; a mismatch surfaces ErrTrailerCorrupt.
func decodeArchive(body []byte) ([]Entry, error) {
	var entries []Entry
	offset := 0
	for offset < len(body) {
		if offset+EntryHeaderSize > len(body) {
			return nil, fmt.Errorf("setuppayload: archive truncated at entry header: %w", ErrTrailerCorrupt)
		}
		nameRaw := body[offset : offset+MaxNameLen]
		name := string(bytes.TrimRight(nameRaw, "\x00"))
		if err := validateName(name); err != nil {
			return nil, fmt.Errorf("setuppayload: archive entry: %w", err)
		}
		offset += MaxNameLen

		size := byteOrder.Uint64(body[offset : offset+8])
		offset += 8

		declaredDigest := body[offset : offset+32]
		offset += 32

		if uint64(len(body)-offset) < size {
			return nil, fmt.Errorf("setuppayload: archive truncated at %q body: %w", name, ErrTrailerCorrupt)
		}
		contents := body[offset : offset+int(size)]
		offset += int(size)

		computed := sha256.Sum256(contents)
		if !bytes.Equal(computed[:], declaredDigest) {
			return nil, fmt.Errorf("setuppayload: sha256 mismatch on %q: %w", name, ErrTrailerCorrupt)
		}
		// Copy the contents slice out of the archive buffer so the
		// caller can retain Entry beyond the buffer's lifetime.
		entries = append(entries, Entry{Name: name, Contents: append([]byte(nil), contents...)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// AsPayloadFS returns an fs.FS shaped like the old //go:embed payload/*
// tree: manifest.json and every payload file live under a single top-
// level directory named "payload/". The enterprise-setup runtime
// (loadEnterprisePayload) reads exactly this shape, so no downstream
// caller has to change once the trailer replaces the embed.
//
// This uses testing/fstest.MapFS, which is a stable stdlib API despite
// the package name — the /fstest/ path is where the fs.FS-implementing
// map type lives.
func (r ReadResult) AsPayloadFS() fs.FS {
	mapFS := fstest.MapFS{}
	// Fixed mtime so an fs.Stat() on the extracted view is not
	// wall-clock-dependent. The runtime's manifest check compares sizes
	// and hashes, not mtimes, so this value is cosmetic.
	fixedMTime := time.Unix(0, 0).UTC()
	mapFS[path.Join("payload", "manifest.json")] = &fstest.MapFile{
		Data:    r.Manifest,
		Mode:    0o644,
		ModTime: fixedMTime,
	}
	for _, e := range r.Entries {
		mapFS[path.Join("payload", e.Name)] = &fstest.MapFile{
			Data:    e.Contents,
			Mode:    0o644,
			ModTime: fixedMTime,
		}
	}
	return mapFS
}

// HasTrailer is a cheap probe used by tools that want to check whether
// an existing EXE already carries a trailer (e.g. a rerun of the
// assembler against an already-assembled artefact should refuse to
// double-append). Returns true only when the footer magic is present at
// the tail; a corrupt trailer body still returns true.
func HasTrailer(ra io.ReaderAt, size int64) bool {
	if size < FooterSize {
		return false
	}
	footerBuf := make([]byte, FooterSize)
	if _, err := ra.ReadAt(footerBuf, size-FooterSize); err != nil {
		if errors.Is(err, io.EOF) {
			return false
		}
		return false
	}
	return string(footerBuf[0:8]) == Magic
}
