// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
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

// authenticodeMaxAlignPadding is the maximum number of alignment bytes
// signtool can insert between an appended trailer and the certificate
// table. Authenticode's Attribute Certificate Table is 8-byte aligned,
// so the padding is 0..7 bytes.
const authenticodeMaxAlignPadding = 7

// imageDirectoryEntrySecurity is the index of the Attribute Certificate
// Table entry inside the PE Optional Header's Data Directory array.
// Not exported as a named constant by debug/pe.
const imageDirectoryEntrySecurity = 4

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

// Read pulls the trailer off ra. `size` is the total byte length of
// the underlying artefact (`ra.Size()` for an *os.File, or
// stat().Size() for a caller that has the value already). Runtime code
// under cmd/defenseclaw-enterprise-setup calls this with the running
// EXE's own file handle.
//
// The trailer is located by findFooterOffset, which is Authenticode-
// aware: for an assembled-but-unsigned Setup EXE (produced by the
// assembler before AVC's signtool step) the trailer sits at the very
// end of the file and the magic starts at `size - FooterSize`; for a
// signed EXE, signtool has appended the Attribute Certificate Table to
// the file's end with 0..7 bytes of alignment padding between the
// trailer and the cert table, so the magic is at
// `certVA - padding - FooterSize` where certVA is the file offset of
// the cert table (PE Optional Header data-directory entry 4).
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

	footerStart, err := findFooterOffset(ra, size)
	if err != nil {
		return ReadResult{}, err
	}

	// Read the fixed 24-byte footer starting at footerStart.
	footerBuf := make([]byte, FooterSize)
	if _, err := ra.ReadAt(footerBuf, footerStart); err != nil {
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
	// The trailer occupies [footerStart - archiveLen - manifestLen, footerStart + FooterSize).
	// Compute the archive/manifest offsets relative to footerStart, not to
	// EOF — for a signed EXE, EOF is past the cert table, not past the
	// trailer.
	manifestStart := footerStart - int64(footer.ManifestLen)
	archiveStart := manifestStart - int64(footer.ArchiveLen)
	if archiveStart < 0 {
		return ReadResult{}, fmt.Errorf("setuppayload: trailer length %d exceeds available bytes before footer at %d: %w",
			int64(footer.ArchiveLen)+int64(footer.ManifestLen)+int64(FooterSize), footerStart, ErrTrailerCorrupt)
	}

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

// findFooterOffset returns the file offset of the DCLWAVC1 magic bytes.
//
// Handles two file shapes:
//
//  1. Unsigned trailer (assembler output before AVC's signtool sign,
//     and the DefenseClaw dev-loop --allow-unsigned path): the trailer
//     sits at the very end of the file, so the magic is at
//     `size - FooterSize`.
//
//  2. Signed trailer (AVC's post-signtool output — what runs on the
//     tester's box): signtool has appended the Authenticode Attribute
//     Certificate Table to the end of the file, with 0..7 bytes of
//     alignment padding between the trailer and the cert table. The
//     PE Optional Header's data-directory entry 4 gives the cert
//     table's file offset. The magic lives at
//     `certVA - padding - FooterSize`.
//
// Falls back to case (1) when the file is not a valid PE (test fixtures
// that use arbitrary bytes) or when the PE has no Attribute Certificate
// Table (unsigned, but structurally-PE files).
func findFooterOffset(ra io.ReaderAt, size int64) (int64, error) {
	if size < FooterSize {
		return 0, ErrTrailerMissing
	}
	certVA, err := peCertificateTableStart(ra)
	if err == nil && certVA > 0 && certVA <= size {
		// Signed path: search the alignment-padding window immediately
		// before the certificate table for the magic.
		buf, readErr := readAuthenticodePaddingWindow(ra, certVA)
		if readErr != nil {
			return 0, readErr
		}
		if off, ok := scanFooterMagicWindow(buf); ok {
			return certVA - int64(len(buf)) + int64(off), nil
		}
		// PE has a cert table but no trailer in the padding window —
		// this file was signed without ever being assembled. Fall
		// through to the EOF path; if the EOF check also fails to
		// find the magic, DecodeFooter will surface ErrTrailerMissing.
	}
	// Unsigned / non-PE / signed-without-trailer path: footer at EOF.
	return size - int64(FooterSize), nil
}

// peCertificateTableStart returns the file offset of the Authenticode
// certificate table, or 0 if the file has no certificate table or is
// not a well-formed PE. Uses debug/pe rather than hand-rolled parsing
// so the file-format quirks (DOS stub, e_lfanew, PE32 vs. PE32+
// optional-header layout) are handled by the stdlib.
func peCertificateTableStart(ra io.ReaderAt) (int64, error) {
	f, err := pe.NewFile(ra)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if imageDirectoryEntrySecurity < len(oh.DataDirectory) {
			dir := oh.DataDirectory[imageDirectoryEntrySecurity]
			if dir.Size == 0 {
				return 0, nil
			}
			return int64(dir.VirtualAddress), nil
		}
	case *pe.OptionalHeader32:
		if imageDirectoryEntrySecurity < len(oh.DataDirectory) {
			dir := oh.DataDirectory[imageDirectoryEntrySecurity]
			if dir.Size == 0 {
				return 0, nil
			}
			return int64(dir.VirtualAddress), nil
		}
	}
	return 0, nil
}

// readAuthenticodePaddingWindow returns the (FooterSize + 7)-byte slice
// ending at certVA — the exact byte range where the DCLWAVC1 footer
// could live given Authenticode's 8-byte alignment padding.
func readAuthenticodePaddingWindow(ra io.ReaderAt, certVA int64) ([]byte, error) {
	windowLen := int(FooterSize) + authenticodeMaxAlignPadding
	windowStart := certVA - int64(windowLen)
	if windowStart < 0 {
		return nil, ErrTrailerMissing
	}
	buf := make([]byte, windowLen)
	if _, err := ra.ReadAt(buf, windowStart); err != nil {
		return nil, fmt.Errorf("setuppayload: read authenticode padding window: %w", err)
	}
	return buf, nil
}

// scanFooterMagicWindow searches the padding-window buffer for the
// DCLWAVC1 magic. The buffer is exactly (FooterSize + 7) bytes ending
// at the certificate-table start. The magic can appear at offsets
// [len(buf) - FooterSize - 7, len(buf) - FooterSize] — 8 candidate
// positions. Returns the offset within the buffer of the magic's first
// byte, or (0, false) if not found.
//
// Pure function; tested directly against synthetic buffers so the PE
// parsing on the surrounding code path can be exercised end-to-end
// without needing a real PE fixture.
func scanFooterMagicWindow(buf []byte) (int, bool) {
	if len(buf) < int(FooterSize) {
		return 0, false
	}
	// Iterate padding from 0 upward — signtool typically emits 0 or a
	// small padding on 8-byte-aligned files, so the low end is the
	// common case.
	for padding := 0; padding <= authenticodeMaxAlignPadding; padding++ {
		offset := len(buf) - int(FooterSize) - padding
		if offset < 0 {
			break
		}
		if offset+len(Magic) > len(buf) {
			continue
		}
		if string(buf[offset:offset+len(Magic)]) == Magic {
			return offset, true
		}
	}
	return 0, false
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
// double-append). Delegates to findFooterOffset so the probe is
// Authenticode-aware: a signed EXE with the trailer positioned before
// the certificate table still reports true. A corrupt trailer body
// still returns true (magic present at a valid position is enough).
func HasTrailer(ra io.ReaderAt, size int64) bool {
	if size < FooterSize {
		return false
	}
	footerStart, err := findFooterOffset(ra, size)
	if err != nil {
		return false
	}
	footerBuf := make([]byte, FooterSize)
	if _, err := ra.ReadAt(footerBuf, footerStart); err != nil {
		if errors.Is(err, io.EOF) {
			return false
		}
		return false
	}
	return string(footerBuf[0:8]) == Magic
}
