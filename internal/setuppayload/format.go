// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package setuppayload defines the on-disk trailer format that binds the
// AVC-signed inner payload files to the prebuilt outer Setup EXE.
//
// The DefenseClaw Windows managed-enterprise release used to embed the
// signed payload at compile time via //go:embed under
// cmd/defenseclaw-enterprise-setup/payload. That forced AVC's Windows
// signing runner to provision Go, because the inner files could only be
// bound to the outer binary AFTER AVC signed them (i.e. after they
// existed in signed form).
//
// The Windows AVC handoff inverts the flow: DefenseClaw prebuilds
// the outer Setup EXE with no payload embedded, ships it plus a
// native Windows amd64 assembler binary to AVC, and the assembler
// appends a deterministic trailer holding the signed payload +
// manifest to the end of the prebuilt EXE. The resulting file is
// then signed by AVC's signtool; Authenticode's hash range covers
// the appended trailer along with the code, so the outer signature
// covers both.
//
// The format is deliberately minimal — no compression, no timestamps,
// fixed field widths — so two independent assembler runs against
// byte-identical input produce byte-identical output. The
// reproducibility contract is expressed as a test in this package's
// writer_test.go.
package setuppayload

import (
	"encoding/binary"
	"errors"
)

// Magic is the 8-byte footer sentinel that lets the runtime locate the
// trailer at the tail of the outer Setup EXE. "DCLWAVC1" stands for
// "DefenseClaw Windows AVC v1"; a v2 layout would use "DCLWAVC2" and
// remain readable by a runtime that supports both.
const Magic = "DCLWAVC1"

// MaxNameLen is the fixed-width byte length of a payload entry name in
// the archive. Every current payload entry fits well under this limit
// (the longest is defenseclaw-cmid-broker.exe = 27 bytes). A stray
// name over the limit is a build-time error, not a truncation.
const MaxNameLen = 64

// FooterSize is the byte length of the trailer's fixed-width footer
// record (magic + archive length + manifest length + CRC32).
const FooterSize = 8 + 8 + 4 + 4

// MaxManifestBytes bounds the manifest.json payload the runtime is
// willing to read. The current manifest.json for a 6-file payload is
// ~1 KB; 1 MiB leaves plenty of headroom without letting a corrupt or
// malicious trailer request an unbounded allocation at boot.
const MaxManifestBytes = 1 << 20

// MaxArchiveBytes bounds the total archive body (all files + their
// per-entry headers). 1 GiB matches the existing runtime cap
// (maximumPayloadTotalBytes in cmd/defenseclaw-enterprise-setup/main.go).
const MaxArchiveBytes = int64(1 << 30)

// EntryHeaderSize is the byte length of the per-file record header in
// the archive body (name + size + sha256).
const EntryHeaderSize = MaxNameLen + 8 + 32

// ErrTrailerMissing is returned when the footer magic bytes at the end
// of the reader stream do not match Magic. The runtime treats this as a
// hard failure: an outer Setup EXE without a trailer is not a valid
// artefact.
var ErrTrailerMissing = errors.New("setuppayload: trailer magic not found at end of file")

// ErrTrailerCorrupt is returned when the trailer's CRC32 check fails or
// when internal offsets are inconsistent (e.g. archive_len larger than
// the available bytes before the footer).
var ErrTrailerCorrupt = errors.New("setuppayload: trailer integrity check failed")

// ErrEntryOversize is returned when a file's name exceeds MaxNameLen or
// its contents exceed the archive-wide cap. Named separately so the
// bundler can surface which file is at fault.
var ErrEntryOversize = errors.New("setuppayload: entry exceeds size limits")

// byteOrder is little-endian across every multi-byte integer in the
// trailer. Fixed on the writer AND reader side so an accidental
// endianness change in one half is caught by the reproducibility test
// in this package.
var byteOrder = binary.LittleEndian

// Footer is the fixed-width record at the tail of an assembled Setup
// EXE. Layout (24 bytes total):
//
//	magic         [8]byte    // "DCLWAVC1"
//	archiveLen    uint64 LE  // byte length of the archive body
//	manifestLen   uint32 LE  // byte length of the manifest JSON
//	crc32         uint32 LE  // CRC32-IEEE over (archive || manifest)
//
// The manifest immediately precedes the footer; the archive immediately
// precedes the manifest. To locate the archive start:
//
//	archive_start = file_size - FooterSize - manifest_len - archive_len
type Footer struct {
	ArchiveLen  uint64
	ManifestLen uint32
	CRC32       uint32
}

// Encode writes the footer bytes into a fresh slice. Used by the
// assembler when composing the trailer.
func (f Footer) Encode() []byte {
	buf := make([]byte, FooterSize)
	copy(buf[0:8], []byte(Magic))
	byteOrder.PutUint64(buf[8:16], f.ArchiveLen)
	byteOrder.PutUint32(buf[16:20], f.ManifestLen)
	byteOrder.PutUint32(buf[20:24], f.CRC32)
	return buf
}

// DecodeFooter parses a 24-byte slice into a Footer, verifying magic.
// Callers that read the tail of a file must pass exactly FooterSize
// bytes.
func DecodeFooter(buf []byte) (Footer, error) {
	if len(buf) != FooterSize {
		return Footer{}, ErrTrailerCorrupt
	}
	if string(buf[0:8]) != Magic {
		return Footer{}, ErrTrailerMissing
	}
	return Footer{
		ArchiveLen:  byteOrder.Uint64(buf[8:16]),
		ManifestLen: byteOrder.Uint32(buf[16:20]),
		CRC32:       byteOrder.Uint32(buf[20:24]),
	}, nil
}

// Entry describes one payload file: its name (as it will appear inside
// the archive) and its byte contents. The assembler-side writer hashes
// contents at write time and embeds the digest in the per-entry header;
// callers do NOT supply a precomputed digest — a name/contents pair
// alone is enough to write the archive deterministically.
type Entry struct {
	Name     string
	Contents []byte
}
