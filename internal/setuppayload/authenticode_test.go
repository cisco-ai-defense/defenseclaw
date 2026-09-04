// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestScanFooterMagicWindow exercises the pure-function padding-window
// search against synthetic buffers. Every legal padding position
// (0..7) must be findable; every illegal buffer must return not-found.
func TestScanFooterMagicWindow(t *testing.T) {
	// Buffer shape: [padding bytes][magic][remaining footer bytes]
	// Total length must be FooterSize + authenticodeMaxAlignPadding = 31.
	windowLen := int(FooterSize) + authenticodeMaxAlignPadding

	for padding := 0; padding <= authenticodeMaxAlignPadding; padding++ {
		buf := make([]byte, windowLen)
		// Fill with 0xAA garbage so a false-positive on '\0' bytes
		// would surface.
		for i := range buf {
			buf[i] = 0xAA
		}
		magicOffset := windowLen - int(FooterSize) - padding
		copy(buf[magicOffset:], []byte(Magic))
		// Fill the rest of the footer with 0xBB so the DecodeFooter
		// path (not exercised here) would see distinct sentinel bytes.
		for i := magicOffset + len(Magic); i < magicOffset+int(FooterSize); i++ {
			buf[i] = 0xBB
		}
		off, ok := scanFooterMagicWindow(buf)
		if !ok {
			t.Errorf("padding=%d: magic not found in window", padding)
			continue
		}
		if off != magicOffset {
			t.Errorf("padding=%d: magic at offset %d, want %d", padding, off, magicOffset)
		}
	}

	// Buffer too short — must return not-found (no panic).
	if _, ok := scanFooterMagicWindow(make([]byte, int(FooterSize)-1)); ok {
		t.Error("undersized buffer: unexpectedly found magic")
	}

	// Buffer with no magic anywhere — must return not-found.
	if _, ok := scanFooterMagicWindow(bytes.Repeat([]byte{0xCC}, windowLen)); ok {
		t.Error("all-CC buffer: unexpectedly found magic")
	}

	// Buffer with magic at an ILLEGAL position (before the padding
	// window) — must NOT be reported. Place it 12 bytes back from the
	// legal minimum, which is padding=7 → offset 0 of the window.
	// A window with magic outside the [0..7] byte range should fail.
	buf := make([]byte, windowLen)
	// Magic at buf[8] — that's 1 byte past the padding=7 position.
	if 8+len(Magic) <= len(buf) {
		copy(buf[8:], []byte(Magic))
	}
	if off, ok := scanFooterMagicWindow(buf); ok {
		t.Errorf("magic at illegal offset %d unexpectedly accepted", off)
	}
}

// TestReadFindsFooterBeforeCertTable is the end-to-end regression for
// the AVC issue: signtool appended a certificate table after the
// trailer, with 0..7 bytes of alignment padding, so the reader must
// locate the footer via the PE cert-table directory rather than via
// EOF-relative offset. Runs the full Read path through
// findFooterOffset → peCertificateTableStart → the padding scan.
func TestReadFindsFooterBeforeCertTable(t *testing.T) {
	entries := []Entry{
		{Name: "DefenseClawEnterprise.psm1", Contents: []byte("Module manifest")},
		{Name: "defenseclaw.exe", Contents: []byte("gateway binary bytes")},
		{Name: "install-enterprise.ps1", Contents: []byte("$Foo = 'bar'")},
	}
	manifest := []byte(`{"schema_version":1,"version":"0.8.6-test"}`)

	// Test every legal padding value.
	for padding := 0; padding <= authenticodeMaxAlignPadding; padding++ {
		t.Run(padding0PadName(padding), func(t *testing.T) {
			// Build the pre-trailer PE body: minimal PE headers + a bit of
			// code padding so the trailer doesn't land inside the headers.
			preTrailer := makeMinimalPEHeadersWithCertDirPlaceholder(1024)

			// Append the trailer.
			var buf bytes.Buffer
			buf.Write(preTrailer)
			if err := WriteTrailer(&buf, entries, manifest); err != nil {
				t.Fatalf("WriteTrailer: %v", err)
			}

			// Append alignment padding bytes (signtool would insert
			// 0..7 zero bytes to 8-byte align the cert table).
			for i := 0; i < padding; i++ {
				buf.WriteByte(0)
			}

			// Append the "certificate table" — arbitrary bytes for
			// this fixture; the reader only cares about its offset,
			// not its contents. Give it 64 bytes so it's not empty.
			certTable := bytes.Repeat([]byte{0xAB}, 64)
			certVA := int64(buf.Len())
			buf.Write(certTable)

			// Patch the PE data-directory[SECURITY] entry with the
			// cert table's actual (file offset, size). The placeholder
			// values are zero, so we overwrite in place.
			raw := buf.Bytes()
			patchSecurityDirectoryEntry(raw, uint32(certVA), uint32(len(certTable)))

			// Sanity: pe.NewFile must accept the raw bytes and expose
			// the cert-table entry we just patched.
			gotCertVA, err := peCertificateTableStart(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("peCertificateTableStart: %v", err)
			}
			if gotCertVA != certVA {
				t.Fatalf("cert table start: got %d, want %d", gotCertVA, certVA)
			}

			// Now Read the trailer via the runtime code path.
			rd := bytes.NewReader(raw)
			result, err := Read(rd, int64(rd.Size()))
			if err != nil {
				t.Fatalf("Read (padding=%d): %v", padding, err)
			}

			// Manifest must round-trip byte-identical.
			if !bytes.Equal(result.Manifest, manifest) {
				t.Errorf("manifest mismatch (padding=%d)", padding)
			}
			// Every entry must round-trip. Match on the sorted order
			// the reader produces.
			if len(result.Entries) != len(entries) {
				t.Fatalf("entry count (padding=%d): got %d want %d",
					padding, len(result.Entries), len(entries))
			}
			wantByName := map[string][]byte{}
			for _, e := range entries {
				wantByName[e.Name] = e.Contents
			}
			for _, got := range result.Entries {
				want, ok := wantByName[got.Name]
				if !ok {
					t.Errorf("unexpected entry %q (padding=%d)", got.Name, padding)
					continue
				}
				if !bytes.Equal(got.Contents, want) {
					t.Errorf("entry %q content mismatch (padding=%d)", got.Name, padding)
				}
			}
		})
	}
}

// TestReadUnsignedPEStillWorks proves the fallback path — a
// structurally-PE file with no cert table (an assembler output before
// signtool has ever seen it) still returns the trailer via the EOF
// route.
func TestReadUnsignedPEStillWorks(t *testing.T) {
	entries := []Entry{{Name: "x.exe", Contents: []byte("body")}}
	manifest := []byte(`{}`)

	preTrailer := makeMinimalPEHeadersWithCertDirPlaceholder(256)

	var buf bytes.Buffer
	buf.Write(preTrailer)
	if err := WriteTrailer(&buf, entries, manifest); err != nil {
		t.Fatalf("WriteTrailer: %v", err)
	}

	// No cert-table patch; data-directory[SECURITY].Size stays 0, so
	// peCertificateTableStart returns 0 and findFooterOffset falls
	// back to EOF.
	rd := bytes.NewReader(buf.Bytes())
	if _, err := Read(rd, int64(rd.Size())); err != nil {
		t.Fatalf("Read (unsigned PE): %v", err)
	}
	if !HasTrailer(rd, int64(rd.Size())) {
		t.Error("HasTrailer returned false for a valid unsigned PE trailer")
	}
}

// TestHasTrailerSignedPE — HasTrailer must recognize a trailer in the
// signed-PE layout too, otherwise the assembler's double-append refusal
// would spuriously pass on a signed-then-re-assembled file.
func TestHasTrailerSignedPE(t *testing.T) {
	entries := []Entry{{Name: "x.exe", Contents: []byte("y")}}
	manifest := []byte(`{}`)

	preTrailer := makeMinimalPEHeadersWithCertDirPlaceholder(256)
	var buf bytes.Buffer
	buf.Write(preTrailer)
	if err := WriteTrailer(&buf, entries, manifest); err != nil {
		t.Fatalf("WriteTrailer: %v", err)
	}
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	certVA := int64(buf.Len())
	buf.Write(bytes.Repeat([]byte{0xEE}, 128))

	raw := buf.Bytes()
	patchSecurityDirectoryEntry(raw, uint32(certVA), 128)

	if !HasTrailer(bytes.NewReader(raw), int64(len(raw))) {
		t.Error("HasTrailer(signed PE): got false, want true")
	}
}

func padding0PadName(padding int) string {
	if padding == 0 {
		return "padding=0"
	}
	return "padding=" + string(rune('0'+padding))
}

// makeMinimalPEHeadersWithCertDirPlaceholder produces a byte slice
// that debug/pe.NewFile accepts, ending with `codeBytes` bytes of
// arbitrary "code" so the trailer that follows in the test lands well
// past the headers. The Security (index 4) data-directory entry is
// left as (VirtualAddress=0, Size=0); the caller patches it in place
// after locating the cert table.
//
// The PE is PE32+ (Machine=AMD64) with 0 sections. Minimal to be
// legal but shaped to look like a real Windows amd64 EXE header.
func makeMinimalPEHeadersWithCertDirPlaceholder(codeBytes int) []byte {
	// Layout:
	//   [0x00 .. 0x3B]  DOS stub (MZ + zeros)
	//   [0x3C .. 0x3F]  e_lfanew = 0x40  (uint32 LE)
	//   [0x40 .. 0x43]  PE signature "PE\0\0"
	//   [0x44 .. 0x57]  COFF file header (20 bytes)
	//   [0x58 .. 0x147] Optional header PE32+ (240 bytes)
	//                     - Magic 0x20B at offset 0
	//                     - NumberOfRvaAndSizes = 16 at offset 108
	//                     - DataDirectory[16] at offset 112 (128 bytes)
	//   [0x148 ..]      arbitrary "code" bytes
	const (
		dosSize          = 0x40
		peSigSize        = 4
		coffHeaderSize   = 20
		optionalHeader64 = 240
	)
	peSigOffset := dosSize
	coffOffset := peSigOffset + peSigSize
	optionalHeaderOffset := coffOffset + coffHeaderSize
	codeStart := optionalHeaderOffset + optionalHeader64
	total := codeStart + codeBytes

	buf := make([]byte, total)

	// DOS header — 'MZ' + e_lfanew.
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], uint32(peSigOffset))

	// PE signature.
	copy(buf[peSigOffset:], []byte{'P', 'E', 0, 0})

	// COFF file header:
	//   Machine (2)               = 0x8664 (AMD64)
	//   NumberOfSections (2)      = 0
	//   TimeDateStamp (4)         = 0
	//   PointerToSymbolTable (4)  = 0
	//   NumberOfSymbols (4)       = 0
	//   SizeOfOptionalHeader (2)  = 240
	//   Characteristics (2)       = 0x0022 (EXECUTABLE + LARGE_ADDRESS_AWARE)
	binary.LittleEndian.PutUint16(buf[coffOffset:], 0x8664)
	binary.LittleEndian.PutUint16(buf[coffOffset+2:], 0)
	binary.LittleEndian.PutUint16(buf[coffOffset+16:], optionalHeader64)
	binary.LittleEndian.PutUint16(buf[coffOffset+18:], 0x0022)

	// Optional header PE32+:
	//   Magic (2)                  = 0x20B
	//   ... (everything else defaults to 0 is fine for debug/pe)
	//   NumberOfRvaAndSizes (4)    = 16   at optional-header offset 108
	//   DataDirectory[16] (128B)              at optional-header offset 112
	binary.LittleEndian.PutUint16(buf[optionalHeaderOffset:], 0x20B)
	binary.LittleEndian.PutUint32(buf[optionalHeaderOffset+108:], 16)
	// DataDirectory entries left zero; caller patches [SECURITY] entry.

	return buf
}

// patchSecurityDirectoryEntry rewrites data-directory index 4 in a
// buffer produced by makeMinimalPEHeadersWithCertDirPlaceholder. The
// data-directory table starts at file offset 0x58 + 112 = 0xC8; entry
// 4 is at 0xC8 + 4*8 = 0xE8.
func patchSecurityDirectoryEntry(buf []byte, virtualAddress, size uint32) {
	const dataDirEntry4Offset = 0x40 + 4 + 20 + 112 + 4*8 // 0xE8
	binary.LittleEndian.PutUint32(buf[dataDirEntry4Offset:], virtualAddress)
	binary.LittleEndian.PutUint32(buf[dataDirEntry4Offset+4:], size)
}
