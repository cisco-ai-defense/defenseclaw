// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package scanner

// OS metadata files in a skill folder (GAP-0106).
//
// A skill copied from macOS (tar, zip, a file share) or through Windows
// Explorer carries files the OS writes on its own: AppleDouble "._name"
// sidecars with a file's Finder info and extended attributes, .DS_Store
// folder views, Thumbs.db thumbnail caches and desktop.ini folder settings.
// skill-scanner read the binary ones as opaque files, so a plain-text skill
// scored "critically low analyzability" (HIGH) and the install watcher
// quarantined it in action mode. A file counts as metadata only when its
// name and its format both say so and it cannot carry file content: an
// AppleDouble file needs its companion file, Finder info, an empty resource
// fork and small attributes under known Apple names only. Anything else (a
// data fork, resource data, an unknown attribute, a metadata name without
// the format) is scanned like any other file. The skill-scanner and
// cli/defenseclaw/scanner/skill.py apply the same checks.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// RuleOSMetadataFile is the INFO finding a skill scan reports for each OS
// metadata file it left out of the content scan.
const RuleOSMetadataFile = "OS_METADATA_FILE"

const (
	appleDoubleMaxBytes     = 64 << 10
	appleDoubleMaxAttrBytes = 4 << 10
	appleDoubleMaxEntries   = 8
	appleDoubleMaxAttrs     = 64
	dsStoreMaxBytes         = 1 << 20
	thumbsDBMaxBytes        = 4 << 20
	desktopINIMaxBytes      = 64 << 10
)

// metadataSidecar is an OS metadata file a scan copy left out.
type metadataSidecar struct {
	Rel  string // path relative to the skill folder
	Kind string // what the file is, for the finding text
}

// appleDoubleAttrNames are the extended attributes macOS sets on a
// downloaded or edited text file; "com.apple.metadata:" names hold
// Spotlight values (where it came from, tags).
var appleDoubleAttrNames = map[string]bool{
	"com.apple.quarantine":      true,
	"com.apple.provenance":      true,
	"com.apple.macl":            true,
	"com.apple.lastuseddate#PS": true,
	"com.apple.TextEncoding":    true,
}

func appleDoubleAttrNameOK(name string) bool {
	return appleDoubleAttrNames[name] || strings.HasPrefix(name, "com.apple.metadata:") && len(name) > len("com.apple.metadata:")
}

// classifySkillFile says how a scan copy treats the regular file rel (size
// bytes) of the skill folder root: kind names an OS metadata file to leave
// out; transcode marks a UTF-16 desktop.ini whose text the scanner should
// read as UTF-8.
func classifySkillFile(root, rel string, size int64) (kind string, transcode bool) {
	name := filepath.Base(rel)
	path := filepath.Join(root, rel)
	switch {
	case strings.HasPrefix(name, "._") && len(name) > 2:
		if size <= appleDoubleMaxBytes && appleDoubleCompanionExists(root, rel) {
			if data, ok := readSkillFileBounded(path, appleDoubleMaxBytes); ok && isAppleDoubleMetadata(data) {
				return "macOS AppleDouble sidecar (Finder info and extended attributes, no file content)", false
			}
		}
	case name == ".DS_Store":
		if size <= dsStoreMaxBytes {
			if data, ok := readSkillFileBounded(path, dsStoreMaxBytes); ok && isDSStore(data) {
				return "macOS Finder folder settings (.DS_Store)", false
			}
		}
	case strings.EqualFold(name, "Thumbs.db"):
		if size <= thumbsDBMaxBytes {
			if data, ok := readSkillFileBounded(path, thumbsDBMaxBytes); ok && isThumbsDB(data) {
				return "Windows Explorer thumbnail cache (Thumbs.db)", false
			}
		}
	case strings.EqualFold(name, "desktop.ini"):
		if size <= desktopINIMaxBytes {
			if data, ok := readSkillFileBounded(path, desktopINIMaxBytes); ok && isUTF16Text(data) {
				return "", true
			}
		}
	}
	return "", false
}

// readSkillFileBounded reads the file at path when it holds at most max bytes.
func readSkillFileBounded(path string, max int64) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, false
	}
	return data, true
}

// appleDoubleCompanionExists reports whether the file "._name" at rel
// describes a file or folder that is there: "name" next to it, or for a
// zip's __MACOSX folder the same path outside it.
func appleDoubleCompanionExists(root, rel string) bool {
	dir, name := filepath.Split(rel)
	parts := strings.Split(filepath.ToSlash(filepath.Clean(dir)), "/")
	if parts[0] == "__MACOSX" {
		parts = parts[1:]
	}
	companion := filepath.Join(append(append([]string{root}, parts...), name[2:])...)
	_, err := os.Lstat(companion)
	return err == nil
}

// isAppleDoubleMetadata reports whether data is an AppleDouble file (RFC
// 1740, the version macOS writes) with metadata only: Finder info with its
// extended attributes, and an empty resource fork.
func isAppleDoubleMetadata(data []byte) bool {
	if len(data) < 26 || binary.BigEndian.Uint32(data) != 0x00051607 || binary.BigEndian.Uint32(data[4:]) != 0x00020000 {
		return false
	}
	n := int(binary.BigEndian.Uint16(data[24:]))
	head := 26 + 12*n
	if n == 0 || n > appleDoubleMaxEntries || head > len(data) {
		return false
	}
	for i := 0; i < n; i++ {
		e := data[26+12*i:]
		id := binary.BigEndian.Uint32(e)
		off := int64(binary.BigEndian.Uint32(e[4:]))
		length := int64(binary.BigEndian.Uint32(e[8:]))
		if off < int64(head) || off+length > int64(len(data)) {
			return false
		}
		switch id {
		case 9: // Finder info
			if !appleDoubleFinderInfoOK(data, off, length) {
				return false
			}
		case 2: // resource fork
			if !emptyResourceFork(data[off : off+length]) {
				return false
			}
		default: // a data fork or any other entry can hold content
			return false
		}
	}
	return true
}

// appleDoubleFinderInfoOK checks the Finder info entry at off: 32 bytes of
// Finder info, then, when macOS stored extended attributes, two pad bytes
// and an "ATTR" header (copyfile attr_header_t) whose attributes all carry
// known Apple names and small values inside the attribute data area.
func appleDoubleFinderInfoOK(data []byte, off, length int64) bool {
	if length < 32 {
		return false
	}
	if length == 32 {
		return true
	}
	const attrHeader = 36
	h := off + 34
	end := off + length
	if h+attrHeader > end || string(data[h:h+4]) != "ATTR" {
		return false
	}
	be32 := func(at int64) int64 { return int64(binary.BigEndian.Uint32(data[at:])) }
	fileLen := int64(len(data))
	dataStart, dataLength := be32(h+12), be32(h+16)
	numAttrs := int(binary.BigEndian.Uint16(data[h+34:]))
	if be32(h+8) > fileLen || dataStart+dataLength > fileLen || numAttrs > appleDoubleMaxAttrs {
		return false
	}
	p := h + attrHeader
	for i := 0; i < numAttrs; i++ {
		if p+11 > end {
			return false
		}
		valueOff, valueLen := be32(p), be32(p+4)
		nameLen := int64(data[p+10])
		if nameLen < 2 || p+11+nameLen > end {
			return false
		}
		name := data[p+11 : p+11+nameLen]
		if name[nameLen-1] != 0 || bytes.IndexByte(name[:nameLen-1], 0) >= 0 || !appleDoubleAttrNameOK(string(name[:nameLen-1])) {
			return false
		}
		if valueLen > appleDoubleMaxAttrBytes || valueOff < dataStart || valueOff+valueLen > dataStart+dataLength {
			return false
		}
		p = (p + 11 + nameLen + 3) &^ 3
	}
	return true
}

// emptyResourceFork reports whether a resource fork holds no resource data:
// none at all, or the small empty fork macOS writes (its header gives a
// resource data length of zero).
func emptyResourceFork(fork []byte) bool {
	if len(fork) == 0 {
		return true
	}
	return len(fork) >= 16 && len(fork) <= 512 && binary.BigEndian.Uint32(fork[8:]) == 0
}

// isDSStore reports whether data is a Finder .DS_Store (a "Bud1" buddy
// allocator file whose root block lies inside the file).
func isDSStore(data []byte) bool {
	if len(data) < 36 || binary.BigEndian.Uint32(data) != 1 || string(data[4:8]) != "Bud1" {
		return false
	}
	off := int64(binary.BigEndian.Uint32(data[8:]))
	size := int64(binary.BigEndian.Uint32(data[12:]))
	return off == int64(binary.BigEndian.Uint32(data[16:])) && size > 0 && 4+off+size <= int64(len(data))
}

var (
	oleMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	// Stream names of Office documents, macros and embedded packages: an
	// OLE file with one of them is a document, not a thumbnail cache.
	oleDocumentStreams = []string{"WordDocument", "Workbook", "Book", "PowerPoint Document", "VBA", "Macros", "_VBA_PROJECT", "Ole10Native", "ObjectPool", "Package"}
)

func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units))
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// isThumbsDB reports whether data is an OLE compound file with no Office
// document, macro or package stream, the format of Explorer's Thumbs.db.
func isThumbsDB(data []byte) bool {
	if len(data) < 512 || !bytes.Equal(data[:8], oleMagic) || data[28] != 0xFE || data[29] != 0xFF {
		return false
	}
	if shift := binary.LittleEndian.Uint16(data[30:]); shift != 9 && shift != 12 {
		return false
	}
	for _, stream := range oleDocumentStreams {
		if bytes.Contains(data, utf16LE(stream)) {
			return false
		}
	}
	return true
}

// isUTF16Text reports whether data is UTF-16 text with a byte order mark
// and no control characters but tab and line breaks.
func isUTF16Text(data []byte) bool {
	bom := bytes.HasPrefix(data, []byte{0xFF, 0xFE}) || bytes.HasPrefix(data, []byte{0xFE, 0xFF})
	if len(data) < 4 || len(data)%2 != 0 || !bom {
		return false
	}
	text, _ := DecodeSkillText(data)
	for _, r := range string(text) {
		if r == utf8.RuneError || r == 0x7F || r < 0x20 && r != '\t' && r != '\r' && r != '\n' {
			return false
		}
	}
	return true
}

// metadataFindings are the INFO findings for the OS metadata files a scan
// copy left out, so the scan still names each one.
func metadataFindings(meta []metadataSidecar) []Finding {
	out := make([]Finding, 0, len(meta))
	for _, m := range meta {
		out = append(out, Finding{
			ID:       RuleOSMetadataFile + "_" + m.Rel,
			Severity: SeverityInfo,
			Title:    "OS metadata file not scanned",
			Description: fmt.Sprintf("%s is a %s. Its format was checked and it holds no file content, so the content scan left it out.",
				m.Rel, m.Kind),
			Location:    m.Rel,
			Remediation: "Remove OS metadata files from the skill folder; on macOS, create archives with COPYFILE_DISABLE=1 to leave out ._ files.",
			Scanner:     "skill-scanner",
			RuleID:      RuleOSMetadataFile,
			Category:    "policy_violation",
		})
	}
	return out
}
