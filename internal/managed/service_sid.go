// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"crypto/sha1" // #nosec G505 -- Windows defines service SIDs with SHA-1; not used for integrity.
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

// virtualServiceSIDString returns the SID Windows assigns to the virtual
// account NT SERVICE\<name>: S-1-5-80 followed by the SHA-1 of the
// upper-cased UTF-16LE service name, read as five little-endian
// sub-authorities. It is the value `sc.exe showsid` prints. Computing it here
// needs no LSA lookup, domain controller or SCM row, so a domain-joined host
// off the corporate network resolves it before the service exists. Callers
// restrict name to ASCII first, so ASCII upper-casing matches Windows'.
func virtualServiceSIDString(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	encoded := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		encoded = binary.LittleEndian.AppendUint16(encoded, unit)
	}
	digest := sha1.Sum(encoded) // #nosec G401 -- see import comment.
	var builder strings.Builder
	builder.WriteString("S-1-5-80")
	for offset := 0; offset < len(digest); offset += 4 {
		builder.WriteByte('-')
		builder.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(digest[offset:])), 10))
	}
	return builder.String()
}
