// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"crypto/sha1" //nolint:gosec // Windows derives service SIDs with SHA-1; this is not a security hash.
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

// windowsServiceSIDString returns the SID of NT SERVICE\<name> the way
// Windows derives it: S-1-5-80 followed by the SHA-1 of the upper-cased
// UTF-16LE service name as five little-endian sub-authorities. It needs no
// installed service, so an uninstall can still name the gateway service SID
// after the service is deleted.
func windowsServiceSIDString(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	data := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(data[2*i:], unit)
	}
	sum := sha1.Sum(data) //nolint:gosec // see the import comment
	var b strings.Builder
	b.WriteString("S-1-5-80")
	for i := 0; i < 5; i++ {
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[4*i:])), 10))
	}
	return b.String()
}
