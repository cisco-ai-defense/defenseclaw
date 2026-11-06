// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package hookpaths

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
)

// xzAllDictionariesWithinBound checks every block named by the XZ stream
// index before the decoder sees any compressed input. XZ's ReaderConfig
// increases DictCap to a block's declared size, so it cannot enforce this.
func xzAllDictionariesWithinBound(file *os.File, size int64) bool {
	if size < 24 || size > maxTarPlainBytes {
		return false
	}
	readAt := func(offset int64, data []byte) bool {
		n, err := file.ReadAt(data, offset)
		return n == len(data) && err == nil
	}
	pos := size
	streams := 0
	for pos > 0 {
		// Stream padding is a multiple of four zero bytes.
		for pos >= 4 {
			var tail [4]byte
			if !readAt(pos-4, tail[:]) {
				return false
			}
			if tail != [4]byte{} {
				break
			}
			pos -= 4
		}
		if pos == 0 {
			break
		}
		if pos < 24 || streams >= 16 {
			return false
		}
		streams++
		var footer [12]byte
		if !readAt(pos-12, footer[:]) || string(footer[10:]) != "YZ" ||
			binary.LittleEndian.Uint32(footer[:4]) != crc32.ChecksumIEEE(footer[4:10]) {
			return false
		}
		indexSize := (int64(binary.LittleEndian.Uint32(footer[4:8])) + 1) * 4
		if indexSize < 8 || indexSize > pos-12 || indexSize > maxTarPlainBytes {
			return false
		}
		indexStart := pos - 12 - indexSize
		index := make([]byte, int(indexSize))
		if !readAt(indexStart, index) || index[0] != 0 ||
			binary.LittleEndian.Uint32(index[len(index)-4:]) != crc32.ChecksumIEEE(index[:len(index)-4]) {
			return false
		}
		i, limit := 1, len(index)-4
		readVLI := func() (uint64, bool) {
			var value uint64
			for shift := uint(0); shift < 63 && i < limit; shift += 7 {
				b := index[i]
				i++
				value |= uint64(b&0x7f) << shift
				if b&0x80 == 0 {
					return value, true
				}
			}
			return 0, false
		}
		count, ok := readVLI()
		if !ok || count == 0 || count > maxTarPlainMembers {
			return false
		}
		blockSizes := make([]int64, 0, int(count))
		var paddedTotal int64
		for n := uint64(0); n < count; n++ {
			unpadded, ok := readVLI()
			if !ok || unpadded < 8 || unpadded > uint64(maxTarPlainBytes) {
				return false
			}
			if _, ok = readVLI(); !ok {
				return false
			}
			padded := int64((unpadded + 3) &^ uint64(3))
			if paddedTotal > maxTarPlainBytes-padded {
				return false
			}
			paddedTotal += padded
			blockSizes = append(blockSizes, padded)
		}
		for ; i < limit; i++ {
			if index[i] != 0 {
				return false
			}
		}
		streamStart := indexStart - paddedTotal - 12
		if streamStart < 0 {
			return false
		}
		var header [12]byte
		if !readAt(streamStart, header[:]) || string(header[:6]) != "\xfd7zXZ\x00" ||
			binary.LittleEndian.Uint32(header[8:]) != crc32.ChecksumIEEE(header[6:8]) ||
			header[6] != footer[8] || header[7] != footer[9] {
			return false
		}
		blockPos := streamStart + 12
		for _, padded := range blockSizes {
			var sizeByte [1]byte
			if !readAt(blockPos, sizeByte[:]) || sizeByte[0] == 0 {
				return false
			}
			headerSize := (int(sizeByte[0]) + 1) * 4
			if int64(headerSize) > padded {
				return false
			}
			block := make([]byte, 12+headerSize)
			copy(block[:6], "\xfd7zXZ\x00")
			if !readAt(blockPos, block[12:]) {
				return false
			}
			if binary.LittleEndian.Uint32(block[len(block)-4:]) != crc32.ChecksumIEEE(block[12:len(block)-4]) {
				return false
			}
			if xzDictionaryCap(bufio.NewReader(bytes.NewReader(block))) == 0 {
				return false
			}
			blockPos += padded
		}
		if blockPos != indexStart {
			return false
		}
		pos = streamStart
	}
	return streams > 0
}
