// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"unicode/utf16"
)

// endpointHealthPlistMaxBytes bounds a property list the gateway parses. A
// package receipt is well under 4 KiB.
const endpointHealthPlistMaxBytes = 64 << 10

// endpointHealthPlistMaxItems bounds the entries of a dictionary and the
// length of a string.
const endpointHealthPlistMaxItems = 4096

var errEndpointHealthPlistKeyMissing = errors.New("property list has no such string key")

// plistTopLevelString returns the string value of key in the top-level
// dictionary of a property list, XML or binary (bplist00). It parses only
// that dictionary's keys and string values; it runs no external tool.
// macOS package receipts under /var/db/receipts are binary property lists.
func plistTopLevelString(data []byte, key string) (string, error) {
	if len(data) > endpointHealthPlistMaxBytes {
		return "", errors.New("property list is too large")
	}
	if bytes.HasPrefix(data, []byte("bplist")) {
		if !bytes.HasPrefix(data, []byte("bplist00")) {
			return "", errors.New("unsupported binary property list version")
		}
		return binaryPlistTopLevelString(data, key)
	}
	return xmlPlistTopLevelString(data, key)
}

func xmlPlistTopLevelString(data []byte, key string) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	// Depth 0 is outside <plist>, 1 inside it, 2 inside the top dict.
	depth := 0
	inTopDict := false
	pendingKey := ""
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return "", errEndpointHealthPlistKeyMissing
		}
		if err != nil {
			return "", errors.New("property list is not valid XML")
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch {
			case depth == 0 && element.Name.Local == "plist":
				depth = 1
			case depth == 1 && element.Name.Local == "dict" && !inTopDict:
				depth, inTopDict = 2, true
			case depth == 2 && element.Name.Local == "key":
				var name string
				if err := decoder.DecodeElement(&name, &element); err != nil {
					return "", errors.New("property list key is malformed")
				}
				pendingKey = name
			case depth == 2 && element.Name.Local == "string" && pendingKey == key:
				var value string
				if err := decoder.DecodeElement(&value, &element); err != nil {
					return "", errors.New("property list string is malformed")
				}
				return value, nil
			default:
				if err := decoder.Skip(); err != nil {
					return "", errors.New("property list is not valid XML")
				}
				if depth == 2 {
					pendingKey = ""
				}
			}
		case xml.EndElement:
			if depth == 2 && element.Name.Local == "dict" {
				return "", errEndpointHealthPlistKeyMissing
			}
		}
	}
}

// binaryPlistTopLevelString reads key from the top-level dictionary of a
// bplist00 document: a 32-byte trailer gives the offset table, which maps
// object references to offsets; a dictionary object lists its key and value
// references; ASCII (0x5n) and UTF-16 (0x6n) strings are the only values
// this reader decodes.
func binaryPlistTopLevelString(data []byte, key string) (string, error) {
	malformed := errors.New("binary property list is malformed")
	if len(data) < 8+32 {
		return "", malformed
	}
	trailer := data[len(data)-32:]
	offsetSize := int(trailer[6])
	refSize := int(trailer[7])
	objects := binary.BigEndian.Uint64(trailer[8:16])
	top := binary.BigEndian.Uint64(trailer[16:24])
	tableOffset := binary.BigEndian.Uint64(trailer[24:32])
	body := uint64(len(data) - 32)
	if offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8 ||
		objects == 0 || objects > body || top >= objects ||
		tableOffset < 8 || tableOffset > body || objects*uint64(offsetSize) > body-tableOffset {
		return "", malformed
	}
	readUint := func(at uint64, size int) (uint64, bool) {
		if at+uint64(size) > body {
			return 0, false
		}
		var value uint64
		for _, b := range data[at : at+uint64(size)] {
			value = value<<8 | uint64(b)
		}
		return value, true
	}
	objectOffset := func(ref uint64) (uint64, bool) {
		if ref >= objects {
			return 0, false
		}
		offset, ok := readUint(tableOffset+ref*uint64(offsetSize), offsetSize)
		if !ok || offset < 8 || offset >= tableOffset {
			return 0, false
		}
		return offset, true
	}
	// length decodes an object's element count: the low nibble, or an int
	// object that follows when the nibble is 0xF.
	length := func(at uint64) (count, next uint64, ok bool) {
		low := uint64(data[at] & 0x0f)
		if low != 0x0f {
			return low, at + 1, true
		}
		if at+1 >= body || data[at+1]>>4 != 0x1 {
			return 0, 0, false
		}
		size := 1 << (data[at+1] & 0x0f)
		if size > 8 {
			return 0, 0, false
		}
		count, ok = readUint(at+2, size)
		return count, at + 2 + uint64(size), ok
	}
	readString := func(ref uint64) (string, bool) {
		at, ok := objectOffset(ref)
		if !ok {
			return "", false
		}
		kind := data[at] >> 4
		count, start, ok := length(at)
		if !ok || count > endpointHealthPlistMaxItems {
			return "", false
		}
		switch kind {
		case 0x5:
			if start+count > tableOffset {
				return "", false
			}
			return string(data[start : start+count]), true
		case 0x6:
			if start+2*count > tableOffset {
				return "", false
			}
			units := make([]uint16, count)
			for index := range units {
				units[index] = binary.BigEndian.Uint16(data[start+2*uint64(index):])
			}
			return string(utf16.Decode(units)), true
		default:
			return "", false
		}
	}
	at, ok := objectOffset(top)
	if !ok || data[at]>>4 != 0xd {
		return "", malformed
	}
	count, start, ok := length(at)
	if !ok || count > endpointHealthPlistMaxItems || start+2*count*uint64(refSize) > tableOffset {
		return "", malformed
	}
	for index := uint64(0); index < count; index++ {
		keyRef, _ := readUint(start+index*uint64(refSize), refSize)
		name, ok := readString(keyRef)
		if !ok || name != key {
			continue
		}
		valueRef, _ := readUint(start+(count+index)*uint64(refSize), refSize)
		value, ok := readString(valueRef)
		if !ok {
			return "", errors.New("binary property list value is not a string")
		}
		return strings.TrimSpace(value), nil
	}
	return "", errEndpointHealthPlistKeyMissing
}
