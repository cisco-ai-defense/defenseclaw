// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"encoding/binary"
	"testing"
)

// Deliberately synthetic ELF metadata, never passed to an exec/mount/seal API.
func inertLoaderShape() []byte {
	data := make([]byte, 256)
	copy(data, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(data[16:], 3)
	binary.LittleEndian.PutUint16(data[18:], 62)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[24:], 0x1000)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], 2)
	binary.LittleEndian.PutUint16(data[58:], 64)
	binary.LittleEndian.PutUint32(data[64:], 1) // PT_LOAD, file-backed executable entry
	binary.LittleEndian.PutUint32(data[68:], 5)
	binary.LittleEndian.PutUint64(data[80:], 0x1000)
	binary.LittleEndian.PutUint64(data[96:], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[104:], uint64(len(data)))
	binary.LittleEndian.PutUint32(data[120:], 2) // one bounded DT_NULL table
	binary.LittleEndian.PutUint64(data[128:], 224)
	binary.LittleEndian.PutUint64(data[152:], 16)
	binary.LittleEndian.PutUint64(data[160:], 16)
	return data
}

func TestClaudeVersionELFRefusesChangedLoaderClosureWithoutExecution(t *testing.T) {
	if validateClaudeELF(inertLoaderShape(), true) != nil {
		t.Fatal("inert fixed loader shape refused")
	}
	for _, change := range []string{"arch", "type", "entry", "wx", "bounds", "needed", "rpath", "runpath", "dynamic", "interpreter"} {
		data := inertLoaderShape()
		switch change {
		case "arch":
			binary.LittleEndian.PutUint16(data[18:], 183)
		case "type":
			binary.LittleEndian.PutUint16(data[16:], 2)
		case "entry":
			binary.LittleEndian.PutUint64(data[24:], 0x9000)
		case "wx":
			binary.LittleEndian.PutUint32(data[68:], 7)
		case "bounds":
			binary.LittleEndian.PutUint64(data[96:], 1<<30)
		case "needed":
			binary.LittleEndian.PutUint64(data[224:], 1)
		case "rpath":
			binary.LittleEndian.PutUint64(data[224:], 15)
		case "runpath":
			binary.LittleEndian.PutUint64(data[224:], 29)
		case "dynamic":
			binary.LittleEndian.PutUint32(data[120:], 0)
		case "interpreter":
			binary.LittleEndian.PutUint32(data[120:], 3)
		}
		if validateClaudeELF(data, true) == nil {
			t.Fatalf("changed %s shape accepted", change)
		}
	}
	if validateClaudeELF(inertLoaderShape(), false) == nil {
		t.Fatal("shared loader relabeled as vendor executable")
	}
}
