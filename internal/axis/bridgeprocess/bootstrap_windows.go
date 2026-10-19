// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"encoding/binary"
	"encoding/hex"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

// This prefix is host-only capability transfer, not a bridgeproto frame or a
// workload plan. It contains no path, environment, policy or credential. The
// numeric handles are usable only because this one peer inherited those exact
// kernel capabilities through the reviewed HANDLE_LIST. Rust must consume the
// complete fixed prefix before accepting the ordinary Prepare frame, verify
// every actual full identity and kind, and clear HANDLE_FLAG_INHERIT first.
const windowsCapabilityMagic = "DCAXIS-WINCAP1\x00\x00" // exactly 16 bytes
const windowsCapabilityHeader = 56
const windowsCapabilityRecord = 40
const windowsCapabilityMaximum = windowsCapabilityHeader + 514*windowsCapabilityRecord

const (
	windowsCapabilityPayload byte = iota + 1
	windowsCapabilityCWD
	windowsCapabilityRead
	windowsCapabilityWrite
)

type windowsCapability struct {
	file      *os.File // noninheritable retained parent copy
	inherited uint64   // distinct inheritable duplicate, child-owned after Create
	role      byte
	directory bool
	id        windowsImageID
}

func encodeWindowsCapabilities(plan bridgeproto.Preparation, binding bridgeproto.Binding, caps []windowsCapability) ([]byte, error) {
	digest, err := bridgeproto.PreparationDigest(plan)
	if err != nil || digest != binding.PreparationHash || len(caps) != 2+len(plan.Filesystem.Read)+len(plan.Filesystem.Write) || len(caps) > 514 {
		return nil, ErrAdmission
	}
	hash, err := hex.DecodeString(digest[7:])
	if err != nil || len(hash) != 32 {
		return nil, ErrAdmission
	}
	result := make([]byte, windowsCapabilityHeader, windowsCapabilityHeader+len(caps)*windowsCapabilityRecord)
	copy(result, windowsCapabilityMagic)
	binary.BigEndian.PutUint16(result[16:18], 1)
	binary.BigEndian.PutUint16(result[18:20], uint16(len(caps)))
	binary.BigEndian.PutUint16(result[20:22], uint16(len(plan.Filesystem.Read)))
	binary.BigEndian.PutUint16(result[22:24], uint16(len(plan.Filesystem.Write)))
	copy(result[24:56], hash)
	seen := map[uint64]bool{}
	for index, cap := range caps {
		role := windowsCapabilityWrite
		switch {
		case index == 0:
			role = windowsCapabilityPayload
		case index == 1:
			role = windowsCapabilityCWD
		case index < 2+len(plan.Filesystem.Read):
			role = windowsCapabilityRead
		}
		if cap.inherited == 0 || cap.inherited == ^uint64(0) || seen[cap.inherited] || cap.role != role ||
			cap.id == (windowsImageID{}) || index == 0 && cap.directory || index == 1 && !cap.directory {
			return nil, ErrAdmission
		}
		seen[cap.inherited] = true
		record := make([]byte, windowsCapabilityRecord)
		record[0] = role
		if cap.directory {
			record[1] = 1
		}
		// Bytes 2..7 remain reserved zero; the receiver rejects nonzero values.
		binary.BigEndian.PutUint64(record[8:16], cap.inherited)
		binary.BigEndian.PutUint64(record[16:24], cap.id.Volume)
		copy(record[24:40], cap.id.File[:])
		result = append(result, record...)
	}
	return result, nil
}
