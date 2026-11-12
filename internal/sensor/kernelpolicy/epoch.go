// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"crypto/rand"
	"encoding/binary"
)

// NewEpoch is a random, non-zero, positive 63-bit id naming one run of a
// count or a sequence: the change sequence of a state file (SeqEpoch) and
// the helper process's since-start counters (KernelStatus.CountersEpoch).
// The gateway only compares two epochs for equality. A wall-clock value
// would name two runs alike when they start in the same clock tick or under
// a frozen container clock (cowork-1-0-8 GAP-0080 review L4).
func NewEpoch() int64 {
	var b [8]byte
	for {
		// crypto/rand.Read does not fail (Go 1.24+): it never returns an error.
		_, _ = rand.Read(b[:])
		if epoch := int64(binary.BigEndian.Uint64(b[:]) >> 1); epoch != 0 {
			return epoch
		}
	}
}
