// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrReadLimit identifies a regular file larger than its read allowance.
var ErrReadLimit = errors.New("safefile: file exceeds the read limit")

// HashOpenedRegularFileBounded hashes a regular file opened for a stable read
// at offset zero. It reports bytes consumed even if reading or the stability
// check fails, and never reads more than limit. The caller owns the handle.
func HashOpenedRegularFileBounded(file *os.File, limit int64) (digest [sha256.Size]byte, consumed int64, err error) {
	info, err := file.Stat()
	if err != nil {
		return digest, 0, err
	}
	if !info.Mode().IsRegular() {
		return digest, 0, fmt.Errorf("safefile: %s is not a regular file", file.Name())
	}
	before, err := readStabilitySnapshot(file)
	if err != nil {
		return digest, 0, err
	}
	if before.size < 0 || before.size > limit {
		return digest, 0, ErrReadLimit
	}
	digest, consumed, err = hashFileContents(file, before.size)
	if err != nil {
		return digest, consumed, err
	}
	after, err := readStabilitySnapshot(file)
	if err != nil {
		return [sha256.Size]byte{}, consumed, err
	}
	if before != after {
		return [sha256.Size]byte{}, consumed, fmt.Errorf("safefile: %s changed while reading", file.Name())
	}
	return digest, consumed, nil
}

func hashFileContents(reader io.Reader, size int64) (digest [sha256.Size]byte, consumed int64, err error) {
	hash := sha256.New()
	consumed, err = io.Copy(hash, io.LimitReader(reader, size))
	if err != nil {
		return digest, consumed, err
	}
	if consumed != size {
		return digest, consumed, io.ErrUnexpectedEOF
	}
	copy(digest[:], hash.Sum(nil))
	return digest, consumed, nil
}
