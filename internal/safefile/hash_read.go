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
	digest, _, consumed, err = HashOpenedRegularFileBoundedCapture(file, limit, 0)
	return digest, consumed, err
}

// HashOpenedRegularFileBoundedCapture additionally retains at most captureLimit
// bytes from the same read that produced the digest. Zero disables retention.
// Bytes are returned only after the opened-file stability check succeeds. Where
// the platform retries a read whose file only changed metadata (macOS: a root
// repair, Spotlight or a scanner adding an xattr), the same handle is read
// again from offset zero, at most readStabilityMetadataRetries times; consumed
// is then the last read's. The caller still owns the handle and verifies its
// current child-name binding.
func HashOpenedRegularFileBoundedCapture(file *os.File, limit int64, captureLimit int) (digest [sha256.Size]byte, captured []byte, consumed int64, err error) {
	if captureLimit < 0 {
		return digest, nil, 0, errors.New("safefile: negative capture limit")
	}
	for attempt := 1; ; attempt++ {
		digest, captured, consumed, err = hashOpenedRegularFileOnce(file, limit, captureLimit, attempt > 1)
		if !errors.Is(err, errReadMetadataChanged) {
			return digest, captured, consumed, err
		}
		if !retryMetadataChange || attempt >= readStabilityMetadataRetries {
			return [sha256.Size]byte{}, nil, consumed, fmt.Errorf("safefile: %s changed while reading", file.Name())
		}
	}
}

// hashOpenedAfterRead runs between a hash read and its closing stability
// snapshot; a test sets it.
var hashOpenedAfterRead func(*os.File)

func hashOpenedRegularFileOnce(file *os.File, limit int64, captureLimit int, rewind bool) (digest [sha256.Size]byte, captured []byte, consumed int64, err error) {
	if rewind {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return digest, nil, 0, err
		}
	}
	info, err := file.Stat()
	if err != nil {
		return digest, nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return digest, nil, 0, fmt.Errorf("safefile: %s is not a regular file", file.Name())
	}
	before, err := readStabilitySnapshot(file)
	if err != nil {
		return digest, nil, 0, err
	}
	if before.size < 0 || before.size > limit {
		return digest, nil, 0, ErrReadLimit
	}

	digest, captured, consumed, err = hashFileContentsCapture(file, before.size, captureLimit)
	if err != nil {
		return digest, nil, consumed, err
	}
	if hashOpenedAfterRead != nil {
		hashOpenedAfterRead(file)
	}
	after, err := readStabilitySnapshot(file)
	if err != nil {
		return [sha256.Size]byte{}, nil, consumed, err
	}
	if before != after {
		if before.size == after.size && before.modified == after.modified && before.attributes == after.attributes {
			return [sha256.Size]byte{}, nil, consumed, errReadMetadataChanged
		}
		return [sha256.Size]byte{}, nil, consumed, fmt.Errorf("safefile: %s changed while reading", file.Name())
	}
	return digest, captured, consumed, nil
}

func hashFileContents(reader io.Reader, size int64) (digest [sha256.Size]byte, consumed int64, err error) {
	digest, _, consumed, err = hashFileContentsCapture(reader, size, 0)
	return digest, consumed, err
}

func hashFileContentsCapture(reader io.Reader, size int64, captureLimit int) (digest [sha256.Size]byte, captured []byte, consumed int64, err error) {
	if size < 0 || captureLimit < 0 {
		return digest, nil, 0, ErrReadLimit
	}
	hash := sha256.New()
	var sink io.Writer = hash
	var capture *boundedHashCapture
	if captureLimit > 0 {
		capture = &boundedHashCapture{data: make([]byte, 0, int(min(size, int64(captureLimit))))}
		sink = io.MultiWriter(hash, capture)
	}
	consumed, err = io.Copy(sink, io.LimitReader(reader, size))
	if err != nil {
		return digest, nil, consumed, err
	}
	if consumed != size {
		return digest, nil, consumed, io.ErrUnexpectedEOF
	}
	copy(digest[:], hash.Sum(nil))
	if capture != nil {
		captured = capture.data
	}
	return digest, captured, consumed, nil
}

// Write accepts the whole stream while retaining only its bounded prefix.
// Returning a short write here would incorrectly stop hashing the remainder.
type boundedHashCapture struct{ data []byte }

func (capture *boundedHashCapture) Write(data []byte) (int, error) {
	keep := min(len(data), cap(capture.data)-len(capture.data))
	capture.data = append(capture.data, data[:keep]...)
	return len(data), nil
}
