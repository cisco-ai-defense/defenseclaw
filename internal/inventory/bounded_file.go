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

package inventory

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

var (
	errBoundedFileNotRegular = errors.New("bounded metadata path is not a regular file")
	errBoundedFileTooLarge   = errors.New("bounded metadata file exceeds size limit")
)

// readBoundedRegularFile reads small metadata files without trusting a stale
// path-level size check. The platform opener is non-blocking on Unix so a FIFO
// swapped into place cannot hang discovery; f.Stat then verifies the opened
// object itself before a limit+1 read enforces the allocation bound.
func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("bounded metadata limit must be positive")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := openReadOnlyNonblocking(resolved, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readOpenedRegularFile(f, limit)
}

// readBoundedRegularFileNoFollow is readBoundedRegularFile for a file a scan
// walked to: it reads the file at path itself, never what a link there points
// at. A package.json linked to /dev/zero made a per-user scan worker allocate
// until the host ran out of memory (GAP-0694).
func readBoundedRegularFileNoFollow(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("bounded metadata limit must be positive")
	}
	f, err := openReadOnlyNonblocking(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readOpenedRegularFile(f, limit)
}

func readOpenedRegularFile(f *boundedReadFile, limit int64) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errBoundedFileNotRegular
	}
	if info.Size() < 0 || info.Size() > limit {
		return nil, errBoundedFileTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errBoundedFileTooLarge
	}
	return raw, nil
}

// readRegularFileTail reads at most limit bytes from the end of a regular
// file (a shell history). A link is followed, as dotfile managers link
// history files, but the opened object must be a regular file, and a FIFO
// never blocks the open.
func readRegularFileTail(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("bounded metadata limit must be positive")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := openReadOnlyNonblocking(resolved, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errBoundedFileNotRegular
	}
	if info.Size() > limit {
		if _, err := f.Seek(info.Size()-limit, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// readRegularFilePrefix is the large-artifact counterpart to
// readBoundedRegularFile. It verifies the opened object is a regular file and
// reads at most limit bytes from its prefix, but deliberately does not reject
// the file merely because the full artifact is larger. Model containers are
// routinely gigabytes while their provenance header is small and bounded.
func readRegularFilePrefix(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("bounded metadata prefix limit must be positive")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := openReadOnlyNonblocking(resolved, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errBoundedFileNotRegular
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// os.File is referenced here so both platform implementations have one
// compile-time signature.
type boundedReadFile = os.File
