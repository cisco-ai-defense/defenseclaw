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
	f, err := openReadOnlyNonblocking(resolved)
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

// os.File is referenced here so both platform implementations have one
// compile-time signature.
type boundedReadFile = os.File
