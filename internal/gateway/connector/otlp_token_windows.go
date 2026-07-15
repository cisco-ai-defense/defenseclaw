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

//go:build windows

package connector

import (
	"os"
)

// otlpValidateDirectory enforces the native Windows owner, DACL, and
// reparse-point contract for every directory controlling a token path.
func otlpValidateDirectory(path string) error {
	return hookAPIValidateDirectory(path)
}

// otlpOpenNoFollow returns 0 on Windows. O_NOFOLLOW is a Unix flag and is not
// available here. (Windows DOES traverse reparse points/symlinks during
// CreateFile unless FILE_FLAG_OPEN_REPARSE_POINT is set, but creating symlinks
// on Windows requires elevation or Developer Mode, and the token file is
// created with O_EXCL, so the practical exposure is limited.)
func otlpOpenNoFollow() int {
	return 0
}

// otlpValidatePerm enforces the native Windows owner/DACL and reparse-point
// contract instead of interpreting synthesized POSIX mode bits.
func otlpValidatePerm(path string, _ os.FileInfo) error {
	return hookAPIValidateWindowsPathElement(path, false, true)
}

// otlpValidateOwner is a no-op on Windows. File ownership uses ACLs and
// the Unix UID check is not applicable.
func otlpValidateOwner(_ string, _ os.FileInfo) error {
	return nil
}
