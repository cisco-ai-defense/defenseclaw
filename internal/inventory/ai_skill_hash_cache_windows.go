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

package inventory

import (
	"fmt"
	"io/fs"
	"syscall"
	"time"
)

// skillChangeStampTamperEvident: a user can set every time Windows keeps on
// a file, so a managed scan does not trust the cache.
const skillChangeStampTamperEvident = false

// skillEntryChangeStamp is the creation time of path. Windows has no change
// time in the file metadata Go reads, so the cache age bound catches a write
// time restored by hand.
func skillEntryChangeStamp(_ string, info fs.FileInfo) (string, time.Time) {
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return fmt.Sprintf("%d", data.CreationTime.Nanoseconds()), time.Unix(0, data.CreationTime.Nanoseconds())
	}
	return "?", time.Time{}
}
