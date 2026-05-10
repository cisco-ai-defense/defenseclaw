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

import "os"

// pluginGetUID is a no-op stub on Windows (UID is a Unix concept).
var pluginGetUID = func() int { return 0 }

// pluginOwnerUID has no meaning on Windows (ownership is ACL-based, not
// UID-based). Returning ok=false signals callers to skip the UID check;
// all neutral callers gate this behind runtime.GOOS != "windows" anyway.
func pluginOwnerUID(_ os.FileInfo) (uint32, bool) {
	return 0, false
}

// pluginInodeIdentity is a no-op on Windows (no stable inode/dev via
// syscall.Stat_t). Neutral callers gate the inode race check behind
// runtime.GOOS != "windows".
func pluginInodeIdentity(_ os.FileInfo) (dev, ino uint64, ok bool) {
	return 0, 0, false
}

// validatePluginOwner is a no-op on Windows. File ownership semantics
// differ (ACLs vs. UID/GID) and the Unix syscall.Stat_t is unavailable.
func validatePluginOwner(_ string) error {
	return nil
}

// validatePluginOwnerFromInfo is a no-op on Windows, mirroring
// validatePluginOwner.
func validatePluginOwnerFromInfo(_ string, _ os.FileInfo) error {
	return nil
}
