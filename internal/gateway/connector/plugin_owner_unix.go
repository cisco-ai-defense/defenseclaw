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

//go:build !windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// pluginGetUID is overridable for tests. Returns the effective UID of
// the running process. The default delegates to os.Getuid().
var pluginGetUID = os.Getuid

// validatePluginOwner verifies the plugin file is owned by the same UID as
// the running process. This prevents a hostile user on a shared host from
// dropping a plugin that gets loaded with the daemon's privileges.
func validatePluginOwner(soPath string) error {
	info, err := os.Lstat(soPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", soPath, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("could not extract owner UID from FileInfo (non-unix FS?)")
	}
	want := uint32(pluginGetUID())
	if stat.Uid != want {
		return fmt.Errorf("%s owner uid=%d does not match running process uid=%d", soPath, stat.Uid, want)
	}
	return nil
}
