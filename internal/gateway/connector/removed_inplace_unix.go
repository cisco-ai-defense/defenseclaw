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

// removedSavedCopyPrivate refuses a saved copy of an edited module that
// the group or other accounts may read or change.
func removedSavedCopyPrivate(info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("its mode is %o, not private (600)", perm)
	}
	return nil
}

// removedInPlaceRefusal says why the stub may not be written into a removed
// connector's script file (nil when it may): only a file that the owner of
// its hooks folder owns is written in place. So a name in the hooks folder
// that leads to another account's file with DefenseClaw's marker (a
// root-owned managed hook) never makes a privileged teardown write it; it
// gets the rename, or keeps its tokens when it has other names. until 1.1,
// with removed.go.
func removedInPlaceRefusal(file, folder os.FileInfo) error {
	fileStat, ok := file.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("its owner cannot be read")
	}
	folderStat, ok := folder.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the hooks folder's owner cannot be read")
	}
	if fileStat.Uid != folderStat.Uid {
		return errors.New("another account than the hooks folder's owner owns it")
	}
	return nil
}
