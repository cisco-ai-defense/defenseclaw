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
func removedSavedCopyPrivate(_ *os.File, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("its mode is %o, not private (600)", perm)
	}
	return nil
}

// removedInPlaceRefusal says why the mode of a hard-linked removed
// connector's stub may not be set through the file (nil when it may): only a
// file that the owner of its hooks folder owns is changed in place. So a
// name in the hooks folder that leads to another account's file never makes
// a privileged teardown change it. until 1.1, with removed.go.
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

// removedStubMetadataRefusal says why the agent may not run or load a removed
// connector's stub, or why another account may change it (nil when neither):
// its owner cannot read it, an executable stub (mode, the one the teardown
// writes, has the owner execute bit) is not executable by its owner, others
// may write it, or another account than the hooks folder's owner owns it.
// until 1.1, with removed.go.
func removedStubMetadataRefusal(file, folder os.FileInfo, mode os.FileMode) error {
	perm := file.Mode().Perm()
	switch {
	case perm&0o400 == 0:
		return fmt.Errorf("its mode is %o, so its owner cannot read it (the teardown writes %o)", perm, mode)
	case mode&0o100 != 0 && perm&0o100 == 0:
		return fmt.Errorf("its mode is %o, so its owner cannot run it (the teardown writes %o)", perm, mode)
	case perm&0o022 != 0:
		return fmt.Errorf("its mode is %o, so other accounts may change it (the teardown writes %o)", perm, mode)
	}
	return removedInPlaceRefusal(file, folder)
}
