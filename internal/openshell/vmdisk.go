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

package openshell

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// defaultVMStateDir is the MicroVM driver's state directory under the home
// of the user the gateway runs as, when its configuration sets none.
var defaultVMStateDir = filepath.Join(".local", "state", "openshell", "vm-driver")

// VMStateDir is the MicroVM driver's state directory, which holds the disks
// it prepares from images: stateDir ([openshell.drivers.vm] state_dir, or
// OPENSHELL_VM_DRIVER_STATE_DIR in gateway.env; VMConfig.StateDir) when it
// is absolute, else ~/.local/state/openshell/vm-driver under home, the home
// of the user the gateway runs as (DefenseClaw's). "" when neither is
// absolute.
func VMStateDir(stateDir, home string) string {
	if filepath.IsAbs(stateDir) {
		return filepath.Clean(stateDir)
	}
	if !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Join(home, defaultVMStateDir)
}

// VMDiskHeadroomBytes is what preparing a MicroVM disk from an image takes
// beyond the image's own size in Docker.
const VMDiskHeadroomBytes = 1 << 30

// vmDiskGuess is the disk the MicroVM driver prepares from a harness image
// whose size is not known: about 5 GB.
const vmDiskGuess = 5 << 30

// VMDiskRoom is the free space a MicroVM create needs where the driver
// prepares a disk from an image it has not prepared one from yet, for an
// image of imageBytes in Docker (0: unknown, about 5 GB): need is what the
// disk takes, about the image's size plus VMDiskHeadroomBytes; below fail
// the create is refused (never below the doctor's VMDiskFailBytes), and
// below warn it is warned about (never below VMDiskWarnBytes).
func VMDiskRoom(imageBytes uint64) (need, fail, warn uint64) {
	if imageBytes == 0 {
		imageBytes = vmDiskGuess
	}
	need = imageBytes + VMDiskHeadroomBytes
	return need, max(VMDiskFailBytes, need), max(VMDiskWarnBytes, 2*need)
}

// ErrVMDiskShort means there is too little free space where the MicroVM
// driver would prepare a disk for a new sandbox.
var ErrVMDiskShort = errors.New("not enough free disk space")

// VMDiskShortage judges free bytes in dir, the MicroVM driver's image
// cache (as the message shows it), for preparing a disk there from an
// image of imageBytes (0: unknown) at what ("this sandbox's first start"):
// an ErrVMDiskShort error below VMDiskRoom's fail, a warning below its
// warn, neither otherwise. Both name what is free and what is needed, and
// what frees space.
func VMDiskShortage(dir string, free, imageBytes uint64, what string) (warning string, err error) {
	need, fail, warn := VMDiskRoom(imageBytes)
	size := humanBytes(need - VMDiskHeadroomBytes)
	switch {
	case free < fail:
		return "", fmt.Errorf("%w for %s: the MicroVM driver prepares a disk of about %s from its image in %s, where %s is free and at least %s is needed; "+
			"free space on that volume first (`%s` removes superseded harness images and the MicroVM disks prepared from them)",
			ErrVMDiskShort, what, size, dir, humanBytes(free), humanBytes(fail), pruneCommand)
	case free < warn:
		return fmt.Sprintf("only %s is free in %s, and %s prepares a MicroVM disk of about %s there (%s or more is recommended; "+
			"`%s` removes superseded harness images and the MicroVM disks prepared from them)",
			humanBytes(free), dir, what, size, humanBytes(warn), pruneCommand), nil
	}
	return "", nil
}

// DiskFree returns the bytes available to unprivileged users on the file
// system holding path.
func DiskFree(path string) (uint64, error) { return diskFree(path) }

// FreeUnder is diskFree of dir, or, while dir does not exist yet (the
// MicroVM driver makes its state directory on its first start), of its
// nearest parent that does.
func FreeUnder(diskFree func(string) (uint64, error), dir string) (uint64, error) {
	measured := dir
	for {
		if _, err := os.Stat(measured); err == nil || filepath.Dir(measured) == measured {
			break
		}
		measured = filepath.Dir(measured)
	}
	return diskFree(measured)
}

// VMImageCache is the MicroVM driver's image cache: images under
// VMStateDir, where it keeps one directory per image it prepared a root
// disk from (PreparedDiskPrefix) next to its own state. "" when the state
// directory is unknown.
func VMImageCache(stateDir, home string) string {
	dir := VMStateDir(stateDir, home)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "images")
}
