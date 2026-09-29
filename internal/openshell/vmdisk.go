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

import "path/filepath"

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
