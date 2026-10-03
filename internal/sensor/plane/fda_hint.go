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

package plane

import (
	"path/filepath"
	"strings"
)

// sensorHelperBinary is the root helper that runs Plane C on a managed
// install. launchd starts it directly, so macOS treats it as the responsible
// process for eslogger and it is the binary that needs Full Disk Access.
const sensorHelperBinary = "defenseclaw-sensor-helper"

// fullDiskAccessHint names the binary that needs Full Disk Access for
// Endpoint Security, given the path of the process that runs eslogger.
//
// On a managed Mac that is the sensor helper, and the fix is an MDM PPPC
// profile for it. A per-user gateway inherits the grant from whatever
// launched it (a terminal app, for example).
func fullDiskAccessHint(executable string) string {
	base := strings.TrimSuffix(filepath.Base(executable), ".exe")
	if executable != "" && base == sensorHelperBinary {
		return "grant Full Disk Access (SystemPolicyAllFiles) to " + executable +
			" with an MDM PPPC profile, or in System Settings > Privacy & Security > " +
			"Full Disk Access, then restart the sensor helper"
	}
	return "grant Full Disk Access to the app or process that launches the gateway " +
		"(System Settings > Privacy & Security > Full Disk Access)"
}
