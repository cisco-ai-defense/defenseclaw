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

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// hostScriptTwinRequests are the requests for the scripts a static powershell,
// pwsh or cmd launcher (or call block, or Invoke-Expression literal) runs, or
// the statements of a PowerShell list, one by one: actionfacts.HostScriptReadings,
// psparse's reading of what the call runs. Each reading is judged beside the
// call as written and joined to it with withOverLimitTwinFindings, which only
// ever adds: a proven block of the script, a stronger proof of a rule the call
// already raised, and the rules the script only records. Nothing the call as
// written raised is removed or weakened, so a wrong psparse result can add a
// false alert (which the precision gate measures) but cannot hide an attack or
// make an unknown call clean.
//
// The wrapper depth is one budget of the call: a twin is read again with the
// layers its parent used, so nested twins never restart it. A bound the reading
// hits (the depth, the nested size budget, a body past the in-list size, a list
// past its statement count) comes back as caps, and the call is truncated at the
// unknown tier of the pack (withBoundedTruncation), never a clean allow.
func hostScriptTwinRequests(request trustedActionRequest, facts actionfacts.Facts) ([]trustedActionRequest, bounded.CapSet) {
	if request.hostScriptTwinOff {
		return nil, bounded.CapSet{}
	}
	reading := actionfacts.HostScriptReadings(request.Input, facts, request.hostTwinDepth, request.hostTwinListed)
	twins := make([]trustedActionRequest, 0, len(reading.Twins))
	for index, input := range reading.Twins {
		// A script that only lists proves no write to the paths it names; its
		// second reading could only repeat the mention of a path as a block.
		if hookpaths.PowerShellListOnlyBody(input.Command, input.ActiveHome) {
			continue
		}
		twin := request
		twin.Input = input
		twin.LegacyText = input.Command
		twin.conflictSource = nil
		twin.record, twin.recordTelemetry = nil, nil
		twin.hostTwinDepth = reading.Depth
		twin.hostTwinListed = index < len(reading.Listed) && reading.Listed[index]
		twins = append(twins, twin)
	}
	return twins, reading.Caps
}
