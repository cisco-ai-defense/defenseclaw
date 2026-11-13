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

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

// hostScriptTwinEnabled turns the script reading of a static PowerShell or cmd
// launcher off, so a test can compare a call's findings with and without it
// (TestHostScriptTwinOnlyAddsFindings). It is always true in production.
var hostScriptTwinEnabled = true

// hostScriptTwinRequest is the request for the script a static powershell,
// pwsh or cmd launcher (or call block, or Invoke-Expression literal) runs:
// actionfacts.HostScriptTwin, psparse's reading of what the launcher runs. The
// reading is judged beside the call as written and joined to it with
// withOverLimitTwinFindings, which only ever adds: a proven block of the
// script, a stronger proof of a rule the call already raised, and the rules the
// script only records. Nothing the call as written raised is removed or
// weakened, so a wrong psparse result can add a false alert (which the
// precision gate measures) but cannot hide an attack or make an unknown call
// clean.
func hostScriptTwinRequest(request trustedActionRequest, facts actionfacts.Facts) (trustedActionRequest, bool) {
	if !hostScriptTwinEnabled {
		return trustedActionRequest{}, false
	}
	input, ok := actionfacts.HostScriptTwin(request.Input, facts)
	if !ok {
		return trustedActionRequest{}, false
	}
	twin := request
	twin.Input = input
	twin.LegacyText = input.Command
	twin.conflictSource = nil
	twin.record, twin.recordTelemetry = nil, nil
	return twin, true
}
