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
	"reflect"
	"slices"

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
	callJudged := request.windowsTwinHosts.ofTwin(request)
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
		twin.windowsTwinHosts = nil
		if callJudged.judges(twin) {
			continue
		}
		twins = append(twins, twin)
	}
	return twins, reading.Caps
}

// judgedHostReadings are the script readings a call judges itself
// (hostScriptTwinRequests), kept for the Windows reading twins made of it
// (windowsReadingTwinRequests). The PowerShell reading of a Codex or Copilot
// shell call placed in no dialect makes the same readings as the call (the
// list after a Set-Location and each statement of it, read as PowerShell in
// the hook's folder), and the twin judged each of them a second time: on
// the Windows gateway that second judgment was a third of the cost of the
// twin of an ordinary Set-Location call with a dozen appends
// (rel-1-0-10:GAP-1316, the GAP-1150 reading).
//
// Leaving them out of the twin changes no finding of the call. The call's
// own reading of a script is the same request but for the flags a reading
// twin turns off (readingTwin, windowsDialectReadings), and those flags only
// ever add readings to it (cap runs, launcher bodies, readable statements,
// the POSIX twin, the unread-PowerShell floor): it proves every finding the
// twin's would, at the same strength or stronger. The call joins it with
// withHostTwinFindings, before the twin's findings are joined
// (withTwinProvenBlocks), and both keep, per finding key, the strongest
// enforcing finding, so the twin's copy of it was never kept. A reading the
// call does not make with the same input, wrapper depth and list flag is
// still the twin's own.
type judgedHostReadings struct {
	requests []trustedActionRequest
}

// note adds the script readings the call judges (nil: none kept).
func (judged *judgedHostReadings) note(twins []trustedActionRequest) {
	if judged != nil {
		judged.requests = append(judged.requests, twins...)
	}
}

// judges reports a script reading the call judges itself: the same input,
// placed in a dialect (an unhinted one is placed by the Windows selection,
// which the flags of the twin change), at the same wrapper depth and with
// the same list flag.
func (judged *judgedHostReadings) judges(twin trustedActionRequest) bool {
	if judged == nil || twin.Input.DialectHint == "" {
		return false
	}
	return slices.ContainsFunc(judged.requests, func(own trustedActionRequest) bool {
		return own.hostTwinDepth == twin.hostTwinDepth && own.hostTwinListed == twin.hostTwinListed &&
			reflect.DeepEqual(own.Input, twin.Input)
	})
}

// windowsTwinsKeepHostReadings makes every Windows reading twin judge all of
// its script readings, so a test can compare the answers with and without
// leaving the call's own out (TestGAP1316WindowsReadingTwinAnswersAreUnchanged).
// Production code never sets it.
var windowsTwinsKeepHostReadings bool

// windowsTwinHostReadings is the script readings of the call one Windows
// reading twin is made of, and that twin's input: only the twin itself
// leaves them out, not a reading it makes in turn (a statement, a capped
// run, an argument command).
type windowsTwinHostReadings struct {
	call  *judgedHostReadings
	input actionfacts.Input
}

// ofTwin returns the call's script readings when request is the twin they
// are kept for, nil otherwise.
func (hosts *windowsTwinHostReadings) ofTwin(request trustedActionRequest) *judgedHostReadings {
	if hosts == nil || !request.readingTwin || request.simpleCommandPass || !reflect.DeepEqual(hosts.input, request.Input) {
		return nil
	}
	return hosts.call
}
