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

package sandboxcli

import (
	"strings"
	"testing"
)

// `sandbox stop --yes` asks the daemon for the stop that accepts the loss
// of a failed MicroVM sync (after a held stop, GAP-1163); a plain stop
// does not.
func TestStopYesAcceptsAnUnsyncedStop(t *testing.T) {
	for _, yes := range []bool{false, true} {
		sb := sampleSandbox("box")
		sb.Phase = "stopped"
		ta := newTestApp(t, "", sb)
		ta.ok(t, ta.Stop(bg, StopOptions{Name: "box", Yes: yes}))
		b := ta.bodies("POST", "box/stop")
		if len(b) != 1 || strings.Contains(b[0], `"accept_unsynced":true`) != yes {
			t.Fatalf("yes=%v: stop bodies %q", yes, b)
		}
	}
}
