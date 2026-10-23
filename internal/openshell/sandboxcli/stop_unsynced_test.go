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

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0902: the daemon does not stop a MicroVM whose disk it could not sync
// first. `sandbox stop` then says what a stop would lose and asks on a
// terminal; only a yes stops it, accepting the loss. --yes does not answer
// that question (the TUI, the macOS app and scripts pass it for the one
// about a detached run), a no or no terminal keeps the MicroVM running
// (no terminal: ExitStopKept, with the flag that stops it anyway), and
// --discard-unsynced accepts the loss up front.
func TestStopOfAMicroVMWhoseSyncFailedAsksFirst(t *testing.T) {
	for _, c := range []struct {
		name    string
		in      string
		tty     bool
		yes     bool
		discard bool
		bodies  []string
		asked   bool
		kept    bool
	}{
		{name: "declined", in: "n\n", tty: true, bodies: []string{"{}"}, asked: true},
		{name: "confirmed", in: "y\n", tty: true, bodies: []string{"{}", `{"discard_unsynced":true}`}, asked: true},
		{name: "--yes still asks", in: "n\n", tty: true, yes: true, bodies: []string{"{}"}, asked: true},
		{name: "no terminal", bodies: []string{"{}"}, kept: true},
		{name: "--yes without a terminal", yes: true, bodies: []string{"{}"}, kept: true},
		{name: "--discard-unsynced", discard: true, bodies: []string{`{"discard_unsynced":true}`}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb := sampleSandbox("vmbox")
			sb.Driver = "vm"
			ta := newTestApp(t, c.in, sb)
			ta.IO.TTY = c.tty
			ta.daemon.unsynced = map[string]bool{"vmbox": true}
			diskAnswers(ta, "run=none\n", dfHalf, 0)
			err := ta.Stop(bg, StopOptions{Name: "vmbox", Yes: c.yes, DiscardUnsynced: c.discard})
			if c.kept {
				wantExit(t, err, ExitStopKept)
				has(t, ta.output(), "`defenseclaw sandbox stop vmbox --discard-unsynced`")
			} else {
				ta.ok(t, err)
			}
			bodies := ta.bodies("POST", "vmbox/stop")
			for i := range bodies {
				bodies[i] = strings.TrimSpace(bodies[i])
			}
			if strings.Join(bodies, " ") != strings.Join(c.bodies, " ") {
				t.Fatalf("stop requests = %q, want %q", bodies, c.bodies)
			}
			if got := strings.Contains(ta.output(), "Stop vmbox anyway and lose what it wrote since its last sync?"); got != c.asked {
				t.Fatalf("asked = %t, want %t:\n%s", got, c.asked, ta.output())
			}
			if len(c.bodies) == 1 && !c.discard {
				has(t, ta.output(), "sandbox vmbox was not stopped: its MicroVM's disk could not be synced first", "it keeps running")
			}
			stopped := ta.daemon.sandboxes["vmbox"].Phase == "stopped"
			if want := c.discard || len(c.bodies) == 2; stopped != want {
				t.Fatalf("stopped = %t, want %t", stopped, want)
			}
		})
	}
}

// GAP-0901: `sandbox status` names every live legacy guest the daemon
// reports, as running unprotected, with the command that ends it.
func TestStatusNamesTheUnprotectedLegacySandboxes(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Unprotected = []sandboxapi.UnprotectedSandbox{
		{Name: "kept", Phase: "ready", Stop: "defenseclaw sandbox stop kept"},
		{Name: "ended", Phase: "completed", Stop: "defenseclaw sandbox delete ended"},
	}
	ta.ok(t, ta.Status(bg, "", OutputText))
	has(t, ta.output(), "kept: "+sandboxapi.LegacyUnprotected+"; no new sandbox runs until it is gone: `defenseclaw sandbox stop kept`",
		"ended: "+sandboxapi.LegacyUnprotected+"; no new sandbox runs until it is gone: `defenseclaw sandbox delete ended`")
	ta.out.Reset()
	ta.ok(t, ta.Status(bg, "", OutputJSON))
	has(t, ta.output(), `"unprotected"`, `defenseclaw sandbox stop kept`)
}
