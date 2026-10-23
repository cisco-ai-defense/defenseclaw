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

//go:build linux || darwin

package sandboxcli

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// probeAtQuestion runs probe once, when the command first writes text: the
// question is open from then until the answer is read.
type probeAtQuestion struct {
	w     io.Writer
	text  string
	probe func()
	done  bool
}

func (p *probeAtQuestion) Write(b []byte) (int, error) {
	if !p.done && strings.Contains(string(b), p.text) {
		p.done = true
		p.probe()
	}
	return p.w.Write(b)
}

// Review P2 (1.0.4 guard loop round 3): a stop or a delete that finds more
// sessions attached than the user was asked about asks again with no lock
// held: while that question is open, the account's gateway lifecycle lock
// (gateway restart, Apply, Rollback, upgrade, managed drain) and the
// sandbox's gate (another attach) are free. Once answered, it takes the gate
// again and counts once more: a session that attached during the question
// is asked about too, and the stop or delete runs only when the count is no
// higher than the last answer covered.
func TestStopAndDeleteAskAgainWithNoLockHeld(t *testing.T) {
	for _, del := range []bool{false, true} {
		ta := newTestApp(t, "", sampleSandbox("box"))
		runAnswers(ta, "run=none\n", "")
		if err := os.MkdirAll(ta.LifecycleDir, 0o700); err != nil {
			t.Fatal(err)
		}
		shortGateWait(t, 300*time.Millisecond)
		defer holdTestSession(t, ta, "box")()
		var second, third func()
		ta.IO.In = &attachAtCopyQuestion{read: strings.NewReader("y\ny\ny\n"), attach: func() { second = holdTestSession(t, ta, "box") }}
		reask := "now; stopping the sandbox ends"
		if del {
			reask = "now; deleting it ends"
		}
		var lifecycleErr, attachErr error
		ta.IO.Out = &probeAtQuestion{w: ta.out, text: reask, probe: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			unlock, err := openshell.LockGatewayLifecycle(ctx, ta.LifecycleDir)
			if lifecycleErr = err; err == nil {
				unlock()
			}
			release, err := ta.holdSession(bg, "box", nil)
			if attachErr = err; err == nil {
				third = release
			}
		}}
		if del {
			ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"box"}}))
		} else {
			ta.ok(t, ta.Stop(bg, StopOptions{Name: "box"}))
		}
		if lifecycleErr != nil || attachErr != nil {
			t.Fatalf("delete=%v: while the question is open the lifecycle lock (%v) and the gate (%v) must be free", del, lifecycleErr, attachErr)
		}
		has(t, ta.output(), "3 terminals are attached to box")
		if stop, d := ta.calls("POST", "box/stop"), ta.calls("DELETE", "box"); stop+d != 1 {
			t.Fatalf("delete=%v: stop %d, delete %d once every attached session was asked about", del, stop, d)
		}
		second()
		third()
	}
}

// Review P2 (1.0.4 guard loop round 3): a run whose launch fails after the
// create deletes the sandbox only under its exclusive gate with no session
// attached. A second terminal that connected to it meanwhile keeps it, and
// the run says how to delete it later.
func TestRunFailedLaunchKeepsASandboxAnotherTerminalAttachedTo(t *testing.T) {
	ta := newTestApp(t, "")
	var other func()
	ta.stream.answer = func([]string) (int, string) {
		if other == nil {
			other = holdTestSession(t, ta, sbName)
		}
		return 124, "timed out"
	}
	wantErr(t, ta.Run(bg, RunOptions{Harness: "claude"}), "does not answer")
	ta.wantCalls(t, 0, "DELETE", sbName)
	has(t, ta.output(), "keeping sandbox "+sbName+" after the failure: 1 terminal is attached to "+sbName, "defenseclaw sandbox delete "+sbName)
	other()
}
