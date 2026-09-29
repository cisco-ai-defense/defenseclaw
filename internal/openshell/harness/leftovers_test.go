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

package harness

import (
	"strings"
	"testing"
)

// TestLaunchersEndWhatTheHarnessLeaves: every harness launcher lets the
// supervisor end what its harness leaves running, except OmniGent's, whose
// host daemon and server serve the next session, and the sandbox exec
// wrapper keeps what its command leaves. The setting is the launcher's own:
// the preamble drops a value from the caller's environment.
func TestLaunchersEndWhatTheHarnessLeaves(t *testing.T) {
	const keep = "\ndc_keep_leftovers=1\n"
	if !strings.Contains(launcherPreamble, "\nunset dc_keep_leftovers\n") {
		t.Error("the preamble does not drop dc_keep_leftovers from the caller's environment")
	}
	if !strings.Contains(launcherJobControl, "${dc_keep_leftovers:+--keep-leftovers} \"$@\"") {
		t.Error("dc_launch does not pass --keep-leftovers to the supervisor")
	}
	for _, name := range Names() {
		spec, _ := Get(name)
		script := string(spec.Launcher().Data)
		pre := strings.Index(script, launcherPreamble)
		at := strings.LastIndex(script, keep)
		if pre < 0 {
			t.Fatalf("%s launcher lacks the preamble", name)
		}
		switch {
		case name == OmniGent.Name && at < pre:
			t.Errorf("the OmniGent launcher does not keep its host daemon and server")
		case name != OmniGent.Name && at >= 0:
			t.Errorf("the %s launcher keeps what %s leaves running", name, spec.DisplayName)
		}
	}
	env := string(shellFile(t, Codex, SandboxEnvPath).Data)
	if at := strings.LastIndex(env, keep); at < strings.Index(env, launcherPreamble) {
		t.Error("the sandbox exec wrapper does not keep what its command leaves running")
	}
}
