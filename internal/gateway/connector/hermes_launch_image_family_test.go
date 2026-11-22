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

package connector

import "testing"

// GAP-0601: a rolled-back 1.0.10 upgrade left the Hermes allowlist naming
// its own launch image after the rollback removed that folder. The next
// upgrade read the entry as a tampered DefenseClaw command and failed the
// signed-in account. Any hook image of the same install bin is DefenseClaw's,
// folder present or not; the command must still be exactly the render.
func TestHermesLaunchImageFamilyCommand(t *testing.T) {
	const standalone = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	for _, tc := range []struct {
		name    string
		command string
		want    bool
	}{
		{"removed launch folder", windowsHermesDirectHookCommand(`C:\Program Files\Cisco\DefenseClaw\bin\hooks\95265bb3041675a9\defenseclaw-hook.exe`), true},
		{"transition image", windowsHermesDirectHookCommand(standalone), true},
		{"another install bin", windowsHermesDirectHookCommand(`D:\Other\bin\hooks\95265bb3041675a9\defenseclaw-hook.exe`), false},
		{"not a launch folder name", windowsHermesDirectHookCommand(`C:\Program Files\Cisco\DefenseClaw\bin\hooks\evil\defenseclaw-hook.exe`), false},
		{"an extra argument", windowsHermesDirectHookCommand(`C:\Program Files\Cisco\DefenseClaw\bin\hooks\95265bb3041675a9\defenseclaw-hook.exe`) + " --other", false},
		{"another program", `"C:/Program Files/Cisco/DefenseClaw/bin/hooks/95265bb3041675a9/defenseclaw-hook.exe" --connector codex`, false},
	} {
		if got := hermesLaunchImageFamilyCommandFor(tc.command, standalone); got != tc.want {
			t.Errorf("%s: %q = %t, want %t", tc.name, tc.command, got, tc.want)
		}
	}
	if hermesLaunchImageFamilyCommandFor(windowsHermesDirectHookCommand(standalone), "") {
		t.Fatal("no standalone install must recognize nothing")
	}
}

// rel-1-0-10 GAP-0794: after `hook-image retire` the guardian writes the
// Hermes allowlist entry for the transition image. 1.0.9 recognizes only its
// own exact command for that path (the 1.0.9 guardian refused any other
// marked entry as "a tampered DefenseClaw command"), so this release must
// render exactly what 1.0.9 rendered: the literal below is the 1.0.9
// windowsHermesDirectHookCommand output (tag 1.0.9, helpers.go).
func TestHermesTransitionCommandIsThe109Command(t *testing.T) {
	const transition = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	const released109 = `"C:/Program Files/Cisco/DefenseClaw/bin/defenseclaw-hook.exe" hook --connector hermes`
	if got := windowsHermesDirectHookCommand(transition); got != released109 {
		t.Fatalf("Hermes transition command = %q, want the 1.0.9 command %q", got, released109)
	}
}
