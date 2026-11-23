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

package actionfacts

import "testing"

// GAP-1914: a fault inside the DefenseClaw control reader is a reading that
// could not resolve the commands: the unknown tier when the text names
// DefenseClaw, nothing otherwise. It never leaves the function.
func TestGAP1914DefenseClawControlFaultIsTheUnknownTier(t *testing.T) {
	defenseClawControlFaultHook = func() { panic("gap1914 injected control fault") }
	t.Cleanup(func() { defenseClawControlFaultHook = nil })
	for text, want := range map[string][]DefenseClawControlFact{
		"DefenseClaw-gateway stop": {{Kind: DefenseClawControlUnproven}},
		"ls -la":                   nil,
	} {
		var got []DefenseClawControlFact
		gap1914NoPanic(t, "DefenseClawControl", func() { got = DefenseClawControl(Analyze(gap1914Input(text)), text) })
		if len(got) != len(want) || len(want) == 1 && got[0] != want[0] {
			t.Errorf("DefenseClawControl(%q) after a fault = %+v, want %+v", text, got, want)
		}
	}
}
