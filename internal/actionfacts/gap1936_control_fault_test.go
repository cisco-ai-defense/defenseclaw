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

import (
	"slices"
	"testing"
)

// GAP-1936: a fault inside the DefenseClaw control reader was answered as
// fewer facts: the facts read before it were dropped, and a text that does
// not spell DefenseClaw got nothing, so the call was allowed where the
// gateway's evaluation-fault answer (or, before GAP-1914, a fail-closed hook)
// blocked it. The fault is now reported, after the facts read before it.
const gap1936Fault DefenseClawControlKind = "evaluator-fault"

func gap1936Faults(facts []DefenseClawControlFact) int {
	count := 0
	for _, fact := range facts {
		if fact.Kind == gap1936Fault {
			count++
		}
	}
	return count
}

func TestGAP1936ControlFaultIsReportedWhateverTheText(t *testing.T) {
	defenseClawControlFaultHook = func() { panic("gap1936 injected control fault") }
	t.Cleanup(func() { defenseClawControlFaultHook = nil })
	for _, text := range []string{"ls -la", "kill $(cat /srv/dc/gateway.pid)", "DefenseClaw-gateway stop"} {
		var got []DefenseClawControlFact
		gap1914NoPanic(t, "DefenseClawControl", func() { got = DefenseClawControl(Analyze(gap1914Input(text)), text) })
		if gap1936Faults(got) != 1 || got[len(got)-1].Kind != gap1936Fault {
			t.Errorf("DefenseClawControl(%q) after a fault = %+v, want the facts then one fault", text, got)
		}
	}
}

func TestGAP1936ControlFaultKeepsTheFactsReadBeforeIt(t *testing.T) {
	text := "defenseclaw-gateway stop"
	want := DefenseClawControl(Analyze(gap1914Input(text)), text)
	if len(want) == 0 || gap1936Faults(want) != 0 {
		t.Fatalf("DefenseClawControl(%q) = %+v without a fault; the test lost its subject", text, want)
	}
	calls := 0
	defenseClawControlFaultHook = func() {
		if calls++; calls == 2 { // the first fact is read; the next step faults
			panic("gap1936 injected control fault")
		}
	}
	t.Cleanup(func() { defenseClawControlFaultHook = nil })
	var got []DefenseClawControlFact
	gap1914NoPanic(t, "DefenseClawControl", func() { got = DefenseClawControl(Analyze(gap1914Input(text)), text) })
	if gap1936Faults(got) != 1 || len(got) != 2 || got[0].Kind != want[0].Kind || got[0].Proven != want[0].Proven {
		t.Errorf("DefenseClawControl(%q) faulting after its first fact = %+v, want %+v then one fault", text, got, want[:1])
	}
	if !slices.ContainsFunc(got, func(fact DefenseClawControlFact) bool { return fact.Kind == gap1936Fault }) {
		t.Errorf("no fault fact in %+v", got)
	}
}
