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
	"reflect"
	"strings"
	"testing"
)

// GAP-1914: an offset found in a case-folded copy of a text cuts the text
// itself. U+023A lowers to a 3-byte letter (the copy grows: the cut runs past
// the end and panics); U+212A and U+0130 lower to ASCII k and i (the copy
// shrinks: the cut lands early and a reading is missed).
const (
	gap1914Grow   = "\u023a"
	gap1914Kelvin = "\u212a"
	gap1914DotI   = "\u0130"
)

func gap1914NoPanic(t *testing.T, name string, run func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", name, recovered)
		}
	}()
	run()
}

func gap1914Input(text string) Input {
	return Input{Tool: "Bash", Command: text, CWD: "/home/u/work", ActiveHome: "/home/u"}
}

func TestGAP1914PidFileInStateGrowingLetterDoesNotPanic(t *testing.T) {
	text := "pkill -F " + strings.Repeat(gap1914Grow, 64) + ".pid; echo done"
	gap1914NoPanic(t, "pidFileInState", func() {
		if pidFileInState(text, "/home/u") {
			t.Errorf("pidFileInState(%q) = true, want false (no state folder)", text)
		}
	})
}

// The guard reads the call as it reads the same call spelled in ASCII.
func TestGAP1914DefenseClawControlGrowingLetterDoesNotPanic(t *testing.T) {
	for _, tail := range []string{"defenseclaw-gateway stop", "echo defenseclaw"} {
		text := "pkill -F " + strings.Repeat(gap1914Grow, 64) + ".pid; " + tail
		ascii := "pkill -F AAAA.pid; " + tail
		var got []DefenseClawControlFact
		gap1914NoPanic(t, "DefenseClawControl", func() {
			got = DefenseClawControl(Analyze(gap1914Input(text)), text)
		})
		if want := DefenseClawControl(Analyze(gap1914Input(ascii)), ascii); !reflect.DeepEqual(got, want) {
			t.Errorf("DefenseClawControl(%q) = %+v, want %+v as for %q", text, got, want, ascii)
		}
	}
}

// Letters that shrink when lowered, earlier in the text, keep the reading of
// the guard's own pid file (a regression guard: the search resumes after a
// wrong cut, so the base healed here).
func TestGAP1914PidFileInStateShrinkingLettersKeepTheCut(t *testing.T) {
	for _, letter := range []string{gap1914Kelvin, gap1914DotI} {
		text := "echo " + strings.Repeat(letter, 24) + "; pkill -F ~/.defenseclaw/gateway.pid"
		if !pidFileInState(text, "/home/u") {
			t.Errorf("pidFileInState(%q) = false, want true (the guard's pid file)", text)
		}
	}
}

func TestGAP1914AzureRoleAssignmentGrowingLetterDoesNotPanic(t *testing.T) {
	resource := "/subscriptions/" + strings.Repeat(gap1914Grow, 64) +
		"/providers/Microsoft.Authorization/roleAssignments/x"
	gap1914NoPanic(t, "exactAzureRoleAssignmentIdentity", func() {
		parent, _, ok := exactAzureRoleAssignmentIdentity(resource)
		if want := "/subscriptions/" + strings.Repeat(gap1914Grow, 64); ok && parent != want {
			t.Errorf("exactAzureRoleAssignmentIdentity(%q) parent %q, want %q", resource, parent, want)
		}
	})
}

func TestGAP1914HTTPSQLGrowingLetterDoesNotPanic(t *testing.T) {
	grow := strings.Repeat(gap1914Grow, 40)
	for name, check := range map[string]func(string) bool{
		"tautology": exactHTTPQuotedBooleanTautology,
		"union":     exactHTTPUnionSelect,
	} {
		for _, value := range []string{
			grow + "' or 'a'='a",
			grow + " union select a --",
			"1 union select a from " + grow + " where a='b' --",
			"1 union select a " + grow + " from t --",
		} {
			gap1914NoPanic(t, name, func() { check(value) })
		}
	}
}

// A Kelvin sign is a letter the prefix pattern takes ((?i) folds it to k):
// lowering it to ASCII k moved the cut two bytes early and the tautology was
// missed.
func TestGAP1914HTTPSQLShrinkingLetterKeepsTheCut(t *testing.T) {
	value := gap1914Kelvin + "' or 'a'='a"
	if got, want := exactHTTPQuotedBooleanTautology(value), exactHTTPQuotedBooleanTautology("k' or 'a'='a"); got != want || !got {
		t.Errorf("exactHTTPQuotedBooleanTautology(%q) = %v, want %v as for the ASCII k", value, got, want)
	}
}

// ASCII text reads as before (the fold is the same byte for byte).
func TestGAP1914ASCIIParity(t *testing.T) {
	for text, want := range map[string]bool{
		"pkill -F ~/.defenseclaw/gateway.pid":           true,
		"pkill -F ~/.DefenseClaw/Gateway.PID":           true,
		"kill $(cat /var/lib/defenseclaw/gateway.pid)":  true,
		"kill $(cat %ProgramData%\\DefenseClaw\\g.pid)": true,
		"pkill -F /tmp/x/.defenseclaw/gateway.pid":      false,
		"pkill -F ~/work/gateway.pid":                   false,
	} {
		if got := pidFileInState(text, "/home/u"); got != want {
			t.Errorf("pidFileInState(%q) = %v, want %v", text, got, want)
		}
	}
	for value, want := range map[string]bool{
		"admin' or 'a'='a": true,
		"ADMIN' OR 'A'='A": true,
		"admin' or 'a'='b": false,
		"admin and 'a'='a": false,
	} {
		if got := exactHTTPQuotedBooleanTautology(value); got != want {
			t.Errorf("exactHTTPQuotedBooleanTautology(%q) = %v, want %v", value, got, want)
		}
	}
	for _, value := range []string{"1' union select null --", "1' UNION SELECT NULL --", "1' union select a from t where a='b' --"} {
		if exactHTTPUnionSelect(value) != exactHTTPUnionSelect(strings.ToLower(value)) {
			t.Errorf("exactHTTPUnionSelect(%q) differs from its lower-case spelling", value)
		}
	}
	resource := "/subscriptions/0000/providers/Microsoft.Authorization/roleAssignments/1111"
	if parent, _, ok := exactAzureRoleAssignmentIdentity(resource); ok && parent != "/subscriptions/0000" {
		t.Errorf("exactAzureRoleAssignmentIdentity(%q) parent %q, want /subscriptions/0000", resource, parent)
	}
}

func BenchmarkGAP1914PidFileInState(b *testing.B) {
	text := "cd /home/u/work && pkill -F ~/.defenseclaw/gateway.pid; echo " + strings.Repeat("Done ", 40)
	b.ReportAllocs()
	for b.Loop() {
		pidFileInState(text, "/home/u")
	}
}
