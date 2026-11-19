// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// rel-1-0-10:GAP-0849: a parameter word binds as PowerShell binds it, in
// every spelling it accepts, and a prefix of more than one parameter does
// not bind.
func TestParameterWordReadsEveryDashAndTheColonForm(t *testing.T) {
	for _, tc := range []struct {
		word, name, value string
		colon, ok         bool
	}{
		{"-ItemType", "itemtype", "", false, true},
		{"–ItemType", "itemtype", "", false, true},
		{"—Type", "type", "", false, true},
		{"―ItemType", "itemtype", "", false, true},
		{"-ITEMTYPE", "itemtype", "", false, true},
		{"-ItemType:", "itemtype", "", true, true},
		{"-ItemType:File", "itemtype", "File", true, true},
		{"-_x", "_x", "", false, true},
		{"-1", "", "", false, false},
		{"-", "", "", false, false},
		{"--", "", "", false, false},
		{"File", "", "", false, false},
		{"", "", "", false, false},
	} {
		name, value, colon, ok := ParameterWord(tc.word)
		if name != tc.name || value != tc.value || colon != tc.colon || ok != tc.ok {
			t.Errorf("ParameterWord(%q) = %q, %q, %v, %v; want %q, %q, %v, %v",
				tc.word, name, value, colon, ok, tc.name, tc.value, tc.colon, tc.ok)
		}
	}
}

func TestNewItemParametersBindAsPowerShellDoes(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		known      bool
	}{
		{"itemtype", "itemtype", true},
		{"type", "itemtype", true},
		{"ty", "itemtype", true},
		{"typ", "itemtype", true},
		{"it", "itemtype", true},
		{"itemt", "itemtype", true},
		{"ITEMTYPE", "itemtype", true},
		{"target", "value", true},
		{"val", "value", true},
		{"pa", "path", true},
		{"path", "path", true},
		{"n", "name", true},
		{"f", "force", true},
		{"ea", "erroraction", true},
		{"wi", "whatif", true},
		// Ambiguous prefixes bind to nothing.
		{"t", "", false}, // Type, Target
		{"i", "", false}, // ItemType, InformationAction, InformationVariable
		{"v", "", false}, // Value, Verbose
		{"p", "", false}, // Path, ProgressAction, PipelineVariable
		{"c", "", false}, // Credential, Confirm
		{"w", "", false}, // WhatIf, WarningAction, WarningVariable
		{"kind", "", false},
		{"literalpath", "", false},
		{"", "", false},
	} {
		got, known := NewItemParameters.Bind(tc.name)
		if known != tc.known || got.Name != tc.want {
			t.Errorf("Bind(%q) = %q, %v; want %q, %v", tc.name, got.Name, known, tc.want, tc.known)
		}
	}
	if got, _ := NewItemParameters.Bind("fo"); !got.Switch {
		t.Errorf("Bind(fo) = %+v, want the Force switch", got)
	}
	got, value, colon, isParameter, known := NewItemParameters.BindWord("–Ty:SymbolicLink")
	if got.Name != "itemtype" || value != "SymbolicLink" || !colon || !isParameter || !known {
		t.Errorf("BindWord = %+v, %q, %v, %v, %v", got, value, colon, isParameter, known)
	}
}
