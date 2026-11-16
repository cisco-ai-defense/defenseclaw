// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// SameAssetName folds case as strings.EqualFold does. The Python twin
// (cli/defenseclaw/enforce/admission.py asset_name_key) is checked against
// the same table in cli/tests/test_admission.py (p0 GAP-1305).
func TestSameAssetNameFoldsLikeThePythonAdmission(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"\u03c3kill", "\u03c2kill", true},
		{"\u03a3kill", "\u03c2kill", true},
		{"MySkill", "myskill", true},
		{"\u212ait", "kit", true},
		{"\u1e9eig", "\u00dfig", true},
		{"caf\u00e9", "CAFE\u0301", true},
		{"\ua7c0kill", "\ua7c1kill", true},
		{"stra\u00dfe", "strasse", false},
		{"\u0130nfo", "info", false},
		{"\u0131nfo", "info", false},
	} {
		if got := SameAssetName(tc.a, tc.b); got != tc.same {
			t.Errorf("SameAssetName(%+q, %+q) = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}
