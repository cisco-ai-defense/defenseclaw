// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import "testing"

func TestIsInteractiveUserSID(t *testing.T) {
	cases := []struct {
		sid         string
		legacy      bool // AllowEntraID=false
		withEntraID bool // AllowEntraID=true
	}{
		{"S-1-5-21-1004336348-1177238915-682003330-1001", true, true},
		{"S-1-5-21-1004336348-1177238915-682003330-500", true, true},
		{"s-1-5-21-1-2-3-1001", true, true},
		{"S-1-5-21-1004336348-1177238915-682003330", false, false}, // bare domain
		{"S-1-12-1-3570884736-1162376387-1447295907-1452683434", false, true},
		{"S-1-12-1-3570884736-1162376387-1447295907", false, false},              // too short
		{"S-1-12-1-3570884736-1162376387-1447295907-1452683434-7", false, false}, // too long
		{"S-1-12-2-3570884736-1162376387-1447295907-1452683434", false, false},   // not an Entra user
		{"S-1-5-18", false, false},
		{"S-1-5-19", false, false},
		{"S-1-5-20", false, false},
		{"S-1-5-32-544", false, false},
		{"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", false, false},
		{"S-1-1-0", false, false},
		{"S-1-5-21-1-2-3-1001.bak", false, false},
		{"S-1-5-21-1-2-3-01001", false, false},
		{"S-1-5-21-1-2-3-4294967296", false, false},
		{"S-1-5-21-1-2--1001", false, false},
		{"", false, false},
		{"not-a-sid", false, false},
	}
	for _, tc := range cases {
		if got := IsInteractiveUserSID(tc.sid, InteractiveUserSIDOptions{}); got != tc.legacy {
			t.Errorf("IsInteractiveUserSID(%q, legacy) = %t, want %t", tc.sid, got, tc.legacy)
		}
		if got := IsInteractiveUserSID(tc.sid, InteractiveUserSIDOptions{AllowEntraID: true}); got != tc.withEntraID {
			t.Errorf("IsInteractiveUserSID(%q, entra) = %t, want %t", tc.sid, got, tc.withEntraID)
		}
	}
}
