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

func TestCopyOperandRolesDestination(t *testing.T) {
	rows := []struct {
		name     string
		words    []string
		wantWord int
		attached string
		options  []bool
	}{
		{"last-operand", []string{"a", "b", "d"}, 2, "", []bool{false, false, false}},
		{"separate-target", []string{"-t", "d", "a", "b"}, 1, "", []bool{true, false, false, false}},
		{"attached-target", []string{"-td", "a"}, -1, "d", []bool{true, false}},
		{"cluster-target", []string{"-at", "d", "a"}, 1, "", []bool{true, false, false}},
		{"cluster-attached-target", []string{"-atd", "a"}, -1, "d", []bool{true, false}},
		{"long-target", []string{"--target-directory", "d", "a"}, 1, "", []bool{true, false, false}},
		{"long-attached-target", []string{"--target-directory=d", "a"}, -1, "d", []bool{true, false}},
		{"abbreviated-target", []string{"--target", "d", "a"}, 1, "", []bool{true, false, false}},
		{"sources-before-target", []string{"a", "-t", "d"}, 2, "", []bool{false, true, false}},
		{"last-target-wins", []string{"-t", "x", "-t", "d", "a"}, 3, "", []bool{true, true, true, false, false}},
		{"no-target-directory-option", []string{"--no-target-directory", "a", "d"}, 2, "", []bool{true, false, false}},
		{"end-of-options", []string{"--", "-t", "d"}, 2, "", []bool{true, false, false}},
		{"suffix-value-is-not-target", []string{"-St", "a", "d"}, 2, "", []bool{true, false, false}},
		{"single-dash-is-an-operand", []string{"-", "d"}, 1, "", []bool{false, false}},
		{"no-operand", []string{"-f"}, -1, "", []bool{true}},
	}
	for _, row := range rows {
		word, attached, options := CopyOperandRoles(row.words)
		if word != row.wantWord || attached != row.attached || len(options) != len(row.options) {
			t.Errorf("%s: CopyOperandRoles(%q) = %d, %q, %v; want %d, %q, %v", row.name, row.words, word, attached, options, row.wantWord, row.attached, row.options)
			continue
		}
		for index := range options {
			if options[index] != row.options[index] {
				t.Errorf("%s: CopyOperandRoles(%q) options = %v; want %v", row.name, row.words, options, row.options)
				break
			}
		}
	}
}
