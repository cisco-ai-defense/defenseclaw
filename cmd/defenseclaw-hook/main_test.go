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

package main

import "testing"

func TestIsHookEntrypoint(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "hook", args: []string{"hook", "--connector", "codex"}, want: true},
		{name: "notify", args: []string{"notify", `{}`}, want: true},
		{name: "empty", want: false},
		{name: "daemon command", args: []string{"start"}, want: false},
		{name: "global flag", args: []string{"--version"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHookEntrypoint(tt.args); got != tt.want {
				t.Fatalf("isHookEntrypoint(%q) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
