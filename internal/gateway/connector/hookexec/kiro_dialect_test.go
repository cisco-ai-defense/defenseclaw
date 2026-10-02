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

package hookexec

import (
	"strings"
	"testing"
)

// The hook forwards its --hook-surface value in the generic dialect header
// only for a value the connector lists, so the gateway applies Kiro's v3
// veto set (UserPromptSubmit and PreToolUse) to the .kiro/hooks config.
func TestHookDialectHeaderIsForwardedOnlyForListedValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connector string
		surface   string
		want      string
	}{
		{name: "kiro v3", connector: "kiro", surface: "v3", want: "v3"},
		{name: "kiro unmarked (CLI 2.x agent config)", connector: "kiro", surface: "", want: ""},
		{name: "kiro unlisted value", connector: "kiro", surface: "v9", want: ""},
		{name: "kiro v2 is never rendered", connector: "kiro", surface: "v2", want: ""},
		{name: "other connector", connector: "claudecode", surface: "v3", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := ok(`{"action":"allow"}`)
			run(t, tc.connector, rt, func(o *Options) {
				o.HookSurface = tc.surface
				o.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse"}`)
			})
			if rt.gotReq == nil {
				t.Fatal("no request captured")
			}
			if got := rt.gotReq.Header.Get(HookDialectHeader); got != tc.want {
				t.Fatalf("%s = %q, want %q", HookDialectHeader, got, tc.want)
			}
		})
	}
}
