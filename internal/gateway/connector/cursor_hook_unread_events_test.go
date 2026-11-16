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

import (
	"bytes"
	"reflect"
	"sort"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestCursorShellHookUnreadEventsMatchGoRoster keeps the event list of
// cursor_event_unread in cursor-hook.sh equal to cursorHookEvents. A Go event
// missing from the shell list would be denied as unread (exit 2); a shell-only
// name would let an event the hook is not registered for answer {} with exit 0
// (rel-1-0-6:GAP-0337).
func TestCursorShellHookUnreadEventsMatchGoRoster(t *testing.T) {
	want := append([]string(nil), cursorHookEvents...)
	sort.Strings(want)
	for _, tc := range []struct {
		name    string
		managed bool
	}{{"per-user", false}, {"managed", true}} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := renderHookTemplate("cursor-hook.sh", templateData{Managed: tc.managed, ConnectorName: "cursor"})
			if err != nil {
				t.Fatal(err)
			}
			file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(bytes.NewReader(body), "cursor-hook.sh")
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			found := false
			syntax.Walk(file, func(node syntax.Node) bool {
				fn, ok := node.(*syntax.FuncDecl)
				if !ok || fn.Name.Value != "cursor_event_unread" {
					return true
				}
				found = true
				syntax.Walk(fn.Body, func(in syntax.Node) bool {
					item, ok := in.(*syntax.CaseItem)
					if !ok {
						return true
					}
					for _, pattern := range item.Patterns {
						lit := pattern.Lit()
						if lit == "" {
							t.Fatalf("cursor_event_unread has a non-literal pattern at %s", pattern.Pos())
						}
						got = append(got, lit)
					}
					return false
				})
				return false
			})
			if !found {
				t.Fatal("the rendered cursor-hook.sh has no cursor_event_unread function")
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("cursor_event_unread events = %v, want cursorHookEvents %v", got, want)
			}
		})
	}
}
