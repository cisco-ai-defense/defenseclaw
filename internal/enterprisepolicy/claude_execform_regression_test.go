// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestR108ExecFormRenderAndWindowsTwin(t *testing.T) {
	wantArgs := []any{"hook", "--connector", "claudecode", "--enterprise-managed"}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			opts := testOptions(t)
			opts.GOOS = goos
			data, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Hooks map[string][]struct {
					Hooks []map[string]any `json:"hooks"`
				} `json:"hooks"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			for event, groups := range doc.Hooks {
				for _, group := range groups {
					for _, handler := range group.Hooks {
						if handler["command"] != opts.HookBinary || !reflect.DeepEqual(handler["args"], wantArgs) {
							t.Fatalf("%s handler = %v", event, handler)
						}
					}
				}
			}
			if len(doc.Hooks) == 0 {
				t.Fatal("no rendered hook groups")
			}
		})
	}
}
